# Array Index Underflow

_6 reports — High/Critical, disclosed_

### [[MK8DX] Improper metadata validation 2](https://hackerone.com/reports/1812732)

- **Report ID:** `1812732`
- **Severity:** High
- **Weakness:** Array Index Underflow
- **Program:** Nintendo
- **Reporter:** @crazy_man123
- **Bounty:** - usd
- **Disclosed:** 2023-08-17T00:16:48.347Z
- **CVE(s):** -

**Summary (team):**

-

**Summary (researcher):**

# Introduction

This vulnerability impacts:

- Mario Kart 8 Deluxe on the Switch
- Mario Kart 8 on the WiiU

**The vulnerability was fixed for Mario Kart 8 Deluxe the 9 March, 2023 with the release of v2.3.0**
**The vulnerability was fixed for Mario Kart 8 the 3 August, 2023 with the release of v4.2 (or v81 for the internal version)**

---
&nbsp;

The competition/tournaments ([SimpleSearchObject](https://github.com/kinnay/NintendoClients/wiki/Matchmake-Extension-Protocol-(MK8D)#simplesearchobject-structure)) contains a 'metadata' field, it is used by the game to store tournament data such as:

- Competition name (**ID 2**)
- Description (unused but still exists, **ID 4**)
- Red/Blue team names (if applicable, **ID 7/8** respectively)
- Icon type (**ID 3**)
- etc ...

It's stored with the ``ChunkData`` format: (stored in little endian for MK8DX)

**ChunkData**

| Type     | Description |
| ------------| ----------- |
| uint16_t      | Magic (0x5a5a, 'ZZ' in ASCII)       |
| ChunkDataList[]  | List of chunk data 'list', goes until end marker       |
| uint8_t      | End marker ( 0xff)     |

**ChunkDataList**

| Type     | Description |
| ------------| ----------- |
| uint8_t      | ID       |
| uint16_t  | Length       |
| T    | Any data of size 'length' (previous field)     |

The ``ChunkDataList`` class in the client code can only hold a given range of ID (choosen by the dev, it's an argument of the constructor) the range is ``[0;12[`` for MK8/MK8DX), the parsing code didn't have any range check (at least in production), so any "out-of-range" ID would trigger a read on a nullptr (because it didn't find a buffer with the given ID), triggering a crash of the process/console (depending on the platform).

So if you created a tournament with metadata containing an ID > 11 < 255 it would crash anyone loading your tournament

---
&nbsp;

## Impact

Combined with the bug that allowed to create official competitions, you could crash any players opening the "Tournament" menu

---

### [Array Index Underflow--http rpc](https://hackerone.com/reports/825091)

- **Report ID:** `825091`
- **Severity:** High
- **Weakness:** Array Index Underflow
- **Program:** Monero
- **Reporter:** @minerscan
- **Bounty:** - usd
- **Disclosed:** 2021-10-11T20:35:12.885Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary:
parserse_base_utils.h:197
const unsigned char tmp = isx[(int)*++it];
Int type will cause the array subscript to appear negative and read wrong data, 
Solution:
const unsigned char tmp = isx[(unsigned char)*++it];

## Releases Affected:

  * up to date version on github
## Steps To Reproduce:
[add details for how we can reproduce the issue]

\#include <iostream>
\#include "serialization/keyvalue_serialization.h"
\#include "storages/portable_storage_template_helper.h"
\#include "storages/portable_storage_base.h"

\#ifdef __cplusplus
extern "C"
\#endif
int LLVMFuzzerTestOneInput(const char *data, size_t size) {
  std::string s(data,size);
  try
  {
    epee::serialization::portable_storage ps;
    ps.load_from_json(s);
  }
  catch (const std::exception &e)
  {
    std::cerr << "Failed to load from binary: " << e.what() << std::endl;
    return 1;
  }
  return 0;
}

## Supporting Material/References:

  * seed file attached

## Impact

1.crash
2.leaking of sensitive info

---

### [Signedness issue in ClassInfo message handler leads to RCE on CS:GO client](https://hackerone.com/reports/876719)

- **Report ID:** `876719`
- **Severity:** Critical
- **Weakness:** Array Index Underflow
- **Program:** Valve
- **Reporter:** @teapotd
- **Bounty:** 7500 usd
- **Disclosed:** 2021-05-27T16:53:16.538Z
- **CVE(s):** -

**Summary (team):**

Title:         Signedness issue in ClassInfo message handler leads to RCE on CS:GO client
Scope:         csgo.exe
Weakness:      Array Index Underflow
Severity:      Critical (9.6)
Link:          https://hackerone.com/reports/876719
Date:          2020-05-17 20:31:35 +0000
By:            @chaynik

Details:
Vulnerability
-------------

`CSVCMsg_ClassInfo` message is used by Source Engine to pass information about entity classes. It is described by the following Protobuf:

```
message CSVCMsg_ClassInfo {
    message class_t {
        optional int32 class_id = 1;
        optional string data_table_name = 2;
        optional string class_name = 3;
    }

    optional bool create_on_client = 1;
    repeated .CSVCMsg_ClassInfo.class_t classes = 2;
}
```

The bug is present in `CSVCMsg_ClassInfo` message handler on client. The pseudocode of function that handles this message:

```cpp
bool ProcessClassInfo(CSVCMsg_ClassInfo *msg) {
    ...
    int nClasses = msg->classes_size;
    ClassInfo *pClasses = new ClassInfo[nClasses];
    ...
    for (int i = 0; i < nClasses; i++) {
        class_t *src = msg->classes[i];
        if (src->class_id >= nClasses) { // class_id can be negative!
            ...
            return false;
        }
        ClassInfo *dst = &pClasses[src->class_id];
        ...
    }
    ...
}
```

An array of appropriate size is allocated to hold the received information. The array is indexed by `class_id`, which is improperly sanitized: it can be an arbitrary negative integer. This allows an out of bounds write, which can be exploited to perform remote code execution.

Any Source Engine (and Source 2) game that uses Protobuf network messages should be affected by this vulnerability, including CS:GO and Dota 2. Only CS:GO has been tested.

Exploit details
---------------

The Proof-of-Concept exploit consists of two main phases:

1. ASLR bypass - the bug is used to get base address of `client_panorama.dll`
2. Remote code execution - the bug is used to divert control flow to ROP chain

In order to craft a [ROP](https://en.wikipedia.org/wiki/Return-oriented_programming) chain, attacker needs to know the absolute address of some application module. The [ASLR](https://en.wikipedia.org/wiki/Address_space_layout_randomization) attempts to prevent it by randomizing memory layout.

### Bypassing the ASLR

Source Engine has mechanism that allows server to set and query "cvars" - variables that control various game-related settings. The exploit leverages cvars to steal a pointer to predictable memory location in game process:

1. Spray the heap with entities
    - we want to make heap allocations more predictable
    - if we allocate 500+ entities there is high chance that last of them are side-by-side
2. Delete last 20 entities
    - deallocated data, including pointers to vtables, remains on heap
3. Set some cvar to a string of appropriate length
    - we want it to be allocated in place of old entities
    - we want the vtable pointer of some old entity to be right after the end of the string
4. Use the vulnerability to overwrite null terminator of cvar string
    - we want the class-infos to get allocated next to cvar
    - if we succeed, the cvar string will be extended to contain the vtable pointer
5. Query the cvar string
    - the leaked vtable pointer allows us to calculate `client_panorama.dll` base address

There is one issue with this idea: the client breaks connection after the vulnerability is used, due to some late sanity check. There's an easy way around it though. Server can queue a `retry` command to be executed on client, so the client automatically reconnects.

### Executing code

After succesful pointer leakage, a ROP chain that runs `calc.exe` is crafted using gadgets from `client_panorama.dll`. The RCE is performed as follows:

1. Deliver the ROP chain in `CCSUsrMsg_ShowMenu` user message
    - client stores it in global buffer in `client_panorama.dll`
    - we can easily calculate address to it
2. Spray the heap with entities
    - we want to make heap allocations more predictable
3. Use the vulnerability to overwrite vtable pointer of some entity
    - we want the class-infos to get allocated after last entity
4. The client breaks connection and deallocates entities
    - the fake vtable will divert control flow to our ROP chain
    - the ROP chain will launch Calculator app

Reproduction
------------

The PoC script simulates a malicious CS:GO server. It demonstrates RCE capability on CS:GO client for Windows (version 13752, 2020-05-14 stable release).

1. Download the attached Python 3 script: F831986
2. Run the script (possibly on another host)
3. Start CS:GO client
4. Connect to the malicious server
5. Wait for `calc.exe` to pop up

Similarly as in #470520, Steam browser protocol can be used to launch an attack from web browser:

1. Download the attached Python 3 script: F831986
2. Run the script (possibly on another host)
3. Download attached HTML file - F831987
4. Set address in iframe URL to the malicious server
5. Open downloaded HTML file and confirm `Open steam`
6. Wait for `calc.exe` to pop up

## Impact

An attacker can execute arbitrary code on the computer of anyone who attempts to connect to the server. After successful exploitation an attacker can gain control over victim's computer.

The connection to the server can be initiated manually by the victim or automatically by visiting malicious web site via Steam browser protocol.

The likelihood of victim joining the server via in-game server browser can be greatly improved by faking high player count and further social engineering. Many players sort server list by player amount.

In case of an attack from web browser many users don't need to click `Open steam` and this method requires no further interaction from user - connection will be initiated without confirmation (even game client will be started if it's not running).

---

### [https://██████ vulnerable to CVE-2020-3187 - Unauthenticated arbitrary file deletion in Cisco ASA/FTD](https://hackerone.com/reports/987090)

- **Report ID:** `987090`
- **Severity:** Critical
- **Weakness:** Array Index Underflow
- **Program:** U.S. Dept Of Defense
- **Reporter:** @pwnsauc3_
- **Bounty:** - usd
- **Disclosed:** 2020-10-16T19:52:42.423Z
- **CVE(s):** CVE-2020-3187

**Vulnerability Information:**

Hi team , while testing i found a host ip https://█████████ which belong to DoD (██████████.mil) running web services interface of Cisco ASA/FTD and it is vulnerable to CVE-2020-3187 - Unauthenticated arbitrary file deletion in Cisco ASA/FTD. An attacker could exploit this vulnerability by sending a crafted HTTP request containing directory traversal character sequences. An exploit could allow the attacker to view or delete arbitrary files on the targeted system. When the device is reloaded after exploitation of this vulnerability, any files that were deleted are restored. The attacker can only view and delete files within the web services file system.

Vulnerable IP : https://█████████
i did a whois search on it and it confirmed it belongs to DoD as you seen below

████

Steps to Reproduce
-----------------------------
go to https://████

█████

you will be redirected to SSL VPN service and you will see a web services interface of Cisco ASA/FTD. In above pic you can see the page we are looking at a web service which is vulnerable to CVE 2020-3187 and you can also see the certificate which indicates that this belongs to █████.mil.

Proof of Concept
-------------------------
Now we know that in CVE-2020-3187 - Unauthenticated arbitrary file deletion in Cisco ASA/FTD. This allow the attacker to view or delete arbitrary files on the targeted system
In this we can delete the files. For example the logo file present on the server at https://████/+CSCOU+/csco_logo.gif can be deleted by the following steps

This can be done by sending a curl request as : curl -H "Cookie: token=../+CSCOU+/csco_logo.gif" https://target/+CSCOE+/session_password.html

1. To delete this just hit the following command on your terminals.
```
curl -H “Cookie: token=../+CSCOU+/csco_logo.gif” https://█████/+CSCOE+/session_password.html
```
If that did not work because sometimes logo.gif/png has permission issues so try this "https://██████/+CSCOE+/blank.html"

2. You can also delete the file "/+CSCOE+/blank.html" (an empty HTML file), as it might be a problem with the permission of the custom logo file sometimes logo.gif has permission issue so we might not be able to delete but we can delete other files

After, this the files ( logo and blank html page ) will be deleted from the server, for better demonstration check out this video :

- https://video.twimg.com/ext_tw_video/1286808440271183873/pu/vid/1270x720/8tccA2VgHV9TDtW4.mp4

Warning : This can lead to a denial of service (DOS) on the VPN by deleting the lua source code files from the file system, which will break the WebVPN interface until the device is rebooted.

Now i haven't deleted the logo file because i didn't wanted to cause any damage so i used another method which can help us confirming that target is vulnerable to this without causing damage and for that just check if "/+CSCOE+/session_password.html" endpoint exists, and it gives "200 OK" status, then it should be vulnerable because this affected endpoint has been removed from the patched versions.

I sent a curl request to check and it gave 200 ok as shown below:

█████

In a nutshell:
```
/+CSCOE+/session_password.html -> 200 = Vulnerable
/+CSCOE+/session_password.html -> 404 = Patched
```
because in patched versions this /+CSCOE+/session_password.html file is removed and you will not see it so if it is showing 200 ok then it is vulnerable as you have seen in above pic where it shows a 200 ok while curl request to

curl -kI https://█████/+CSCOE+/session_password.html

Mitigation/Remediation Actions
--------------------------------------------
Upgrade the ASA software version per the referenced advisory. This advisory is available at the following link:
https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-asaftd-path-JE3azWw43

Reference
----------------
https://twitter.com/aboul3la/status/1286809567989575685
https://medium.com/@parasarora06/hunting-for-cve-2020-3187-2020-3452-9f0dcc66f4d8
https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-asaftd-path-JE3azWw43
http://packetstormsecurity.com/files/158648/Cisco-Adaptive-Security-Appliance-Software-9.7-Arbitrary-File-Deletion.html

## Impact

High - This vulnerability allows the attacker to delete files within the web services file system.

---

### [Unchecked weapon id in WeaponList message parser on client leads to RCE](https://hackerone.com/reports/513154)

- **Report ID:** `513154`
- **Severity:** Critical
- **Weakness:** Array Index Underflow
- **Program:** Valve
- **Reporter:** @nyancat0131
- **Bounty:** 3000 usd
- **Disclosed:** 2019-09-17T17:34:14.845Z
- **CVE(s):** -

**Vulnerability Information:**

Let's look at WeaponList message parser code in the HLSDK:
``` cpp
int CHudAmmo::MsgFunc_WeaponList(const char *pszName, int iSize, void *pbuf )
{
	BEGIN_READ( pbuf, iSize );
	
	WEAPON Weapon;

	strcpy( Weapon.szName, READ_STRING() );
	Weapon.iAmmoType = (int)READ_CHAR();	
	
	Weapon.iMax1 = READ_BYTE();
	if (Weapon.iMax1 == 255)
		Weapon.iMax1 = -1;

	Weapon.iAmmo2Type = READ_CHAR();
	Weapon.iMax2 = READ_BYTE();
	if (Weapon.iMax2 == 255)
		Weapon.iMax2 = -1;

	Weapon.iSlot = READ_CHAR();
	Weapon.iSlotPos = READ_CHAR();
	Weapon.iId = READ_CHAR();
	Weapon.iFlags = READ_BYTE();
	Weapon.iClip = 0;

	gWR.AddWeapon( &Weapon );

	return 1;
}
```

And `WeaponResource::AddWeapon`:

``` cpp
void AddWeapon( WEAPON *wp ) 
{ 
		rgWeapons[ wp->iId ] = *wp;	
		LoadWeaponSprites( &rgWeapons[ wp->iId ] );
}
```
There are no boundary check, and the range of `iId` is `[-128, 128)`, so I can modify many things in the data section.

In `client.dll`, there's an object called `gEngfuncs`, it is a function table that has various functions of the engine. After some calculations on latest CS 1.6 `client.dll`, I concluded that this function table could be overwritten using the above bug.

I have attached a PoC that will pop `calc.exe` on latest CS 1.6 client when connected to malicious server. The AMXX plugin will catch `InitHUD` message, and send crafted `WeaponList` message to overwrite the address of function used in `HUD_DirectorMessage` to execute client cmds to a ROP gadget that will trigger the chain sent in the next `SendCmd` call. To overwrite that address, I used a crafted weapon sprite list (`weapon_pwn.txt`) (see `WEAPON` struct, file `cl_dll/ammo.h` in the HLSDK).

## Impact

Since it's RCE, attacker can do almost anything that don't require higher privilege (ex. compromise account, inject malware, ...)

---

### [Your page has 2 blocking CSS resources. This causes a delay in rendering your page.](https://hackerone.com/reports/365968)

- **Report ID:** `365968`
- **Severity:** Critical
- **Weakness:** Array Index Underflow
- **Program:** Node.js
- **Reporter:** @joy261
- **Bounty:** - usd
- **Disclosed:** 2018-07-15T19:34:10.174Z
- **CVE(s):** -

**Summary (team):**

This report was not deemed to be a security vulnerability and the reporter was asked to open an issue upstream to fix publicly.

---
