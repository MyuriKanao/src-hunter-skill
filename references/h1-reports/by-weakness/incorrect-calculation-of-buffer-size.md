# Incorrect Calculation of Buffer Size

_2 reports — High/Critical, disclosed_

### [Zip bomb](https://hackerone.com/reports/263663)

- **Report ID:** `263663`
- **Severity:** Critical
- **Weakness:** Incorrect Calculation of Buffer Size
- **Program:** Tor
- **Reporter:** @zerx
- **Bounty:** - usd
- **Disclosed:** 2023-11-28T09:01:49.763Z
- **CVE(s):** -

**Vulnerability Information:**

Hi, if you go to this site https://blog.haschek.at/tools/bomb.php
 from Tor Browser, the Tor browser hangs along with the system.

---

### [size_t-to-int vulnerability in exFAT leads to memory corruption via malformed USB flash drives](https://hackerone.com/reports/1340942)

- **Report ID:** `1340942`
- **Severity:** High
- **Weakness:** Incorrect Calculation of Buffer Size
- **Program:** PlayStation
- **Reporter:** @theflow0
- **Bounty:** 10000 usd
- **Disclosed:** 2022-09-21T19:06:48.490Z
- **CVE(s):** -

**Summary (team):**

## Summary

A heap-based buffer overflow can be triggered by a malformed exFAT USB flash drive. 

## Vulnerability

The vulnerability is in Sony's exFAT implementation where there is an integer truncation from 64bit to 32bit on a size variable that is used to allocate the up-case table:

```c
int UVFAT_readupcasetable(void *unused, void *fileSystem) {
  ...
  size_t dataLength = *(size_t *)(upcaseEntry + 24);
  size_t size = sectorSize + dataLength - 1;
  size = size - size % sectorSize;
  uint8_t *data = sceFatfsCreateHeapVl(0, size);
  ...
  while (1) {
    ...
    UVFAT_ReadDevice(fileSystem, offset, sectorSize, data);
    ...
    data += sectorSize;
    ...
  }
}
```

Namely, `dataLength` and `size` are both 64bit wide, however the `size` argument of `sceFatfsCreateHeapVl()` is 32bit wide:

```c
void *sceFatfsCreateHeapVl(void *unused, int size) {
  return malloc(size, M_EXFATFSPATH, M_WAITOK | M_ZERO);
}
```

When using a big size for `dataLength`, this function will therefore only allocate a small buffer, and as a result overflow and corrupt subsequent objects on the heap when calling `UVFAT_ReadDevice()`.

For example, using `sectorSize=0x200` and `dataLength=0x100000200` we have:

```
    size = (sectorSize + dataLength - 1) - (sectorSize + dataLength - 1) % sectorSize;
<=> size = (0x200 + 0x100000200 - 1) - (0x200 + 0x100000200 - 1) % 0x200;
<=> size = 0x1000003FF - 0x1FF;
<=> size = 0x100000200;
```

When passing this size to `sceFatfsCreateHeapVl()`, the leading 1 is cut off to `0x200`.


## Exploitation

This vulnerability allows us to allocate any buffer on the heap with size >= 512 and multiple of 512, and allows us to overflow by a multiple of 512. There are interesting objects that one could spray on the heap such as `struct usb_endpoint` which contain interesting pointers that one could corrupt.


## Impact

Jailbreak the PS4/PS5 by plugging in the USB and directly getting kernel code execution.

---
