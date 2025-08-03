# catharsis

**Authors:** [Leonardo Galli](https://twitter.com/galli_leo_)

**Tags:** rev, cts, windows

**Points:** 420

> hgarrereyn said he would rage quit if I made a windows rev so Have fun! Consider this my catharsis from reversing genshin impact

**Note:** This write up is cut short, because I did not have enough time to properly finish it before the week deadline :(

The description already promised tons of fun and definitely no italian cursing.
Opening the binary in IDA of course further confirmed my suspicion: This was just an elaborate trolling attempt by fellow CTF "player" cts.

![funny_functions](./fns.png)

Deciding that I should maybe do some dynamic analysis as well, I booted up my Windows VM.
Always helpful, Windows in turn decided it was time to install some updates (on a VM image from them directly, intended for developers)

![fml](./windows.png)

Now that we are done setting up our environment, let me give you an overview of the challenge and how much time I spent solving the different parts:

| Description | Time Spent |
|--------------|------------|
| Get Windows VM into a working state | 1h |
| Figure out most of text is encrypted | 10 min |
| Decrypting most of text | 20 min |
| Finding the actual main function | 5h |
| Needlessly reverse C++ STL code | 2h |
| Figure out what exception handling does | 30 min |
| Making main readable by patching anti debugging with nops | 20 min |
| Figuring out that main constructs a JSON object based on flag | 30 min |
| Dump constraints and write solve script | 1h |
| Debug why solve script is slightly off | 2h |

I continued with some static analysis and noticed two exception handlers being installed.
The first is more complicated and will be discussed later.
The second seems to use some decryption scheme.
Seeing as most of the text section was just gibberish in IDA, I deduced that most of text was encrypted.
Using a quick decryption script, I created a binary that was hopefully mostly decrypted.
(Of course it was not that simple in actuality, I spent most of the time needlessly complicating things, by only decrypting pages I was sure where encrypted, instead of just doing most of them directly.)
Said decryption script:

```python
import os
import sys
from pwn import *

def decrypt(page: bytes, vaddr) -> bytes:
    ret = b""
    for i in range(0x1000 // 8):
        val = page[8*i:8*(i+1)]
        val = u64(val)
        key = vaddr ^ ((~i) & 0xffffffffffffffff)
        res = (val ^ key) & 0xffffffffffffffff
        ret += p64(res)
        vaddr += 8
    return ret

inf = "bingus.exe"
outf = "bingus.dec.exe"
data = b""
with open(inf, "rb") as f:
    data = f.read()

head = data[:0x400]
data = data[0x400:]
dec_data = head
DEC_PAGES = list(range(0x01000, 0x53000, 0x1000))
BASE = 0x140000000

max_page = len(data) // 0x1000
last_off = 0
for page in range(max_page):
    off = page*0x1000
    page_data = data[off:off+0x1000]
    vaddr = BASE + off + 0x1000
    if off+0x1000 in DEC_PAGES:
        log.info("Decrypting at 0x%x", off)
        page_data = decrypt(page_data, vaddr)
    dec_data += page_data
    last_off = off+0x1000

dec_data += data[last_off:]

print(hex(dec_data[PATCH_NOP]), hex(PATCH_NOP))

with open(outf, "wb") as f:
    f.write(dec_data)

with open("bingus.final.exe", "wb") as f:
    f.write(dec_data)
```

However, I got got when trying to search for the main function.
I stumbled upon a small function pretty quickly that could have been main, if it were not for the halt immediately in there.
I found the string `'Enter your flag: '` pretty quickly, but no references.
Thinking this was just some windows bullshittery going on, I pressed on and waded through way too many CRT functions in hopes of finding main that way somehow.
In the end, I somehow went back to the function with the halt and actually looked at the disassembly. To my surprise, immediately after the halt, there was a reference to the aforementioned string and I had just uncovered the main function.

After some almost useless C++ STL reversing, I had also finally figured out the purpose of the first exception handler.
It basically acts like some kind of syscall/hvcall thingy magig.
In short, the following happens inside there:

- If current exception is `Privileged Instruction (0xC0000096)` and current instruction is `halt (0xf4)`, then:
    - If did_init = False, then insert halt at the beginning of `HeapAlloc`, `HeapFree` and two more functions, let's dub them `cringe` and `more_cringe`. The original byte at the location the halt was inserted was saved in an `std::unordered_map<off_t, char>`.
    - Otherwise, it would try to find the address of rip in the aforementioned hashmap. If it was found, another function responsible for executing the actual ``syscall'' was called. Depending on what the current instruction pointer is, different things happen, see below. Finally, the original byte is put back, current rip is saved and the processor is single stepped.
- If current exception is `Access Violation (0xC0000005)`, try to find the (page aligned) address inside our other `std::unordered_map`. If found, map a page at the requested address, decrypt the "backing" store to the newly mapped page, save the faulting address to a global and finally single step.
- If the current exception is due to single stepping `(0x80000004)`, check whether the current address was saved by handler of `0xC0000096` or `0xC0000005`.
    - If saved by `0xC0000096`, restore the halt instruction and continue execution.
    - If saved by `0xC0000005`, encrypt the contents of the just mapped page, save it back to the "backing" store and free the mapped page. Then continue execution.

The syscalls are as follows:

| RIP (Function Name) | Description |
|----|----|
| `HeapAlloc` | Modifies heap allocation as follows: We allocate pages instead of stuff on the actual heap. However, we then return an offset from 0 as the address where allocation was done. The address offset from 0 is later translated to the actual allocated page in the above exception handler. This way the backing memory is actually encrypted. The mapping between address offset from 0 and actual page is kept inside another `std::unordered_map` |
| `HeapFree` | Not implemented. |
| `cringe` | Basically just: `return !a1` |
| `more_cringe` | Basically just: `some_global += 0x123; return some_global;` |

Since we don't need to keep the encrypted memory and we just ignore the `cringe` and `more_cringe` functions for now, I just patched out any halts from the binary.
Furthermore, the binary also had a bunch of anti debug and anti vm code, like the following in it:
```c
v33 = 10000i64;
v34 = __rdtsc();
do
{
    _RAX = 1i64;
    __asm { cpuid }
    v52 = __PAIR64__(_RBX, _RAX);
    v53 = _RCX;
    v54 = _RDX;
    --v33;
}
while ( v33 );
v40 = __rdtsc();
v41 = v40 - v34;
if ( (__int64)(v40 - v34) < 0 )
{
    v43 = v41 & 1 | ((v40 - v34) >> 1);
    v42 = (float)(int)v43 + (float)(int)v43;
}
else
{
    v42 = (float)v41;
}
if ( (float)(v42 / 10000.0) < 250.0 )
    break;
if ( ++v32 >= 5 )
{
    memset((void *)((unsigned __int64)v51 & 0xFFFFFFFFFFFFF000ui64), 255, 0xFFFFFFFFFFFFui64);
    __debugbreak();
}
```
So I also patched out those things.
The script to do the patching can be seen below:
```python
import idaapi
import ida_ua
import ida_funcs
import ida_bytes
import ida_allins
import idautils

MAIN_ADDR = 0x140003110

MAIN_END_ADDR = 0x1400174E6

JUST_FYI = 0x140056230

SOME_TIME_ADDR = 0x140071EE8

def info(conts):
    print(f"[*] {conts}")
    # idaapi.msg(f"[*] {conts}")

def dec_insn(addr) -> idaapi.insn_t:
    tmp = idaapi.insn_t()
    l = ida_ua.decode_insn(tmp, addr)
    return tmp

curr = MAIN_ADDR

info(f"Starting flow from @ 0x{curr:x}")

ret_insn = dec_insn(MAIN_END_ADDR)

info(f"Ret type: {ret_insn.itype}")

POSS_RETS = [ida_allins.IA64_ret, ida_allins.I960_ret, ida_allins.I196_ret, ida_allins.NN_retn]
info(f"Poss rets: {POSS_RETS}")

NOP_PATTERNS = [
    "E8 64 2C 05 00", # call just fyi
    "83 F8 03 7C 2A 8B 04 24 48 83 EC 10 48 8D 4C 24 30 8B 01 48 81 E1 00 F0 FF FF BA FF 00 00 00 49 B8 FF FF FF FF FF FF 00 00 E8 5A D5 02 00 CC" # haha got you
]

# flow through instructions
# while curr != idaapi.BADADDR and curr <= MAIN_END_ADDR:
    # flags = ida_bytes.get_flags(curr)
    # if (flags & ida_bytes.FF_CODE) == 0:
    #     ret = idaapi.create_insn(curr)
    #     if ret == 0:
    #         info(f"Failed to create instr @ 0x{curr:x}")
        # print("not marked as code!")
    # ins = dec_insn(curr)
    # if ins.itype == idaapi.NN_call:
    #     call_addr = ins.Op1.addr
    #     if call_addr == JUST_FYI:
    #         patch = b"\x48\x31\xc0"
    #         patch = patch.ljust(ins.size, b"\x90")
    #         ida_bytes.patch_bytes(curr, patch)
    # if ins.itype == idaapi.NN_retn:
    #     info(f"Encountered ret @ 0x{curr:x}")
    #     break
    # if ins.itype == ida_allins.NN_hlt:
    #     info(f"Encountered hlt @ 0x{curr:x}")
    #     # patch hlt to nop, should hopefully work?
    #     idaapi.patch_byte(curr, 0x90)
    # update curr
    # curr += ins.size

def find_pat(patt):
    curr = MAIN_ADDR
    while True:
        out = ida_bytes.compiled_binpat_vec_t()
        ida_bytes.parse_binpat_str(out, curr, patt, 16)
        curr = ida_bytes.bin_search(curr, MAIN_END_ADDR, out, ida_bytes.BIN_SEARCH_FORWARD | ida_bytes.BIN_SEARCH_CASE)
        if curr == idaapi.BADADDR:
            break
        yield curr
        curr += 1


import binascii

def nop_pattern(patt):
    info(f"nopping pattern {patt}")
    curr = MAIN_ADDR
    patt_b = binascii.unhexlify(patt.replace("?", "00").replace(" ", ""))
    while True:
        out = ida_bytes.compiled_binpat_vec_t()
        ida_bytes.parse_binpat_str(out, curr, patt, 16)
        curr = ida_bytes.bin_search(curr, MAIN_END_ADDR, out, ida_bytes.BIN_SEARCH_FORWARD | ida_bytes.BIN_SEARCH_CASE)
        if curr == idaapi.BADADDR:
            break
        patch_size = len(patt_b)
        for off in range(patch_size):
            ida_bytes.patch_byte(curr + off, 0x90)

# for pat in NOP_PATTERNS:
#     nop_pattern(pat)

first_marker = "0F 31 48 C1 E2 20 48 0B C2"
pattern_start_act = binascii.unhexlify("488B068B0C07")

for first_addr in find_pat(first_marker):
    info(f"Found marker @ 0x{first_addr:x}")
    unique_addr = first_addr + 0x10
    cmp_insn = dec_insn(unique_addr)
    if cmp_insn.itype == ida_allins.NN_cmp and cmp_insn.Op2.value == 0x5F5E100:
        info(f"Found compare, looking gucci")
        pattern_start = first_addr - 0x3f
        start_bs = ida_bytes.get_bytes(pattern_start, len(pattern_start_act))
        if pattern_start_act == start_bs:
            info(f"Found start, looking very good")
            end_addr = first_addr + 0x5e
            end_insn = dec_insn(end_addr)
            act_end_addr = end_addr + end_insn.size
            if end_insn.itype == ida_allins.NN_mov and end_insn.Op1.addr == SOME_TIME_ADDR:
                info("yep we gucci here!")
                # patch everything in between with nops!
                num_bytes = act_end_addr - pattern_start
                ida_bytes.patch_bytes(pattern_start, b"\x90"*num_bytes)
```

After all of that, the basic idea behind the main function became pretty clear.
It converts the input (flag) into a bitstream, iterates over the bitstream to create a json object.
Then it asserts a bunch of constraints on the object.
A python version of the conversion can be found below:
```python
import sys
import binascii
import os
from pwn import *
import json

class Typ:
    Num = 0
    Null = 1
    Bool = 2
    Char = 3

class BitStream:
    def __init__(self, bs: bytes):
        self.bs = bs
        self.bytes = ""
        for b in bs:
            self.bytes += bin(b)[2:].rjust(8, "0")
        
    @property
    def avail(self) -> int:
        return len(self.bytes)

    def _get_bits(self, n: int) -> str:
        head = self.bytes[:n]
        log.debug("head: %s", head)
        self.bytes = self.bytes[n:]
        return head

    def get_bits(self, n: int) -> int:
        assert(n <= self.avail)
        head = self._get_bits(n)
        head = head[::-1]
        return int(head, 2)

def decode(flag: bytes) -> str:
    bs = BitStream(flag)
    prev = None
    curr = None
    while bs.avail >= 15:
        typ = bs.get_bits(2)
        if typ == Typ.Num:
            num = bs.get_bits(12)
            log.info("Num %d", num)
            curr = num
        if typ == Typ.Null:
            log.info("Null")
            curr = None
        if typ == Typ.Bool:
            val = bs.get_bits(1) == 1
            log.info("Bool: %s", val)
            curr = val
        if typ == Typ.Char:
            val = bs.get_bits(6)
            car = chr(32 + val)
            log.info("Char: %s", car)
            curr = car
        idk = bs.get_bits(1)
        if idk == 1:
            key = json.dumps(curr)
            prev = {key: prev}
            log.info("Dict")
        else:
            log.info("Arr")
            prev = [prev, curr]
    return json.dumps(prev, indent=4)

def main():
    flag = input("Enter your flag: ").strip()
    
    log.info("Done with initial: \n%s", decode(flag.encode()))
if __name__ == "__main__":
    main()
```

With all that figured out, I had to somehow get the constraints out of the binary, into a useable form.
Luckily, the constraints had very simple patterns, so I just copied the decompilation of the main function and ran some regexes across it.
The script for extracting constraints and the final solving can be seen below:

```python
import os
import sys
from pwn import *
import re

outf = "check_simple.txt"
inf = "check.cpp"

TYP_CHECK = re.compile(r"!is_(?P<typ>(object|int|string|array|bool|null))", re.IGNORECASE)
SIZE_CHECK = re.compile(r"get_size\(.*\).*(?P<size>\d)", re.IGNORECASE)
STR_DEST = "std::string::~string"
CMP_CHECK = re.compile(r"!= (?P<cmp>(.){2,4}) ", re.IGNORECASE)
GLOB_CHECK = re.compile(r"inc_and_ret_shitty_global\((?P<in>\d+).*\)", re.IGNORECASE)
BOOL_CHECK = re.compile(r"check_rcx_is_0\((?P<in>\d+).{0,2}\)", re.IGNORECASE)


lines = []
with open(inf) as f:
    lines = f.readlines()

out = []

direct = []

mapping = {
    "object": "Obj",
    "array": "Arr",
}

typ = None
next_line_str = False
shitty_global = 0xabc
inc = 0x123
flip = 0
for line in lines:
    m = TYP_CHECK.search(line)
    sm = SIZE_CHECK.search(line)
    gm = GLOB_CHECK.search(line)
    bm = BOOL_CHECK.search(line)
    if m is not None:
        typ = m.group('typ')
        if typ == "object" or typ == "array":
            direct.append(mapping[typ])
            out.append("")
        if typ == "null":
            direct.append("N")
        out.append(f"typ == {typ}")
    elif sm is not None:
        out.append(f"size == {sm.group('size')}")
    elif STR_DEST in line:
        next_line_str = True
    elif next_line_str:
        next_line_str = False
        cm = CMP_CHECK.search(line)
        out.append(f"char == {cm.group('cmp')}")
        direct.append(f"Char({cm.group('cmp')})")
    elif gm is not None:
        inp = int(gm.group('in'))
        shitty_global += inc
        diff = (inp - shitty_global) % 0x1000
        out.append(f"num {diff}")
        direct.append(f"Num({diff})")
    elif bm is not None:
        inp = int(bm.group('in'))
        inp = inp ^ 1
        if inp == 1:
            out.append(f"True")
            direct.append(f"TTrue")
        else:
            out.append(f"False")
            direct.append(f"TFalse")
    

with open(outf, "w") as f:
    f.write("\n".join(out))

print("[")
print(",\n".join(direct))
print("]")
```

```python
import os
import sys
from typing import List, Tuple
from pwn import *
from decomp import BitStream as BS
from decomp import Typ
from decomp import decode
import random

class BitStream:
    def __init__(self) -> None:
        self.bytes = ""

    def write_bits(self, val, n):
        s = bin(val)[2:]
        s = s.rjust(n, "0")
        s = s[::-1]
        self.bytes += s

    @property
    def bs(self):
        ret = b""
        for off in range(0, len(self.bytes), 8):
            val = self.bytes[off:off+8]
            val = val.ljust(8, "0")
            b = int(val, 2)
            ret += bytes([b])
        return ret

class Tok:
    typ: int = 0

    def __init__(self, val) -> None:
        self.val = val

    def enc(self) -> Tuple[int, int]:
        if self.val == 1:
            return (1, 1)
        return (1, 0)

Obj = Tok(1)
Arr = Tok(0)

class Num(Tok):
    typ = Typ.Num

    def enc(self) -> Tuple[int, int]:
        return (12, self.val)

class Null(Tok):
    typ = Typ.Null
    def enc(self) -> Tuple[int, int]:
        return (0, 0)

N = Null(0)

class Bool(Tok):
    typ = Typ.Bool

    def enc(self) -> Tuple[int, int]:
        return (1, 1 if self.val else 0)

TTrue = Bool(1)
TFalse = Bool(0)

class Char(Tok):
    typ = Typ.Char
    def __init__(self, val) -> None:
        self.val = val
        if isinstance(val, str):
            self.val = ord(val)
        self.val = self.val - 32
    def enc(self) -> Tuple[int, int]:
        return (6, self.val)


def encode(tokens: List[Tok]) -> bytes:
    tokens.reverse()
    b = BitStream()
    for tok in tokens:
        if not type(tok) is Tok:
            val = tok.typ
            b.write_bits(val, 2)
        bits, val = tok.enc()
        if bits == 0:
            continue
        b.write_bits(val, bits)
        log.info("bs: %s", b.bytes)
    log.info("bs: %s", b.bytes)
    return b.bs


CURRENT = [
Arr,
Char('K'),
Obj,
N,
Obj,
Char('6'),
Arr,
N,
Arr,
Num(2666),
Obj,
Num(2156),
Obj,
Num(2650),
Arr,
Num(1849),
Obj,
TTrue,
Arr,
Char('L'),
Arr,
N,
Obj,
Num(2179),
Arr,
TTrue,
Arr,
N,
Arr,
Num(360),
Obj,
Char('$'),
Arr,
N,
Arr,
N,
Obj,
Char(74),
Arr,
Num(1045),
Arr,
Num(2504),
Obj,
Char(50),
Obj,
Char('L'),
Obj,
TFalse,
Arr,
TTrue,
Obj,
N,
Arr,
N,
Arr,
Num(3129),
Arr,
Num(3110),
Arr,
TFalse,
Obj,
N,
Obj,
Char('2'),
Obj,
Num(3387),
Obj,
Char('.'),
Obj,
TTrue,
Obj,
Char(52),
Arr,
N,
Obj,
Num(843),
Arr,
TTrue,
Obj,
Num(3049),
Obj,
TTrue,
Obj,
N,
Arr,
Char(91),
Obj,
Num(1117),
Arr,
N,
Obj,
N,
Obj,
Char('Z'),
Obj,
Char(','),
Obj,
N,
Obj,
N,
Arr,
N,
Arr,
Num(3565),
Arr,
Char(':'),
Arr,
TTrue,
Arr,
N,
Obj,
Char(';'),
Obj,
TFalse,
Obj,
N,
Obj,
N,
Obj,
N,
Arr,
Char(54),
Obj,
TTrue,
Obj,
N,
Arr,
Num(319),
Arr,
TFalse,
Obj,
TTrue,
Obj,
N,
Arr,
N,
Obj,
N,
Arr,
Char('>'),
Obj,
Char(84),
Obj,
N,
Obj,
TFalse,
Obj,
Char('<'),
Arr,
N,
Obj,
N,
Obj,
Char('Z'),
Obj,
Char(','),
Obj,
N,
Obj,
TFalse,
Arr,
Char('L'),
Arr,
Num(3628),
Arr,
Char(77),
Obj,
Num(2734),
Arr,
N,
Obj,
Char(41),
Obj,
Num(2005),
Obj,
Char('D'),
Obj,
N,
Arr,
Char(38),
Arr,
Char(92),
Arr,
N,
Obj,
Num(374),
Obj,
Num(2328),
Obj,
TTrue
]
res = encode(CURRENT)

print(res)

with open("sol.json", "w") as f:
    f.write(decode(res))


def test_bs():
    enc = BS(b"ASDFasdf")
    stuff = []
    while enc.avail > 0:
        mx = 12
        if mx > enc.avail:
            mx = enc.avail
        bits = random.randint(1, mx)
        val = enc.get_bits(bits)
        stuff.append((bits, val))

    print(stuff)

    dec = BitStream()
    for bits, val in stuff:
        dec.write_bits(val, bits)

    print(dec.bs)

```