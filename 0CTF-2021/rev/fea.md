# fea

**Authors:** gallileo, null
**Tags:** rev, obfuscation
**Points:** 458
**Description:**
> nc 111.186.58.164 30212

Only a netcat connection as description for a rev challenge, off to a good start I see. After connecting and solving the POW[^1], we receive the following:

```
[1/3]
Here is your challenge:

f0VMRgIBAQAAAAAAAAAAAAIAPgAB...

Plz beat me in 10 seconds X3 :)
```

So it seems that this is a twist on the old automatic exploitation challenge :).
I wrote a quick script to collect as many samples as possible, thinking that maybe they were just cycling a few different binaries:

```python
class chal_info:
    def __init__(self, idx, md5):
        self.md5 = md5
        self.occurrences = 1
        self.idx = idx

    def did_see(self):
        self.occurrences += 1

    @property
    def filename(self):
        return os.path.join("samples", f"chal_{self.idx}")

idx = 0
chals: Dict[str, chal_info] = {}
while True:
    try:
        io = start()

        proof_of_work_line = io.recvline(keepends=False).decode("utf-8")
        io.recvline()
        hashable_suffix = re.search('sha256\(XXXX\+(.*)\) ==', proof_of_work_line).group(1)
        hash = re.search('== (.*)', proof_of_work_line).group(1)
        log.info("Solving POW %s for %s", hashable_suffix, hash)
        proof = solve_proof_of_work(hashable_suffix, hash)
        io.sendline(proof)
        io: tube

        import base64

        def read_challenge():
            io.readuntil("Here is your challenge:")
            # swallow 2 newlines
            io.recvline()
            io.recvline()
            challenge = io.recvline()
            return base64.b64decode(challenge)

        chal = read_challenge()

        chal_md5 = hashlib.md5(chal).hexdigest()
        if chal_md5 in chals:
            chals[chal_md5].did_see
        else:
            info = chal_info(idx, chal_md5)
            idx += 1
            chals[chal_md5] = info
            with open(info.filename, "wb") as f:
                f.write(chal)

        log.info("Statistics:")
        for key, chal in chals.items():
            print(f"\t{chal.filename}: #{chal.occurrences} ({chal.md5})")


        io.close()
    except:
        log.warning("Had an error")
```

I started analyzing one of the binaries in my favourite disassembler. `main` looked pretty bad and the other functions didn't look pretty either:

```c
__int64 __fastcall main(__int64 a1, char **a2, char **a3)
{
  int v3; // esi
  int v4; // ecx
  int v5; // eax
  int v6; // ecx
  int v7; // ecx
  int i; // [rsp+4Ch] [rbp-34h]
  int v10; // [rsp+5Ch] [rbp-24h]
  char *s; // [rsp+60h] [rbp-20h]

  sub_400D90(a1, a2, a3);
  s = (char *)mmap(0LL, 0x100000uLL, 7, 34, -1, 0LL);
  memset(s, 0, 0x100000uLL);
  for ( i = 911436592; ; i = v4 )
  {
    while ( 1 )
    {
      while ( 1 )
      {
        while ( 1 )
        {
          while ( 1 )
          {
            while ( 1 )
            {
              while ( 1 )
              {
                while ( 1 )
                {
                  if ( i == -1611068981 )
                  {
                    perror(aPu);
                    exit(-1);
                  }
                  if ( i != -1554549674 )
                    break;
                  i = 1518786008;
                  usleep(0x186A0u);
                }
                if ( i != -1535510725 )
                  break;
                v10 = sub_404740(&unk_6060D0, 73569LL, s, 0xFFFFFFLL);
                v7 = -1085199925;
                if ( !v10 )
                  v7 = -1611068981;
                i = v7;
              }
              if ( i == -1297152665 )
              {
                perror(a1P);
                exit(-1);
              }
              if ( i != -1085199925 )
                break;
              sub_400EC0();
              i = 1628391944;
              ((void (*)(void))&s[dword_6060C0])();
            }
            if ( i != -122192319 )
              break;
            sub_400EC0();
            i = 1518786008;
          }
          if ( i != 610093714 )
            break;
          v5 = sub_4014E0();
          v6 = -1554549674;
          if ( v5 != dword_6180D0 )
            v6 = 620693745;
          i = v6;
        }
        if ( i != 620693745 )
          break;
        ((void (*)(void))loc_400AC0)();
        i = -1554549674;
      }
      if ( i != 911436592 )
        break;
      v3 = -122192319;
      if ( s == (char *)-1LL )
        v3 = -1297152665;
      i = v3;
    }
    if ( i != 1518786008 )
      break;
    v4 = -1535510725;
    if ( !dword_6180CC )
      v4 = 610093714;
  }
  munmap(s, 0x100000uLL);
  return 0LL;
}
```

I also noticed that the strings must be encrypted, because one of the functions was doing a `sprintf` without any format specifiers in a weird looking string:

```c
snprintf(s, 0x400uLL, &byte_618040, v8);
char byte_618040[16] =
{
  '\xE6', '\xB9', '\xBB', '\xA6', '\xAA', '\xE6', '\xEC', '\xAD', '\xE6', '\xAA', '\xA4', '\xAD', '\xA5', '\xA0', '\xA7', '\xAC'
};

```

One xref later, we found an init function that decrypts the string. Some IDA scripting later, and we can decrypt the strings in the binary:

```python
import idaapi
import ida_segment
import logging
log = logging.getLogger("decrypt_strings")

def do_init_array():
    seg: idaapi.segment_t = ida_segment.get_segm_by_name(".init_array")
    log.info("Found init_array: 0x%x - 0x%x", seg.start_ea, seg.end_ea)
    funcs = []
    ea = seg.start_ea
    idx = 1
    while ea != idaapi.BADADDR and ea < seg.end_ea:
        func_addr = idaapi.get_qword(ea)
        funcs.append(func_addr)
        idaapi.set_name(func_addr, f"init{idx}")
        ea += 8
        idx += 1
    return funcs

init_funcs = do_init_array()

dec_loop_size = 0x43
dec_addr_off = 0x12
dec_key_off = 0x18
dec_size_off = 0x26
import idc

def decrypt_string(loop_start):
    log.info("Decrypting string@0x%x", loop_start)
    mov_insn = idaapi.insn_t()
    xor_insn = idaapi.insn_t()
    sub_insn = idaapi.insn_t()
    idaapi.decode_insn(mov_insn, loop_start+dec_addr_off)
    idaapi.decode_insn(xor_insn, loop_start+dec_key_off)
    idaapi.decode_insn(sub_insn, loop_start+dec_size_off)
    addr = mov_insn.Op2.addr
    key = xor_insn.Op2.value
    size = sub_insn.Op2.value
    log.info("Decrypting string @ 0x%x of size 0x%x", addr, size)
    dec_str = ""
    for i in range(size+1):
        car = idaapi.get_byte(addr + i)
        dec_car = (car ^ key) & 0xff
        dec_str += chr(dec_car)
        idaapi.patch_byte(addr + i, dec_car)

    idaapi.create_strlit(addr, 0, 0)

    log.info("Decrypted string: %s", dec_str)

def decrypt_strings():
    decrypt_string_func = init_funcs[0]
    log.info("Decrypt strings@0x%x", decrypt_string_func)
    curr = decrypt_string_func
    for i in range(8):
        decrypt_string(curr)
        curr += dec_loop_size

decrypt_strings()
```

Turns out the strings were not so useful after all, they are just used for anti debugging. Basically, the binary checks whether the command line is one of `gdb`, `strace`, `ltrace` or `linux_server64`, and if yes, enters infinite recursion.

However, I also found another interesting looking init function:

```c
__int64 init4()
{
  __int64 result; // rax
  int v1; // esi
  unsigned int i; // [rsp+2Ch] [rbp-14h]
  void *s; // [rsp+30h] [rbp-10h]

  signal(14, sub_400AF0);
  alarm(1u);
  dword_6180D0 = sub_4014E0();
  s = mmap((void *)0xDEAD0000LL, 0x1000uLL, 3, 34, -1, 0LL);
  memset(s, 0, 0x1000uLL);
  for ( i = 691787201; ; i = v1 )
  {
    result = i;
    if ( i == -794482235 )
      break;
    if ( i == 397321255 )
    {
      perror(a1P);
      exit(-1);
    }
    v1 = -794482235;
    if ( s == (void *)-1LL )
      v1 = 397321255;
  }
  return result;
}

```
It seems to install a SIGALARM handler and also mmaps `0xDEAD0000`. The SIGALARM handler basically just sets a variable, such that main can advance. While this looked a lot nicer, it was still clearly obfuscated. I remembered reading about similar obfuscation and there being an IDA plugin that can help with that.

I found the plugin again and it proved to be quite useful: https://eshard.com/posts/d810_blog_post_1/

With the plugin installed and configured correctly (make sure to turn off the rules about global variables), functions suddenly looked perfectly fine again:

```c
__int64 __fastcall main(__int64 a1, char **a2, char **a3)
{
  char *s; // [rsp+60h] [rbp-20h]

  sub_400D90();
  s = (char *)mmap(0LL, 0x100000uLL, 7, 34, -1, 0LL);
  memset(s, 0, 0x100000uLL);
  sub_400EC0();
  while ( !dword_6180CC )
  {
    if ( (unsigned int)sub_4014E0() != dword_6180D0 )
      ((void (*)(void))loc_400AC0)();
    usleep(0x186A0u);
  }
  sub_404740(&unk_6060D0, 73569LL, s, 0xFFFFFFLL);
  sub_400EC0();
  ((void (*)(void))&s[dword_6060C0])();
  munmap(s, 0x100000uLL);
  return 0LL;
}
```

After some basic analysis using our newly found powers, we can see that main is very simple:

```c
__int64 __fastcall main(__int64 a1, char **a2, char **a3)
{
  void (__fastcall **s)(__int64); // [rsp+60h] [rbp-20h]

  setup();
  s = (void (__fastcall **)(__int64))mmap(0LL, 0x100000uLL, 7, 34, -1, 0LL);
  memset(s, 0, 0x100000uLL);
  check_for_debugger();
  while ( !did_alarm )
  {
    if ( (unsigned int)count_breakpoints() != init_num_bps )
      ((void (*)(void))probably_crash)();
    usleep(0x186A0u);
  }
  unpack(some_buf, 72638, (char *)s, 0xFFFFFF);
  check_for_debugger();
  ((void (*)(void))((char *)s + entry_off))();
  munmap(s, 0x100000uLL);
  return 0LL;
}
```

`setup` sets up buffering, gets pid and checks the command line. It also installs the following interesting SIGTRAP handler:

```c
void handler()
{
  MEMORY[0xDEAD0000] ^= 0xDEADBEEF;
}
```

At first, I thought this was just another anti debugging technique, but as it turns out later, this is used in the binary.
Next, we see that it just waits for the first alarm, then unpacks a buffer and executes it (at an offset). My team mate started working on an unpacker. He said "the source code is self documenting", so here you go ;):

```python
#!/usr/bin/env python3


def unpack(binary):
    packed_full = binary[0x60d0:] # TODO: find real size
    unpacked = bytearray()

    # the packed data is always consumed linearly, so just "eat" prefixes to avoid annoying index calc
    packed = packed_full

    def eat(n):
        nonlocal packed
        val = packed[:n]
        packed = packed[n:]
        return val

    def eat_byte():
        return eat(1)[0]

    firsthigh = packed[0] >> 5
    assert firsthigh == 0 or firsthigh == 1
    big_chungus = (firsthigh == 1)
    assert big_chungus # could remove this assert, but it seems like every chal is actually big chungus

    # remove high bits from very first byte to treat it like a regular memcpy
    packed = bytes([packed[0] & 0x1f]) + packed[1:]

    def eat_size():
        # yeah, this is shitty code
        if big_chungus:
            eaten = eat_byte()
            result = eaten
            while eaten == 0xff:
                # print("BIG CHUNGUS SIZE")
                eaten = eat_byte()
                result += eaten
            return result
        else:
            return eat_byte()
            

    # this ends up reading more than the size of the original packed buffer, which means it produces garbage at the end.
    # we probably don't care, but TODO: possibly fix this
    while len(packed):
        firstbyte = eat_byte()
        high, low = firstbyte >> 5, firstbyte & 0x1f
        # print(high, low) 
        if high == 0:
            # simple memcpy
            size = low + 1
            unpacked += eat(size)
        else:
            if high == 7: # all bits set
                size = (high - 1) + eat_size() + 3
            else:
                size = (high - 1) + 3
            least_sig_offset = eat_byte()
            rel_offset = -(least_sig_offset + 1 + 0x100*low)
            # print("size ", size)
            if big_chungus and least_sig_offset == 0xff and low == 0x1f:
                # print("BIG CHUNGUS OFFSET")
                most_sig = eat_byte()
                least_sig = eat_byte()
                rel_offset = -(0x2000 + (most_sig << 8) + least_sig)
            
            # print("rel offset ", rel_offset, "; size", size, "; copied", len(unpacked))
            assert -rel_offset <= len(unpacked)
            offset = rel_offset + len(unpacked)
            # existing = unpacked[offset:offset+size]
            # unpacked += existing.ljust(size, b"\x00")
            # weird memmove aliasing behavior means we need to copy byte by byte
            for i in range(size):
                unpacked += bytes([unpacked[offset + i]])
    return unpacked

if __name__ == "__main__":
    filename = "chals/chal_16"
    binary = open(filename, 'rb').read()
    unpacked = unpack(binary)
    open(filename + "__unpacked", "wb").write(unpacked)


```

In case the source code isn't quite as self-documenting as he claimed:

- In every binary, the packed data always starts at a constant offset `0x60d0`. This makes it easy to extract. While the length varies by some amount (and could be extracted from the binary), it turned out to be sufficient to simply decode as much as we can and ignore the excess.
- We're not sure if the format of the packed data is well-known somehow (or a variant of something well-known), but it's fairly simple either way.
- The packed data consists of a sequence of what we will call *chunks*. The 3 most significant bits of the  first byte of a chunk determine its type:
    - If they're 0, this is a simple "constant" chunk. The size is determined by least significant 5 bits plus 1, i.e. `(firstbyte & 0x1f) + 1` bytes of data follow, which are copied into the output.
    - If they're non-zero, the chunk references a certain amount of bytes *from the output that was already written, relative to the end of the output buffer*. Both the size and the relative offset are encoded in a variable-length scheme.
        - The contents of the output buffer are `memmove`d instead of `memcpy`'d. Special care has to be taken for cases where the source and destination memory ranges overlap, which can and does happen.
- The very first chunk is always treated as constant data. Its 5 most significant bits instead set what we call the `big_chungus` flag (`True` if they are equal to 1, `False` if 0, error of they're set to anything else). This flag appears to enable some additional variable-length encoding of sizes and offsets, and always seems to be set to true in the binaries we were given. The unpacking function in the binary, `sub_404740`, in fact calls two different functions; the big-chungus-enabled `sub_403E50` or the apparently unused `sub_402760`.

I patched out the anti debugging checks and signal handlers and started debugging.
I dumped the unpacked code into a binary file and loaded it into IDA once again.
I also continued debugging the unpacked code. It was really annyoing to debug and statically analyze, since most functions have the following snippet interspersed every few instructions:

```x86asm
nullsub_428:
    ret

call    nullsub_428
call    sub_2258E

sub_2258E:
    add     qword ptr [rsp+0], 1
    retn
```

Basically, this skips over the byte after the second call and hence IDA cannot really reconstruct the control flow / figure out where instructions are. However, this is nothing a little IDA scripting can't fix ;):

```python
import binascii
import idaapi
import ida_funcs
import ida_bytes
import idc
import logging
log = logging.getLogger("patching")

shitty_func = binascii.unhexlify("4883042401C3")

def run(start, end):
    log.info("Running from 0x%x - 0x%x", start, end)
    curr = start
    while curr != idaapi.BADADDR and curr < end:
        # make code
        # idaapi.del_items(curr)
        insn = idaapi.insn_t()
        ret = idaapi.create_insn(curr, insn)
        if ret == 0:
            idaapi.del_items(curr, 8)
            idaapi.del_items(curr+1, 8)
            ret = idaapi.create_insn(curr, insn)
            if ret == 0:
                log.error("Failed to create instruction at 0x%x", curr)
                return
        # insn_size = ret
        next_ea = idaapi.get_first_cref_from(curr)
        # if call, check if skip next byte
        if idaapi.is_call_insn(insn):
            call_addr = insn.Op1.addr
            is_skip = True
            log.info("Shitty func: %s", shitty_func.hex())
            for i, c in enumerate(shitty_func):
                if idaapi.get_byte(call_addr + i) != c:
                    log.info("Mismatched")
                    is_skip = False
                    break
            if is_skip:
                log.info("Identified skip call @ 0x%x", curr)
                idaapi.patch_byte(curr, 0xe9)
                idaapi.patch_byte(curr + 1, 0x01)
                idaapi.del_items(curr)
                idaapi.create_insn(curr, insn)
                next_ea += 1
                log.info("Next ea: 0x%x", next_ea)
                # return
        curr = next_ea
        # patch to jmp rel
        # else inc curr

run(0x0, 0x222C8)
```

Basically, this goes through the instructions and if it sees a call to such a function, it patches it with a jmp to the next byte. Armed with this and debugging some more, it becomes apparent what the function does (manual decompilation):

```c
int user[2];
int final[2] = {};

read(0, user, 8);
sub_223F3(user);
sub_0(final);
if (final[0] == user[0] && final[1] == user[1]) {
    puts("Right!");
} else {
    puts("Wrong!");
}
```

Unfortunately, for the longest time, I thought that sub_0 was getting called with our input and not zeroes (more on that later). In any case, I tried running angr on it, but it seemed to not really work. One issue was that sub_0 actually has a lot of int 3 instructions. I tried doing the following to implement the sighandler from the binary, but I still didn't get an answer[^2]:

```python
class SimEngineFailure(angr.engines.engine.SuccessorsMixin):
    def process_successors(self, successors, **kwargs):
        state = self.state
        jumpkind = state.history.parent.jumpkind if state.history and state.history.parent else None

        if jumpkind is not None:
            if jumpkind == "Ijk_SigTRAP":
                val = state.mem[0xDEAD0000].dword
                state.mem[0xDEAD0000].dword = val.resolved ^ 0xDEADBEEF
                self.successors.add_successor(state, state.regs.rip, state.solver.true, 'Ijk_Boring')
                self.successors.processed = True
                return

        return super().process_successors(successors, **kwargs)


class UberUberEngine(SimEngineFailure,angr.engines.UberEngine):
    pass

```

So I started reving sub_0 manually (still thinking it depended on our input and hence we would need to know what it does). Unfortunately, even with the patched binary, IDA still didn't want to include all of the function in the function, so some more scripting later, I was finally able to hit decompile on the whole thing:

```python
def find_prev_next(addr):
    res = idaapi.BADADDR
    for i in range(10):
        res = idaapi.get_first_cref_from(addr-i)
        if res != idaapi.BADADDR:
            return res
    return res
    
def append_chunk(curr):
    if idaapi.append_func_tail(f, curr, idaapi.BADADDR):
        print(f.tails.count)
        print(f.tails[f.tails.count-1].start_ea)
        end_ea = f.tails[f.tails.count-1].end_ea
        print(hex(end_ea))
        next_ea = find_prev_next(end_ea)
        return next_ea
    return None
    
for i in range(400):
    curr = append_chunk(curr)
    if curr == idaapi.BADADDR:
        print("ERROR")
        break
```

Before being able to hit F5 and see something, I had to increase the max function size in IDA (this was already very promising), but I finally got to see it in all it's glory:

```c
__int64 __fastcall sub_0(__int64 a1)
{
  v603 = *(_DWORD *)a1 ^ *(_DWORD *)(a1 + 4);
  nullsub_1(a1);
  dword_DEAD0000 = v603 - 471 + 261;
  __debugbreak();
  v604 = (((dword_DEAD0000 - 396) & 0x7D ^ 0xCA | 0x1E1u) >> 2) | (((dword_DEAD0000 - 396) & 0x7D ^ 0xCA | 0x1E1) << 6);
  nullsub_2();
  nullsub_3();
  dword_DEAD0000 = v604 / 0x1DF / 0x2E % 0x34;
  __debugbreak();
  v605 = (((unsigned int)dword_DEAD0000 >> 2) | (dword_DEAD0000 << 6)) % 0x25;
  nullsub_4();
  dword_DEAD0000 = ((((v605 - 292) % 0x16A) | 0x30) + 208) & 0x22;
  __debugbreak();
  dword_DEAD0000 = (((dword_DEAD0000 + 137) | 0xB9) ^ 0x166) + 67;
  __debugbreak();
  dword_DEAD0000 = (8 * (dword_DEAD0000 & 0x19E)) | ((unsigned __int16)(dword_DEAD0000 & 0x19E) >> 5);
  __debugbreak();
  v1 = (unsigned int)dword_DEAD0000 >> 5;
  v606 = ((((((unsigned int)v1 | (8 * dword_DEAD0000)) ^ 0x1D8 | 0x33) + 87) % 0x2A / 0x1C5) ^ 0x25) % 0x7B;
  // ---------------------------------
  // ... around 2500 lines of this lol
  // ---------------------------------
  v602 = ((797940 * ((((unsigned int)v251 | (16 * v601)) + 293) & 0x1B6) - 477) << 6) | ((797940
                                                                                        * ((((unsigned int)v251 | (16 * v601))
                                                                                          + 293) & 0x1B6)
                                                                                        - 477) >> 2);
  v723 = (((2 * v602) | (v602 >> 7)) >> 6) | (4 * ((2 * v602) | (v602 >> 7)));
  *(_DWORD *)a1 = v723 - 0x50EF943B;
  result = a1 + 4;
  *(_DWORD *)(a1 + 4) = v723 - 0x6F1DB3B;
  return result;
}
```

Obviously, this was not going to be possible to reverse by hand. However, it seemed to be just constant operations. Just for the fun of it, I added two rules to the aforementiond deobfuscation plugin:

- replace nullsubs with nops
- replace __debugbreak with `*0xDEAD0000 ^= 0xDEADBEEF`

I did this by adding the following to `chain_rules.py`:

```python
class NullSubChain(ChainSimplificationRule):
    DESCRIPTION = "Replace calls to nullsubs with nops"

    def check_and_replace(self, blk: mblock_t, ins: minsn_t):
        if blk is None:
            return None
        mba: mba_t = blk.mba
        if mba.maturity != MMAT_PREOPTIMIZED:
            return None
        if ins.opcode == m_call:
            left: mop_t = ins.l
            if left.t == mop_v:
                name = idaapi.get_name(left.g)
                if "nullsub" in name:
                    chain_logger.info("Found nullsub call at 0x%x", ins.ea)
                    blk.make_nop(ins)
                    return None #??
                
        return super().check_and_replace(blk, ins)

class DebugBreakChain(ChainSimplificationRule):
    DESCRIPTION = "Replace calls to debugbreak with sigtrap handler implementation"

    def check_and_replace(self, blk: mblock_t, ins: minsn_t):
        if blk is None:
            return None
        mba: mba_t = blk.mba
        if mba.maturity != MMAT_PREOPTIMIZED:
            return None
        if ins.opcode == m_call:
            left: mop_t = ins.l
            if left.t == mop_h:
                if left.helper == "__debugbreak":
                    chain_logger.info("Found debugbreak at 0x%x", ins.ea)
                    new_insn = minsn_t(ins.ea)
                    new_insn.opcode = m_xor
                    new_insn.l.make_gvar(0xdead0000)
                    new_insn.l.size = 4
                    new_insn.r.make_number(0xdeadbeef, 4)
                    new_insn.d.make_gvar(0xdead0000)
                    new_insn.d.size = 4
                    return new_insn

        return super().check_and_replace(blk, ins)
```

I was not expecting that much, but after hitting F5 (and waiting like 2 minutes):

```c
__int64 __fastcall sub_0(__int64 a1)
{
  __int64 result; // rax

  dword_DEAD0000 = 0xDEADBEE0;
  *(_DWORD *)a1 = 0x2B106BC4;
  result = a1 + 4;
  *(_DWORD *)(a1 + 4) = 0x750E24C4;
  return result;
}
```

And then I realized, oh our input is constant and hence this just sets our input to the constants seen above. My teammate wrote a quick binary, that mmaps the unpacked shellcode, runs the sub_0 function and prints the resulting values:

```c
#include <stdio.h>
#include <err.h>
#include <sysexits.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <stdint.h>
#include <signal.h>

static int* const deadpage = (void*)0xdead0000;

void handler(int sig) {
    *deadpage ^= 0xdeadbeef;
}

int main(int argc, char** argv) {
    if (argc != 2) {
        errx(EX_USAGE, "usage: %s <unpacked-blob>", argv[0]);
    }

    int fd = open(argv[1], O_RDONLY);
    if (fd < 0) {
        err(EX_NOINPUT, "couldn't open file");
    }

    void *mem = mmap(NULL, 0x100000, PROT_READ | PROT_EXEC, MAP_FILE | MAP_PRIVATE, fd, 0);
    if (mem == MAP_FAILED) {
        err(EX_OSERR, "couldn't map file");
    }

    void *deadmapping = mmap(deadpage, 0x1000, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, -1, 0);
    if (deadmapping == MAP_FAILED) {
        err(EX_OSERR, "couldn't map 0xdead....");
    }
    if (deadmapping != deadpage) {
        // what is MAP_FIXED lol
        errx(EX_OSERR, "couldn't actualy map 0xdead....");
    }

    if (signal(SIGTRAP, handler) != 0) {
        err(EX_OSERR, "couldn't install signal handler");
    }

    int buf[2] = {0};
    ((void(*)(int*))mem)(buf);
    printf("%08x %08x\n", buf[0], buf[1]);
}
```

The final piece of the puzzle left, was function `sub_223F3`, which actually does something with our input. Fortunately, it seems it was exactly the same for every binary. I translated it into z3 and was able to solve for our input (after wasting some time debugging why it wasn't working, because I mistyped v1 as v4):

```python
import z3
from pwn import *

def hiword(val):
    return z3.Extract(31, 16, val)

def loword(val):
    return z3.Extract(15, 0, val)

def toint(val):
    num = val.size()
    if num == 32:
        return val
    return z3.ZeroExt(32-num, val)

def thingy(a, b, cond, c):
    return z3.If(cond != 0,
        toint(a) - toint(b) - (z3.LShR(toint(a) - toint(b), 16)),
        toint(c)
    )

def wtf(num):
    x = z3.BitVecVal(num, 32)
    res = z3.simplify(toint(loword(x)) - toint(hiword(x)) - (z3.LShR(toint(loword(x)) - toint(hiword(x)), 16)))
    return res.as_long()

def do_solve(t1, t2):
    inp = []
    for i in range(2):
        inp.append(z3.BitVec(f'inp_{i}', 32))
    a1 = inp
    v1 = a1[1]
    v2 = 7 * toint(hiword(a1[0]))
    v3 = thingy(loword(v2), hiword(v2), v2, -6 - toint(hiword(a1[0])))
    v4 = a1[0] + 6
    v5 = toint(hiword(v1)) + 5
    v6 = toint(4 * toint(loword(v1)))

    v1 = thingy(loword(v6), hiword(v6), v6, -3 - toint(loword(v1)))

    v7 = toint(3 * toint(loword(v3 ^ v5)))
    v8 = thingy(loword(v7), hiword(v7), v7, -3 - toint(loword(v3 ^ v5)))

    v9 = toint(loword(v8 + (v1 ^ v4)))
    r1 = loword(2*v9)
    r2 = loword(z3.LShR(toint(2*v9), 16))
    v10 = thingy(r1, r2, 2*v9, ~v9)
    s = z3.Solver()
    res1 = (z3.ZeroExt(16, loword(v5 ^ v10)) | ((v10 ^ v3) << 16))
    res2 = ((toint(loword((v10 + v8) ^ v1))) | (((v10 + v8) ^ v4) << 16))
    s.assert_and_track(t1 == res1, "res1")
    s.assert_and_track(t2 == res2, "res2")
    assert s.check() == z3.sat
    m = s.model()
    nums = [m.eval(i).as_long() for i in inp]
    in_val = b""
    for num in nums:
        in_val += p32(num)
    return in_val
```

With all of that done, we can now write our exploit script and get the flag :):

```python
#!/usr/bin/env python
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template --host 111.186.58.164 --port 30212
from pwn import *
from hashlib import sha256
from itertools import product
import re
from pwnlib.tubes.tube import tube
# import pow

# Set up pwntools for the correct architecture
context.update(arch='i386')
exe = './path/to/binary'

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141
host = args.HOST or '111.186.58.164'
port = int(args.PORT or 30212)

def local(argv=[], *a, **kw):
    '''Execute the target binary locally'''
    if args.GDB:
        return gdb.debug([exe] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe] + argv, *a, **kw)

def remote(argv=[], *a, **kw):
    '''Connect to the process on the remote host'''
    io = connect(host, port)
    if args.GDB:
        gdb.attach(io, gdbscript=gdbscript)
    return io

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.LOCAL:
        return local(argv, *a, **kw)
    else:
        return remote(argv, *a, **kw)

# Specify your GDB script here for debugging
# GDB will be launched if the exploit is run via e.g.
# ./exploit.py GDB
gdbscript = '''
continue
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================

def solve_proof_of_work(hashable_suffix, hash) :
    alphabet = (string.ascii_letters + string.digits + '!#$%&*-?')
    for hashable_prefix in product(alphabet, repeat=4) :
        current_hash_in_hex = sha256((''.join(hashable_prefix) + hashable_suffix).encode()).hexdigest()
        if current_hash_in_hex == hash :
            return ''.join(hashable_prefix)


io = start()

proof_of_work_line = io.recvline(keepends=False).decode("utf-8")
io.recvline()
hashable_suffix = re.search('sha256\(XXXX\+(.*)\) ==', proof_of_work_line).group(1)
hash = re.search('== (.*)', proof_of_work_line).group(1)
log.info("Solving POW %s for %s", hashable_suffix, hash)
proof = solve_proof_of_work(hashable_suffix, hash)
io.sendline(proof)
io: tube

import base64

def read_challenge():
    io.readuntil("Here is your challenge:")
    # swallow 2 newlines
    io.recvline()
    io.recvline()
    challenge = io.recvline()
    return base64.b64decode(challenge)

for i in range(3):

    log.info("Downloading challenge %d", i)
    chal1 = read_challenge()
    with open(f"chal{i}", "wb") as f:
        f.write(chal1)

    import unpack
    log.info("Unpacking challenge")
    unpacked = unpack.unpack(chal1)

    with open(f"chal{i}_unpacked", "wb") as f:
        f.write(unpacked)

    log.info("Running wrapper")
    p = process(["./wrapper", f"chal{i}_unpacked"])
    res1 = p.readuntil(" ")
    res1 = int(res1, 16)
    res2 = p.readuntil("\n")
    res2 = int(res2, 16)

    log.info("Targets: 0x%x, 0x%x", res1, res2)

    import do_solve
    sender = do_solve.do_solve(res1, res2)

    io.send(sender)

io.interactive()
```

[^1]: For some reason I tried making a fast GPU based POW solver, turns out it's slower than just python hashlib :face_palm:

[^2]: This was probably for other reasons, angr did manage to work later on.
