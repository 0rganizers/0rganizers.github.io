# Very Long Flag Validator

**Author**: TheBadGod

**Tags:** rev

**Points:** 1000 (2 solves)

**Description:** 

> Can you find the flag?

#### Initial reversing

After opening the binary in ida and adjusting the maximum size for functions
to actually get a nicer decompilation, I could identify some C++ functions
(it took some time to figure out that ida applied wrong lumina data and
it was actually just `vector::push_back` and not some Variadic thingy...

Anyway, after identifying that the main struct initialized in main is
64 vectors, 64 mutexes, 64 conditional variables and 64 chars and that
this struct is passed to 64 threads it was pretty clear that there will be
some inter-trhead communication.

So after looking at the first thread's function for some time I realized
that it locks the lock with a certain index in the struct, then checks if
there's something in the vector and if not, it waits using the conditional
variable with the same index as the lock. Then it pops a value from the vector,
(by getting the start pointer, dereffing and then popping the value using again
a C++ function which was a bit tricky to identify).

This value is then split into the lowest bit as well as the upper bits,
the upper bits are then compared with certain values (different in each
function), if the value matches, we store the lowest bit value in a local
variable (which was initialized to -1 to signify no value). There are always
three inputs which belong together, they are inputs into a full-adder, so we
have three inputs and two outputs, the carry was pushed into the vector
of the next function (in order they were started in / are stored in the binary)
the upper bits were set to one of the values that function was expecting.
The xor result of the three inputs was pushed into the vector of the same
function, again using one of the specified upper bits for this function.

#### Parsing of the stuff (pain)

So this seems to be a dataflow machine, each function is a adding-station,
and it waits for certain tagged inputs to add them. There are eight functions
which belong together in the sense that the carry will go to the next function.
And of these pairs of eight functions there are eight, for a total of 64
functions. At this point I assumed that it doesn't matter in which function
we are and that we just need to care about the tag of the inputs/outputs,
so I spent a long time to come up with a good way to parse all the station's
inputs and outputs. In the end I came up with the following grep command:
`objdump --insn-width=100 -d -M intel main | grep -e ret -e cmp -e "[^x]or" -A 2`
which prints all the compares and since grep is smart is prints consecutive
matches as one block and then separates different blocks by a single line
of `--`. So by counting the amount of newlines between two `--` I was able
to determine if it was a block where we check for the two or three input
tag numbers. Then I just extracted the numbers from the compare instructions
to get the inputs. Finally if there was an or instruction I assumed that this
sets the upper bits of the output, there were some complications with this,
as the compiler is smart and emits an `or ah, 1` in cases where the tag
was 256, so I had to adjust that (and spend about an hour to find a bug
as one single function used dh instead of ah...).

After having parsed all of thses things it's just a matter of putting
all the initial values and rules into z3 and letting it solve for the
correct input. This was easily done, as I could just copy the decompiled
code from main, fix up a few bits (again because of the ah). Then
I could easily parse that code to get the tags and corresponding values
(wether that was a constant or one of our input bits).

#### Final script

The final script to parse all the things and solver looks like this:
```python
from z3 import *

# objdump --insn-width=100 -d -M intel main | grep -e ret -e cmp -e "[^x]or" -A 2 > cmps
x = open("cmps").read().split("--")

#the tags which symbolize the final value of a station
tgts = [0xec,0x16d,0x182,0x185,0x194,0x197,0x1a0,0x1a3,0x2ae,0x2cf,0x2d2,0x2e4,0x2f3,0x2ff,0x308,0x30e,0x4cd,0x4d0,0x4e5,0x4e8,0x4f7,0x4fa,0x4fd,0x503,0x57e,0x6a4,0x6b9,0x6bc,0x6cb,0x6ce,0x6d7,0x6dd,0x800,0x84e,0x863,0x866,0x869,0x86c,0x86f,0x875,0xa43,0xa46,0xa5b,0xa6d,0xa7c,0xa7f,0xa88,0xa8e,0xb6c,0xbd5,0xbff,0xc02,0xc11,0xc1d,0xc20,0xc26,0xce3,0xdb8,0xdcd,0xdd0,0xdd3,0xdd6,0xdd9,0xddf]
# order the threads are started in
bitorder = [2,28,46,4,32,5,14,40,29,43,25,0,19,35,16,63,59,7,24,22,62,30,36,56,44,42,6,11,58,47,39,34,17,31,26,41,37,3,50,53,13,27,21,49,1,12,51,20,9,52,55,18,10,15,61,8,38,45,23,54,33,60,57,48]
# the expected outputs, checked in main
expected = [1,0,1,1,1,0,1,1,0,1,1,0,1,0,1,1,0,1,1,0,0,1,0,1,1,1,1,0,1,1,1,1,0,1,0,0,0,0,1,1,1,1,0,0,1,0,1,0,0,0,0,0,1,0,0,0,1,1,1,0,1,1,1,1]

last_outs = []
last_inputs = []

# init solver & values for each tag
s = Solver()
tags = [Bool(f"tag_{i}") for i in range(3554)]

# pushes from main
xx = open("pushes.c").read().split("\n")

bit = 0
tag = 0
inputs = [Bool(f"in[{i}]") for i in range(64)] # our input, 64 bits (aka 8 bytes == 16 hex chars)
consts = [0]*64
for i,l in enumerate(xx):
    if l == "": continue
    if i & 1:   
        idx = int(l.split("[")[1].split("]")[0])
        s.add(tags[tag] == bit)
    else:
        if "|" in l:
            tag = eval(l.split("|")[1].split(";")[0].strip())
            assert(tag & 1 == 0)
            tag >>= 1
            input_idx = int(l.split("[")[1].split("]")[0])
            bit = inputs[input_idx]
        else:
            val = int(l.split("=")[1].strip()[:-1])
            bit = (val & 1) == 1
            tag = val >> 1
            consts[tag] = bit

# the constant values
#print([1 if x else 0 for x in consts])

# the adding stations...
idx = -5
for i in x:
    if "ret" in i:
        idx += 1
        if idx == 64:
            break

    fl = i.split("\n")[1]
    if "or" in fl and "0x" in fl:
        xx = int(fl.split(",")[-1].strip(),0)
        if xx > 0x10000:
            xx = xx & 0xff
        if "ah" in fl or "dh" in fl:# man fuck dh
            xx<<=8

        assert(xx&1 == 0)
        last_outs.append(xx>>1)

        if (idx in [7, 15, 23, 31, 39, 47, 55, 63] and len(last_outs) == 1) or len(last_outs) == 2:
            #print(last_inputs, "=>", last_outs)
            xored_tgt = last_outs[-1]

            if len(last_inputs) == 2:
                s.add(Xor(tags[last_inputs[0]], tags[last_inputs[1]]) == tags[xored_tgt])
            else:
                # Man fuck z3, why does it allow Xor(a,b,c) with three inputs but doesn't fucking work
                # This could've been solved like 3 hours earlier but because of this fucking
                # z3 thingy they were lost, rip
                s.add(Xor(Xor(tags[last_inputs[0]], tags[last_inputs[1]]), tags[last_inputs[2]]) == tags[xored_tgt])
        
            if xored_tgt in tgts:
                print("Target found: ", idx, last_inputs, last_outs)

        if len(last_outs) == 2:
            ovf_tgt = last_outs[0]
            #print(idx, last_inputs, last_outs)
            if len(last_inputs) == 2:
                s.add(And(tags[last_inputs[0]], tags[last_inputs[1]]) == tags[ovf_tgt])
            else:
                a, b, c = tags[last_inputs[0]], tags[last_inputs[1]], tags[last_inputs[2]]
                s.add(Or(And(a,b), And(a,c), And(b,c)) == tags[ovf_tgt])

    if i.count("\n") > 6:
        last_inputs = []
        last_outs = []
        for l in i.split("\n"):
            if "cmp" in l:
                last_inputs.append(int(l.split(",")[-1],0))
        last_inputs = list(set(last_inputs))
        #print(idx, last_inputs)

# extract the resulting bits
results = [tags[tgts[i]] for i in range(64)]

# add the conditions
for i in range(64):
    s.add(results[i] == (1==expected[bitorder[i]]))

if s.check() == sat:
    m = s.model()
    x = ""
    for i in inputs:
        print(1 if m[i] else 0,end="")
        x += "1" if m[i] else "0"
    print()
    print(hex(int(x[::-1],2))[:1:-1])
else:
    print("oof")
```