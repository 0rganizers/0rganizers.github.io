# Case-insensitive

**Authors**: [Spittfire](https://twitter.com/Spittfires_), Aylmao, dd

**Tags**: misc, crypto

**Points**: 305 (8 solves)

> I implemented bcrypt-based signing. Can you expose the key?
>
> `nc case-insensitive.quals.seccon.jp 8080`

## Introduction

Last weekend we played SECCON and ended up 2nd overall. It was very fun ! We will present how we solved case-insensitive, a challenge made by [kurenaif](https://twitter.com/fwarashi). This challenge was the least solved misc challenge with only 8 solves.


## Challenge structure

We are provided with a single python file named `problem.py`. It contains the code that is run remotely. The code simply hashes a provided message appended to the flag using bcrypt and returns the resulting hash. There is also a functionality to verify that a provided hash corresponds to the hash  of a provided message appended to the flag. We rapidly concluded that bruteforcing the hash made out of a single message + flag would be impossible as the flag length could easily be more then 32 bytes and that the hashing algorithm used was bcrypt with 5 round salts.


## Bcrypt Library code analysis

By inspecting the bcrypt library [source code](https://github.com/pyca/bcrypt)  of the used functions we notices that the function `hashpw` only hashed the first 72 bytes of the provided password which is our message appended to the flag.
```python
password = password[:72]
```
This is looks promising as we can use this in our advantage. By providing a long enough message we can compute a hash containing the message we provide appended to only the first few bytes of the hash. In this way we can bruteforce it.
For example, to leak the first byte of the flag we can provide a message containing 71 bytes. Then, the flag would be appended to the end of the message and the `hashpw` would get called. We know that only the 72 first bytes are taken which would mean that the resulting hash can be bruteforced by simply computing the hash of every single possible printable character append to our provided message.


## Length check bypass

The above presented idea has only one problem. There is a check that bounds the message size to 24 characters. From a [challenge](https://polygl0ts.ch/writeups/2021/b01lers/pyjail3/README.html) of [b01lers CTF 2021](https://b01lers.net/)  , we knew that it was possible to mess with the length of a string by using ligatures in python. By trying out with the ligature `ﬂ`. We noticed that we were able to provide a message having length 24 but that would in the end be made of 48 bytes. We then found a ligature made of 3 characters : `ﬄ` to reach 72 bytes with a message of 24 characters. This works because the call to upper messes up the actual length of the message. This is an expected behaviour according to the unicode conventions. Calling `upper()` on `ﬂ` is actually well defined. In the [unicode specification](https://www.unicode.org/Public/UCD/latest/ucd/SpecialCasing.txt) we can see that : 

`FB02; FB02; 0046 006C; 0046 004C` shows that the character with code `FB02` is represented in lower as `FB02` and as `0046 006C` in upper case. 

## Solution script

Using the gathered knowledge we started to write a script that would leak 1 byte of the flag at a time and then find the corresponding character by bruteforcing it over the set of all printable characters.

Here is our solution script :
```python
# Imports
from pwn import * # To interact with the server
import bcrypt
from tqdm import tqdm
import string # To bruteforce on

char_3 = "ﬃ"
char_2 = "ﬂ"

def make_to_length(l):
    nb_of_3 = int(l/3)
    nb_of_2 = int((l-nb_of_3*3)/2)
    remaining = l - (3*nb_of_3 + 2*nb_of_2)
    return char_3*nb_of_3 + char_2*nb_of_2 + remaining*"A"


# Phase 1 : Getting all the hashes
#remote = process('./problem.py')
remote = remote('case-insensitive.quals.seccon.jp',8080)

def sign(conn, msg):
    conn.sendline(b"1")
    d = conn.recvuntil(b'message: ')
    print(d)
    conn.sendline(msg.encode())
    raw = conn.recvline()
    return raw.split(b": ")[1]

# Hashing all the combinations
results = {}
salts = {}
for i in tqdm(range(48, 72)):
    results[i] = sign(remote, make_to_length(i)).strip()
    salts[i] = results[i][0:29]
flag = ""
for i in range(48, 72)[::-1]:
    print("bruteforcing : ", i)
    s = salts[i]
    r = results[i]
    found = None
    for c in string.printable:
        leading = make_to_length(i).upper()
        payload = (leading + flag + c).encode()
        attempt = bcrypt.hashpw(payload, s)
        if r == attempt:
            print("FOUND !", c)
            found = c
            break
    flag += found
    if "}" in flag:
        break
print(flag)
```

Flag: `SECCON{uPPEr_is_M4g1c}`

## Conclusion

It was a really nice challenge to remember us how unsafe `len()` can be in python ^^.
