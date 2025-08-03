# 0KPR00F

**Author:** zeski

**Tags:** crypto

**Points:** 253

> Sh0w me the pr00f that y0u understand 0kpr00f. If its 0k, i’ll give y0u what y0u want!


## Challenge source
We are given the following source code, along with source code for py_ecc which we can also find [here](https://github.com/ethereum/py_pairing) as an ethereum library.
```py
#!/usr/bin/env python3

import signal
import socketserver
import string
import os
from secret import flag
from py_ecc import bn128

lib = bn128
FQ, FQ2, FQ12, field_modulus = lib.FQ, lib.FQ2, lib.FQ12, lib.field_modulus
G1, G2, G12, b, b2, b12, is_inf, is_on_curve, eq, add, double, curve_order, multiply = \
  lib.G1, lib.G2, lib.G12, lib.b, lib.b2, lib.b12, lib.is_inf, lib.is_on_curve, lib.eq, lib.add, lib.double, lib.curve_order, lib.multiply
pairing, neg = lib.pairing, lib.neg

LENGTH = 7


def Cx(x,length=LENGTH):
    res = []
    for i in range(length):
        res.append(pow(x,i,curve_order) % curve_order)
    return res

def C(x,y,length=LENGTH):
    assert len(x) == len(y) == length
    res = multiply(G1, curve_order)
    for i in range(length):
        res = add(multiply(x[i],y[i]),res) 
    return res 

def Z(x):
    return (x-1)*(x-2)*(x-3)*(x-4) % curve_order


def genK(curve_order,length=LENGTH):
    t = int(os.urandom(8).hex(),16) % curve_order
    a = int(os.urandom(8).hex(),16) % curve_order
    Ct = Cx(t)
    PKC = []
    for ct in Ct:
        PKC.append(multiply(G1, ct))
    PKCa = []
    for ct in Ct:
        PKCa.append(multiply(multiply(G1, ct), a))

    PK = (PKC,PKCa)
    VKa = multiply(G2, a)
    VKz = multiply(G2, Z(t))
    VK = (VKa,VKz)
    return PK,VK

def verify(proof,VK):
    VKa,VKz = VK
    PiC,PiCa,PiH = proof

    l = pairing(VKa, PiC)
    r = pairing(G2, PiCa)
    if l !=r:
        return False
    l = pairing(G2,PiC)
    r = pairing(VKz,PiH)
    if l !=r:
        return False
    return True


class Task(socketserver.BaseRequestHandler):
    def __init__(self, *args, **kargs):
        super().__init__(*args, **kargs)


    def OKPROOF(self,proof,VK):
        return verify(proof,VK)


    def dosend(self, msg):
        try:
            self.request.sendall(msg.encode('latin-1') + b'\n')
        except:
            pass

    def timeout_handler(self, signum, frame):
        raise TimeoutError

    def handle(self):
        try:
            signal.signal(signal.SIGALRM, self.timeout_handler)
            self.dosend('===========================')
            self.dosend('=WELCOME TO 0KPR00F SYSTEM=')
            self.dosend('===========================')
            PK,VK = genK(curve_order)
            self.dosend(str(PK))
            self.dosend('now give me your proof')
            msg = self.request.recv(1024).strip()
            msg = msg.decode('utf-8')
            tmp = msg.replace('(','').replace(')','').replace(',','')
            tmp = tmp.split(' ')
            assert len(tmp) == 6
            PiC = (FQ(int(tmp[0].strip())),FQ(int(tmp[1].strip())))
            PiCa = (FQ(int(tmp[2].strip())),FQ(int(tmp[3].strip())))
            PiH = (FQ(int(tmp[4].strip())),FQ(int(tmp[5].strip())))
            proof = (PiC,PiCa,PiH)
            if self.OKPROOF(proof,VK):
                self.dosend("Congratulations！Here is flag:"+flag)
            else:
                self.dosend("sorry")
            

        except TimeoutError:
            self.dosend('Timeout!')
            self.request.close()
        except:
            self.dosend('Wtf?')
            self.request.close()


class ThreadedServer(socketserver.ForkingMixIn, socketserver.TCPServer):
    pass

if __name__ == "__main__":
    HOST, PORT = '0.0.0.0', 13337
    server = ThreadedServer((HOST, PORT), Task)
    server.allow_reuse_address = True
    server.serve_forever()
```

## Analysis
We see we are dealing with some kind of zero knowledge proofs based on bilinear pairings. We are given the values

$$
[t]G_1, [t^2]G_2, [t^3]G_2, [t^4]G_2, [t^5]G_2, [t^6]G_2
$$

$$
[at]G_1, [at^2]G_2, [at^3]G_2, [at^4]G_2, [at^5]G_2, [at^6]G_2
$$

where $a,t$ are randomly sampled integers, and $G_2$ the group generator over the elliptic curve the library is using.
Our task is to send a proof $(\text{Pic},\text{PiCa},\text{PiH})$ that satisfies the verify function, which checks the following:

$$
e(\text{VKa}, \text{PiC}) = e(G_2, \text{PiCa})
$$

and

$$
e(G_2,\text{PiC}) = e(\text{VKz},\text{PiH})
$$

where $e(\cdot,\cdot)$ is the pairing and $(\text{VKa}, \text{VKz}) = ([a]G_2, [Z(t)]G_2)$ is the verification key. So our task is to prove that we know the evaluation of 

$$
Z(t) = (t-1)(t-2)(t-3)(t-4) = t^4 - 10t^3 + 35t^2 -50t + 24
$$

Let $(\text{Pic},\text{PiCa},\text{PiH}) = ([x]G_1, [y]G_1, [z]G_1)$, where $x,y,z$ are unknown integers. Now we look at the pairings in the verification function.

$$
e(\text{VKa}, \text{PiC}) = e([a]G_2, [x]G_1) = e(G_2,G_1)^{ax}
$$

$$
e(G_2, \text{PiCa}) = e(G_2, [y]G_1) = e(G_2,G_1)^y
$$

and

$$
e(G_2,\text{PiC}) = e(G_2, [x]G_1) = e(G_2,G_1)^x
$$

$$
e(\text{VKz},\text{PiH}) = e([Z(t)]G_2, [z]G_1) = E(G_2,G_1)^{Z(t)z}
$$

So we get the equations

$$
ax = y
$$

$$
x = Z(t)z
$$

and set $x = Z(t), y = aZ(t), z = 1$. So our proof is $([Z(t)]G_1, [aZ(t)]G_1, G_1)$, which we can compute from the values we are given, using scalar multiplications and point additions.
## Solution script
```py
from pwn import *
from py_ecc import bn128

G1, FQ, add, curve_order, multiply = bn128.G1, bn128.FQ, bn128.add, bn128.curve_order, bn128.multiply

def ev(xs):
    out = multiply(xs[0], 24)
    out = add(out, multiply(xs[1], curve_order-50))
    out = add(out, multiply(xs[2], 35))
    out = add(out, multiply(xs[3], curve_order-10))
    out = add(out, xs[4])
    return out

io = remote("47.254.47.63", 13337)

for _ in range(3): io.recvline()

PK = eval(io.recvline())
PK0 = [(FQ(x[0]), FQ(x[1])) for x in PK[0]]
PK1 = [(FQ(x[0]), FQ(x[1])) for x in PK[1]]

tup = (ev(PK0), ev(PK1), G1)

io.sendlineafter(b"proof\n", str(tup).encode())

print(io.recvall(30))
```

`rwctf{How_do_you_feel_about_zero_knowledge_proof?}`
