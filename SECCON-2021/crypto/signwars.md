# Sign Wars

**Author**: Robin_Jadoul, solved together with [esrever](https://twitter.com/esrever_25519)

**Tags**: crypto, ecdsa, lattice, mt19937

**Points**: 305 (8 solves)

## The challenge

> A long time ago in a galaxy far, far away....

```python
from Crypto.Util.number import bytes_to_long, long_to_bytes
from Crypto.Util.Padding import pad
import random
from secret import msg1, msg2, flag

flag = pad(flag, 96)
flag1 = flag[:48]
flag2 = flag[48:]

# P-384 Curve
p = 39402006196394479212279040100143613805079739270465446667948293404245721771496870329047266088258938001861606973112319
a = -3
b = 27580193559959705877849011840389048093056905856361568521428707301988689241309860865136260764883745107765439761230575
curve = EllipticCurve(GF(p), [a, b])
order = 39402006196394479212279040100143613805079739270465446667946905279627659399113263569398956308152294913554433653942643
Z_n = GF(order)
gx = 26247035095799689268623156744566981891852923491109213387815615900925518854738050089022388053975719786650872476732087
gy = 8325710961489029985546751289520108179287853048861315594709205902480503199884419224438643760392947333078086511627871
G = curve(gx, gy)

for b in msg1:
    assert b >= 0x20 and b <= 0x7f
z1 = bytes_to_long(msg1)
assert z1 < 2^128

for b in msg2:
    assert b >= 0x20 and b <= 0x7f
z2 = bytes_to_long(msg2)
assert z2 < 2^384

# prequel trilogy
def sign_prequel():
    d = bytes_to_long(flag1)
    sigs = []
    for _ in range(80):
        # normal ECDSA. all bits of k are unknown.
        k1 = random.getrandbits(128)
        k2 = z1
        k3 = random.getrandbits(128)
        k = (k3 << 256) + (k2 << 128) + k1
        kG = k*G
        r, _ = kG.xy()
        r = Z_n(r)
        k = Z_n(k)
        s = (z1 + r*d) / k
        sigs.append((r,s))

    return sigs

# original trilogy
def sign_original():
    d = bytes_to_long(flag2)
    sigs = []
    for _ in range(3):
        # normal ECDSA
        k = random.getrandbits(384)
        kG = k*G
        r, _ = kG.xy()
        r = Z_n(r)
        k = Z_n(k)
        s = (z2 + r*d) / k
        sigs.append((r,s))

    return sigs


def sign():
    sigs1 = sign_prequel()
    print(sigs1)
    sigs2 = sign_original()
    print(sigs2)
    

if __name__ == "__main__":
    sign()
```

## Preliminary analysis

We observe that the flag is cut into two separate pieces, and we get some ECDSA signatures (over the P-384 curve) for two separate (ascii-range) messages where each part of the flag is used as a secret key respectively. We however do not learn either of the messages being signed.
For the first part of the flag, we get 80 signatures, where the message being signed is embedded into the random nonce as $k = k_3\cdot 2^{256} + z_1 \cdot 2^{128} + k_1$ where each of $k_1, k_3, z_1$ consists of 128 bits. Having a bias to an (EC)DSA signature nonce, along with a fair amount of signatures quickly points towards a lattice attack exploiting the bias, similar to e.g. [this paper](https://eprint.iacr.org/2019/023.pdf), through a reduction to the Hidden Number Problem.
For the second part, we only get 3 signatures, and the nonce bias has disappeared. So it seems we can't apply the same approach here anymore. The only way we can attack this (even solving the discrete logarithm won't help us here, as we can't recover a public key without knowing the message either), is by knowing exactly what randomness we're dealing with. Luckily for us, the challenge is using `random.getrandbits`, which is using a Mersenne twister behind the scenes, and given enough outputs of a Mersenne twister, we can predict other outputs. Where can we get such known outputs, you ask? Well we have some $80 \times 256$ bits of randomness we can recover from the signatures in part one if we manage to recover both the private key and the message being signed there.

## What's a CTF crypto challenge without lattices?

The straightforward transformation from ECDSA to HNP generally assumes we know the value of the fixed bits. This is, given that we don't know the message being signed yet, not the case here, so we'll need to massage our signatures a bit first.
Our goal will be to "sacrifice" one of our signatures to subtract away the $z_1$ in the other nonces and arrive at a known bias of 0 for the remaining 79 signatures. With some rewriting, we obtain the following:
\begin{align\*}
     &&s^{(j)} \cdot k^{(j)} &= z_1 + r^{(j)}\cdot d + m^{(j)} \cdot |G| \newline
\iff &&(s^{(j)} \cdot 2^{128} - 1) \cdot z_1 &= -s^{(j)} \cdot (k_3^{(j)}\cdot 2^{256} + k_1^{(j)}) + r^{(j)}\cdot d + m^{(j)}\cdot |G|
\end{align\*}
And by rewriting an arbitrary fixed signature (say the very first one) into an equivalent form, equating $z_1 = z_1$ and doing a cross multiplication, we get
\begin{align\*}
    &&(s^{(j)}\cdot 2^{128} - 1) \cdot \left(-s^{(j)} \cdot (k_3^{(j)}\cdot 2^{256} + k_1^{(j)}) + r^{(j)}\cdot d + m^{(j)}\cdot |G|\right)\newline
    &= \newline
    &&(s^{(0)}\cdot 2^{128} - 1) \cdot \left(-s^{(0)} \cdot (k_3^{(0)}\cdot 2^{256} + k_1^{(0)}) + r^{(0)}\cdot d + m^{(0)}\cdot |G|\right)
\end{align\*}

From this set of linear constraints, along with the known (or easy-to-derive) bounds on each of the unknown variables, we can then apply some [black magic](https://github.com/rkm0959/Inequality_Solving_with_CVP/)[^rkm] and obtain the secret key (which is the first half of the flag), and some of the $k_1^{(j)}$ and $k_3^{(j)}$ we care about for the next part of the challenge at once.

### Some lattice code

With the theoretical part out of the way, we first just setup our wrapper around rkm's work that allows us to simply specify our linear (in)equalities and to automatically get the lattice out of it.

```python
from dataclasses import dataclass
from typing import Any, Callable, List, Mapping


@dataclass
class Constraint:
    """ Constraint on a linear function
    The corresponding formula is:
        lower_bound <= sum(coefficients[var] * var, for all var) <= upper_bound
    """
    coefficients: Mapping[str, int]
    lower_bound: int
    upper_bound: int

    def __str__(self):
        formula = ' + '.join(f'{c}*{x}' for x, c in self.coefficients.items())
        return f'{self.lower_bound} <= {formula} <= {self.upper_bound}'


def constraints_to_lattice(
    constraints: List[Constraint],
    debug: bool = False
) -> (List[List[int]], List[str]):
    from itertools import chain

    if debug:
        print('constraints = [')
        print(',\n'.join(f'\t{c}' for c in constraints))
        print(']')

    variables = sorted(list(set(chain.from_iterable(
        c.coefficients.keys() for c in constraints
    ))))

    lattice = [[0] * len(constraints) for _ in range(len(variables))]
    for i, c in enumerate(constraints):
        for var, coef in c.coefficients.items():
            lattice[variables.index(var)][i] = coef

    if debug:
        print(f'variables = {variables}')
        print(f'lattice_nrows = {len(variables)} variables')
        print(f'lattice_ncols = {len(constraints)} constraints')
        print('lattice =')
        for row in lattice:
            print(''.join('*' if v else '.' for v in row))

    return lattice, variables


# ===== rkm solver =====


def load_rkm_solver(
    filename: str = None
) -> Callable:
    """ Load rkm's solver without overwriting solve() in globals() """
    from copy import copy

    if filename is None:
        filename = 'https://raw.githubusercontent.com/rkm0959/Inequality_Solving_with_CVP/main/solver.sage'  # noqa
    context = copy(globals())
    sage.repl.load.load(filename, context)
    return context['solve']


def rkm_wrapper(
    constraints: List[Constraint],
    debug: bool = False,
    solver: Callable = load_rkm_solver(),
    **kwargs: Any,
) -> Mapping[str, int]:
    """ Wrapper for rkm's inequalities solver """
    lattice, variables = constraints_to_lattice(constraints, debug)

    # Call solver
    if debug:
        print('Start solving...')
    weighted_close_vec, weights, sol_vec = \
        solver(matrix(lattice),
               [c.lower_bound for c in constraints],
               [c.upper_bound for c in constraints],
               **kwargs)

    # Get solution
    if sol_vec is None:
        weighted_lattice = matrix(lattice) * matrix.diagonal(weights)
        H, U = weighted_lattice.hermite_form(transformation=True)
        sol_vec = H.solve_left(weighted_close_vec).change_ring(ZZ) * U
    solution = dict(zip(variables, sol_vec))
    if debug:
        print(f'solution = {solution}')

    # Check solution
    for c in constraints:
        coefs, lb, ub = c.coefficients, c.lower_bound, c.upper_bound
        val = sum(coef * solution[var] for var, coef in coefs.items())
        if not lb <= val <= ub:
            raise Exception('Constrained value out-of-bound, '
                            f'lb={lb}, ub={ub}, value={val}, coefs={coefs}, '
                            f'solution={solution}')

    return solution
```

After which we encode the constraints, and get a stimulating first half of the flag.

```python
sigs = ... # challenge data


from itertools import product

# Constants
order = 39402006196394479212279040100143613805079739270465446667946905279627659399113263569398956308152294913554433653942643


# STEP: solve d

# Variables
n_samples = 7

d_var = 'd'
k1s = [f'k1_{i}' for i in range(n_samples)]
k3s = [f'k3_{i}' for i in range(n_samples)]
ms = [f'm_{i}' for i in range(n_samples)]

# Constraints
constraints = []

# Size: 0 <= d < 2**384
constraints.append(Constraint({d_var: 1}, 0, 2 ** 384 - 1))
# Size: 0 <= k1s[i], k3s[i] < 2**128
for var in k1s + k3s:
    constraints.append(Constraint({var: 1}, 0, 2 ** 128 - 1))

# ss[i] * (k3s[i] || z1 || k1s[i]) = z1 + rs[i]*d + m[i]*order
# => z1 = (-ss[i]*k3s[i]*2**256 - ss[i]*k1s[i] + rs[i]*d + m[i]*order) / (ss[i]*2**128 - 1)
for i in range(1, n_samples):
    r0, s0 = sigs[0]
    ri, si = sigs[i]
    cz0 = s0*2**128 - 1
    czi = -1 * (si*2**128 - 1)
    coefs = {
        d_var: ri*cz0 + r0*czi,
        k1s[i]: cz0 * -si,
        k3s[i]: cz0 * -si * 2**256,
        ms[i]: order * cz0,
        k1s[0]: czi * -s0,
        k3s[0]: czi * -s0 * 2**256,
        ms[0]: order * czi,
    }
    constraints.append(Constraint(coefs, 0, 0))

# Solve
solution = rkm_wrapper(constraints, debug=False)
d = solution[d_var] % order
print(f'd = {d} = {int(d).to_bytes(48, "big")}')
```
> SECCON{New_STARWARS_Spin-Off_The_Book_Of_Boba_Fe

*Quick note:* It's very likely possible and even simple to forgo the sacrifice for $z_1$ and just directly add it as a constraint in our lattice solver. This is just the way we went about it before deciding to just pick up that hammer instead of setting up a clean lattice specifically for the resulting HNP.

## Dancing a twist

From here, we can either recover $z_1$ first, so we can extract the randomness from the signatures, or just use all signatures rather than only 7 of them to let the lattice do all the work.
We chose to go with the former:
```python
def get_z1_num(s, k3, k1, r, d, m):
    return -s*k3*2**256 - s*k1 + r*d + m*order
def get_z1_denom(s):
    return s*2**128 - 1
def get_z1(s, k3, k1, r, d, m):
    num = get_z1_num(s, k3, k1, r, d, m)
    denom = get_z1_denom(s)
    assert num % denom == 0
    return num // denom
z1s = []
for i in range(n_samples):
    z1s.append(get_z1(sigs[i][1], solution[k3s[i]], solution[k1s[i]], sigs[i][0], solution[d_var], solution[ms[i]]))
assert z1s == [z1s[0]] * len(z1s), 'z1 not all equal'
z1 = z1s[0] % order
print(f'z1 = {z1} = {int(z1).to_bytes(16, "big")}')
```
immediately already recovered all randomness that came from the Mersenne Twister during part 1, and hence we should have plenty of data to recover the full nonces of part 2. We simply dig through old CTF files lying around in our home directory (because who would ever think of cleanly organizing any of this...) and dig up our z3-based solver.
*Yes, it's easy enough to do it without SMT solving, but having these kinds of hammers lying around is always so much more inviting.*
```python
import random
from z3 import *

class MT19937:
    W = 32
    N = 624
    M = 397
    R = 31
    A = 0x9908B0DF
    U = 11
    D = 0xFFFFFFFF
    S = 7
    B = 0x9D2C5680
    T = 15
    C = 0xEFC60000
    L = 18

    F = 1812433253

    def __init__(self, seed=None):
        if seed is None:
            seed = int.from_bytes(os.urandom(self.W // 8), byteorder='little')
        self.state = [seed % (2**self.W)]
        for i in range(1, self.N):
            self.state.append((self.F * (self.state[-1] ^ (self.state[-1] >> (self.W - 2))) + i) % (2**self.W))
        self.idx = self.N

    def rand(self):
        if self.idx >= self.N:
            self._twist()
        y = self.state[self.idx]
        y ^= (y >> self.U) & self.D
        y ^= (y << self.S) & self.B
        y ^= (y << self.T) & self.C
        y ^= y >> self.L
        self.idx += 1
        return y % (2**self.W)

    def rand128(self):
        result = self.rand()
        for i in range(1, 4):
            result = (self.rand() << (i*32)) | result
        return result

    def _twist(self):
        lower_mask = (1 << self.R) - 1
        upper_mask = (~lower_mask) % (2**self.W)
        for i in range(0, self.N):
            x = (self.state[i] & upper_mask) + (self.state[(i + 1) % self.N] & lower_mask)
            xA = x >> 1
            if x % 2 != 0:
                xA ^= self.A
            self.state[i] = self.state[(i + self.M) % self.N] ^ xA
        self.idx = 0

class Z3MT19937:
    W = 32
    N = 624
    M = 397
    R = 31
    A = 0x9908B0DF
    U = 11
    D = 0xFFFFFFFF
    S = 7
    B = 0x9D2C5680
    T = 15
    C = 0xEFC60000
    L = 18

    F = 1812433253

    def __init__(self):
        self.state = [BitVec(f"state_{i}", 32) for i in range(self.N)]
        self.idx = self.N

    def rand(self):
        if self.idx >= self.N:
            self._twist()
        y = self.state[self.idx]
        y ^= LShR(y, self.U) & self.D
        y ^= (y << self.S) & self.B
        y ^= (y << self.T) & self.C
        y ^= LShR(y, self.L)
        self.idx += 1
        return y
    
    def rand128(self):
        result = self.rand()
        for i in range(1, 4):
            result = Concat(self.rand(), result)
        assert result.size() == 128
        return result

    def _twist(self):
        lower_mask = (1 << self.R) - 1
        upper_mask = (~lower_mask) % (2**self.W)
        for i in range(0, self.N):
            x = (self.state[i] & upper_mask) + (self.state[(i + 1) % self.N] & lower_mask)
            xA = LShR(x, 1)
            xA = If(x & 1 == 1, xA ^ self.A, xA)
            self.state[i] = self.state[(i + self.M) % self.N] ^ xA
        self.idx = 0

def crack(inputs, offset=0):
    fr = Z3MT19937()
    initstate = fr.state[:]

    s = Solver()
    for _ in range(offset):
        fr.rand128()
    for inp in inputs:
        s.add(inp == fr.rand128())
    s.check()
    dup = MT19937()
    dup.state = [s.model()[x].as_long() for x in initstate]
    with open('state.txt', 'w') as f:
        f.write(str(dup.state))
    for _ in inputs:
        dup.rand128()
    for _ in range(offset):
        dup.rand128()
    return dup

blocks = []
for i, (r, s) in enumerate(sigs):
    k = (z1 + r*d) / s % order
    assert (k >> 128) % 2**128 == z1, f'bad k, i = {i}'
    blocks.append(k % 2**128)
    blocks.append(k >> 256)

rnd = crack(blocks)
ks = [y[0] + 2^128 * y[1] + 2^256 * y[2] for _ in range(3) for y in [[rnd.rand128() for _ in range(3)]]]
```

From there, the only obstacle left is that we're once again unaware of the value taken by $z_2$. So we repeat our approach of combining two signatures to cancel it out, and solve for the private key.

```python
d = (sigs[0][1]*ks[0] - sigs[1][1]*ks[1]) / (sigs[0][0] - sigs[1][0]) % order
print(int(d).to_bytes(48, 'big'))
z2 = (sigs[0][1] * ks[0] - sigs[0][0] * d) % order
print(int(z2).to_bytes(48, 'big').strip(b'\0'))
```

## Fin
And there we go, just apply the right hammers and you can smash a CTF challenge into tiny bits.
The full flag:
> SECCON{New_STARWARS_Spin-Off_The_Book_Of_Boba_Fett_Will_Premiere_On_December_29-107c360aab}

And just for fun, the messages being signed:

> th1s_1s_n0t_fl4g

> May_The_Lattice_Reduction_Be_With_You...


[^rkm]: Thanks again, rkm!
