# Cycling

**Author**: Robin_Jadoul

**Tags**: RSA, factoring

**Points**: 201 (50 solves)

**Alternate URL**: <https://ur4ndom.dev/posts/2022-07-04-gctf-cycling/>

**Description**:

> It is well known that any RSA encryption can be undone by just encrypting the ciphertext over and over again.
> If the RSA modulus has been chosen badly then the number of encryptions necessary to undo an encryption is small.
> However, if the modulus is well chosen then a cycle attack can take much longer. This property can be used for a timed release of a message.
> We have confirmed that it takes a whopping 2^1025-3 encryptions to decrypt the flag.
> Pack out your quantum computer and perform 2^1025-3 encryptions to solve this challenge. Good luck doing this in 48h.


## Exploring the challenge

Let's have a brief look at the source code we're provided with:

```python
e = 65537
n = ... # snip
ct = ... # snip
# Decryption via cycling:
pt = ct
for _ in range(2**1025 - 3):
  pt = pow(pt, e, n)
# Assert decryption worked:
assert ct == pow(pt, e, n)

# Print flag:
print(pt.to_bytes((pt.bit_length() + 7)//8, 'big').decode())
```

In short, we're faced with an RSA encryption of the flag, and one additional "fact" that's supposed to help us in some way.
The fact is that when we repeat the encrypting exponentiation $R = 2^{1025} - 3$ times, we achieve the same as decrypting the ciphertext.
Working through the math, this tells us that $x^{e^{R}} \equiv x$ holds, at the very least when $x$ represents the flag.

A well-known fact when dealing with RSA, and modular exponentiation in general, is that the order of the multiplicative group mod $n$ is equal to the number of integers $< n$ that are coprime to $n$.
This quantity is known as Euler's totient $\varphi(n)$.

Furthermore, from Euler's theorem (or Lagrange's theorem if we frame it in a group-theoretic way), we know that any number $x$ taken to the $\varphi(n)$th power (mod $n$), results in the identity $1$.
This property is in fact vital for the correctness of RSA, as we rely on the fact that $x^{\varphi(n)} \equiv 1 \pmod n$ when we say that $x^{ed} \equiv \left(x^{\varphi(n)}\right)^k x \equiv x$.

From all this known theory underlying the RSA cryptosystem, we can now finally make a first deduction: $e^{R + 1} \equiv 1 \pmod{\varphi(n)}$.

## Background: Carmichael's $\lambda$

Actually, that previous statement is what you would say with a basic understanding of the principles underlying RSA, but it's in fact not entirely correct.
It could very well be the case that $x^\ell \equiv 1 \pmod n$ for $\ell < \varphi(n)$.
Moreover, this will for the case for *every* $x$ when $n = pq$ is an RSA modulus.
One thing that Lagrange's theorem will still give us, even when $\ell \ne \varphi(n)$, is that $\ell \mid \varphi(n)$.[^1]

The *smallest* exponent such that $x^\ell \equiv 1 \pmod n$ for *all* $x$ is known as the Carmichael function $\lambda(n)$.
We know that $\lambda(n) \mid \varphi(n)$, but we can even write down a nicer formula:[^2] 

$$
\lambda(p_1^{r_1}p_2^{r_2}\ldots p_m^{r_m}) = \mathrm{lcm}(p_1^{r_1 - 1}(p_1 - 1), \ldots, p_m^{r_m - 1}(p_m - 1))
$$

which, when we apply this to our RSA modulus $n$, becomes 

$$
\lambda(pq) = \mathrm{lcm}(p - 1, q - 1)
$$

Returning to our wrong statement from before, we now know that $e^{R + 1} \equiv 1 \pmod \ell$ where $\ell \mid \lambda(n)$, and furthermore, since $e$ doesn't look too suspicious, nor can a readable flag be influenced all *that* much, we can in fact hope that $e^{R + 1} \equiv 1 \pmod{\lambda(n)}$.

[^1]: Read as: $\ell$ divides $\varphi(n)$
[^2]: For simplicity, we restrict the choices of $p_i^{r_i}$ here to those values where $p_i \ne 2$ or $r_i < 3$, see e.g. the [wikipedia page](https://en.wikipedia.org/wiki/Carmichael_function) for the full details.

## Factors of factors of factors; and some subtractions

Now that we understand the nuances of the formula $x^\ell \equiv 1$ a bit better, we can think further towards solving this challenge.
Remember what we wrote down earlier?

$$
e^{R + 1} \equiv 1 \pmod{\lambda(n)}
$$

This tells us something more, since we have exactly the form of statement that lead us to introducing $\lambda(n)$ in the first place.
We could now say that $R + 1 \mid \lambda(\lambda(n))$, which gives us a somewhat nice relation between the value $R$ we'd been given, and our RSA modulus $n$.

Let's not worry about the possibility that $R + 1$ is only a divisor, and instead assume that it holds with equality $R + 1 = \lambda(\lambda(n))$.
Then we can try to write down what we expect $R + 1$ to be:[^3]

$$
\begin{aligned}
R + 1 = \lambda(\lambda(n)) &= \lambda(\mathrm{lcm}(p - 1, q - 1)) \\
                            &= \lambda(2s_1s_2\ldots s_m) \\
                            &= \mathrm{lcm}(s_1 - 1, \ldots, s_m - 1)
\end{aligned}
$$

We now would like to relate these values $s_i - 1$ to $R$ somehow.
By the above, it should be clear that any $s_i - 1 \mid R + 1$, so when we list all divisors of $R + 1$ in turn, and add $1$ to them, we should end up with a set of candidates $\mathcal{C}$, such that $\\{s_i\\}_i \subseteq \mathcal{C}$.
The value $R + 1$ itself is not particularly easy to factor in a short amount of time, but luckily it's not an esoteric, unknown value, but a nicely structured one.
And as it often happens to nicely structured values, they show up on [factordb](http://factordb.com/index.php?query=2%5E1025+-+2).

[^3]: Yet another minor assumption is introduced here, that none of the prime factors we deal with has a higher power than $1$. As we'll be able to observe from the factorization of $R + 1$ later, this doesn't seem too unlikely.


## Who cares if it's not *the* private key? It works

With the set $\mathcal{C}$, what could we do?
One option to consider is applying the same trick again, but using $\mathcal{C}$ rather than the factorization of $R + 1$, to recover $p$ and $q$.
Annoyingly, $\mathcal{C}$ is a rather large set, and enumerating all subsets of it takes exponential time, so we'll have to throw that idea out.

Instead, let's look back at our initial, more naive, understanding of the RSA cryptosystem, where we used $\varphi(n)$ rather than $\lambda(n)$ to compute the decryption exponent $d = e^{-1} \pmod{\varphi(n)}$.
Even though we didn't have the smallest modulus possible, we still had full correctness, since --- as we know by now --- $\lambda(n) \mid \varphi(n)$.
We can take that to the extreme: we know/assume that all factors of $\lambda(n)$ are among our values $s_i$, so if we simply take $\Xi = \prod_i s_i$, it should hold that $\lambda(n) \mid \Xi$, and as such, we could use $\Xi$ as a "replacement" for $\lambda(n)$ or $\varphi(n)$ when it comes to computing a decryption exponent.

With this, we have enough ideas and information to finally solve this challenge[^4].

> `CTF{Recycling_Is_Great}`

[^4]: [...] for the first time. We'll also look at the intended solution after this, which takes a somewhat similar approach initially, but then applies it to factoring $n$ directly.

## All your factorbase are belong to us

The official [intended solution](https://github.com/google/google-ctf/blob/master/2022/crypto-cycling/src/solve.py) relies on similar observations, but instead of finding some number $k\lambda(n)$, it uses those potential factors of $\lambda(n)$ to directly factor the modulus $n$.[^5]
To understand how this factorization works, we look back at a well-known, simple special-purpose factoring algorithm: [Pollard's `p - 1` algorithm](https://en.wikipedia.org/wiki/Pollard%27s_p_%E2%88%92_1_algorithm).

Pollard's algorithm allows finding a factor $p$ (say for $n = pq$) under the assumption that $p - 1$ is $B$-powersmooth.
That is, all prime power divisors $s^r \mid p - 1$ are bounded by $s^r < B$.
This property enables us to find some product $M$ of prime powers less than $B$, such that $p - 1 \mid M$ but $q - 1 \nmid M$.
In turn, looking at Fermat's little theorem, we can see that for all $a$, it holds that $a^M \equiv 1 \pmod p$, but it will often be the case that $a^M \not\equiv 1 \pmod q$, and so looking for $\gcd(a^M - 1, n)$ should allow us to recover $p$.
Traditionally, Pollard's method computes $a^M \pmod n$ by repeatedly taking $s$th powers of an accumulator and testing whether the $\gcd$ results in a factorization.
The advantage of this is twofold: one doesn't need to fully compute $M$ in its entirety[^6] and as long as the largest factor of $p - 1$ differs from the largest factor of $q - 1$,[^7] the method will still work, rather than yielding $n$ as the $\gcd$.

To abstract the bound $B$ away, we simply notice that all it gives us is some superset $\mathcal{C}$ of prime (power) factors of $p - 1$.
This is exactly what we already found by enumerating primes $s_i$ such that $s_i - 1 \mid R + 1$!
If we call such a set $\mathcal{C}$ a [factor base](https://en.wikipedia.org/wiki/Factor_base), and slightly generalize Pollard's algorithm, we can apply it to our situation as well.
And this is exactly the approach we see in the official solution script: we take some base $a$ (there called $m$), repeatedly exponentiate it by potential prime factors, and check if $\gcd(a' - 1, n) \notin \{1, n\}$.

Once a factorization of $n$ is found, it is of course only a matter of performing regular RSA decryption to obtain the flag.

[^5]: In this script, we can also observe a clean explanation of why $R + 1$ can be easily factored or found on factordb: $R + 1 = 2(2^{1024} - 1)$ is twice a [Mersenne number](https://en.wikipedia.org/wiki/Mersenne_prime).
[^6]: Computing all of $M$ would result in a potentially huge number that is unwieldy to work with.
[^7]: Alternatively, we could reorder the factors in question, replace the notion of "largest" by "latest in the reordered sequence", though that is less practical from an implementation point of view.

## Does this always work?

Until now, we've made several assumptions that turned out to be correct, in order to solve this challenge.
Even the official solution turns out to rely on those assumptions,[^8] so we'd like to have a look at how much trouble we'd be in when the assumptions would be invalidated.
To restate our assumptions more explicitly:

1. $R + 1 = \lambda(\lambda(n))$
    - The inner $\lambda$ corresponds to the multiplicative order of the flag, $\|m\| \pmod n$
    - The outer $\lambda$ corresponds to the multiplicative order of $e$, modulo $\|m\|$
2. $p - 1$ and $q - 1$ are square-free, that is, none of their prime factors occur with multiplicity $> 1$.
3. All $s_i - 1$ are square-free, where $s_i \mid \lambda(n)$, but this has been confirmed by the factorization of $R + 1$

And let's also introduce some counterexamples for all of these, where our assumption is invalidated, and our solution becomes broken:

1. We explore the possibility for both $\lambda$s:
    - Let $n = 77$, then $\lambda(n) = \mathrm{lcm}(6, 10) = 30$, but for the message $m = 15$, it's already true that $m^5 \equiv 1 \pmod n$, rather than the expected $m^{30}$.
      This in turn implies that we only need $e^{R + 1} \equiv 1 \pmod 5$ to complete decrypt this message by cycling.
    - We now use $n = 989 = 23\times43$, so $\lambda(n) = 2\times3\times7\times11 = 462$ and $\lambda(\lambda(n)) = \mathrm{lcm}(2, 6, 10) = 30$, but for instance $e = 379$ only has multiplicative order $5$ modulo $\lambda(n)$.
2. Consider $n = 163\times67 = 10921$, then $\lambda(n) = \mathrm{lcm}(2\times3^4, 2\times3\times11) = 2\times3^4\times11 = 1782$.
   $\lambda(\lambda(n))$ would then be $2\times3^3\times5$, and we'd never pick up $3^4$ as a potential factor out of any subset.
3. Similar issues to the earlier point occur, except they are introduced slightly later in the process of computing $\lambda(\lambda(n))$.

Other than those assumptions, there's some more things that can go wrong.
We've relied on enumerating all subsets of factors of $R + 1$, but --- as we remarked with an initial failed idea of repeating such an enumeration on the result of that --- that takes exponential time in the number of factors.
If we end up with a large amount of these factors, we might in fact already get in trouble trying to enumerate all subsets, and spend a long time waiting for that.[^9]
On the other side of that medallion, to obtain that initial list of factors, we need to be able to factor this value $R + 1$.
Now, if we consider for instance the worst case, where $p$ and $q$ are what we could call *doubly-safe* primes, i.e. $p = 2(2p' + 1) + 1$, $p$ and $\frac{p - 1}{2}$ are both safe primes, there's only a minor difference in number of bits between $n$ and $\lambda(\lambda(n))$ and the latter is even a new RSA modulus.
By assumed security of RSA (unless you get extra information like in this challenge), factoring that would not be feasible.


[^8]: After the end of the CTF, one of the organizers clarified that the challenge description would have better stated that the given number of repetitions works for *any* exponent $e$. [reference](https://discord.com/channels/984515980766109716/984516677624541194/993499537580761119).
[^9]: This does make me wonder if some other modification of e.g. the `p - 1` algorithm might be able to deal with this issue, but so far I've been unable to come up with a proper adaptation. I'm always open for comments or ideas if you would happen to have any on this topic.

## Can we fix it?

> Yes we can!

Sort of, at least.
Unless my very vague notion from the footnote in the previous section pans out, I don't expect we could get around the exponential time enumeration, or the factoring problems.
We can however try to fix up some of the problems our assumptions brought along, and get a slightly more generic solution.

Let's first look at the case where $\|m\| < \lambda(n)$.
Since for our original approach, we only care about $m$ itself, and not about factoring, we only need to find a multiple of $\|m\|$, which we still get from our powerset enumeration (under the assumption, for now, that we get $\lambda(\|m\|)$).
This means we can still compute an effective decryption exponent that works for $m$ itself, and any element with an order dividing $\| m\|$.
Moreover, we can still use this to fully factor $n$ too.
Once we decrypt $m$, we know that $m^{k\mid m\|} \equiv 1 \pmod n$, which means we can again apply our `p - 1` approach with a factor base to find an exponent $M$ such that $m^M \equiv 1 \pmod p$.
Note that we require the use of $m$ as basis here, rather than an arbitrary number $a$.
The only condition under which this will still necessarily fail is when $\|m\|$ divides $\gcd(p - 1, q - 1)$, since then any exponent such that $m^M \equiv 1 \pmod p$ also satisfies $m^M \equiv 1 \pmod q$.[^10]

[^10]: Taken to the extreme, we might suddenly be able to factorize again, when e.g. $m^2 \equiv 1 \pmod n$.

Next, we investigate the case where $R + 1 \ne \lambda(\|m\|)$.
Unfortunately, the solution here isn't quite as clean.
When the order of $e$ is too small, we simply lack the information to recover enough primes.
When the order of $e$ is only slightly too small, we should be able to salvage it with only a constant cost to our computation time.
Pick a fixed-size (multi)set of small primes $\mathcal{P}$, and let $\mathcal{C}' = \mathcal{C} \cup \mathcal{P}$.
This increases the computation time with a factor $2^{\|\mathcal{P}\|}$, but as long as the "lost" factor of $\lambda(\|m\|)$ is factorable over $\mathcal{P}$, our algorithm works again.
Optionally, if we would like to deal with more complex situations, we could also construct more complex ways to add extra factors.
For example, an approach comparable to the "two-stage" variant of the `p - 1` algorithm is possible, where we take e.g. at most 4 "small" primes and 1 "medium" sized extra prime.

Finally, how can we deal with the annoyance of prime powers?
To deal with prime power divisors of $\lambda(n)$, it's possible to apply a strategy similar to the `p - 1` factoring algorithm, where every prime factor is simply included multiple times.
Since exponents larger than $2$ can be detected in the factorization of $R + 1$, we recommend including each factor twice, unless evidence to the contrary is present from the factorization of $R + 1$.[^11]
The more conservative approach would be to include each prime $s$ a number of times proportional to $\frac{\log(n)}{\log(s)}$, which comes at an obvious computational cost.
For the prime power divisors of $\lambda(\lambda(n))$, we'll need to do just a bit more work.
If we see a prime power $s^r$ when factoring $R + 1$, it should be clear from how $\lambda$ works that we expect to also see the factors of $s - 1$ appear.
In that case, it's obvious that $s^{r + 1}$ should be in $\mathcal{C}$.
When however $s^2 \mid s_i$, we only see $s$ and the factors of $s - 1$ appear when factoring $R + 1$.
Hence, when we add a prime to $\mathcal{C}$ that still divides $R + 1$, we should add it with a higher multiplicity.

[^11]: One exception here might be for powers of $2$, since that's always the oddest prime, and it behaves differently when computing $\lambda$.

## Talk is cheap, show me the code

We present here the code as we implemented it during the CTF.
That is, making maximal assumptions such that it still gets the flag.
The code for factorization based on Pollard's `p - 1` algorithm can be found in the [official solution](https://github.com/google/google-ctf/blob/master/2022/crypto-cycling/src/solve.py).
Interested readers are encouraged to understand, implement and share the suggested improvements of this article :)

```sage
proof.all(False) # speed up primality checking a bit
import itertools
from Crypto.Util.number import long_to_bytes

# From the itertools documentation/example
def powerset(iterable):
    "powerset([1,2,3]) --> () (1,) (2,) (3,) (1,2) (1,3) (2,3) (1,2,3)"
    s = list(iterable)
    return itertools.chain.from_iterable(itertools.combinations(s, r) for r in range(len(s)+1))

# From factordb
factors = [2, 3, 5, 17, 257, 641, 65537, 274177, 2424833, 6700417, 67280421310721, 1238926361552897, 59649589127497217, 5704689200685129054721, 7455602825647884208337395736200454918783366342657, (2^256+1)//1238926361552897, (2^512+1)//18078591766524236008555392315198157702078226558764001281]
assert 2**1025-2 == prod(factors)

C = []
for ps in powerset(factors):
    v = prod(ps) + 1
    if is_prime(v):
        C.append(prod(ps) + 1)
Ξ = prod(C)

e = 65537
n = 0x99efa9177387907eb3f74dc09a4d7a93abf6ceb7ee102c689ecd0998975cede29f3ca951feb5adfb9282879cc666e22dcafc07d7f89d762b9ad5532042c79060cdb022703d790421a7f6a76a50cceb635ad1b5d78510adf8c6ff9645a1b179e965358e10fe3dd5f82744773360270b6fa62d972d196a810e152f1285e0b8b26f5d54991d0539a13e655d752bd71963f822affc7a03e946cea2c4ef65bf94706f20b79d672e64e8faac45172c4130bfeca9bef71ed8c0c9e2aa0a1d6d47239960f90ef25b337255bac9c452cb019a44115b0437726a9adef10a028f1e1263c97c14a1d7cd58a8994832e764ffbfcc05ec8ed3269bb0569278eea0550548b552b1
ct = 0x339be515121dab503106cd190897382149e032a76a1ca0eec74f2c8c74560b00dffc0ad65ee4df4f47b2c9810d93e8579517692268c821c6724946438a9744a2a95510d529f0e0195a2660abd057d3f6a59df3a1c9a116f76d53900e2a715dfe5525228e832c02fd07b8dac0d488cca269e0dbb74047cf7a5e64a06a443f7d580ee28c5d41d5ede3604825eba31985e96575df2bcc2fefd0c77f2033c04008be9746a0935338434c16d5a68d1338eabdcf0170ac19a27ec832bf0a353934570abd48b1fe31bc9a4bb99428d1fbab726b284aec27522efb9527ddce1106ba6a480c65f9332c5b2a3c727a2cca6d6951b09c7c28ed0474fdc6a945076524877680

d = pow(e, -1, Ξ)
print(long_to_bytes(int(pow(ct, d, n))))
```
