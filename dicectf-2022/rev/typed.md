# typed

**Authors:** Robin_Jadoul 

**Tags:** rev, rust 

**Points:** 362 (8 solves) 

**Challenge Author:** aplet123 

**Description:**
~~Haskell~~ Rust is a dynamically typed, interpreted language. Can you get my code to stop erroring?

## Lay of the land

A reversing challenge where we're given the [source code](typed.rs).
How hard could it be?

Alright, so it's clearly not as trivial as having source code makes it sound,
but typelevel metaprogramming is fun and often follows some recognizable patterns.
Let's first have a look at the general outline:

- Some types and traits are defined to represent data/values and operations on those
- Some of those operations induce constraints that should be satisfied on the data
- The flag is defined with a new type alias per character
- We perform some operations on and add some constraints to the flag characters
- If it typechecks, the program compiles and outputs the flag when run

## Eyes on the prize

So let's have a look at how the final constraints are defined:

```rust
type DanceDanceGice = <DanceDanceGong as DanceGang>::DidGong;
fn main() {
    print_flag();
    let _: DanceDanceGice = panic!();
}
```

All weird naming aside, we just need `DanceDanceGice` to be a valid type, and hence for `DanceDanceGong` to
implement the `DanceGang` trait.
The associated type `DidGong` of that `DanceGang` trait will then be a valid type.

Looking a bit higher in the file, we can see this calling into some more constraints, and eventually getting
into some massive line of code the does a bunch of different things with the flag characters.
I'll consider the margins of this theoretically infinitely large webpage as too small to reproduce the monstrosity here.[^walloftext]

Now, it's time to really go in the deep end.
We'll go all the way back to the top of the file, and try to identify what's going on.

## Look mom, I can do mathematics

```rust
#![recursion_limit = "10000"]
use std::marker::PhantomData;
struct DidGongGong<DiceDiceGice>(PhantomData<DiceDiceGice>);
struct DangGong;
trait DangGangGang<DidGang> {
    type DidGong;
}
impl<DiceDiceGice> DangGangGang<DangGong> for DiceDiceGice {
    type DidGong = DiceDiceGice;
}
impl<DiceDiceGice, DanceDanceGig> DangGangGang<DidGongGong<DanceDanceGig>> for DiceDiceGice
where
    DiceDiceGice: DangGangGang<DanceDanceGig>,
{
    type DidGong = DidGongGong<<DiceDiceGice as DangGangGang<DanceDanceGig>>::DidGong>;
}
```

Alright, very first line, let's ask the rust compiler for some mercy, because we're about to hurt it.
~~This will be fun.~~
Then some import to make our types happy if we don't actually make them inhabited, and off we go.

Now, let's see:

- We have two structs that are related: an empty struct, and a struct that contains *some* other type, but only kinda. (Since we never actually instantiate our types)
- And then we can define some operation on those types, where we juggle around the `DangGangGang` wrapper.

My eyes are already watering, let's try some renaming.
We're dealing with operations, and that `DidGong` name looks familiar from before.
Let's just call it `Result` from now on.[^naming]
Then, let's try to think what this is doing, is it ringing any bells yet?
What else could it be than our ever beloved [Peano arithmetic](https://en.wikipedia.org/wiki/Peano_axioms) of course.
Some more renaming, and suddenly things are looking ~~a lot~~ maybe somewhat more readable.

```rust
struct Succ<T>(PhantomData<T>);
struct Zero;

trait Add<V> {
    type Result;
}

impl<T> Add<Zero> for T {
    type Result = T;
}

impl<T, U> Add<Succ<U>> for T
where
    T: Add<U>,
{
    type Result = Succ<<T as Add<U>>::Result>;
}
```

And you know what, now that we've defined this, let's just get some convenience out of the way and
rename some of the numerals that we see popping up throughout the rest of the file.

```rust
type One = Succ<Zero>;
type Two = Succ<One>;
type Three = Succ<Two>;
type Four = Succ<Three>;
type Five = Succ<Four>;
type Six = Succ<Five>;
type Seven = Succ<Six>;
type Eight = Succ<Seven>;
type Nine = Succ<Eight>;
type Ten = Succ<Nine>;
```

Beautiful, isn't it?

To finish off the arithmetic part, we'll want some more operations[^lonely-addition].
So, without hurting our eyes again with the original code, I present you with the rename operations.

```rust
trait Mult<V> {
    type Result;
}

impl<T> Mult<Zero> for T {
    type Result = Zero;
}

impl<T, U> Mult<Succ<U>> for T
where
    T: Mult<U>,
    T: Add<<T as Mult<U>>::Result>,
{
    type Result = <T as Add<<T as Mult<U>>::Result>>::Result;
}


trait SubAndAssertPositive<V> {
    type Result;
}

impl<T> SubAndAssertPositive<Zero> for T {
    type Result = T;
}

impl<T, U> SubAndAssertPositive<Succ<U>> for Succ<T>
where
    T: SubAndAssertPositive<U>,
{
    type Result = <T as SubAndAssertPositive<U>>::Result;
}


trait NotEqual<V> {
    type Result;
}

impl NotEqual<Zero> for Zero {
    type Result = Zero;
}

impl<T> NotEqual<Zero> for Succ<T> {
    type Result = One;
}

impl<T> NotEqual<Succ<T>> for Zero {
    type Result = One;
}

impl<T, U> NotEqual<Succ<U>> for Succ<T>
where
    T: NotEqual<U>,
{
    type Result = <T as NotEqual<U>>::Result;
}

```

Now there's one more thing that's interesting to remark here:
when we try to instantiate the `SubAndAssertPositive` trait, it'll only work when `T` represents a number greater than `V`.
Hence this is the first type-level constraint that we encounter and that'll be used to enforce the correct values of our flag.
You'd almost start to think I put actual thought into renaming these things.

## Mama, just made a lisp

Alright, that's the first part out of the way, we're mostly done dealing with the simple arithmetic now.
Now, we first introduce some more data, and then we'll skip a bit ahead because things become repetitive, and dare I say almost boring.

```rust
struct DiceGice;
struct DiceGig<DanceGigGig, DiceDiceGice>(PhantomData<DanceGigGig>, PhantomData<DiceDiceGice>);
```

We see an empty type/data/value thing again, and something that contains two other types/values.
I suppose you could call it a pair?
Nah, for obvious reasons, we'll give it a more friendly name: `Cons`.
Our friend `DiceGice` shall furthermore henceforth be known under the name `Nil`.

Skipping ahead, we come to the next interesting part:

```rust
trait DanceGang {
    type Result;
}
// snip
impl DanceGang for Zero {
    type Result = Zero;
}
impl<T> DanceGang for Succ<T> {
    type Result = Succ<T>;
}
impl DanceGang for Cons<DidGig, DiceGice> {
    type Result = DiceGice;
}
impl<R, T> DanceGang for Cons<DidGig, Cons<R, T>>
where
    R: DanceGang,
{
    type Result = Cons<<R as DanceGang>::Result, T>;
}
```

[Oh no!](https://youtu.be/S74rvpc6W60?t=9)
It looks like we're evaluating lists of the form `(operation value0 value1 ...)`.

> I'm afraid you have a lisp sir, and it's incurable.

Cutting an already overly long story short, we've got a bunch of different "functions" that perform some pattern matching
and have some computations associated with it.
Classical and expected examples of course include things such as:

- `Sum`
- `Product`
- `Map`

There are some less expected but not overly hard operations like:

- `EveryThird`
- `SkipEveryThird`
- `AssertAllEqual`

However, once you start naming things like this, it's time to realize you have a problem, and intervene:

- `WTF1`
- `WTF2`
- `WeirdEquals`
- `WeirdNotEquals`

So to avoid boring my readers entirely to death, I'll just give you the opportunity to read my [reworked source code](typed_rev.rs)
at the point where I decided to give up on trying to understand it.

## Do you even lift, bro?

It was around this point that I decided I'd rather painstakingly reimplement each of these instructions in what most
people would consider to be a more normal programming language than this lisp, while trying to stay as close to the original
to avoid getting bugs lost in translation.

First things first, as there's still a massive wall of text to be processed, we'll have to deal with that.
I do not want to manually rewrite it, and I'm a bit afraid to mess things up if I start doing it with vim macros and regex replaces.[^vim]
So that leaves us with one real options: we'll have to parse it.
String wrangling is error-prone and tricky, so let's search google for some arbitrary python-based implementation of parser combinators.[^parsing][^monads]

We don't really care about any kind of whitespace and ignoring token separation makes it easier, so we'll just strip all of that out.
Introduce a our friends `Cons` and `Nil` to the big friendly snake, find some shortcut to evaluate operations, and we can actually parse and consume the entire wall of text. (The implementation of `Eval` is left open below, since that was refactored to use the rest of what I'll describe below in a later iteration)

```python
import parsy as P
from collections import namedtuple

Nil = object()
Cons = namedtuple("Cons", "head tail")

def Oper(op, lhs, rhs):
    if op == "Add":
        return Eval(lhs) + Eval(rhs) # Not technically Eval, but good enough for constant values
    elif op == "Mult":
        return Eval(lhs) * Eval(rhs) # Not technically Eval, but good enough for constant values
    else:
        assert False, op

numbers = {
        "Zero": 0,
        "One": 1,
        "Two": 2,
        "Three": 3,
        "Four": 4,
        "Five": 5,
        "Six": 6,
        "Seven": 7,
        "Eight": 8,
        "Nine": 9,
        "Ten": 10,
        "Hundred": 100,
        }
lits = {x: eval(x) for x in "Sum Prod EvalBothAndSub ApplyAll WTF1 AssertAllEqual AssertNotEqual Map WeirdEquals WeirdNotEquals EveryThird SkipEveryThird Apply Nil".split()}

def parse(v):
    pExpr = P.forward_declaration()

    @P.generate
    def pCons():
        yield P.string("Cons<")
        head = yield pExpr
        yield P.string(",")
        tail = yield pExpr
        yield P.string(">")
        return Cons(head, tail)

    @P.generate
    def pOper():
        yield P.string("<")
        lhs = yield pExpr
        yield P.string("as")
        op = yield P.string("Add") | P.string("Mult") | P.string("SubAndAssertPositive") | P.string("NotEqual")
        yield P.string("<")
        rhs = yield pExpr
        yield P.string(">>::Result")
        return Oper(op, lhs, rhs)


    literals = [P.string(x) for x in numbers.keys()] + [
                P.string(f"Flag{i}") for i in range(26)
            ][::-1] + [
                P.string(x) for x in lits.keys()
            ]
    pLit = literals[0]
    for n in literals[1:]: pLit |= n

    pExpr.become(pCons | pOper | pLit)
        
    v = v.replace(" ", "").replace("\n", "").replace("\t", "")
    return pExpr.parse(v)
```

Now we can start re-implementing each of our lispy operations in new functions, which gets heavily spiced with `isNil` and `isCons` calls,
because that was the most braindead and mechanical way I could still think of to perform the typesystem's pattern matching.
I'll humour you with the implementations of `Eval` and `WeirdEquals`, and leave the rest to the [final implementation](typed_solver.py).

```python
def Eval(x):
    if x in numbers:
        return numbers[x]
    if x in lits:
        return lits[x]
    if isinstance(x, int):
        return x
    if isinstance(x, str) and x.startswith("Flag"):
        return Flag[int(x[4:])]
    if isinstance(x, z3.ExprRef):
        return x
    assert isinstance(x, Cons)
    return Eval(x.head)(x)
    
def WeirdEquals(x):
    if isCons(x.tail) and isNil(x.tail.tail):
        sxyt = x.tail.head
        if isCons(sxyt.tail) and isCons(sxyt.tail.tail):
            s = sxyt.head
            x = sxyt.tail.head
            yt = sxyt.tail.tail
            if isCons(yt.tail) and isNil(yt.tail.tail):
                y = yt.head
                t = yt.tail.head
                return Cons("AssertAllEqual", Cons(Cons(s, Cons(x, Cons(y, Nil))), Cons(t, Nil)))
    assert False
```

From that point onwards, it's a surprisingly simple matter to add in symbolic variables and constraint enforcement with
the ever-glorious [z3 solver](https://github.com/Z3Prover/z3).
The gist of it is: when evaluating a flag character, use its corresponding symbolic variable instead; when you encounter something
for which you put `Assert` in the name earlier, add in a constraint on the global variable[^global] containing the solver object.

## Let it simmer a bit and serve hot

We clench our cheeks together, place our salt wards shaped as parentheses, pray to our favourite deities,
type `python typed_solver.py` and hope for the best.
We let it run for a while, have discord crash on us, almost run out of memory because we're doing way too much at once,
and fear that z3 the magnificent might not be able to do it.

Shortly after that, a flag appears.
Sometimes fears are completely unfounded, it would appear.

> `dice{l1sp_insid3_rus7_9afh1n23}`

## Closing thoughts

I would love to write as good a post and be as witty as the [inspiration for the challenge description](https://aphyr.com/posts/342-typing-the-technical-interview), but I'm afraid you'll have to make do with what this turned out as.
Nevertheless, as it turns out, type-level programming can be a lot of fun, and exercising the rust compiler
is a nice way to pass the time.
I'd like to thank aplet123 for this lovely challenge, and my teammates for suffering through my complaints
about how horrible a lisp implemented in the rust typesystem is while trying to reverse engineer it.
Maybe I should try to make an internet law out of the statement "A good CTF challenge is pain while solving it, and fun only in retrospect." :)[^internet-law]

---
[^walloftext]: And while I must already assume some level of masochism given that you are reading this post, I will consider it a kindness on my part towards the hypothetical reader's sanity.
[^naming]: I low-key think of these types as being bullied by me and being referred to by another name against their will now. Should I feel bad about this?
[^lonely-addition]: We wouldn't want our little friend that we're so harshly calling `Add` instead of `DangGangGang`, to feel lonely, now would we?
[^vim]: I shall remark here -- it's been a while since I last interjected with a footnote, sorry for that -- that I may or may not have tried to do exactly that earlier and may or may not have messed it up. Sometimes mysteries are simply meant to remain mysteries.
[^parsing]: In the given situation one might feel the need to stick to something familiar. Unfortunately, after sufficient mind-warping the functional-programming-inspired parsing paradigm is what starts to feel familiar now.
[^monads]: The particular library I ended up with used what the challenge author later referred to as "discount monads", implemented with generators/coroutines.
[^global]: It's CTF code, written after staring into the abyss for too long, don't hate me!
[^internet-law]: Tell your friends you heard it here first!
