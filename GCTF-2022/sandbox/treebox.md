# Treebox

**Author**: Robin_Jadoul

**Tags**: pyjail

**Points**: 50 (268 solves)

**Alternate URL**: <https://ur4ndom.dev/posts/2022-07-04-gctf-treebox/>

**Description**:

> I think I finally got Python sandboxing right.


## On the topic of pyjails

Python was one of the first programming languages I became acquainted with, and to this day remains one of -- and probably even *the* -- main language I go back to when I need to quickly write something, ranging from a proof of concept, to a hacky script that does some math when I'm too lazy, to the ever-recurring CTF solution scripts.[^1]
As such, ever since I started playing CTFs and encountering pyjail challenges, I've thoroughly enjoyed the concept of these jails, the act of playing Houdini, and even occasionally creating some pyjail challenges myself.
For some examples of earlier pyjails I particularly enjoyed, you can for example refer to my writeups for [this recent challenge on DiceCTF](https://ur4ndom.dev/posts/2022-02-08-dicectf-ti1337/) or [the 0CTF/TCTF challenge](https://ur4ndom.dev/posts/2020-06-29-0ctf-quals-pyaucalc/) that to the best of my knowledge was the first to introduce the audit hook system as a jailing mechanism[^audithookctf].

[^1]: And of course, the existence of tools such as [sage](https://sagemath.org) that plug into this ecosystem and that are indispensable for cryptographic exploration only serve to enhance my dependency on python.
[^audithookctf]: Since writing this, I've been informed that there were in fact earlier CTFs doing this that I was unaware of. For instance this [French CTF](https://redoste.xyz/2020/05/04/fr-write-up-fcsc-2020-why-not-a-sandbox/) did it before, and potentially there'd be others too.

Through this fascination and repeated exposure to pyjail challenges, in combination with coincidentally opening up the challenge rather early on, I was able to snatch the first blood on it.
In a move that surprised myself too, I was able to have a turnaround time only **2** minutes between first looking at the challenge file, and obtaining the flag.

I was able to find several of the approaches and techniques presented further on by myself/independently, but in order to present a wider overview of the used attack surfaces, I also referenced the publicly posted exploits in the CTF discord.
Even for those approaches where I constructed my own viable payloads, I attempt to reference some messages posted in the #sandbox channel of the [public discord](https://discord.gg/nt6JFkk3mu) after the conclusion of the CTF.

One interesting thing to notice for this challenge in particular, and presumably a reason for the high solve count, is that several of the pyjail escape methods listed on [the hacktricks page](https://book.hacktricks.xyz/generic-methodologies-and-resources/python/bypass-python-sandboxes) apply directly to this challenge, so the situation is already well-documented.

## The great snake, constricted

Let's first have a look at what the challenge allows us to do, or rather what it doesn't allow us to do:

```python
#!/usr/bin/python3 -u
#
# Flag is in a file called "flag" in cwd.
#
# Quote from Dockerfile:
#   FROM ubuntu:22.04
#   RUN apt-get update && apt-get install -y python3
#
import ast
import sys
import os

def verify_secure(m):
  for x in ast.walk(m):
    match type(x):
      case (ast.Import|ast.ImportFrom|ast.Call):
        print(f"ERROR: Banned statement {x}")
        return False
  return True

abspath = os.path.abspath(__file__)
dname = os.path.dirname(abspath)
os.chdir(dname)

print("-- Please enter code (last line must contain only --END)")
source_code = ""
while True:
  line = sys.stdin.readline()
  if line.startswith("--END"):
    break
  source_code += line

tree = compile(source_code, "input.py", 'exec', flags=ast.PyCF_ONLY_AST)
if verify_secure(tree):  # Safe to execute!
  print("-- Executing safe code:")
  compiled = compile(source_code, "input.py", 'exec')
  exec(compiled)
```

Summarized: there is an `ast` based blacklist in place that prevents us from either calling functions[^2] or importing modules through the `import` statement.
As far as I'm aware, `ast` relies on the actual parser that the python interpreter itself uses, so we're unlikely to encounter any parser differentials to abuse here.
On the upside, and something that's certainly not a guarantee in this kind of challenge, we do have full access to all python builtins.
There are also no character-level blocks, so we *could* use parentheses in some context if we wanted; as long as they're not used to call a function.

On the topic of `import` statements, it's worth noting that, with the access to the python builtins that we have, being able to call functions is enough, since the `__import__` function could do everything we need from it.

[^2]: Or prevents us from calling *callables* in general, really. For instance constructing a class isn't really calling a function, but it would get caught here too.

Our end goal for this challenge would be an (arbitrary) file read of the `flag` file, but of course we won't say no to getting full code execution if it happens to fit our needs.

My very first solution is similar to the [polygl0ts writeup](https://polygl0ts.ch/writeups/2021/b01lers/pyjail_noparens/README.html) for the [noparensjail](https://github.com/b01lers/b01lers-ctf-2021/tree/main/misc/noparensjail) challenge from b01lers CTF 2021.
Contrary to the intended solution presented by the people from b01lers, we can't directly use `import`, so we need some other approach.
Luckily, the polygl0ts approach works, but is a bit more convoluted than what we really need.

To see why exactly, and to see the beauty of this exploit, we first make a quick detour through two *short* python expressions that can give us full code execution without further restrictions[^3] (either still in python, or directly in a shell).
Without a doubt, the shortest expression I know that achieves this is `help()`, which can spawn a shell through the `more` pager if a topic that takes up more than a page is requested at the interactive help prompt.
Unfortunately, that requires both a pager being present, and a tty, which isn't the case for this challenge.
So instead, I went for the second convenient method I knew: `exec(input())`.
Since we arrive in a fresh execution context, with arbitrary code sent through stdin, the `ast` blacklist no longer applies to our new code, and we can do whatever we want from there.

[^3]: As long as we still have access to the python builtins, otherwise we need to circumvent that, potentially in the second stage again too.

So the full exploit code is something as simple as

```python
@exec
@input
class X:
    pass
```

and keeping in mind how [decorators](https://docs.python.org/3/glossary.html#term-decorator) works, we can see that this code is equivalent to

```python
class X:
    pass
X = input(X)
X = exec(X)
```

which is essentially the same as our wanted `exec(input())` other than the fact that `input(X)` will also print a representation of the class `X` to stdout before reading.

Since decorators aren't parsed as call expressions or statements, this passes the blacklist, and allows us to finally pass in an input such as `import os; os.system("sh")` to obtain a shell and display the flag.

See [this example](https://discord.com/channels/984515980766109716/992433413351018526/993233705927712899) for a similar exploit template, but going through some different methods to establish code execution.

## Alternative approaches

With my initial solution behind us now, let's have a look at some of the other approaches, and general techniques that can also allow flag recovery on this challenge.
The general spirit behind all of these will obviously be to use something in the python ecosystem that ends up calling a function, without being an *explicit* function call.
The approaches I found or observed roughly fall into three categories:

- Operator overloading
- Function overwriting
- Interpreter hooks

These categories can of course overlap somewhat, or not exactly cover everything, but you get the idea :)

### Operator overloading, aka `x.equals("string")` sucks

In python, operator overloading in general works by writing custom functions on your class with special names.
These are also known as *dunder* methods, after how the names are all enclosed in *d*ouble *under*scores, such as the well-known `__init__` constructor.
So if we can overwrite functions such as `__getitem__` or `__add__` on a class, or if we can write our own classes with those methods, we can get function calls for example with

```python
obj[argument]
# Or
obj + argument
```

To overwrite these methods on existing classes/objects, we need to find something that's implemented in plain python, as things implemented in C/in extension modules are read-only.
Some of the possible approaches are for example:

- the `ast.AST` class and the available `tree` object ([example 1](https://discord.com/channels/984515980766109716/992433413351018526/993310441516314739), [example 2](https://discord.com/channels/984515980766109716/992433413351018526/993241943284924546))
- the `os.environ` object ([example](https://discord.com/channels/984515980766109716/992433413351018526/993359479477391461))

### Hippity, hoppity, this attribute is now my property

Since some of these don't take any arguments at all, we'll also need some "one-shot" functions that we can leverage to get either an arbitrary file read, or more python control.

For arbitrary file read, one approach includes overwriting some of the innards of the `license()` builtin function.[^4]
More in particular, overwriting the "private"[^5] member variable that specifies from which files it reads license information.
Another approach calls the `breakpoint()` builtin, that by default points to `pdb.set_trace()`, which spawns a pdb debugger.
With a debugger, we can easily evaluate arbitrary python code again to obtain a system shell.

Another function that can be overwritten to get one-shot function call includes `sys.stdout.flush` which would get called upon interpreter exit, or `sys.stderr.flush` which can be triggered when an exception occurs.
Both the `os` and `sys` modules were already imported in the parent context, so we can access either `sys` directly, or pass through `os.sys`.

[^4]: See [hacktricks](https://book.hacktricks.xyz/generic-methodologies-and-resources/python/bypass-python-sandboxes#read-file-with-builtins-help) for a reference on exactly which member to write to.
[^5]: Heh, thanks python.


### Everything is an object, even if it's a class

Next up, let's explore a few ways to create objects, of course without calling the constructor explicitly.
The first approach towards this we can use relies on the concept of [metaclasses](https://docs.python.org/3/reference/datamodel.html#metaclasses).
In short, a class is itself also an object, and its type/class is known as a metaclass.
The standard metaclass for classes is `type`, whose own metaclass is, interestingly, `type`.
The key thing that metaclasses allow us to do is make an instance of a class, without calling the constructor directly, by creating a new class with the target class as metaclass.[^6]
Since this is all a bit confusing, perhaps, let's show some example code:

```python
# This will define the members on the "sub"class
class Metaclass:
    __getitem__ = exec # So Sub[string] will execute exec(string)
# Note: Metaclass.__class__ == type
    
class Sub(metaclass=Metaclass): # That's how we make Sub.__class__ == Metaclass
    pass # Nothing special to do

assert isinstance(Sub, Metaclass)
sub['import os; os.system("sh")']
```

One other example takes this further by overloading the `__instancecheck__` dunder and triggering it through a `match` statement ([example](https://discord.com/channels/984515980766109716/992433413351018526/993222030545666060)).

[^6]: This is starting to feel like a "how many times can you use the word class in a sentence while still being understandable and correct"...

### Exceptional function calls

Another approach to making instances of a class is also documented on [hacktricks](https://book.hacktricks.xyz/generic-methodologies-and-resources/python/bypass-python-sandboxes#rce-declaring-exceptions): throw and catch an exception.
Throwing an exception without arguments will automatically call its constructor.
Then we can either use of our previously-covered one-shot functions ([example](https://docs.python.org/3/reference/datamodel.html#metaclasses)), or use the operator overloading as with the metaclasses above (what hacktricks does).

Writing a one-shot function taking three arguments to `sys.excepthook` could also allow for exploitation by throwing an (uncaught) exception.

And finally, looking at the [reference solution](https://github.com/google/google-ctf/blob/master/2022/sandbox-treebox/healthcheck/solution.py), we can see that there's even some room to exploit OS/distro-specific functionality to combine with error handling and operator overloading to execute code.
In particular, here the interpreter will try to import an apt-specific module to potentially report an error in ubuntu-provided modules, but import will instead construct an object that will call an overloaded operator to execute code.
Without overwriting `__import__` and applying the previous exception-based object construction instead, we could also apply the same `__init__` to `__iadd__` chaining as demonstrated here.
More generally, defining `__init__` will allow for similar one-shot approaches taking an arbitrary number of arguments, such as we wished for above:

```python
class X:
    def __init__(self, a, b, c):
        self += "os.system('sh')"
    __iadd__ = exec
sys.excepthook = X
1/0
```

## Conclusion

This jail was leakier than a sieve, and it probably had the highest amount of sufficiently distinct potential solutions I've ever seen on a pyjail so far.
Together with some payloads that could be directly copy-pasted from previous writeups and hacktricks, this led to a high amount of solves.
The challenge itself was however still a lot of fun, and particularly interesting as a case-study of exploitation approaches that are allowed by a minimal-but-not-trivial AST-based blacklist,[^7] for which I would like to thank the author.


[^7]: And obviously, that is exactly what this writeup aims to be :)

### Addendum

While there were a lot of different exploits possible, I'm particularly happy with my initial one, for a few arbitrary reasons:

- It got me a quick first blood
- It's one of the few exploits that don't need any parentheses at all
- When looking at it as a code golf challenge, it has the lowest amount of characters I've seen in any of the solutions posted on discord. This is even improved upon slightly be replacing the `pass` in the class body with simply the constant `0`.
