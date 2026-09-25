# Fourchain - Prologue

> Nspace — 11/27/2022 5:34 AM
> 
> &nbsp;&nbsp;we have the browser chain
> 
> gallileo [flagbot] — 11/27/2022 5:39 AM
> 
> &nbsp;&nbsp;I think we are ready for remote
> 
> &nbsp;&nbsp;2-3 minutes for vm to launch
> 
> david — 11/27/2022 5:40 AM
> 
> &nbsp;&nbsp;hell yeah
> 
> Nspace — 11/27/2022 5:41 AM
> 
> &nbsp;&nbsp;we have a shell on the vm 
> 
> &nbsp;&nbsp;root on the vm
> 
> The Organizer — 11/27/2022 5:43 AM
> 
> &nbsp;&nbsp;The flag: `hitcon{G00dbY3_1_4_O_h3LL0_Pwn_2_Own_BTW_vB0x_Y_U_N0_SM3P_SM4P_??!!}`
> 
> gallileo [flagbot] — 11/27/2022 5:43 AM
> 
> &nbsp;&nbsp;first try everything and first blood
> 
> &nbsp;&nbsp;didnt have to restart a single exploit 🙂
> 

#### The discord convo during our solve of the final fullchain challenge, does not do our emotions justice ;) Probably the longest and most exhilarating exploit I have ran.

## Introduction

Fourchain was a series of four[^1] challenges released during HITCON 22 CTF.
After the [CHAOS series from last year's edition](../../HITCON-2021/pwn/chaos), we thought it would be hard to top that.
However, the good people at HITCON managed to do it and I can confidently say that this series of challenges was the best pwnables I have encountered so far.
Not only were they quite fun and insanely challenging, they also showcased that CTF challenges are not just simple exercises, but reflect the actual real world (more on that later).
What follows are writeups of the four separate parts, followed by the fullchain and finally some closing thoughts.
If you follow along, you should be able to create your own exploit, going from javascript code execution to escaping the hypervisor, just like seen below ;)

[^1]: Technically five, but the fifth challenge "just" consisted of chaining the other four together.

<video width="100%" controls="controls">
  <source src="./img/fourchain_gui.mp4">
</video>

## Table of Contents

Since the different stages are mostly independent, you can read them in any order.
However, to understand the fullchain, it makes sense to first have read all of the other ones.
The chapters are as follows:

- **[Prologue](./fourchain-prologue) (You are here)**
- [Chapter 1: Hole](./fourchain-hole): Using the "hole" to pwn the V8 heap and some delicious Swiss cheese.
- [Chapter 2: Sandbox](./fourchain-sandbox): Pwning the Chrome Sandbox using `Sandbox`.
- [Chapter 3: Kernel](./fourchain-kernel): Chaining the Cross-Cache Cred Change
- [Chapter 4: Hypervisor](./fourchain-hv): Lord of the MMIO: A Journey to IEM
- [Chapter 5: One for All](./fourchain-fullchain): Uncheesing a Challenge and GUI Troubles
- [Epilogue](./fourchain-epilogue): Closing thoughts

