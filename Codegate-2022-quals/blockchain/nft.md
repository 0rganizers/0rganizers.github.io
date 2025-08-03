# NFT

**Author**: Robin_Jadoul

**Tags:** blockchain

**Points:** 907 (17 solves)

**Description:** 

> NFT should work as having a deeply interaction with third-party like https://opensea.io/
>
> We all know that blockchain is opened to all, which give us some guaranty thus it will work as we expected, however can we trust all this things?
>
> contract: 0x4e2daa29B440EdA4c044b3422B990C718DF7391c
> 
> service: http://13.124.97.208:1234
> 
> rpc: http://13.124.97.208:8545/
> 
> faucet: http://13.124.97.208:8080
> 
> network info: mainnet, petersburg

This is mostly a web challenge with a bit of blockchain flavor. We observe that part of the token URI is directly fed into `os.path.join` after stripping away a prefix. Reading [the documentation](https://docs.python.org/3/library/os.path.html#os.path.join), we see that

> If a component is an absolute path, all previous components are thrown away and joining continues from the absolute path component.

so we can get an absolute path out of it. The only obstacle remaining at this point is to find an IP address that:

- starts with a digit but not a 0
- doesn't contain `127.0.0.1` or `0.0.0.0`
- but is equivalent to `127.0.0.1` or `0.0.0.0`

To this end, we see that in the python version used, the `ipaddress` module was still fairly naive, and didn't allow e.g. a numeric IP, unfortunately. On the flip side, it didn't check for leading zeroes in octets yet either, so we can abuse that to have `127.0.0.01` as our IP instead and pass the checks.

To perform the actual exploit:

- Create an account and login
- Mint an NFT with tokenURI set to `127.0.0.01/account/storages//home/ctf/flag.txt` with the private key of the account
- visit the NFT listing for the account