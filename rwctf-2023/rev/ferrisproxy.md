# Ferris Proxy

In the client and server we find hardcoded private keys.

The first packet contains some information about the key used. In the first
attachment this was missing so we were not able to really decrypt anything.

In the second one we could decrypt the data after the first packet using the
rc4 key "explorer". Then using the private keys we can RSA decrypt the data
to get 16 random bytes from the client and 16 random bytes from the server.
Xored together they are the session key for the current session. (Indicated by
one of the first few ints in the packet). All the packets are encrypted using
AES128, so pretty easy to decrypt from that.

After that I wrote a parser for SOCKS5 and thought how I can decrypt the SSL
traffic and if there was some form of ssl intercept which would make that
possible.

Turns out it wasn't and the attachment was just wrong *again*, after the second
update three or four teams immediatly had the flag, so I know that I wasn't the
only one trying to decrypt ssl...
