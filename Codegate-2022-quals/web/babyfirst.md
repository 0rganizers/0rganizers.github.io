# babyFirst

**Author**: jkr

**Tags:** web

**Points:** 718 (29 solves)

**Description:** 

> get the flag

The memo application babyFirst allows to write, list and read memos that are created. The complete application logic is in the `MemoServlet.class`. After decompilation we see the request routing and user/session handling. The only function that is standing out to be exploitable is `lookupImg()` that gets called when viewing a memo. 

```java=
  private static String lookupImg(String memo) {
    Pattern pattern = Pattern.compile("(\\[[^\\]]+\\])");
    Matcher matcher = pattern.matcher(memo);
    String img = "";
    if (matcher.find()) {
      img = matcher.group();
    } else {
      return "";
    } 
    String tmp = img.substring(1, img.length() - 1);
    tmp = tmp.trim().toLowerCase();
    pattern = Pattern.compile("^[a-z]+:");
    matcher = pattern.matcher(tmp);
    if (!matcher.find() || matcher.group().startsWith("file"))
      return ""; 
    String urlContent = "";
    try {
      URL url = new URL(tmp);
      BufferedReader in = new BufferedReader(new InputStreamReader(url.openStream()));
      String inputLine = "";
      while ((inputLine = in.readLine()) != null)
        urlContent = urlContent + inputLine + "\n"; 
      in.close();
    } catch (Exception e) {
      return "";
    } 
    Base64.Encoder encoder = Base64.getEncoder();
    try {
      String encodedString = new String(encoder.encode(urlContent.getBytes("utf-8")));
      memo = memo.replace(img, "<img src='data:image/jpeg;charset=utf-8;base64," + encodedString + "'><br/>");
      return memo;
    } catch (Exception e) {
      return "";
    } 
  }
```

A `java.net.URL` class will be initialized for a given URL in square brackets. Java without custom classes supports several protocols out-of-the-box like `http`, `https` as well as `file` (for local file reads). As the given URL is downcased we can't use `FILE:///flag` to read as `file` protocol is blacklisted. Looking into the `java.net.URL` source code we find following special case while parsing the URI:

```c=
        try {
            limit = spec.length();
            while ((limit > 0) && (spec.charAt(limit - 1) <= ' ')) {
                limit--;        //eliminate trailing whitespace
            }
            while ((start < limit) && (spec.charAt(start) <= ' ')) {
                start++;        // eliminate leading whitespace
            }

            if (spec.regionMatches(true, start, "url:", 0, 4)) {
                start += 4;
            }
            (...)
```

By prefixing the blacklisted `file:///flag` with `url:` we can access the flag by posting (and afterwards viewing) a memo with content:

`[url:file:///flag]`