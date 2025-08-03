# superbee

**Author**: Andris

**Tags:** web

**Points:** 100 (89 solves)

We have an API with the following relevant endpoints:
1) `/main/index` gives us the flag provided that we have the session cookie set to `MD5("admin" + auth_key)`.
2) `/admin/authkey` gives us `AES-CBC-ENCRYPT(ptxt=auth_key, iv=PADDED(auth_crypt_key), key=PADDED(auth_crypt_key))` if the server's domain is `localhost`.

We are also given this config
```
app_name = superbee
auth_key = [----------REDEACTED------------]
id = admin
password = [----------REDEACTED------------]
flag = [----------REDEACTED------------]
```
which is loaded as follows.
```
app_name, _ = web.AppConfig.String("app_name")
auth_key, _ = web.AppConfig.String("auth_key")
auth_crypt_key, _ = web.AppConfig.String("auth_crypt_key")
admin_id, _ = web.AppConfig.String("id")
admin_pw, _ = web.AppConfig.String("password")
flag, _ = web.AppConfig.String("flag")
```

In order to call endpoint 1 and get the flag, we need to get the auth_key. We can call endpoint 2 by simply manually setting the `Host` header to `localhost`. From there we need to compute
`AES-CBC-DECRYPT(ctxt=encrypted_auth_key, iv=PADDED(auth_crypt_key), key=PADDED(auth_crypt_key))`
Meaning we need to find out the `auth_crypt_key`. Since `auth_crypt_key` is read from the config but not actually stored there, it defaults to `""`. So by setting the session cookie to
`MD5("admin" + AES-CBC-DECRYPT(ctxt=encrypted_auth_key, iv=PADDED(""), key=PADDED("")))` 
we can get the flag from endpoint 1.