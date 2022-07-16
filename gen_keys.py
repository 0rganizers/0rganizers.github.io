import json
import urllib.request
import base64
import os
req = urllib.request.Request("https://api.github.com/orgs/0rganizers/members?per_page=100")
username = os.getenv("READ_ORG_USER", "galli-leo")
password = os.getenv("READ_ORG_TOKEN", "[redacted]")

credentials = ('%s:%s' % (username, password))
encoded_credentials = base64.b64encode(credentials.encode('ascii'))
req.add_header('Authorization', 'Basic %s' % encoded_credentials.decode("ascii"))
keys = ""
print(f"[+] getting all members")
with urllib.request.urlopen(req) as response:
    members_text = response.read()
    members = json.loads(members_text)
    for member in members:
        user = member['login']
        print(f"[+] getting keys for user: {user}")
        try:
            with urllib.request.urlopen(f'https://github.com/{user}.keys') as response:
                user_keys = response.read()
                keys += user_keys.decode()
        except:
            print(f"[!] user {user} probably has no keys, oh well!")
print(f"[+] writing to keys file")
with open("keys", "w") as f:
    f.write(keys)
