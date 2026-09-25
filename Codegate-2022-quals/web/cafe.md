# CAFE

**Author**: Andris

**Tags:** web

**Points:** 100 (138 solves)

**Description:** 

> You can enjoy this cafe :)
> 
> upload text, youtube, ...

bot.py contains

```
driver.get('http://3.39.55.38:1929/login')
driver.find_element_by_id('id').send_keys('admin')
driver.find_element_by_id('pw').send_keys('$MiLEYEN4')
driver.find_element_by_id('submit').click()
time.sleep(2)
```

Loging in with these credentials gives a list with all of the admin's notes. The first of which (titled _flag_) contains the flag.
