### Glastopf Analytics :: easy honeypot statistics v2.0

[Glastopf](https://github.com/glastopf/glastopf) is a Python web application honeypot founded by Lukas Rist.

---

This Perl script provides simple statistics for the Glastopf. While accessing default SQLite glastopf.db, it can retrieve some basic informations about your honeypot.

#### Usage

First edit patch to glastopf database in /bin/app.pl at line 9:

set 'database'  =>  '/opt/myhoneypot/db/glastopf.db';

```
root@honeypot:~/Glastopf-Analytics$ perl ./bin/app.pl
```