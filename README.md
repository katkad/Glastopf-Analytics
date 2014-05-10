### Glastopf Analytics :: easy honeypot statistics v2.0

[Glastopf](https://github.com/glastopf/glastopf) is a Python web application honeypot founded by Lukas Rist.

---

This Perl script provides simple statistics for the Glastopf. While accessing default SQLite glastopf.db, it can retrieve some basic informations about your honeypot.

#### Requirements

DBI - Database independent interface for Perl (apt-get install libcpan-sqlite-perl)
Dancer2 - Lightweight yet powerful web application framework
Geo::IP - Look up location and network information by IP Address (apt-get install libgeo-ip-perl)

#### Installation

```
root@honeypot::~# git clone https://github.com/vavkamil/Glastopf-Analytics.git
```

#### Usage

First edit path to glastopf database & change username and password in ./lib/MyWeb/App.pm at lines 9-11:

set 'database'  =>  '/opt/myhoneypot/db/glastopf.db';
set 'username'  =>  'admin';
set 'password'  =>  'password';

```
root@honeypot:~/Glastopf-Analytics$ perl ./bin/app.pl
```

#### Example

[![IMAGE ALT TEXT HERE](http://img.youtube.com/vi/WSRGPYnC73A/0.jpg)](http://www.youtube.com/watch?v=WSRGPYnC73A)