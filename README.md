### Glastopf Analytics :: easy honeypot statistics v1.0

[Glastopf](https://github.com/glastopf/glastopf) is a Python web application honeypot founded by Lukas Rist.

---

This Perl script provides simple statistics for the Glastopf. While accessing default SQLite glastopf.db, it can retrieve some basic informations about your honeypot.

#### Example

This is a small overview about what the script prints out:

```
root@honeypot:~# perl glastopf-analytics.pl

* * * * * * * * * * * * * * * * * * * * * * * * * * * *
* Glastopf Analytics :: easy honeypot statistics v1.0 *
* * * * * * * * * * * * * * * * * * * * * * * * * * * *
* What to do?
*
* 1) Show last 10 events
* 2) Show last 10 files
* 3) Show top 10 countries
* 4) Show top 10 user-agents
* 5) Show top 10 event patterns
* 6) Show top 10 requested filetypes
* 7) Show top 10 attackers
* 8) Show top 10 files
* 9) Delete IP address from events
* 10) Exit
*
* Enter number of your choice (1-10):
```
