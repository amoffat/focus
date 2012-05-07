Focus.py helps you keep focused by applying schedulable firewall rules
to distracting websites.  An example firewall rule looks like this:

``` python
def domain_reddit_com(dt):
    return dt.hour == 21 # allow from 9-10pm
```

Starting
========

Add the following line to the top of your `/etc/resolv.conf`, *before* any
other nameservers:

    nameserver 127.0.0.1
    
Now start Focus:

    sudo python focus.py &
    
    
Filtering Domains
=================

Firewall rules involving schedules and timeframes can get complicated fast.
For this reason, the scheduling specification is pure Python, so you can make
your filtering rules as simple or as complex as you want.

The default filter rules is created on first startup in `/etc/focus_blacklist.py`:

```python
import re

def domain_ycombinator_com(dt):
    # return dt.hour % 2 # every other hour
    return False

def domain_reddit_com(dt):
    # return dt.hour in (12, 21) # at noon-1pm, or from 9-10pm
    return False
    
def domain_facebook_com(dt):
    return False

def default(domain, dt):
    # do something with regular expressions here?
    return True
```

The format is simple; Just define a function named like the domain you
want to block, preceeded by "domain_".  Have it take a single datetime object
and have it return True or False.  In the body, you can write whatever logic
makes the most sense for
you.  Maybe you want to write your own Pomodoro routine, or maybe you want to
scrape your google calendar for exam dates, and block certain websites on those dates.

For sites without their own scheduler function, the default() function is called.

There's no need to restart Focus if you redefine your schedules.


Configuration
=============

Focus.py tries to start with a sensible configuration, but if you need to change
it, edit `/etc/focus.json.conf`


How it works
============

Focus.py is, at its core, a DNS server.  By making it your primary nameserver,
it receives all DNS lookup requests.  Based on the domain name being requested,
it either responds with a "fail ip" address (blocked), or passes the request
on to your other nameservers (not blocked).  In both cases, Focus adjusts the TTL of each
DNS response so that the service requesting the DNS lookup will do minimal
caching on the IP, allowing Focus's filtering rules to be more immediate.


FAQ
===

- Q: I started Focus, but it's not blacklisting the site I picked.
- A: Your browser may be caching that site's ip.  Give it a few minutes.

- Q: Why do I need to start Focus with sudo?
- A: Focus needs to listen on a privileged port as a DNS server.

- Q: How do I stop Focus?
- A: You'll need to find the process id.  Try `sudo netstat --inet -anpu | grep :53`.
After you identify the process listening on port 53, run `sudo kill -9` with the process id.
