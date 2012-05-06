Focus.py is a simple DNS-based firewall for Linux that helps you stop
procrastinating.  Just give it a list of sites you spend too much time on and
enjoy not being to access them (easily :)


Starting
========

Add the following line to the top of your `/etc/resolv.conf`, *before* any
other nameservers:

    nameserver 127.0.0.1
    
Now start Focus:

    sudo python focus.py &
    
    
Blocking Domains
================

Firewall rules involving schedules and timeframes can get complicated fast.
For this reason, the scheduling specification is pure Python, so you can make
your blacklist schedules as simple or as complex as you want.

The default scheduler is created on first startup in `/etc/focus_blacklist.py`:

```python
import re

def news_ycombinator_com(dt):
    # return dt.hour % 2 # every other hour
    return False

def reddit_com(dt):
    # return dt.hour in (12, 21, 22) # at noon, or from 9-10pm
    return False
    
def facebook_com(dt):
    return False

def default(domain, dt):
    # do something with regular expressions here?
    return True
```

The format is simple; Just define a function named like the domain you
want to block.  Have it take a single datetime object and have it return True
or False.  In the body, you can write whatever logic makes the most sense for
you.  Maybe you want to write your own Pomodoro routine, or maybe you want to
scrape your google calendar for exam dates.

For sites without their own scheduler function, the default() function is called.

There's no need to restart Focus if you redefine your schedules.


Configuration
=============

Focus.py tries to start with a sensible configuration, but if you need to change
it, edit `/etc/focus.json.conf`


FAQ
===

Q: I started Focus, but it's not blacklisting the site I picked.
A: Your browser may be caching that site's ip.  Give it a few minutes.

Q: Why do I need to start Focus with sudo?
A: Focus needs to listen on a privileged port as a DNS server.

Q: How do I stop Focus?
A: You'll need to find the process id.  Try `sudo netstat --inet -anpu | grep :53`.
After you identify the process listening on port 53, run `sudo kill -9` with the process id.