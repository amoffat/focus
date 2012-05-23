#===============================================================================
# Copyright (C) 2012 by Andrew Moffat
# 
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
# 
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
# 
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.
#===============================================================================


import struct
import socket
import re
import socket
import logging
import time
import os
from os.path import exists
from datetime import datetime
import json
import sys
import select
from imp import reload
import atexit
from optparse import OptionParser


IS_PY3 = sys.version_info[0] == 3
if IS_PY3:
    raw_input = input
    unicode = str
    xrange = range
else:
    pass

__version__ = "0.1"
__author__ = "Andrew Moffat <andrew.robert.moffat@gmail.com>"
__project_url__ = "http://amoffat.github.com/focus"



sys.path.append("/etc")

try: import focus_blacklist as blacklist
except ImportError: blacklist = None


# this will be populated via load_config at runtime
config = {}

resolv_conf = "/etc/resolv.conf"
config_file = "/etc/focus.json.conf"
blacklist_file = "/etc/focus_blacklist.py"
pid_file = "/var/run/focus.py.pid"
_default_config = {
    "bind_ip": "127.0.0.1",
    "fail_ip": "127.0.0.1",
    "bind_port": 53,
    "ttl": 1,
}

_last_checked_blacklist = 0
_default_blacklist = """
import re


def domain_news_ycombinator_com(dt):
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
""".strip()


# these are special characters that are common to domain names but must be
# replaced with an underscore in order for the domain name to be referenced
# as a function in focus_blacklist.  for example, you cannot call
# test-site.com()...you must convert it to test_site_com()
_domain_special_characters = "-."


# used for readability
request_types = {
    "A": 1,
    "MX": 15,
    "CNAME": 5,
    "AAAA": 28,
}
# this is used for looking up the request type for logging
request_types_inv = dict([(v,k) for k,v in request_types.items()])



def read_pascal_string(data):
    size = struct.unpack("!B", data[0:1])[0] + 1
    return struct.unpack("!"+str(size)+"p", data[:size])[0]

def create_pascal_string(data):
    size = len(data)+1
    return struct.pack("!"+str(size)+"p", data) 


def parse_dns(packet):
    """ parse out the pertinent information from the dns request packet """
    qid, flags, qcount, acount, auth_count, addl_count = struct.unpack("!6H", packet[:12])
    packet = packet[12:]
    
    domain = []
    
    while packet[0:1] != b"\x00":
        s = read_pascal_string(packet)
        domain.append(s)
        packet = packet[len(s)+1:]
        
    packet = packet[1:]
    domain = ".".join([part.decode("ascii") for part in domain])
    
    qtype, qclass = struct.unpack("!2H", packet[:4])
    
    packet = packet[4:]
    return qid, domain, qtype



def build_blacklist_response(qid, domain, fail_ip, ttl):
    """ build a packet that directs our dns request to an ip that doesn't
    really belong to the domain...while saying we're authoritative """
    
    # the flags are a little counter-intuitive
    # bits, flag:
    #
    # 1, its a response
    # 4, (ignore)
    # 1, authoritative!
    # 1, not truncated
    # 1, (ignore)
    # 1, no recursion
    # 3, (ignore)
    # 4, ok status
    flags = 0x8400
    packet = b""
    
    packet += struct.pack("!H", qid) # query id
    packet += struct.pack("!H", flags) # flags
    packet += struct.pack("!4H", 1, 1, 0, 0) # 1 question, 1 answer
    
    # repeat question
    packet += "".join([create_pascal_string(chunk.encode("ascii")).decode("ascii") for chunk in domain.split(".")]).encode("ascii")
    packet += b"\x00"
    packet += struct.pack("!2H", request_types["A"], 1)
    
    # answer
    packet += b"\xc0" # name is a pointer
    packet += b"\x0c" # offset
    packet += struct.pack("!2H", request_types["A"], 1)
    packet += struct.pack("!I", ttl)
    packet += struct.pack("!H", 4) # ip length
    packet += socket.inet_aton(fail_ip)
    return packet




def can_visit(domain):
    """ determine if the domain is blacklisted at this time """
    
    refresh_blacklist()
    
    
    # here we do a cascading lookup for the function to run.  example:
    # for the domain "herp.derp.domain.com", first we try to find the
    # following functions in the following order:
    #
    # herp_derp_domain_com()
    # derp_domain_com()
    # domain_com()
    #
    # and if one still isn't found, we go with default(), if it exists
    parts = domain.split(".")
    for i in xrange(len(parts)-1):
        domain_fn_name = "domain_" + ".".join(parts[i:])
        domain_fn_name = re.sub("["+_domain_special_characters+"]", "_", domain_fn_name)
        fn = getattr(blacklist, domain_fn_name, None)
    
        if fn: return fn(datetime.now())
        
    fn = getattr(blacklist, "default", None)
    if fn: return fn(domain, datetime.now())
        
    return True



def load_config():
    config = {}
    
    if not exists(config_file):
        log.error("couldn't find %s, creating with default values", config_file)
        with open(config_file, "w") as h: h.write(json.dumps(_default_config, indent=4))
        
    with open(config_file, "r") as h: config.update(json.loads(h.read().strip() or "{}"))
        
    config.setdefault("bind_ip", "127.0.0.1")
    config.setdefault("bind_port", 53)
    config.setdefault("fail_ip", "127.0.0.1")
    config.setdefault("ttl", 1)
    
    # don't allow a ttl less than 1...google why its a bad idea
    if config["ttl"] < 1: config["ttl"] = 1
    
    return config


def refresh_blacklist():
    global _last_checked_blacklist, blacklist
    
    log = logging.getLogger("blacklist_refresher")    

    # we also check for not exists because the pyc file may be left around.
    # in that case, blacklist name will exist, but the file will not
    if not blacklist or not exists(blacklist_file):
        log.error("couldn't find %s, creating a default blacklist", blacklist_file)
        with open(blacklist_file, "w") as h: h.write(_default_blacklist)
        import focus_blacklist as blacklist
    
    # has it changed?
    changed = os.stat(blacklist_file).st_mtime
    if changed > _last_checked_blacklist:
        log.info("blacklist %s changed, reloading", blacklist_file)
        reload(blacklist)
        _last_checked_blacklist = changed


def load_nameservers(resolv_conf):
    """ read all of the nameservers used by the system """
    with open(resolv_conf, "r") as h: resolv = h.read()
    m = re.findall("^nameserver\s+(.+)$", resolv, re.M | re.I)
    return m or []



def forward_dns_lookup(nameserver, packet):
    """ send a dns question packet to a nameserver, return the response """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(packet, (nameserver, 53))
    reply, addr = sock.recvfrom(1024)
    return reply





class ForwardedDNS(object):
    """ the purpose of this class is to encapsulate necessary state and
    related helper methods, for when a forwarded dns socket gets put into
    the select.select() list of readers """
    
    def __init__(self, sender, ns, packet, adjust_ttl=None):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setblocking(0)
        self.sock.sendto(packet, (ns, 53))
        self._adjust_ttl = adjust_ttl
        self.sender = sender
        self.created = time.time()
    
    def __del__(self):
        self.sock.close()
    
    def fileno(self):
        return self.sock.fileno()

    def get_answer(self):
        answer, addr = self.sock.recvfrom(1024)
        if self._adjust_ttl: answer = self.adjust_ttl_in_reply(answer, self._adjust_ttl)
        return answer, self.sender
    
    def adjust_ttl_in_reply(self, reply, ttl):
        # essentially what we need to do with all of this is find the beginning
        # of the answer packets, so that we can replace the TTL.  so we do some
        # calculations to figure out where the answers start
        questions = struct.unpack("!H", reply[4:6])[0]
        answers = struct.unpack("!H", reply[6:8])[0]
        
        question_offset = 12
        answer_offset = question_offset
        for q in xrange(questions):
            answer_offset += reply[answer_offset:].find(b"\x00") + 5
            
            
        # now that we know where the answers start, we can adjust the TTL in each
        # answer, and then forward the answer_offset to the next answer, so that
        # we can repeat the process
        for i in xrange(answers):
            ttl_offset = answer_offset + 6
            
            old_ttl = struct.unpack("!I", reply[ttl_offset: ttl_offset + 4])[0]
            reply = reply[:ttl_offset] + struct.pack("!I", ttl) + reply[ttl_offset + 4:]
            
            ip_length_offset = ttl_offset + 4
            ip_length = struct.unpack("!H", reply[ip_length_offset: ip_length_offset + 2])[0]
            answer_offset = ip_length_offset + 2 + ip_length
            
        return reply

def clean_up_pid():
    if exists(pid_file):
        logging.info("cleaning up pid file")
        os.remove(pid_file)


if __name__ == "__main__":
    cli_parser = OptionParser()
    cli_parser.add_option("-l", "--log", dest="log", default=None)
    cli_parser.add_option("-n", "--nameserver", dest="nameserver", default=None)
    cli_options, cli_args = cli_parser.parse_args()

    logging.basicConfig(
        format="(%(process)d) %(asctime)s - %(name)s - %(levelname)s - %(message)s",
        level=logging.INFO,
        filename=cli_options.log
    )
    log = logging.getLogger("server")

    with open(pid_file, "w") as f: f.write(str(os.getpid()))
    atexit.register(clean_up_pid)
    
    config.update(load_config())
    refresh_blacklist()    
    
    
    nameservers = load_nameservers(resolv_conf)
    if config["bind_ip"] not in nameservers:
        raise Exception("%s not a nameserver in %s, please add it" %
            (config["bind_ip"], resolv_conf))
    
    # if we don't remove the ip we've bound to from the list of fallback
    # nameservers, we run the risk of recursive dns lookups    
    nameservers.remove(config["bind_ip"])
    
    if not nameservers:
        if cli_options.nameserver:
            nameservers.append(cli_options.nameserver)
        else:
            raise Exception("you need at least one other nameserver in %s" %
            resolv_conf)

    # create our main server socket
    server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server.setblocking(0)
    server.bind((config["bind_ip"], config["bind_port"]))
    
    readers = [server]
    last_cleaned_readers = 0
    
    
    # start our main select loop
    while True:
        to_read, to_write, to_err = select.select(readers, [], [])
        
        for sock in to_read:
            if isinstance(sock, ForwardedDNS):
                reply, sender = sock.get_answer()
                readers.remove(sock)
                
            elif sock is server:
                question, sender = server.recvfrom(1024)
                
                qid, domain, qtype = parse_dns(question)
                qtype_readable = request_types_inv.get(qtype, "UNKNOWN")
                
                
                # a request for an ip for a domain
                if qtype is request_types["A"]:
                    # if we can visit it now, it might be either A) not on the blacklist
                    # or B) on the blacklist, but not blacklisted at this time (due to
                    # the schedule permitting access).  in both cases, we should
                    # adjust the TTL, so that lookups with us happen as frequently as
                    # possible
                    if can_visit(domain):
                        log.info("%s for %r (%s) is allowed", qtype_readable, domain, qid)
                        fdns = ForwardedDNS(sender, nameservers[0], question, config["ttl"])
                        readers.append(fdns)
                        continue
                        
                    # if we can't visit it now, direct it to the FAIL_IP
                    else:
                        log.info("%s for %r (%s) is BLOCKED, pointing to %s", qtype_readable, domain, qid, config["fail_ip"])
                        reply = build_blacklist_response(qid, domain, config["fail_ip"], config["ttl"])
                        
                    
                # all other types of requests..MX, CNAME, etc, just let the regular
                # nameservers look those up, and don't adjust ttl
                else:
                    log.info("%s for %r (%s) is allowed", qtype_readable, domain, qid)
                    fdns = ForwardedDNS(sender, nameservers[0], question)                        
                    readers.append(fdns)
                    continue


            server.sendto(reply, sender)
            
        
        # occasionally we'll have created a ForwardedDNS request that never
        # gets read from, for one reason or another.  maybe the packet got
        # dropped along the way.  in any case, we don't want these dead
        # objects to stick around forever, slowing growing the memory, so
        # every once in awhile, we need to clean them out
        now = time.time()
        if now - 120 > last_cleaned_readers:
            cleaned = 0
            for sock in list(readers):
                if isinstance(sock, ForwardedDNS) and now - 60 > sock.created:
                    readers.remove(sock)
                    cleaned += 1
            log.info("cleaning out %d dead requests", cleaned)
            last_cleaned_readers = now
        
    
    server.close()
