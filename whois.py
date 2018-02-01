# !/usr/bin/env python

import sys
import telnetlib
import re

rootWhoisServer = 'whois.iana.org'
port = '43'

def printLine():
    print('-' * 80)

def lookup_once(domain, host=None, port='43', timeout=5):
    if host is None:
        host = rootWhoisServer
    printLine()
    print('Connecting to %s' % (host) )
    printLine()

    tn = telnetlib.Telnet(host, port, timeout)
    tn.write( domain + "\n")
    contents = tn.read_all()

    print(contents)

    printLine()
    print('Disconnected from %s' % (host))
    printLine()

    return contents

def lookup(domain):
    feedback = lookup_once(domain)

    refer_matcher = r'^\s*refer:\s*(?P<whoisServer>whois[.].*)$'
    next_whois_server = None
    for line in feedback:
        if (re.match(refer_matcher, line, re.I)):
            m = re.search(refer_matcher, line, re.I)
            next_whois_server = m.group('whoisServer')
            break
    # do another lookup
    if next_whois_server is not None:
        lookup_once(domain, host=next_whois_server)

if __name__ == '__main__':
    input_params_num = len(sys.argv)
    if (input_params_num <= 1):
        raise RuntimeError('Invalid domain')
    target = str(sys.argv[1])
    lookup(target)
