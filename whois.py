# !/usr/bin/env python

import sys
import telnetlib
import re

root_whois_server = 'whois.iana.org'
port = '43'

def printLine():
    print('-' * 80)

def lookup_once(domain, host, port='43', timeout=5):
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
    feedback = ''
    whois_server = None

    refer_whois_server_matcher = r'^\s*refer:\s+(?P<whoisServer>whois[.].*)$'
    registrar_whois_server_matcher = r'^\s*Registrar WHOIS Server:\s+(?P<whoisServer>whois[.].*)$'

    matcher_list = [refer_whois_server_matcher, registrar_whois_server_matcher]

    # lookup
    whois_server = root_whois_server
    while(True):
        feedback = lookup_once(domain, host=whois_server)
        next_whois_server = None
        for line in feedback.splitlines():
            for matcher in matcher_list:
                if (re.match(matcher, line, re.I)):
                    m = re.search(matcher, line, re.I)
                    next_whois_server = m.group('whoisServer')
                    break
            if next_whois_server is not None:
                break
        if next_whois_server is not None and str(next_whois_server).strip().lower() != whois_server.lower():
            whois_server = next_whois_server
        else:
            break

if __name__ == '__main__':
    input_params_num = len(sys.argv)
    if (input_params_num <= 1):
        raise RuntimeError('Invalid domain')
    target = str(sys.argv[1])
    lookup(target)
