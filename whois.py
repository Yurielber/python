# !/usr/bin/env python

import sys
import telnetlib

whoisServers = ['whois.iana.org', 'whois.verisign-grs.com', 'whois.markmonitor.com']
port = '43'
timeout = 5

for host in whoisServers:
    print('Connecting to %s' % (host))
    tn = telnetlib.Telnet(host, port, timeout)
    tn.write("com" + "\n")

    contents = tn.read_all()

    print("-----------------------------")
    print(contents)
    print("-----------------------------")

    print("Disconnected from {}".format(host))
