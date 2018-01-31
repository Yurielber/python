#!/usr/bin/env python

import getpass
import sys
import telnetlib

whoisServers = ['whois.iana.org', 'whois.verisign-grs.com', 'whois.markmonitor.com' ]
port = '43'
timeout = 5

for host in whoisServers:
    print("Connecting to {}".format(host))
    telnet = telnetlib.Telnet(host, port, timeout)
    telnet.write("com" + "\n")
    print("-----------------------------")
    contents = telnet.read_all()
    print(contents)
    print("-----------------------------")
    print("Disconnected from {}".format(host))
