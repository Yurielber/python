#!/usr/bin/env python

import commands
import os
import platform
import re
import socket
import sys


protocol_list = ('udp', 'tcp')
port = 53
address_list = []
# DNS server type: named | nsd
dns_type = None


def get_protocol_filter_regex():
    pattern = ''
    for proto in protocol_list:
        pattern += '(' + proto + ')' + '|'
    # remove trailing "|"
    return pattern[:-1]


def is_ipv4_address(address_str):
    # ipv4 pattern
    simple_ipv4_pattern = r'^(\d{1,3}[.]){3}\d{1,3}$'
    addr = str(address_str).strip()
    if addr and re.match(simple_ipv4_pattern, addr):
        return addr
    else:
        return None


def extract_address(config_file_path):
    # check if named or nsd
    address_regex = ''
    if dns_type == 'nsd':
        # ip-address: 127.0.0.1
        # ip-address: 127.0.0.2
        address_regex = r'^\s*ip-address:\s(?P<address>.*)'
    elif dns_type == 'named':
        # listen-on port 53 { 127.0.0.1; 192.168.1.1; 192.168.0.1}
        # listen-on { 127.0.0.1; 192.168.1.1; 192.168.0.1}
        address_regex = r'^\s*listen-on(\s+port\s+\d+)?\s+[{](?P<address>.*)[}]'
    # invoke extract process
    extract_address_from_config_file(config_file_path, address_regex)


def extract_address_from_config_file(file_path, regex_pattern):
    # store extract addresses
    addresses = []
    with open(str(file_path), "r") as f:
        lines = f.readlines()
    for line in lines:
        m = re.search(regex_pattern, line, re.I)
        if m:
            address_str = m.group('address')
            if address_str.find(";") != -1:  # multiple ip address in line
                addr_str_list = address_str.strip().split(';')
                for item in addr_str_list:
                    if is_ipv4_address(item):
                        addresses.append(item.strip())
                else:
                    break  # finish process, extract only the first line
            else:  # only one ip address in line
                if is_ipv4_address(address_str):
                    addresses.append(address_str.strip())
    # modify global variable
    global address_list
    address_list = addresses


def get_all_listening_address():
    cmd_template = "netstat --udp --tcp --listening --numeric --inet " \
                   '| awk \'{print $1" "$4}\' ' \
                   "| grep -o -E '^(%s)[[:space:]]+[.[:digit:]]+:%s' " \
                   "| sed 's/:%s//' " \
                   '| sort --unique'
    protocol_filter_regex = get_protocol_filter_regex()
    cmd = cmd_template % (protocol_filter_regex, port, port)
    return commands.getoutput(cmd).strip()


def all_address_are_listening(command_output_text):
    normal = False
    # extract protocol and address form command output
    actual = []
    for line in command_output_text.splitlines():
        proto_with_address = str(line).strip()
        # skip empty line
        if not proto_with_address:
            continue
        proto_address_tuple = tuple(proto_with_address.split(' '))
        actual.append(proto_address_tuple)
    # combine expect protocol with all address
    expectations = []
    for proto in protocol_list:
        for addr in address_list:
            proto_address_tuple = (proto, addr)
            expectations.append(proto_address_tuple)
    # check if all protocol and address are listening
    for expected in expectations:
        if expected not in actual:
            protocol, addr = expected
            print 'not listening on %s:%s with protocol %s' % (addr, port, protocol)
            break
    else:
        normal = True
    return normal


def acquire_exclusive_lock():
    if platform.system().lower() != 'linux':  # only works on Linux
        return
    # Without holding a reference to our socket somewhere it gets garbage
    # collected when the function exits
    command_name = 'DNSServerMonitorScriptCron'
    acquire_exclusive_lock._lock_socket = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    try:
        acquire_exclusive_lock._lock_socket.bind('\0' + command_name)
    except socket.error:
        print('acquire lock fail, another instance already running')
        sys.exit(1)


def validate_input(parameters):
    # input parameter length should great than 1
    if not parameters or len(parameters) <= 1:
        raise RuntimeError('please provide config file path')
    # check the file is there
    file_path = str(parameters[1])
    if not os.path.exists(file_path):
        raise RuntimeError('file [%s] not exist' % str(file_path))
    # check if named or nsd
    global dns_type
    if file_path.find('nsd') != -1:
        dns_type = 'nsd'
    elif file_path.find('named') != -1:
        dns_type = 'named'
    else:
        raise RuntimeError('unsupported config file')
    return file_path


def everything_is_fine(file_path):
    extract_address(file_path)
    return all_address_are_listening(get_all_listening_address())


def restart_dns_service():
    print('restarting dns server...')
    cmd_template = "service %s restart"
    cmd = ''
    if dns_type == 'nsd':
        cmd = cmd_template % 'nds'
    elif dns_type == 'named':
        cmd = cmd_template % 'named'
    commands.getoutput(cmd).strip()


def main():
    acquire_exclusive_lock()  # make sure only one python script running
    file_path = validate_input(sys.argv)
    if not everything_is_fine(file_path):
        restart_dns_service()


if __name__ == '__main__':
    main()
