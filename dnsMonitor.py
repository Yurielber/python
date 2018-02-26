#!/usr/bin/env python

import commands
import os
import platform
import re
import socket
import sys
import time


protocol_list = ('udp', 'tcp')
port = 53
address_list = []
# DNS server type: named | nsd
dns_type = None
control_port = {'named': 953, 'nsd': 8952}
max_wait_time_in_seconds = 60


def is_ipv4_address(address_str):
    # ipv4 pattern
    simple_ipv4_pattern = r'^(\d{1,3}[.]){3}\d{1,3}$'
    addr = str(address_str).strip()
    return addr if re.match(simple_ipv4_pattern, addr) else None


def extract_address(config_file_path):
    # check if named or nsd
    address_regex = ''
    if dns_type == 'nsd':
        # ip-address: 127.0.0.1
        # ip-address: 127.0.0.2
        # r'^\s*ip-address:\s(?P<address>.+)'
        address_regex = """
        ^                   # beginning of line
        \s*                 # white-space, optional
        ip-address:         # keyword in config file
        \s+                 # white-space, at least one
        (?P<address>        # beginning of named group, name: "address"
        .+                  # any character, at least one (should be ip address)
        )                   # end of group
        """
    elif dns_type == 'named':
        # listen-on port 53 { 127.0.0.1; 192.168.1.1; 192.168.0.1;};
        # listen-on { 127.0.0.1; 192.168.1.1; 192.168.0.1;};
        # r'^\s*listen-on(\s+port\s+\d+)?\s+[{](?P<address>.+)[}]'
        address_regex = """
        ^                   # beginning of line
        \s*                 # white-space, optional
        listen-on           # keyword in config file
        (                   # beginning of named group
        \s+                 # white-space, at least one
        port                # keyword "port"
        \s+                 # white-space, at least one
        \d+                 # digital, at least one (port number for listen)
        )                   # end of group
        ?                   # this group is optional
        \s+                 # white-space, at least one
        [{]                 # single character "{", escape curly bracket
        (?P<address>        # beginning of named group, name: "address"
        .+                  # any character, at least one (should be ip address list)
        )                   # end of group
        [}]                 # single character "}", escape curly bracket
        """
    # invoke extract process
    extract_address_from_config_file(config_file_path, address_regex)


def extract_address_from_config_file(file_path, regex_pattern):
    # store extract addresses
    addresses = []
    with open(str(file_path), "r") as f:
        lines = f.readlines()
    pattern = re.compile(regex_pattern, re.I | re.VERBOSE)
    for line in lines:
        mo = pattern.search(line)
        if mo:
            address_str = mo.group('address').strip()
            # extract from BIND config file
            if address_str.find(";") != -1:
                for item in address_str.split(';'):
                    addr = is_ipv4_address(item)
                    if addr:
                        addresses.append(addr)
                break  # multiple ip address in a line, should be only one line, so break after first line
            # extract from NSD config file, aggregate address from multiple line
            else:
                addr = is_ipv4_address(address_str)
                if addr:
                    addresses.append(addr)
    global address_list
    address_list = addresses  # reassign global variable


def get_all_listening_address():
    # protocol filter
    protocol_filter_regex = '|'.join(protocol_list)

    command = [
        # list network listening connections with ipv4 and protocol udp/tcp
        ' netstat --udp --tcp --listening --numeric --inet ',
        ' awk \'{print $1" "$4}\' ',  # extract columns { Proto, Local Address }
        # filter line with given protocol, ipv4 address, port number
        " grep -o -E '^(%s)[[:space:]]+[.[:digit:]]+:%s' " % (protocol_filter_regex, port),
        " sed -r 's/:[[:digit:]]+$//' ",  # remove trailing port number
        ' sort --unique '  # remove duplicate line
    ]

    cmd = '|'.join(command)
    status, outs = commands.getstatusoutput(cmd)
    if status != 0:
        raise RuntimeError('error run command')
    return outs


def all_address_are_listening(command_output_text):
    is_normal = False
    if not command_output_text:
        print('command output text is empty, all address not listening')
        return is_normal
    # extract protocol and address form command output
    actual = []
    for line in command_output_text.splitlines():
        proto_with_address = str(line).strip()
        # skip empty line
        if not proto_with_address:
            continue
        proto_address_tuple = tuple(proto_with_address.split()[:2])  # split by whitespace, keep first two element
        actual.append(proto_address_tuple)
    # combine expect protocol with all address
    expectations = [(proto, addr) for proto in protocol_list for addr in address_list]
    # check if all protocol and address are listening
    for expected in expectations:
        if expected not in actual:
            proto, addr = expected
            print '%s:%s not listening with protocol %s' % (addr, port, proto)
            break
    else:
        print 'all address are listening'
        is_normal = True
    return is_normal


def is_control_channel_listening():
    is_ok = False;
    control_channel_port_number = control_port[dns_type]
    command = [
        # list network listening connections with ipv4 and protocol tcp
        ' netstat --tcp --listening --numeric --inet ',
        ' awk \'{print $4}\' ',  # extract columns { Local Address }
        # filter line with given port number, localhost 127.0.0.1 only
        " grep -F '127.0.0.1:%s' " % control_channel_port_number,
        ' sort --unique '  # remove duplicate line
        ' wc -l '  # count
    ]

    cmd = '|'.join(command)
    status, outs = commands.getstatusoutput(cmd)
    if status == 0 and str(outs) and int(str(outs)) > 0:
        is_ok = True
    else:
        print 'control channel port not listening %s' % control_channel_port_number
    return is_ok


def acquire_exclusive_lock():
    # skip if not linux
    if platform.system().lower() != 'linux':
        return
    # Without holding a reference to our socket somewhere it gets garbage
    # collected when the function exits
    socket_name = 'DNSMonitorCronScript'
    acquire_exclusive_lock._lock_socket = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    try:
        # The null byte (\0) means the the socket is created in the abstract namespace instead of being created
        # on the file system itself.
        acquire_exclusive_lock._lock_socket.bind('\0' + socket_name)
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
    # handle custom timeout parameter
    if len(parameters) > 2 and str(parameters[2]):
        custom_timeout = 0
        try:
            custom_timeout = int(str(parameters[2]))
        except ValueError:
            pass
        if custom_timeout > 0:
            global max_wait_time_in_seconds
            max_wait_time_in_seconds = custom_timeout
    return file_path


def everything_is_fine(file_path):
    extract_address(file_path)
    if dns_type == 'nsd':
        return is_control_channel_listening() and all_address_are_listening(get_all_listening_address())
    elif dns_type == 'named':
        # only wait for BIND
        #   check if process exists
        #   *) if process exists
        #      do validate until timeout
        #        if OK, return true
        #        if NOT, wait and retry
        #   *) else return false
        if is_named_process_exists():
            wait_time = 0
            wait_interval = 5
            while wait_time < max_wait_time_in_seconds:
                is_address_listening = is_control_channel_listening() \
                        and all_address_are_listening(get_all_listening_address())
                if is_address_listening:
                    return True
                else:
                    wait_time += wait_interval
                    time.sleep(wait_interval)
        return False


def is_named_process_exists():
    command = ' ps -ef | grep -v grep | grep -F "/sbin/named" | wc -l'  # named process check for public and private

    status, outs = commands.getstatusoutput(command)
    if status != 0 or not outs or int(str(outs)) < 1:
        return False
    else:
        return True


def restart_dns_service():
    print('restarting dns server...')
    cmd_template = "service %s restart"
    cmd = ''
    if dns_type == 'nsd':
        cmd = cmd_template % 'nsd'
    elif dns_type == 'named':
        cmd = cmd_template % 'named'
        dns_fencing()  # enable iptable fence before restart
    commands.getoutput(cmd)


def dns_fencing():
    script_location = '/opt/dns/dns_fencing.py'
    if os.path.isfile(script_location):
        print 'start fencing...'
        cmd = "%s block" % script_location
        commands.getoutput(cmd)


def is_root_user():
    cmd = 'id -u -n'
    status, outs = commands.getstatusoutput(cmd)
    if not (status == 0 and outs and 'root' == outs):
        raise RuntimeError("insufficient permission, need root user")


def main():
    acquire_exclusive_lock()  # make sure only one python script running
    is_root_user()  # make sure root user
    file_path = validate_input(sys.argv)  # after this, the DNS server type is acquired
    if not everything_is_fine(file_path):
        restart_dns_service()


if __name__ == '__main__':
    main()
