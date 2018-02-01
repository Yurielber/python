# !/usr/bin/env python

import sys
import telnetlib
import re

iana_whois_server = 'whois.iana.org'
port = '43'

def printLine():
    print('-' * 80)

def lookup(domain, host, port='43', timeout=5):
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

def lookup_by_iana(domain, port='43', timeout=5):
    success = False
    refer_server = None
    lines = []

    host = iana_whois_server

    contents = lookup(domain, host)
    lines = contents.splitlines()

    iana_query_result_matcher = r'^%\s+This query returned (?P<matchedRecordNum>\d*?) object.*$'
    iana_refer_whois_server_matcher = r'^\s*refer:\s+(?P<referWhoisServer>whois[.].*)$'

    # test if query result valid
    for line in lines:
        if (re.match(iana_query_result_matcher, line, re.I)):
            m = re.search(iana_query_result_matcher, line, re.I)
            record_matched = m.group('matchedRecordNum')
            print('-' * 20 + str(record_matched) )
            # check return value
            if record_matched is None:
                raise RuntimeError('IANA not return')
            # whether success or fail
            try:
                success = True if int(record_matched) > 0 else False
            except ValueError:
                print('value not an integer')
            break

    # test if refer whois server exist
    for line in lines:
        if (re.match(iana_refer_whois_server_matcher, line, re.I)):
            m = re.search(iana_refer_whois_server_matcher, line, re.I)
            refer_server = m.group('referWhoisServer')
            # validate refer whois server None or empty
            if refer_server is None or not refer_server:
                raise RuntimeError('got invalid refer server')
            break

    # remove comment lines
    comment_line_matcher = r'^% .*$'
    new_lines = [line for line in lines if not re.match(comment_line_matcher, line, re.I)]
    lines = new_lines
    return success, refer_server, lines

def lookup_by_registrar(domain, host, port='43', timeout=5):
    success = False
    registrar_server = None
    lines = []

    contents = lookup(domain, host)

    lines = contents.splitlines()

    registrar_success_matcher = r'^\s*Domain Name:\s+(?P<domainName>.*)$'
    registrar_whois_server_matcher = r'^\s*Registrar WHOIS Server:\s+(?P<whoisServer>whois[.].*)$'

    # test if target domain found
    for line in lines:
        if (re.match(registrar_success_matcher, line, re.I)):
            m = re.search(registrar_success_matcher, line, re.I)
            target_domain = m.group('domainName')
            # check return value
            if target_domain is None or not target_domain:
                raise RuntimeError('can\'t found target domain name')
            # test if domain match
            success = True if target_domain.lower() == str(domain).lower() else False
            break

    # test if additional whois server found
    for line in lines:
        if (re.match(registrar_whois_server_matcher, line, re.I)):
            m = re.search(registrar_whois_server_matcher, line, re.I)
            registrar_server = m.group('whoisServer')
            # validate refer whois server None or empty
            if registrar_server is None or not registrar_server:
                raise RuntimeError('invalid whois server')
            break
    return success, registrar_server, lines

def find_best_response(response_list):
    if response_list is None or len(response_list) <= 0:
        return
    response_weight = []
    for response in response_list:
        response_weight.append(weight(response))
    max_weight = max(response_weight)
    # find max response
    index = 0
    for item in response_weight:
        if item == max_weight:
            return response_list
        else:
            index += 1

def weight(response):
    valid_line_matcher = r'^\s*(?P<key>\w+):\s+(?P<value>.*)$'
    total = 0
    for line in response:
        if (re.match(valid_line_matcher, line, re.I)):
            total += 1
    print('=' * 30)
    print(response)
    print('Weight: %s' % (total) )
    print('=' * 30)
    return total

def query(domain):
    received_response = []
    success, refer_server, lines = lookup_by_iana(domain)
    if not success:
        raise RuntimeError('fail to query domain by IANA')
    else:# success
        if refer_server is None:
            # got final answer
            received_response.append(lines)
        else:
            # need more lookup, clean up before query
            received_response = []
            whois_server = refer_server
            max_number_of_lookup = 2
            lookup_count = 0
            while(lookup_count < max_number_of_lookup):
                success, registrar_server, lines = lookup_by_registrar(domain, host=whois_server)
                lookup_count += 1
                if not success:
                    break
                # success
                received_response.append(lines)
                if registrar_server is not None and whois_server.lower() != str(registrar_server).strip().lower():
                    # prepare to do another query
                    whois_server = registrar_server
                else:
                    break
    print('+' * 80)
    print(find_best_response(received_response))

if __name__ == '__main__':
    input_params_num = len(sys.argv)
    if (input_params_num <= 1):
        raise RuntimeError('Invalid domain')
    target = str(sys.argv[1])
    query(target)
