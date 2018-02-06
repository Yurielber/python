#!/usr/bin/env python

import sys
import telnetlib
import re

iana_whois_server = 'whois.iana.org'


def print_line():
    print('-' * 80)


def lookup(domain, host, port='43', timeout=5, verbose=False):
    contents = []

    try:
        if verbose:
            print_line()
            print 'Connecting to %s' % host
            print_line()

        tn = telnetlib.Telnet(host, port, timeout)
        tn.write(domain + "\n")
        contents = tn.read_all()

        if verbose:
            print(contents)

        if verbose:
            print_line()
            print 'Disconnected from %s' % host
            print_line()
    except:
        pass

    return contents


def lookup_by_iana(domain, port='43', timeout=5):
    success = False
    refer_server = None
    lines = []

    host = iana_whois_server

    lines = lookup(domain, host).splitlines()

    # test if query result valid
    iana_query_result_pattern = r'^%\s+This query returned (?P<matchedRecordNum>\d+?) object.*$'

    for line in lines:
        m = re.search(iana_query_result_pattern, line, re.I)
        if m:  # not None when regex matched
            record_matched = m.group('matchedRecordNum')
            # print('-' * 20 + str(record_matched) )
            # whether success or fail
            try:
                success = True if int(record_matched) > 0 else False
                break
            except ValueError:
                print('value not an integer')

    # test if refer whois server exist
    iana_refer_whois_server_pattern = r'^\s*refer:\s+(?P<referWhoisServer>.+)$'

    for line in lines:
        m = re.search(iana_refer_whois_server_pattern, line, re.I)
        if m:
            refer_server = m.group('referWhoisServer')  # if regex match, the server must non-empty

    # remove comment lines
    comment_line_pattern = r'^% .*$'  # comment line start with %
    cleanup_lines = [line for line in lines if not re.match(comment_line_pattern, line)]

    return success, refer_server, cleanup_lines


def lookup_by_registrar(domain, host, port='43', timeout=5):
    success = False
    registrar_whois_server = None
    lines = []

    lines = lookup(domain, host).splitlines()

    # test if target domain found
    registrar_success_pattern = r'^\s*Domain Name:\s+(?P<domainName>.+)$'

    for line in lines:
        m = re.search(registrar_success_pattern, line, re.I)
        if m:
            target_domain = m.group('domainName')
            # test if domain match
            success = True if target_domain.lower().strip() == str(domain).lower() else False
            # handle for multiple domain name match, e.g., query domain in chinese often return multiple result
            if success:  # found one, then break
                break
    # target domain not found
    if not success:
        return success, None, None

    # test if additional whois server found
    registrar_whois_server_pattern = r'^\s*Registrar WHOIS Server:\s+(?P<whoisServer>whois[.].+)$'

    for line in lines:
        m = re.search(registrar_whois_server_pattern, line, re.I)
        if m:
            registrar_whois_server = m.group('whoisServer')
            break

    return success, registrar_whois_server, lines


def find_response_with_best_priority(response_list):
    if not response_list:  # None or empty list []
        return None
    elif len(response_list) == 1:
        return response_list[0]
    all_response_priority = []
    for response in response_list:
        all_response_priority.append(priority(response))
    max_priority = max(all_response_priority)
    # find max priority response
    for x in xrange(len(all_response_priority)):
        if all_response_priority[x] == max_priority:
            return response_list[x]


def priority(response):
    valid_line_pattern = r'^\s*(?P<key>[^:]+):\s+(?P<value>.*)$'  # the key: value format
    comment_line_begin_pattern = r'^>>> .* <<<$'
    body_line_count = 0
    for line in response:
        m = re.search(valid_line_pattern, line)
        if m:
            body_line_count += 1
            # print('\t%50s --> %s' % (m.group('key'), m.group('value') ) )
        comment = re.search(comment_line_begin_pattern, line)
        if comment:
            break  # here comment block begin, skip calculate
    return body_line_count


def query(domain):
    candidate_response = []
    # first query by IANA
    success, refer_server, lines = lookup_by_iana(domain)
    if not success:
        raise RuntimeError('fail to query domain by IANA')
    # otherwise success
    if refer_server is None:
        # when no refer whois server found, this final answer
        candidate_response.append(lines)
    else:  # found refer whois server, need more lookup
        whois_server = refer_server
        candidate_response = []  # clean up before query
        max_number_of_lookup = 2
        lookup_count = 0
        while lookup_count < max_number_of_lookup:
            # query
            success, registrar_whois_server, lines = lookup_by_registrar(domain, host=whois_server)
            lookup_count += 1
            if not success:
                break  # break if query fail
            candidate_response.append(lines)
            if registrar_whois_server is not None and whois_server.lower() != str(
                    registrar_whois_server).strip().lower():
                # prepare to do another query
                whois_server = registrar_whois_server
            else:  # no query need, quit
                break
    lines = find_response_with_best_priority(candidate_response)
    if lines is not None and isinstance(lines, list):  # empty list []
        print('+' * 80)
        for line in lines:
            print(line)
        print('+' * 80)


if __name__ == '__main__':
    if len(sys.argv) <= 1:
        raise RuntimeError('please input domain to query')
    target = str(sys.argv[1]).strip()
    query(target)
