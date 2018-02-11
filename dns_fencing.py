#!/bin/python

import sys
import commands

RPOTOCOLS = ('tcp', 'udp')

def isRootPermission():
	# get current user info
	cmd='id -u -n'
	(rc, stdout) = commands.getstatusoutput(cmd)
	if rc == 0 and stdout:
		return 'root' == stdout
	else:
		return False

def extractRules(rules):
	ruleList = []
	if rules is not None:
		for rule in rules:
			if len(rule) > 0:
				paramArray = rule.split()
				if (len(paramArray)) > 8:
					paramArray = paramArray[0:8]
				(num, target, prot, opt, source, destination, prot1, dstPort) = paramArray
				if (target == 'DROP') and (prot in RPOTOCOLS) and (dstPort == 'dpt:53'):
					ruleList.append((target, prot, dstPort))
	return ruleList

def listAllRules():
	inputRulesListCmd = r'iptables -t mangle -L PREROUTING -n --line-numbers | grep -e "^[[:digit:]]\+"'
	inputRulesCountCmd = inputRulesListCmd + ' 2>/dev/null | wc -l'
	# count rules
	(rc, stdout) = commands.getstatusoutput(inputRulesCountCmd)
	if rc != 0 or not stdout:
		return None
	try:
		if int(stdout) == 0:
			return None
	except ValueError:
		print 'command execte fail'
		return None
	# get rules list
	(rc, stdout) = commands.getstatusoutput(inputRulesListCmd)
	if rc == 0 and len(stdout) > 0:
		return stdout.splitlines()
	else:
		return None
		
def modifyRules(action, prot):
	cmd='iptables -t mangle -%s PREROUTING -p %s --dport 53 -j DROP'
	if 'block' == action:
		op = 'A'
	elif 'unblock' == action:
		op = 'D'
	else:
		return
	for p in prot:
		cmds = cmd % (op, p)
		commands.getstatusoutput(cmds)

def toggle(mode):
	if not ('block' == mode or 'unblock' == mode):
		print 'illegal arguments'
		sys.exit(1)
	rules = extractRules(listAllRules())
	# clear all rules
	for rule in rules:
		for p in RPOTOCOLS:
			if ('DROP', p, 'dpt:53') == rule:
				modifyRules('unblock', (p,))
	# add block rules
	if 'block' == mode:
		modifyRules(mode, RPOTOCOLS)

def main():
	if not isRootPermission():
		print 'ERROR: need root permission'
		sys.exit(1)
	if len(sys.argv) >= 2:
		action = sys.argv[1]
		toggle(action)
	else:
		print 'illegal arguments'
		sys.exit(1)

if __name__=='__main__':
	main()
