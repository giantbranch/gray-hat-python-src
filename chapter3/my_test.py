# -*- coding: utf-8 -*-
# @Date    : 2016-08-12 14:18:10
# @Author  : giantbranch (giantbranch@gmail.com)
# @Link    : http://blog.csdn.net/u012763794?viewmode=contents

# use: python my_test.py
import my_debugger
from my_debugger_defines import *
debugger = my_debugger.debugger()
# debugger.load("C:\\WINDOWS\\system32\\calc.exe")
pid = raw_input("Enter the PID of the process to attach to:")
debugger.attach(int(pid))
printf_address = debugger.func_resolve("msvcrt.dll", "printf")
print "[*] Address of printf:0x%08x" % printf_address
# debugger.bp_set(printf_address)
# debugger.bp_set_hw(printf_address, 1, HW_EXECUTE)
debugger.bp_set_mem(printf_address, 0x7000)

debugger.run()

# threadList = debugger.enumerate_threads()
# for thread in threadList:
# 	thread_context = debugger.get_thread_context(thread)
# 	# %08x就是8位的十六进制，不够就0补充咯
# 	print "[*] Dumping registers for thread ID:0x%08x" % thread
# 	print "[**] EIP:0x%08x" % thread_context.Eip
# 	print "[**] ESP:0x%08x" % thread_context.Esp
# 	print "[**] EBP:0x%08x" % thread_context.Ebp
# 	print "[**] EAX:0x%08x" % thread_context.Eax
# 	print "[**] EBX:0x%08x" % thread_context.Ebx
# 	print "[**] ECX:0x%08x" % thread_context.Ecx
# 	print "[**] EDX:0x%08x" % thread_context.Edx
# 	print "[*] END DUMP"

debugger.detach()