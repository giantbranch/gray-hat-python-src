# -*- coding: utf-8 -*-
# @Date    : 2016-08-14 10:04:29
# @Author  : giantbranch (giantbranch@gmail.com)
# @Link    : http://blog.csdn.net/u012763794?viewmode=contents

from pydbg import *
from pydbg.defines import *
import struct
import random

# 这是我们定义的回调函数
def printf_randomizer(dbg):
	# 用esp索引count局部变量的值
	parameter_addr = dbg.context.Esp + 0x10
	counter = dbg.read_process_memory(parameter_addr, 4)
	counter = struct.unpack("L", counter)[0]
	if counter != 1807708002:
		print "Counter:%d" % int(counter)
		# 生成1到100的随机数，再转换成二进制格式的
		random_counter = random.randint(1, 100)
		random_counter = struct.pack("L", random_counter)[0]


		dbg.write_process_memory(parameter_addr, random_counter)
	# print GetLastError()
	return DBG_CONTINUE

dbg = pydbg()
pid = raw_input("Please Enter the printf_loop.py PID:")
# 附加
dbg.attach(int(pid))
# printf_address = dbg.func_resolve("msvcrt", "printf")
# printf_address = dbg.func_resolve("msvcr90", "_vsnprintf")
printf_address = dbg.func_resolve("python27", "PyOS_snprintf")
# print printf_address
# description为断点设置名字，handler设置回调函数
dbg.bp_set(printf_address, description="printf_address", handler=printf_randomizer)
# 启动起来
dbg.run()


