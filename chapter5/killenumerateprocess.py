# -*- coding: utf-8 -*-
# @Date    : 2016-08-19 21:26:28
# @Author  : giantbranch (giantbranch@gmail.com)
# @Link    : http://blog.csdn.net/u012763794?viewmode=contents

import immlib

def main(args):
	# 实例化
	imm = immlib.Debugger()
	# 获取两个函数的地址
	process32first = imm.getAddress("kernel32.Process32FirstW")
	process32next = imm.getAddress("kernel32.Process32NextW")
	function_list = [process32first, process32next]
	imm.log("process32first:0x%08x" % process32first)
	imm.log("process32next:0x%08x" % process32next)
	patch_bytes = imm.assemble("SUB EAX,EAX\nRET")
	for address in function_list:
		# opcode = imm.disasmForward(address, nlines = 1)
		# re = imm.writeMemory(opcode.address, patch_bytes)
		re = imm.writeMemory(address, patch_bytes)
		if re:
			imm.log("success")
		else:
			imm.log("fail")
	return "finished kill the enumerate process"
