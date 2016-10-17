# -*- coding: utf-8 -*-
# @Date    : 2016-08-21 09:12:35
# @Author  : giantbranch (giantbranch@gmail.com)
# @Link    : http://blog.csdn.net/u012763794?viewmode=contents

import immlib
import immutils

def getRet(imm, allocaddr, max_opcodes = 300):
	addr = allocaddr
	for a in range(0, max_opcodes):
		# 这个函数应该是以这个地址开始解析一条指令,默认行数是1
		# 返回汇编指令
		op = imm.disasmForward(addr)
		# 判断是否为ret指令
		if op.isRet():
			if op.getImmConst() == 0xC:
				# 以当前地址向前反汇编3条指令
				op = imm.disasmBackward(addr, 3)
				return op.getAddress()
		addr = op.getAddress()
	return 0x0

def showresult(imm , a, rtlallocate, extra = ""):
	if a[0] == rtlallocate:
		imm.log("RtlAllocateHeap(0x%08x,0x%08x,0x%08x) <- 0x%08x %s" % (a[1][0], a[1][1], a[1][2], a[1][3], extra), address = a[1][3])
		return "done"
	else:
		imm.log("RtlFreeHeap(0x%08x,0x%08x,0x%08x) %s" % (a[1][0], a[1][1], a[1][2], extra))

def main(args):
	imm = immlib.Debugger()
	Name = "hippie"
	# Gets python object from the knowledge database.
	# 下面会用addKnowledge储存到knowledge database
	fast = imm.getKnowledge(Name)
	if fast:
		# 我们之前已经设置hooks了，所以我们打印结果
		hook_list = fast.getAllLog()
		rtlallocate,rtlfree = imm.getKnowledge("FuncNames")
		for a in hook_list:
			ret = showresult(imm, a, rtlallocate)
		return "Logged: %d hook hits." % len(hook_list)
	# 暂停进程
	imm.pause()
	rtlfree = imm.getAddress("ntdll.RtlFreeHeap")
	rtlallocate  = imm.getAddress("ntdll.RtlAllocateHeap")
	imm.log("rtlallocate:0x%08x" % rtlallocate, address = rtlallocate)
	module = imm.getModule("ntdll.dll")
	# 若还没分析这个模块，就去分析
	if not module.isAnalysed():
		imm.analyseCode(module.getCodebase())
	# 我们寻找正确的函数退出点(返回点)
	rtlallocate = getRet(imm, rtlallocate, 1000)
	imm.log("RtlAllocateHeap hook:0x%08x" % rtlallocate, address = rtlallocate)
	# 储存hook的地址
	imm.addKnowledge("FuncNames", (rtlallocate, rtlfree))
	# 开始构建hook
	fast = immlib.STDCALLFastLogHook(imm)

	imm.log("Logging on Alloc 0x%08x" % rtlallocate, address = rtlallocate)
	# 我们要hook的是rtlallocate函数中的某个地址（这个地址会被跳转指令覆盖）
	fast.logFunction(rtlallocate)
	# 根据EBP的偏移获取数据
	fast.logBaseDisplacement("EBP", 8)
	fast.logBaseDisplacement("EBP", 0xC)
	fast.logBaseDisplacement("EBP", 0x10)
	# 跟踪eax寄存器
	fast.logRegister("EAX")

	imm.log("Logging on RtlFreeHeap 0x%08x" % rtlfree, address = rtlfree)
	fast.logFunction(rtlfree, 3)
	# 设置钩子 
	fast.Hook()
	# 储存钩子对象
	imm.addKnowledge(Name, fast, force_add = 1)
	return "Hooks setm press F9 to continue the process."
