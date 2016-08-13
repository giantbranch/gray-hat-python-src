# -*- coding: utf-8 -*-
# @Date    : 2016-08-11 16:48:16
# @Author  : giantbranch (giantbranch@gmail.com)
# @Link    : http://blog.csdn.net/u012763794?viewmode=contents

from ctypes import *
from my_debugger_defines import *
kernel32 = windll.kernel32
class debugger():
	
	# 初始化
	def __init__(self):
		# 进程句柄
		self.h_process	= None
		self.pid 		= None
		# 记录当前的调试状态，默认不在调试状态中
		self.debugger_active = False
		self.h_thread = None
		self.context = None
		self.exception = None
		self.exception_address = None
		self.breakpoints = {}
		self.first_breakpoint = True
		self.hardware_breakpoints = {}
		system_info = SYSTEM_INFO()
		kernel32.GetSystemInfo(byref(system_info))
		self.page_size = system_info.dwPageSize

		self.guarded_pages = []
		self.memory_breakpoints = {}

	# 启动程序
	def load(self, path_to_exe):
		creation_flags = DEBUG_PROCESS
		startupinfo = STARTUPINFO()

		process_information = PROCESS_INFORMATION()

		startupinfo.dwFlags = 0x1
		startupinfo.wShowWindow = 0x0

		startupinfo.cb = sizeof(startupinfo)
		if kernel32.CreateProcessA(path_to_exe,
									None,
									None,
									None,
									None,
									creation_flags,
									None,
									None,
									byref(startupinfo),
									byref(process_information)):
			print "[*] we have successfully launched the process!"
			print "[*] PID:%d" % process_information.dwProcessId
			self.h_process = self.open_process(process_information.dwProcessId)
		else:
			print "[*] Error:0x%08x." % kernel32.GetLastError()

	# 获取进程的句柄，要调试当然要全不权限了		
	def open_process(self, pid):
		# h_process = kernel32.OpenProcess(PROCESS_ALL_ACCESS, pid, False)
		h_process = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
		return h_process
	
	# 附加		
	def attach(self, pid):
		self.h_process = self.open_process(pid)
		#尝试附加到某个pid的程序上
		if kernel32.DebugActiveProcess(pid):
			self.debugger_active = True
			self.pid = pid
			# self.run()
		else:
			print "[*] Unable to attach to the process."
	
	#既然都附加上去了，等待调试事件咯
	def run(self):
		while self.debugger_active == True:
			self.get_debug_event()

	# 等待调试事件，获取调试事件
	def get_debug_event(self):
		debug_event = DEBUG_EVENT()
		continue_status = DBG_CONTINUE
		#INFINITE表示无限等待
		if kernel32.WaitForDebugEvent(byref(debug_event), INFINITE):
			#现在我们暂时不对事件进行处理
			#现在只是简单地恢复进程的运行吧
			# raw_input("Press a key to continue...")
			# self.debugger_active = False
			self.h_thread = self.open_thread(debug_event.dwThreadId)
			# self.context = self.get_thread_context(self.h_thread)
			self.context = self.get_thread_context(debug_event.dwThreadId)

			print "Event Code:%d Thread ID:%d" % (debug_event.dwDebugEventCode, debug_event.dwThreadId)
			# 如果是例外事件就，处理它
			if debug_event.dwDebugEventCode == EXCEPTION_DEBUG_EVENT:
				self.exception = debug_event.u.Exception.ExceptionRecord.ExceptionCode
				self.exception_address = debug_event.u.Exception.ExceptionRecord.ExceptionAddress
				# 内存访问异常（如写入一个只读的内存区域）
				if self.exception == EXCEPTION_ACCESS_VIOLATION:
					print "Access Violation Detected."
				# 断点
				elif self.exception == EXCEPTION_BREAKPOINT:
					continue_status = self.exception_handler_breakpoint()
				# 访问了具有PAGE_GUARD属性的保护页面	
				elif self.exception == EXCEPTION_GUARD_PAGE:
					print "Guard Page Access Detected."
				# 单步
				elif self.exception == EXCEPTION_SINGLE_STEP:
					# print "Single Stepping."
					self.exception_handler_single_step()
			kernel32.ContinueDebugEvent(debug_event.dwProcessId,debug_event.dwThreadId, continue_status)

	# 分离
	def detach(self):
		if kernel32.DebugActiveProcessStop(self.pid):
			print "[*] Finished debugging. Exiting..."
		else:
			print "There was an error"
			return False

	# 通过线程id打开线程
	def open_thread(self, thread_id):
		h_thread = kernel32.OpenThread(THREAD_ALL_ACCESS, None, thread_id)
		if h_thread is not None:
			return h_thread
		else:
			print "[*] Could not obtain a valid thread handle."
			return False
	
	# 枚举线程
	def enumerate_threads(self):
		thread_entry = THREADENTRY32()
		thread_list = []
		snapshot = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, self.pid)
		if snapshot is not None:
			thread_entry.dwSize = sizeof(thread_entry)
			success = kernel32.Thread32First(snapshot,  byref(thread_entry))
			while success:
				if thread_entry.th32OwnerProcessID == self.pid:
					thread_list.append(thread_entry.th32ThreadID)
				success = kernel32.Thread32Next(snapshot, byref(thread_entry))

			kernel32.CloseHandle(snapshot)
			return thread_list
		else:
			print "enumerate_threads fail."
			return False

	# 获取线程上下文		
	def get_thread_context(self, thread_id):
		context = CONTEXT()
		context.ContextFlags = CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS
		h_thread = self.open_thread(thread_id)
		if kernel32.GetThreadContext(h_thread, byref(context)):
			kernel32.CloseHandle(h_thread)
			return context
		else:
			print "get_thread_context fail."
			return False

	# 处理断点的函数		
	def exception_handler_breakpoint(self):
		# print "[*] Inside the breakpoint handler."
		print "Exception Address: 0x%08x" % self.exception_address
		if not self.breakpoints.has_key(self.exception_address):  
			# if it is the first Windows driven breakpoint
			# then let's just continue on
			if self.first_breakpoint == True:
				self.first_breakpoint = False
				print "[*] Hit the first breakpoint."  
		else:
			print "[*] Hit user defined breakpoint."

		return DBG_CONTINUE  

	# 读内存	
	def read_process_memory(self, address, length):
		data = ""
		read_buf = create_string_buffer(length)	
		count = c_ulong(0)
		print self.h_process
		if not kernel32.ReadProcessMemory(self.h_process, address, read_buf, length, byref(count)):
			return False
		else:
			data += read_buf.raw
			return data

	# 写内存
	def write_process_memory(self, address, data):
		count = c_ulong(0)
		length = len(data)
		c_data = c_char_p(data[count.value:])
		if not kernel32.WriteProcessMemory(self.h_process, address, c_data, length, byref(count)):
			return False
		else:
			return True

	# 设置断点
	def bp_set(self, address):
		# 看看断点的字典里是不是已经存在这个断点的地址了
		if not self.breakpoints.has_key(address):
			try:
				# 先读取原来的一个字节，保存后再写入0xCC
				original_byte = self.read_process_memory(address, 1)
				# print original_byte
				# print GetLastError()
				res = self.write_process_memory(address, '\xCC')
				# if res:
				# 	print "write success"
				# else:
				# 	print "write fail"
				self.breakpoints[address] = (address, original_byte)
			except:
				return False
		return True

	# 获取某个模块（一般是dll）中的某个函数的地址
	def func_resolve(self, dll, function):
		handle = kernel32.GetModuleHandleA(dll)
		address = kernel32.GetProcAddress(handle, function)
		kernel32.CloseHandle(handle)
		return address

	# 设置硬件断点
	def bp_set_hw(self, address, length, condition):
		# 硬件断点对字节有限制，看od就知道了
		if length not in (1,2,4):
			return False
		else:
			length -= 1

		if condition not in (HW_ACCESS, HW_EXECUTE, HW_WRITE):
			return False
		
		# 看看那个调试寄存器是空闲的
		if not self.hardware_breakpoints.has_key(0):
		# 若Dr0没在硬件断点的字典里，就设置值available为0
			available = 0
		elif not self.hardware_breakpoints.has_key(1):
			available = 1
		elif not self.hardware_breakpoints.has_key(2):
			available = 2
		elif not self.hardware_breakpoints.has_key(3):
			available = 3
		else:
			return False

		# 给每个线程都设置调试寄存器
		for thread_id in self.enumerate_threads():
			context = self.get_thread_context(thread_id = thread_id)
			# 在Dr上设置断点的属性
			context.Dr7 |= 1 << (available*2)

			# 将断点的地址存在空闲的4个调试寄存器中的一个
			if available == 0:
				context.Dr0 = address
			elif available == 1:
				context.Dr1 = address
			elif available == 2:
				context.Dr2 = address
			elif available == 3:
				context.Dr3 = address 

			# 设置断点的调试（执行，写入，还是读出呢）
			context.Dr7 |= condition <<((available*4) + 16)

			# 设置长度
			context.Dr7 |= length << ((available*4) + 18)

			# 设置一下线程的上下文
			h_thread = self.open_thread(thread_id)
			kernel32.SetThreadContext(h_thread, byref(context))

		self.hardware_breakpoints[available] = (address, length, condition)	
		return True

	# 处理硬件断点的异常的
	def exception_handler_single_step(self):
		# Dr6是状态寄存器，说明了被断点触发的调试事件类型
		# 是Dr0那个断点产生的那，Dr1，还是。。。。。
		if self.context.Dr6 & 0x1 and self.hardware_breakpoints.has_key(0):
			slot = 0
		elif self.context.Dr6 & 0x2 and self.hardware_breakpoints.has_key(1):
			slot = 1
		elif self.context.Dr6 & 0x4 and self.hardware_breakpoints.has_key(2):
			slot = 2
		elif self.context.Dr6 & 0x8 and self.hardware_breakpoints.has_key(3):
			slot = 3
		else:
			continue_status = DBG_EXCEPTION_NOT_HANDLED

		# 从列表中删除断点
		if self.bp_del_hw(slot):
			continue_status = DBG_CONTINUE
		print "[*] Hardware breakpoint removed."
		return continue_status

	# 删除硬件断点
	def bp_del_hw(self, slot):
		for thread_id in self.enumerate_threads():
			context = self.get_thread_context(thread_id = thread_id)
			# 重置Dr7对应的位
			context.Dr7 &= ~(1<<slot*2)
			# 地址置0
			if slot == 0:
				context.Dr0 = 0x00000000
			elif slot == 1:
				context.Dr1 = 0x00000000
			elif slot == 2:
				context.Dr2 = 0x00000000
			elif slot == 3:
				context.Dr3 = 0x00000000
			# 条件位也要复位
			context.Dr7 &= ~(3 << ((slot*4) + 16))
			# 长度位复位
			context.Dr7 &= ~(3 << ((slot*4) + 18))

			# 重新设置进程上下文
			h_thread = self.open_thread(thread_id)
			kernel32.SetThreadContext(h_thread, byref(context))
		# 从字典中清除
		del self.hardware_breakpoints[slot]
		return True

	# 设置内存断点
	def bp_set_mem(self, address, size):
		# 找到当前地址所在的页
		mbi = MEMORY_BASIC_INFORMATION()
		if kernel32.VirtualQueryEx(self.h_process, address, byref(mbi), sizeof(mbi)) < sizeof(mbi):
			return False
		current_page = mbi.BaseAddress

		while current_page <= address + size:
			self.guarded_pages.append(current_page)
			old_protection = c_ulong(0)
			# 添加保护页属性
			if not kernel32.VirtualProtectEx(self.h_process, current_page, size, mbi.Protect | PAGE_GUARD, byref(old_protection)):
				return False
			current_page += self.page_size

		self.memory_breakpoints[address] = (address, size, mbi)

		return True





