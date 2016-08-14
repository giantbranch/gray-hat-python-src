# -*- coding: utf-8 -*-
# @Date    : 2016-08-14 21:44:59
# @Author  : giantbranch (giantbranch@gmail.com)
# @Link    : http://blog.csdn.net/u012763794?viewmode=contents

from pydbg import *
from pydbg.defines import *
import threading
import time
import sys

class snapshotter(object):
	"""docstring for snapshotter"""
	def __init__(self, exe_path):
		self.exe_path = exe_path
		self.pid = None
		self.dbg = None
		self.running = True

		# 开启调试器的线程，循环直到设置了目标进程的PID
		pydbg_thread = threading.Thread(target=self.start_debugger)
		pydbg_thread.setDaemon(0)
		pydbg_thread.start()

		while self.pid == None:
			time.sleep(1)

		# 现在我们有了目标的PID，并且他在运行，我们开另外一个线程去拍快照吧
		monitor_thread = threading.Thread(target=self.monitor_debugger)
		monitor_thread.setDaemon(0)
		monitor_thread.start()
	
	def monitor_debugger(self):
		while self.running == True:
			input = raw_input("Enter :'snap', 'restore' or 'quit'\n")	
			input = input.lower().strip()

			if input == "quit":
				print "[*] Exiting the snapshotter."
				self.running = False
				self.dbg.terminate_process()
			elif input == "snap":
				# 挂起
				print "[*] Suspending all threads."
				self.dbg.suspend_all_threads()
				# 拍快照
				print "[*] Obtaining snapshot."
				self.dbg.process_snapshot()
				#恢复	
				print "[*] Resuming operation."
				self.dbg.resume_all_threads()
			elif input == "restore":
				# 挂起
				print "[*] Suspending all threads."
				self.dbg.suspend_all_threads()
				# 利用快照restore
				print "[*] Obtaining snapshot."
				self.dbg.process_restore()
				#恢复
				print "[*] Resuming operation."
				self.dbg.resume_all_threads()

	def start_debugger(self):
		self.dbg = pydbg()

		pid = self.dbg.load(self.exe_path)
		self.pid = self.dbg.pid
		self.dbg.run()

# exe_path = "C:\\WINDOWS\\system32\\calc.exe"
exe_path = "D:\\All_Code\\VC++6.0\\test\\aaa\\Debug\\aaa.exe"
snapshotter(exe_path)
