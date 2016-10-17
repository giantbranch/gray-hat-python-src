# -*- coding: utf-8 -*-
# @Date    : 2016-09-15 11:33:17
# @Author  : giantbranch (giantbranch@gmail.com)
# @Link    : http://blog.csdn.net/u012763794?viewmode=contents

from pydbg import *
from pydbg.defines import *
import utils
import random
import sys
import struct
import threading
import os
import shutil
import time
import getopt

class file_fuzzer:
	# 构造方法
	def __init__(self, exe_path, ext, notify):
		# 初始化一些变量，用于跟踪记录文件的基础信息
		self.exe_path = exe_path
		self.ext = ext
		self.notify_crash = notify
		self.orig_file = None
		self.mutated_file = None
		self.iteration = 0
		self.crash = None
		self.send_notify = False
		self.pid = None
		self.in_accessv_handler = False
		self.dbg = None
		self.running = False
		self.ready = False
		# Optional 可选的,设置一下邮件的参数
		self.smtpserver = ''
		self.recipents = ['admin@xx.com',]
		self.sender = ''
		self.test_cases = ["%s%n%s%n%s%n", "\xff", "\x00", "A"]

	# 列出某个目录，跟着随机选取一个进行变形，并将其复制为test文件
	def file_picker(self):
		file_list = os.listdir("examples/")
		list_length = len(file_list) 
		file = file_list[random.randint(0, list_length-1)]
		shutil.copy("examples\\%s" % file, "test.%s" % self.ext)
		return file

	def fuzz(self):
		while 1:
			# 第一步，确保只有一个调试进程在运行或者访问违例的处理程序没有在搜集崩溃信息（因为搜集完的话他会将running设置为false）
			if not self.running:
				# 调用选取函数并保存该文件
				self.test_file = self.file_picker()
				# 传入变形函数
				self.mutate_file()

				# 文件变形完成，就开启调试线程
				pydbg_thread = threading.Thread(target=self.start_debugger)
				# setDaemon设置是否为守护进程，这是是false
				# 在linux或者unix操作系统中，守护进程（Daemon）是一种运行在后台的特殊进程，它独立于控制终端并且周期性的执行某种任务或等待处理某些发生的事件。
				pydbg_thread.setDaemon(0)
				pydbg_thread.start()

				# 当程序创建成功，得到了新的pid
				while self.pid == None:
					time.sleep(1)

				# 开始监视线程
				monitor_thread = threading.Thread(target=self.monitor_debugger)
				monitor_thread.setDaemon(0)
				monitor_thread.start()

				# 统计变量
				self.iteration += 1
			
			#等待一次fuzz完成 
			else:
				time.sleep(1)

	# 开启调试器
	def start_debugger(self):
		print "[*] Starting debugger for iteration: %d" % self.iteration
		self.running = True
		self.dbg = pydbg()
		# 如果有访问违例就调用check_accessv函数
		self.dbg.set_callback(EXCEPTION_ACCESS_VIOLATION,self.check_accessv)
		pid = self.dbg.load(self.exe_path, "test.%s" % self.ext)
		self.pid = self.dbg.pid
		self.dbg.run()

	def check_accessv(self, dbg):
		if dbg.dbg.u.Exception.dwFirstChance:
			return DBG_CONTINUE
		print "[*] Woot! Handling an access violation!"
		self.in_accessv_handler = True
		crash_bin = utils.crash_binning.crash_binning()
		crash_bin.record_crash(dbg)
		self.crash = crash_bin.crash_synopsis()
		# 记录崩溃的信息
		crash_fd = open("crashes\\crash-%d" % self.iteration, "w")
		crash_fd.write(self.crash)
		# 备份文件
		shutil.copy("test.%s" % self.ext, "crashes\\%d.%s" % (self.iteration, self.ext))
		shutil.copy("examples\\%s" % self.test_file, "crashes\\%d_orig.%s" % (self.iteration, self.ext))
		self.dbg.terminate_process()
		self.in_accessv_handler = False
		self.running = False
		return DBG_EXCEPTION_NOT_HANDLED

	# 监视进程，确保在一段事件以后杀死被调试的进程
	def monitor_debugger(self):
		counter = 0;
		print "[*] Monitor thread for pid: %d waiting." % self.pid,
		while counter < 3:
			time.sleep(1)
			print counter,
			counter += 1
		# 不在处理访问违规就结束那个被调试的进程
		if self.in_accessv_handler != True:
			time.sleep(1)
			self.dbg.terminate_process()
			self.pid = None
			self.running = False
		else:
			print "[*] The access violation handler is doing its business.Waiting."

			while self.running:
				time.sleep(1)

	def notify(self):
		crash_message = "From:%s\r\n\r\nTo:\r\n\r\nIteration: %d\n\nOutput:\n\n %s" % (self.sender, self.iteration, self.crash)
		session = smtplib.SMTP(smtpserver)
		session.sendemail(sender, recipents, crash_message)
		session.quit()
		return
    
    # 变形函数
	def mutate_file(self):
		# 打开我们的测试文件，读取里面的内容
		fd = open("test.%s" % self.ext, "rb")
		stream = fd.read()	
		fd.close()

		# 随机选取前面的测试用例来测试
		test_case = self.test_cases[random.randint(0, len(self.test_cases)-1)]
		# 看看文件数据流有多长，根据这个来随机选择位置来插入
		stream_length = len(stream)
		rand_offset = random.randint(0, stream_length-1)
		# 随机选取插入次数
		rand_len = random.randint(0, 1000)
		# 将选出来的测试用例乘以次数
		test_case = test_case * rand_len

		# 在选取的插入位置处插入我们的测试用例
		fuzz_file = stream[0:rand_offset]
		fuzz_file += str(test_case)
		fuzz_file += stream[rand_offset]

		# 最后将其输出文件
		fd = open("test.%s" % self.ext, "wb")
		fd.write(fuzz_file)
		fd.close()
		return

def print_usage():
	print "[*]"
	print "[*] file_fuzzer.py -e <Executable Path> -x <File Extension>"
	print "[*]"
	sys.exit(0)

if __name__ == '__main__':
	print "[*] Generic File Fuzzer."
	try:
		opts,argo = getopt.getopt(sys.argv[1:], "e:x:n")
	except getopt.GetoptError:
		print_usage()
		
	exe_path = None
	ext = None
	notify = False

	for o,a in opts:
		if o == "-e":
			exe_path = a
		elif o == "-x":
			ext = a
		elif o == "-n":
			notify = True

	if exe_path is not None and ext is not None:
		fuzzer = file_fuzzer(exe_path, ext, notify)
		fuzzer.fuzz()
	else:
		print_usage()



