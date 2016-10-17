# -*- coding: utf-8 -*-
# @Date    : 2016-08-21 15:24:02
# @Author  : giantbranch (giantbranch@gmail.com)
# @Link    : http://blog.csdn.net/u012763794?viewmode=contents

import sys
from ctypes import *
# 初始化，获取传入参数的操作
PAGE_READWRITE = 0x4
PROCESS_ALL_ACCESS = (0x000F0000|0x00100000|0xFFF)
VIRTUAK_MEM = (0x1000|0x2000)
kernel32 = windll.kernel32
pid = sys.argv[1]
dll_path = sys.argv[2]
dll_len = len(dll_path)

# 获得目标进程的句柄
h_process = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, int(pid))
if not h_process:
	print "[*] Couldn't acquire a handle to PID:%s" % pid

# 分配内存给dll_path那个字符串
arg_address = kernel32.VirtualAllocEx(h_process, 0, dll_len, VIRTUAK_MEM, PAGE_READWRITE)
# 将dll_path写入已分配的内存
written = c_int(0)
kernel32.WriteProcessMemory(h_process, arg_address, dll_path, dll_len, byref(written))
# 我们要获取LoadLibraryA的地址
h_kernel32 = kernel32.GetModuleHandleA("kernel32.dll")
h_loadlib = kernel32.GetProcAddress(h_kernel32, "LoadLibraryA")
# 开始利用创建远程线程进行注入
thread_id = c_ulong(0)
if not kernel32.CreateRemoteThread(h_process, None, 0, h_loadlib, arg_address, 0, byref(thread_id)):
	print "[*] Failed to inject the DLL. Exiting."
	sys.exit(0)
print "[*] Remote thread with ID 0x%08x created." % thread_id.value


