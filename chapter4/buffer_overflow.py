# -*- coding: utf-8 -*-
# @Date    : 2016-08-14 20:53:53
# @Author  : giantbranch (giantbranch@gmail.com)
# @Link    : http://blog.csdn.net/u012763794?viewmode=contents

from ctypes import *
msvcrt = cdll.msvcrt
raw_input("Once the debugger is attached, press any key.")
# 定义一个缓冲区
buffer = c_char_p("AAAAA")
# 用于溢出的字符串
overflow = "A" * 100
# 溢出
msvcrt.strcpy(buffer, overflow)