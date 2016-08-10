# -*- coding: utf-8 -*-
# @Date    : 2016-08-10 17:35:59
# @Author  : giantbranch (giantbranch@gmail.com)
# @Link    : http://blog.csdn.net/u012763794?viewmode=contents

from ctypes import *
msvcrt = cdll.msvcrt
message_string = "HelloWorld!\n"
msvcrt.printf("using c printf: %s", message_string)