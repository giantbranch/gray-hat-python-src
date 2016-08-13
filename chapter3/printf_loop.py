# -*- coding: utf-8 -*-
# @Date    : 2016-08-13 19:18:37
# @Author  : giantbranch (giantbranch@gmail.com)
# @Link    : http://blog.csdn.net/u012763794?viewmode=contents

from ctypes import *
import time

msvcrt = cdll.msvcrt
counter = 0
while 1:
 	msvcrt.printf("Loop iteration %d!\n" % counter) 
 	time.sleep(2)
 	counter = counter + 1