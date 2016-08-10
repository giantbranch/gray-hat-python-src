# -*- coding: utf-8 -*-
# @Date    : 2016-08-10 20:39:24
# @Author  : giantbranch (giantbranch@gmail.com)
# @Link    : http://blog.csdn.net/u012763794?viewmode=contents

from ctypes import *

#python
class barley_amount(Union):
	_fields_ = [
		("barley_long", c_long),
		("barley_int", c_int),
		("barley_char", c_char*8),
	]

value = raw_input("请输入装进啤酒桶里大麦的数量\n")
my_barley = barley_amount(int(value))
print "长整形: %ld" % my_barley.barley_long
print "整型: %d" % my_barley.barley_int
print "字符型: %s" % my_barley.barley_char

