# -*- coding: utf-8 -*-
# @Date    : 2016-08-10 20:30:23
# @Author  : giantbranch (giantbranch@gmail.com)
# @Link    : http://blog.csdn.net/u012763794?viewmode=contents

from ctypes import *
c_int()
c_char_p('Hello world!')
c_ushort(65531)
c_short(-5)
seitz = c_char_p("loves the python")
print seitz
print seitz.value
exit()
