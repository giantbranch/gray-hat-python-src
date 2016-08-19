# -*- coding: utf-8 -*-
# @Date    : 2016-08-15 09:10:15
# @Author  : giantbranch (giantbranch@gmail.com)
# @Link    : http://blog.csdn.net/u012763794?viewmode=contents

import immlib
def main(args):
	imm = immlib.Debugger()
	imm.log("args:%s" % args)
	search_code = " ".join(args)
	imm.log("search_code:%s" % search_code)
	search_byte = imm.assemble(search_code)
	imm.log(repr(search_byte))
	search_result = imm.search(search_byte)
	for hit in search_result:
		code_page = imm.getMemoryPageByAddress(hit)
		access = code_page.getAccess(human = True)
		if "execute" in access.lower():
			imm.log("[*] Found: %s (0x%08x)" % (search_code, hit), address = hit) 
	return "[*] Finished searching for instructions,check the Log window."

