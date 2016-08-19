/**
 * 
 * @authors giantbranch (giantbranch@gmail.com)
 * @date    2016-08-19 16:03:39
 */
#include <windows.h>

extern "C" BOOL WINAPI IsDebuggerPresent(void);

int main(){
	if (IsDebuggerPresent())
	{
		MessageBox(NULL, "正在调试。。", "标题", NULL);
	}else{
		MessageBox(NULL, "没有调试哦", "标题", NULL);
	}
	return 0;
}