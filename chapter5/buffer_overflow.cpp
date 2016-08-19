#include <stdio.h>
#include <windows.h>

int overflow_here(char *key){
	char buffer[66];
	strcpy(buffer, key);
	return 0;
}

int main(){
	char  key[666];
	FILE *fp;
	LoadLibrary("user32.dll");
	if (!(fp = fopen("key.txt", "rw+"))){
		exit(0);
	}
	fscanf(fp, "%s", key);
	overflow_here(key);
	printf("come on, overflow me!");
	return 0;
}

