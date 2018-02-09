#include <stdio.h>
#include <string.h>
#include <windows.h>

#define CP_ANSI 0

int main(int argc, char *argv[]) {

   int i;
   
	HMODULE hSfc;
	WINBASEAPI BOOL WINAPI (*SfcIsFileProtected)(HANDLE RpcHandle, LPWSTR ProtFileName);
	
	BOOL boolIsSfcProtected;
	
   char *szModule;
   HMODULE hModule;
	
	char szModuleFileName[MAX_PATH+1];
   wchar_t wszModuleFileName[MAX_PATH+1];
	DWORD nModuleFileNameLength;
	int mbret;
   
   FARPROC lpProc;
   
   printf("library\\procaddr dump utility for CLT20 (c) JPanic.\n\n");
	if (argc < 2) {
		printf("usage: %s modulename <space seperated proc list>\n",argv[0]);
		return 1;
	}
	
	hSfc = LoadLibrary("sfc");
	if (!hSfc) printf("sfc.dll not loaded.\n\n");
	else {
		SfcIsFileProtected = GetProcAddress(hSfc, "SfcIsFileProtected");
		if (!SfcIsFileProtected) printf("sfc.dll: SfcIsFileProtected not found.\n\n");
	}
   
   szModule = argv[1];
   
   hModule = LoadLibrary(szModule);
   if (hModule == NULL) {
      printf("%s not loadable.\n",szModule);
      return(2);
   }
   
	boolIsSfcProtected = 0;
   nModuleFileNameLength = GetModuleFileName(hModule, szModuleFileName, MAX_PATH);
   if (nModuleFileNameLength) {
		szModuleFileName[nModuleFileNameLength] = 0;
		mbret = MultiByteToWideChar(CP_ANSI, 0, szModuleFileName, -1, wszModuleFileName, MAX_PATH);
		boolIsSfcProtected = (*SfcIsFileProtected)(NULL, wszModuleFileName);
	}
   else strcpy(szModuleFileName,"Unknown");
   
   printf("Module: %s, Load Address: %p\n", szModule, hModule);
   printf("Module FileName: %s\n",szModuleFileName);
	printf("Module Is SFC Protected: %s\n", (boolIsSfcProtected) ? "Yes" : "No");
   
   for (i = 2; i < argc; i++) {
      if (i == 2) printf("\n");
      
      lpProc = GetProcAddress(hModule, argv[i]);
      printf("Procedure: %s Address: ", argv[i]);
      if (lpProc == NULL) {
         printf("NULL (not found).\n");
      }
      else printf ("%p\n",lpProc);
   }   
   
   return(0);
}
