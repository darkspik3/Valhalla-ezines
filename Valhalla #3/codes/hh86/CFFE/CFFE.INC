IMAGE_DOS_HEADER_E_LFANEW                             equ     3ch

IMAGE_EXPORT_DIRECTORY_NUMBER_OF_NAMES                equ     18h
IMAGE_EXPORT_DIRECTORY_ADDRESS_OF_FUNCTIONS           equ     1ch
IMAGE_EXPORT_DIRECTORY_ADDRESS_OF_NAMES               equ     20h
IMAGE_EXPORT_DIRECTORY_ADDRESS_OF_NAME_ORDINALS       equ     24h


;setup timeout for awaiting the process to be launched
TIMEOUT                                               equ     1000 * 2

;erase or comment line to disable its use
WaitObject                                            equ

KERNEL32 struct
    kWaitForSingleObject  DWORD ?
    kSetErrorMode         DWORD ?
    kLoadLibraryA         DWORD ?
    kGlobalFree           DWORD ?
    kGlobalAlloc          DWORD ?
    kFindNextFileA        DWORD ?
    kFindFirstFileA       DWORD ?
    kFindClose            DWORD ?
    kCreateProcessA       DWORD ?
    kCloseHandle          DWORD ?
KERNEL32 ends

ADVAPI32 struct
    aRegQueryKeyExA  DWORD ?
    aRegOpenKeyExA   DWORD ?
    aRegCloseKey     DWORD ?
ADVAPI32 ends

WIN32_FIND_DATA struct
    dwFileAttributes  DWORD ?
    ftCreationTime    QWORD ?
    ftLastAccessTime  QWORD ?
    ftLastWriteTime   QWORD ?
    nFileSizeHigh     DWORD ?
    nFileSizeLow      DWORD ?
    dwReserved0       DWORD ?
    dwReserved1       DWORD ?
    cFileName         BYTE  260 dup (?)
    cAlternate        BYTE  0eh dup (?)
WIN32_FIND_DATA ends

LIST_ENTRY struct
    FLink  DWORD ?
    BLink  DWORD ?	
LIST_ENTRY ends

_PEB_LDR_DATA struct
    dwLength                           DWORD ?
    bInitialized                       DWORD ?
    dwSsHandle                         DWORD ?
    dwInLoadOrderModuleList            LIST_ENTRY <?>
    dwInMemoryOrderModuleList          LIST_ENTRY <?>
    dwInInitializationOrderModuleList  LIST_ENTRY <?>
_PEB_LDR_DATA ends

PROCESS_ENVIRONMENT_BLOCK struct
	bInhiritedAddressSpace     BYTE  ?
	bReadImageFileExecOptions  BYTE  ?
	bBeingDebugged             BYTE  ?
	bSpare                     BYTE  ?
	hMutant                    DWORD ?
	dwImageBaseAddress         DWORD ?
	lpLoaderData               DWORD ?
	lpProcessParameters        DWORD ?
PROCESS_ENVIRONMENT_BLOCK ends

include windows.inc
include user32.inc
include kernel32.inc

includelib user32.lib
includelib kernel32.lib