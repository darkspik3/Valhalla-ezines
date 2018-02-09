JNI_VERSION_1_6                                       equ     10006h

DestroyJavaVM                                         equ     0ch
DefineClass                                           equ     14h
DeleteLocalRef                                        equ     5ch
NewObject                                             equ     70h
GetMethodID                                           equ     84h
NewByteArray                                          equ     2c0h
SetByteArrayRegion                                    equ     340h

JavaVMInitArgs struct
    version             dd ?
    nOptions            dd ?
    options             dd ?       ;pointer to JavaVMOption
    ignoreUnrecognized  dd ?
JavaVMInitArgs ends

LIST_ENTRY struct
    FLink  dd ?
    BLink  dd ?
LIST_ENTRY ends

_PEB_LDR_DATA struct
    dwLength                           dd ?
    bInitialized                       dd ?
    dwSsHandle                         dd ?
    dwInLoadOrderModuleList            LIST_ENTRY <?>
    dwInMemoryOrderModuleList          LIST_ENTRY <?>
    dwInInitializationOrderModuleList  LIST_ENTRY <?>
_PEB_LDR_DATA ends

PROCESS_ENVIRONMENT_BLOCK struct
	bInhiritedAddressSpace     db ?
	bReadImageFileExecOptions  db ?
	bBeingDebugged             db ?
	bSpare                     db ?
	hMutant                    dd ?
	dwImageBaseAddress         dd ?
	lpLoaderData               dd ?
	lpProcessParameters        dd ?
PROCESS_ENVIRONMENT_BLOCK ends

