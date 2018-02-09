CUDA_DRIVER_VERSION                                   equ     5000
CU_DEVICE_ATTRIBUTE_COMPUTE_MODE                      equ     20
CU_CTX_SCHED_BLOCKING_SYNC                            equ     4

regmap struct
    regEdi  dd ?
    regEsi  dd ?
    regEbp  dd ?
    regEsp  dd ?
    regEbx  dd ?
    regEdx  dd ?
    regEcx  dd ?
    regEax  dd ?
regmap ends

sehmap struct
    pSEHPFrame         dd ?
    pExceptionHandler  dd ?
    Registers          regmap <?>
sehmap ends

nvcudadrv struct
    cuModuleUnload             dd ?
    cuModuleLoadDataEx         dd ?
    cuModuleGetFunction        dd ?
    cuMemcpyHtoD               dd ?
    cuMemcpyDtoH               dd ?
    cuMemFree                  dd ?
    cuMemAlloc                 dd ?
    cuLaunchKernel             dd ?
    cuInit                     dd ?
    cuDriverGetVersion         dd ?
    cuDeviceGetCount           dd ?
    cuDeviceGetAttribute       dd ?
    cuDeviceComputeCapability  dd ?
    cuCtxSynchronize           dd ?
    cuCtxDestroy               dd ?
    cuCtxCreate                dd ?
nvcudadrv ends

kernel32 struct
    kUnmapViewOfFile     dd ?
    kSetFileAttributesW  dd ?
    kMapViewOfFile       dd ?
    kLoadLibraryA        dd ?
    kGetProcAddress      dd ?
    kFindNextFileW       dd ?
    kFindFirstFileW      dd ?
    kFindClose           dd ?
    kCreateFileW         dd ?
    kCreateFileMappingW  dd ?
    kCloseHandle         dd ?
kernel32 ends

WIN32_FIND_DATA struct
    dwFileAttributes  dd ?
    ftCreationTime    dq ?
    ftLastAccessTime  dq ?
    ftLastWriteTime   dq ?
    nFileSizeHigh     dd ?
    nFileSizeLow      dd ?
    dwReserved0       dd ?
    dwReserved1       dd ?
    cFileName         dw 260 dup (?)
    cAlternate        dw 0eh dup (?)
WIN32_FIND_DATA ends

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

include windows.inc
include kernel32.inc
include user32.inc

includelib kernel32.lib
includelib user32.lib
