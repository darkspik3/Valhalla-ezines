MAX_PATH                        equ     260

FILE_DIRECTORY_FILE             equ     00000001h
FILE_SYNCHRONOUS_IO_NONALERT    equ     00000020h
FILE_OPEN_FOR_BACKUP_INTENT     equ     00004000h

FILE_SHARE_READ                 equ     00000001
FILE_SHARE_WRITE                equ     00000002

FILE_READ_DATA                  equ     0001h
FILE_LIST_DIRECTORY             equ     0001h
FILE_WRITE_DATA                 equ     0002h
FILE_APPEND_DATA                equ     0004h
FILE_WRITE_ATTRIBUTES           equ     0100h

SYNCHRONIZE                     equ     00100000h

FileBothDirectoryInformation    equ     3
FileBasicInformation            equ     4

FILE_ATTRIBUTE_DIRECTORY        equ     00000010h
FILE_ATTRIBUTE_ARCHIVE          equ     00000020h

IMAGE_FILE_MACHINE_I386         equ     14ch    ;14d/14e do not exist.  if you don't believe, then try it
IMAGE_FILE_32BIT_MACHINE        equ     0100h
IMAGE_FILE_MACHINE_AMD64        equ     8664h

IMAGE_FILE_RELOCS_STRIPPED      equ     0001h
IMAGE_FILE_EXECUTABLE_IMAGE     equ     0002h
IMAGE_FILE_SYSTEM               equ     1000h
IMAGE_FILE_DLL                  equ     2000h
IMAGE_FILE_UP_SYSTEM_ONLY       equ     4000h

IMAGE_SUBSYSTEM_WINDOWS_GUI     equ     2
IMAGE_SUBSYSTEM_WINDOWS_CUI     equ     3

RANDPADMIN                      equ     4096
RANDPADMAX                      equ     2048 ;RANDPADMIN is added to this

PAGE_READWRITE                  equ     04

STANDARD_RIGHTS_REQUIRED        equ     000F0000h
SECTION_QUERY                   equ     0001
SECTION_MAP_WRITE               equ     0002
SECTION_MAP_READ                equ     0004

IMAGE_SCN_MEM_EXECUTE           equ     20000000h
IMAGE_SCN_MEM_WRITE             equ     80000000h

EXCEPTION_CONTINUE_EXECUTION    equ     -1

ContextRecord_RIP               equ     0xf8

align           1                               ;byte-packed structures
struc   ntdcrcstk
        .kRtlSetCurrentDirectory_U            :    resq    1
        .kRtlRemoveVectoredExceptionHandler   :    resq    1
        .kRtlRandom                           :    resq    1
        .kRtlFreeHeap                         :    resq    1
        .kRtlDosPathNameToRelativeNtPathName_U:    resq    1
        .kRtlAllocateHeap                     :    resq    1
        .kRtlAddVectoredExceptionHandler      :    resq    1
        .kNtUnmapViewOfSection                :    resq    1
        .kNtSetInformationFile                :    resq    1
        .kNtQueryDirectoryFile                :    resq    1
        .kNtOpenFile                          :    resq    1
        .kNtMapViewOfSection                  :    resq    1
        .kNtCreateSection                     :    resq    1
        .kNtClose                             :    resq    1
endstruc
ntdcrc_count    equ     ntdcrcstk_size >> 3

struc   UNICODE_STRING
        .UniLength    : resw    1
        .MaximumLength: resw    1
        .padding      : resd    1
        .Buffer       : resq    1
endstruc

struc   UNICODE_STRINGDD
        .UniString:     resb    UNICODE_STRING_size
        .RootDir  :     resq    1
endstruc

struc   LARGE_INTEGER
        .dwordLow :     resd    1
        .dwordHigh:     resd    1
endstruc

struc   FILE_DIRECTORY_INFORMATION
        .dirNextEntryOffset:    resd            1
        .dirUnknown1       :    resd            1
        .dirCreationTime   :    resb            LARGE_INTEGER_size
        .dirLastAccessTime :    resb            LARGE_INTEGER_size
        .dirLastWriteTime  :    resb            LARGE_INTEGER_size
        .dirChangeTime     :    resb            LARGE_INTEGER_size
        .dirRealFileSize   :    resb            LARGE_INTEGER_size
        .dirAllocatedSize  :    resb            LARGE_INTEGER_size
        .dirFileAttributes :    resd            1
        .dirFileNameLength :    resd            1
        .dirUnknown2       :    resw            0fh
        .dirFileName       :    resw            MAX_PATH + 1
endstruc

struc   findlist
        .findprev:      resq    1
        .findhand:      resq    1
        .findname:      resb    UNICODE_STRING_size
        .findmask:      resb    UNICODE_STRINGDD_size
        .finddata:      resb    FILE_DIRECTORY_INFORMATION_size
endstruc

struc   coffhdr
        .pemachine   :  resw    1               ;04
        .pesectcount :  resw    1               ;06
        .petimedate  :  resd    1               ;08
        .pesymbrva   :  resd    1               ;0C
        .pesymbcount :  resd    1               ;10
        .peopthdrsize:  resw    1               ;14
        .peflags     :  resw    1               ;16
endstruc

struc   pedir
        .dirrva :       resd    1
        .dirsize:       resd    1
endstruc

struc   pehdr
        .pesig        : resd    1               ;00
        .pecoff       : resb    coffhdr_size
        .pemagic      : resw    1               ;18
        .pemajorlink  : resb    1               ;1A
        .peminorlink  : resb    1               ;1B
        .pecodesize   : resd    1               ;1C
        .peidatasize  : resd    1               ;20
        .peudatasize  : resd    1               ;24
        .peentrypoint : resd    1               ;28
        .pecodebase   : resd    1               ;2c
        .pedatabase   : resd    1               ;30
        .peimagebase  : resd    1               ;34
        .pesectalign  : resd    1               ;38
        .pefilealign  : resd    1               ;3c
        .pemajoros    : resw    1               ;40
        .peminoros    : resw    1               ;42
        .pemajorimage : resw    1               ;44
        .peminorimage : resw    1               ;46
        .pemajorsubsys: resw    1               ;48
        .peminorsubsys: resw    1               ;4a
        .pereserved   : resd    1               ;4c
        .peimagesize  : resd    1               ;50
        .pehdrsize    : resd    1               ;54
        .pechksum     : resd    1               ;58
        .pesubsys     : resw    1               ;5C
        .pedllflags   : resw    1               ;5E
        .pestackmax   : resd    1               ;60
        .pestacksize  : resd    1               ;64
        .peheapmax    : resd    1               ;68
        .peheapsize   : resd    1               ;6C
        .peldrflags   : resd    1               ;70
        .pervacount   : resd    1               ;74
        .peexport     : resb    pedir_size      ;78
        .peimport     : resb    pedir_size      ;80
        .persrc       : resb    pedir_size      ;88
        .peexcpt      : resb    pedir_size      ;90
        .pesecurity   : resb    pedir_size      ;98
        .pereloc      : resb    pedir_size      ;A0
        .pedebug      : resb    pedir_size      ;A8
        .pearch       : resb    pedir_size      ;B0
        .peglobal     : resb    pedir_size      ;B8
        .petls        : resb    pedir_size      ;C0
        .peconfig     : resb    pedir_size      ;C8
        .pebound      : resb    pedir_size      ;D0
        .peiat        : resb    pedir_size      ;D8
        .pedelay      : resb    pedir_size      ;E0
        .pecom        : resb    pedir_size      ;E8
        .persrv       : resb    pedir_size      ;F0
endstruc

struc   pehdr64
        .pe64sig        :   resd    1               ;000
        .pe64coff       :   resb    coffhdr_size
        .pe64magic      :   resw    1               ;018
        .pe64majorlink  :   resb    1               ;01A
        .pe64minorlink  :   resb    1               ;01B
        .pe64codesize   :   resd    1               ;01C
        .pe64idatasize  :   resd    1               ;020
        .pe64udatasize  :   resd    1               ;024
        .pe64entrypoint :   resd    1               ;028
        .pe64codebase   :   resd    1               ;02C
        .pe64imagebase  :   resq    1               ;030
        .pe64sectalign  :   resd    1               ;038
        .pe64filealign  :   resd    1               ;03C
        .pe64majoros    :   resw    1               ;040
        .pe64minoros    :   resw    1               ;042
        .pe64majorimage :   resw    1               ;044
        .pe64minorimage :   resw    1               ;046
        .pe64majorsubsys:   resw    1               ;048
        .pe64minorsubsys:   resw    1               ;04A
        .pe64reserved   :   resd    1               ;04C
        .pe64imagesize  :   resd    1               ;050
        .pe64hdrsize    :   resd    1               ;054
        .pe64chksum     :   resd    1               ;058
        .pe64subsys     :   resw    1               ;05C
        .pe64dllflags   :   resw    1               ;05E
        .pe64stackmax   :   resq    1               ;060
        .pe64stacksize  :   resq    1               ;068
        .pe64heapmax    :   resq    1               ;070
        .pe64heapsize   :   resq    1               ;078
        .pe64ldrflags   :   resd    1               ;080
        .pe64rvacount   :   resd    1               ;084
        .pe64export     :   resb    pedir_size      ;088
        .pe64import     :   resb    pedir_size      ;090
        .pe64rsrc       :   resb    pedir_size      ;098
        .pe64excpt      :   resb    pedir_size      ;0A0
        .pe64security   :   resb    pedir_size      ;0A8
        .pe64reloc      :   resb    pedir_size      ;0B0
        .pe64debug      :   resb    pedir_size      ;0B8
        .pe64arch       :   resb    pedir_size      ;0C0
        .pe64global     :   resb    pedir_size      ;0C8
        .pe64tls        :   resb    pedir_size      ;0D0
        .pe64config     :   resb    pedir_size      ;0D8
        .pe64bound      :   resb    pedir_size      ;0E0
        .pe64iat        :   resb    pedir_size      ;0E8
        .pe64delay      :   resb    pedir_size      ;0F0
        .pe64com        :   resb    pedir_size      ;0F8
        .pe64rsrv       :   resb    pedir_size      ;100
endstruc

struc   peexp
        .expflags    :  resd    1
        .expdatetime :  resd    1
        .expmajorver :  resw    1
        .expminorver :  resw    1
        .expdllrva   :  resd    1
        .expordbase  :  resd    1
        .expadrcount :  resd    1
        .expnamecount:  resd    1
        .expadrrva   :  resd    1
        .expnamerva  :  resd    1
        .expordrva   :  resd    1
endstruc

struc   tib
        .ExceptReg  :   resd    1
        .StackBase  :   resd    1
        .StackLimit :   resd    1
        .SubSystem  :   resd    1
        .FiberData  :   resd    1
        .UserPointer:   resd    1
        .TibSelf    :   resd    1
        .TibUnknown :   resd    5
        .TibTeb     :   resd    1
endstruc

struc   tib64
        .ExceptReg  :   resq    1
        .StackBase  :   resq    1
        .StackLimit :   resq    1
        .SubSystem  :   resq    1
        .FiberData  :   resq    1
        .UserPointer:   resq    1
        .TibSelf    :   resq    1
        .TibUnknown :   resq    5
        .TibTeb     :   resq    1
endstruc

struc   teb64
        .tebUnknown1:   resq    3
        .tebLdr     :   resq    1
        .tebuser    :   resq    1
        .tebUnknown2:   resq    1
        .heaphand   :   resq    1
endstruc

struc   ldr
        .ldrUnknown              :      resq    6
        .ldrInLoadOrderModuleList:      resq    1
endstruc

struc   modlist
        .mlUnknown:     resq    2
        .mlDllBase:     resq    1
endstruc

struc   OBJECT_ATTRIBUTES
        .ObjLength               :      resq    1
        .RootDirectory           :      resq    1
        .ObjectName              :      resq    1
        .Attributes              :      resq    1
        .SecurityDescriptor      :      resq    1
        .SecurityQualityOfService:      resq    1
endstruc

struc   openstk
        .openobj :      resb    OBJECT_ATTRIBUTES_size
        .openname:      resb    UNICODE_STRING_size
        .openedi :      resq    1
        .openebx :      resq    1
endstruc

struc   FILE_BASIC_INFORMATION
        .basCreationTime         resb   LARGE_INTEGER_size
        .basLastAccessTime       resb   LARGE_INTEGER_size
        .basLastWriteTime        resb   LARGE_INTEGER_size
        .basChangeTime           resb   LARGE_INTEGER_size
        .basFileAttributes       resq   1
endstruc

struc   mzhdr
        .mzsig     :    resw    1               ;00
        .mzpagemod :    resw    1               ;02
        .mzpagediv :    resw    1               ;04
        .mzrelocs  :    resw    1               ;06
        .mzhdrsize :    resw    1               ;08
        .mzminalloc:    resw    1               ;0A
        .mzmaxalloc:    resw    1               ;0C
        .mzss      :    resw    1               ;0E
        .mzsp      :    resw    1               ;10
        .mzchksum  :    resw    1               ;12
        .mzip      :    resw    1               ;14
        .mzcs      :    resw    1               ;16
        .mzreloff  :    resw    1               ;18
        .mzfiller  :    resb    22h             ;1A
        .mzlfanew  :    resd    1               ;3C
endstruc

struc   pesect
        .sectname     : resb    8
        .sectvirtsize : resd    1
        .sectvirtaddr : resd    1
        .sectrawsize  : resd    1
        .sectrawaddr  : resd    1
        .sectreladdr  : resd    1
        .sectlineaddr : resd    1
        .sectrelcount : resw    1
        .sectlinecount: resw    1
        .sectflags    : resd    1
endstruc

struc   mapvehstk
        .mapvehregs  :  resq    3
        .mapdummy    :  resq    12h
        .mapvehinfret:  resq    1
endstruc

struc   EXCEPTION_POINTERS
        .ExceptionRecord:       resq    1
        .ContextRecord  :       resq    1
endstruc
align 16                                        ;restore default alignment
