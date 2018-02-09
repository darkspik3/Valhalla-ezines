EXCEPTION_CONTINUE_EXECUTION        equ     -1
POINTER_CONTEXT_RECORD              equ     8
CONTEXT_RIP                         equ     0f8h
CONTEXT_RSP                         equ     98h
CONTEXT_R12                         equ     0d8h

PROCESS_ENVIRONMENT_BLOCK           equ     0
PEB_LDR_DATA                        equ     18h
Ldr                                 equ     0
InMemoryOrderModuleList             equ     20h

rip                                 equ

INT3_OPCODE                         equ     0cch

IMAGE_FILE_MACHINE_AMD64            equ     8664h
IMAGE_OH64_SUBSYSTEM                equ     5ch
IMAGE_OH64_DLLCHARACTERISTICS       equ     5eh
IMAGE_SUBSYSTEM_WINDOWS_GUI         equ     2
IMAGE_SUBSYSTEM_WINDOWS_CUI         equ     3
IMAGE_OHDD64_EXPORT_TABLE           equ     88h
IMAGE_OHDD64_EXCEPTION_DIRECTORY    equ     0a0h
IMAGE_OHDD64_RELOC_TABLE            equ     0b0h

UNW_FLAG_EHANDLER                   equ     1
UNW_FLAG_UHANDLER                   equ     2

IMAGE_SCN_MEM_EXECUTE               equ     20000000h
IMAGE_SCN_MEM_WRITE                 equ     80000000h

kUnmapViewOfFile                    equ     qword ptr [rdi]
kMapViewOfFile                      equ     qword ptr [rdi + 8]
kFindNextFileA                      equ     qword ptr [rdi + 10h]
kFindFirstFileA                     equ     qword ptr [rdi + 18h]
kCloseHandle                        equ     qword ptr [rdi + 20h]
kCreateFileMappingA                 equ     qword ptr [rdi + 28h]
kCreateFileA                        equ     qword ptr [rdi + 30h]

ntRtlRemoveVectoredExceptionHandler equ     qword ptr [rdi + 38h]
ntRtlAddVectoredExceptionHandler    equ     qword ptr [rdi + 40h]


IMAGE_DOS_HEADER struct
    e_magic     WORD    ?
    e_cblp      WORD    ?
    e_cp        WORD    ?
    e_crlc      WORD    ?
    e_cparhdr   WORD    ?
    e_minalloc  WORD    ?
    e_maxalloc  WORD    ?
    e_ss        WORD    ?
    e_sp        WORD    ?
    e_csum      WORD    ?
    e_ip        WORD    ?
    e_cs        WORD    ?
    e_lfarlc    WORD    ?
    e_ovno      WORD    ?
    e_res       WORD    4 dup (?)
    e_oemid     WORD    ?
    e_oeminfo   WORD    ?
    e_res2      WORD    0ah dup (?)
    e_lfanew    DWORD   ?
IMAGE_DOS_HEADER ends

IMAGE_OPTIONAL_HEADER64 struct
    Magic                         WORD     ?
    MajorLinkerVersion            BYTE     ?
    MinorLinkerVersion            BYTE     ?
    SizeOfCode                    DWORD    ?
    SizeOfInitializedData         DWORD    ?
    SizeOfUninitializedData       DWORD    ?
    AddressOfEntryPoint           DWORD    ?
    BaseOfCode                    DWORD    ?
    ImageBase                     QWORD    ?
    SectionAlignment              DWORD    ?
    FileAlignment                 DWORD    ?
    MajorOperatingSystemVersion   WORD     ?
    MinorOperatingSystemVersion   WORD     ?
    MajorImageVersion             WORD     ?
    MinorImageVersion             WORD     ?
    MajorSubsystemVersion         WORD     ?
    MinorSubsystemVersion         WORD     ?
    Win32VersionValue             DWORD    ?
    SizeOfImage                   DWORD    ?
    SizeOfHeaders                 DWORD    ?
    CheckSum                      DWORD    ?
    Subsystem                     WORD     ?
    DllCharacteristics            WORD     ?
    SizeOfStackReserve            QWORD    ?
    SizeOfStackCommit             QWORD    ?
    SizeOfHeapReserve             QWORD    ?
    SizeOfHeapCommit              QWORD    ?
    LoaderFlags                   DWORD    ?
    NumberOfRvaAndSizes           DWORD    ?
IMAGE_OPTIONAL_HEADER64 ends

IMAGE_FILE_HEADER struct
    Machine               WORD     ?
    NumberOfSections      WORD     ?
    TimeDateStamp         DWORD    ?
    PointerToSymbolTable  DWORD    ?
    NumberOfSymbols       DWORD    ?
    SizeOfOptionalHeader  WORD     ?
    Characteristics       WORD     ?
IMAGE_FILE_HEADER ends

IMAGE_NT_HEADERS struct
    Signature         DWORD    ?
    FileHeader        IMAGE_FILE_HEADER       <>
    OptionalHeader64  IMAGE_OPTIONAL_HEADER64 <>
IMAGE_NT_HEADERS ends

IMAGE_SECTION_HEADER struct
    Name1                 BYTE     8 dup (?)
    union Misc
        PhysicalAddress   DWORD    ?
        VirtualSize       DWORD    ?
    ends
    VirtualAddress        DWORD    ?
    SizeOfRawData         DWORD    ?
    PointerToRawData      DWORD    ?
    PointerToRelocations  DWORD    ?
    PointerToLinenumbers  DWORD    ?
    NumberOfRelocations   WORD     ?
    NumberOfLinenumbers   WORD     ?
    Characteristics       DWORD    ?
IMAGE_SECTION_HEADER ends

IMAGE_EXPORT_DIRECTORY struct
    Characteristics        DWORD    ?
    TimeDateStamp          DWORD    ?
    MajorVersion           WORD     ?
    MinorVersion           WORD     ?
    nName                  DWORD    ?
    nBase                  DWORD    ?
    NumberOfFunctions      DWORD    ?
    NumberOfNames          DWORD    ?
    AddressOfFunctions     DWORD    ?
    AddressOfNames         DWORD    ?
    AddressOfNameOrdinals  DWORD    ?
IMAGE_EXPORT_DIRECTORY ends

IMAGE_RUNTIME_FUNCTION_ENTRY struct
    BeginAddress      DWORD    ?
    EndAddress        DWORD    ?
    UnwindInfoAddress DWORD    ?
IMAGE_RUNTIME_FUNCTION_ENTRY ends

WIN32_FIND_DATA struct
    dwFileAttributes  DWORD    ?
    ftCreationTime    QWORD    ?
    ftLastAccessTime  QWORD    ?
    ftLastWriteTime   QWORD    ?
    nFileSizeHigh     DWORD    ?
    nFileSizeLow      DWORD    ?
    dwReserved0       DWORD    ?
    dwReserved1       DWORD    ?
    cFileName         BYTE     260 dup (?)
    cAlternate        BYTE     0eh dup (?)
WIN32_FIND_DATA ends