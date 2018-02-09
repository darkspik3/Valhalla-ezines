.xlist
;=============================================================================
.486
;-----------------------------------------------------------------------------

UCHAR                           EQU <db>
USHORT                          EQU <dw>
UINT                            EQU <dd>
ULONG                           EQU <dd>

;-----------------------------------------------------------------------------
NULL                            EQU       0
FALSE                           EQU       0
TRUE                            EQU       1
MAX_PATH                        EQU       260
INVALID_HANDLE_VALUE            EQU       -1
STANDARD_RIGHTS_REQUIRED        EQU       000F0000h

;-----------------------------------------------------------------------------
GENERIC_READ                    EQU       80000000h
GENERIC_WRITE                   EQU       40000000h


;-----------------------------------------------------------------------------
FILE_SHARE_READ         	EQU       00000001h
FILE_SHARE_WRITE        	EQU       00000002h

;-----------------------------------------------------------------------------
CREATE_NEW			EQU       1
CREATE_ALWAYS			EQU       2
OPEN_EXISTING			EQU       3
OPEN_ALWAYS			EQU       4
TRUNCATE_EXISTING		EQU       5

;-----------------------------------------------------------------------------
FILE_ATTRIBUTE_READONLY         EQU       00000001h
FILE_ATTRIBUTE_HIDDEN           EQU       00000002h
FILE_ATTRIBUTE_SYSTEM           EQU       00000004h
FILE_ATTRIBUTE_DIRECTORY        EQU       00000010h
FILE_ATTRIBUTE_ARCHIVE          EQU       00000020h
FILE_ATTRIBUTE_DEVICE		EQU	00000040h
FILE_ATTRIBUTE_NORMAL           EQU       00000080h
FILE_ATTRIBUTE_TEMPORARY        EQU       00000100h
FILE_ATTRIBUTE_SPARSE_FILE      EQU       00000200h
FILE_ATTRIBUTE_REPARSE_POINT    EQU       00000400h
FILE_ATTRIBUTE_COMPRESSED       EQU       00000800h
FILE_ATTRIBUTE_OFFLINE        	EQU       00001000h
FILE_ATTRIBUTE_VIRTUAL		EQU		00010000h

; flags -
FILE_ATTRIBUTE_POSIX_SEMANTICS      EQU       01000000h
FILE_ATTRIBUTE_BACKUP_SEMANTICS     EQU       02000000h
FILE_ATTRIBUTE_DELETE_ON_CLOSE      EQU       04000000h
FILE_ATTRIBUTE_SEQUENTIAL_SCAN      EQU       08000000h
FILE_ATTRIBUTE_RANDOM_ACCESS        EQU       10000000h
FILE_ATTRIBUTE_NO_BUFFERING         EQU       20000000h
FILE_ATTRIBUTE_OVERLAPPED           EQU       40000000h
FILE_ATTRIBUTE_WRITE_THROUGH        EQU       80000000h

BAD_FILE_ATTRIBUTES	=	(FILE_ATTRIBUTE_HIDDEN			OR\
				FILE_ATTRIBUTE_SYSTEM			OR\
				FILE_ATTRIBUTE_DIRECTORY		OR\
				FILE_ATTRIBUTE_DEVICE			OR\
				FILE_ATTRIBUTE_SPARSE_FILE		OR\									
				FILE_ATTRIBUTE_OFFLINE			OR\
				FILE_ATTRIBUTE_TEMPORARY)
									


;-----------------------------------------------------------------------------
SECTION_QUERY                   EQU     00001h
SECTION_MAP_WRITE               EQU     00002h
SECTION_MAP_READ                EQU     00004h
SECTION_MAP_EXECUTE             EQU     00008h
SECTION_EXTEND_SIZE             EQU     00010h

SECTION_ALL_ACCESS      =       (STANDARD_RIGHTS_REQUIRED       OR\
                                SECTION_QUERY                   OR\
                                SECTION_MAP_WRITE               OR\
                                SECTION_MAP_READ                OR\
                                SECTION_MAP_EXECUTE             OR\
                                SECTION_EXTEND_SIZE)

FILE_MAP_COPY       EQU     SECTION_QUERY
FILE_MAP_WRITE      EQU     SECTION_MAP_WRITE
FILE_MAP_READ       EQU     SECTION_MAP_READ
FILE_MAP_ALL_ACCESS EQU     SECTION_ALL_ACCESS

;-----------------------------------------------------------------------------
PAGE_NOACCESS           EQU     001h
PAGE_READONLY           EQU     002h
PAGE_READWRITE          EQU     004h
PAGE_WRITECOPY          EQU     008h
PAGE_EXECUTE            EQU     010h
PAGE_EXECUTE_READ       EQU     020h
PAGE_EXECUTE_READWRITE  EQU     040h
PAGE_EXECUTE_WRITECOPY  EQU     080h
PAGE_GUARD              EQU     0100h
PAGE_NOCACHE            EQU     0200h
       
MEM_COMMIT              EQU     01000h
MEM_RESERVE             EQU     02000h
MEM_DECOMMIT            EQU     04000h
MEM_RELEASE             EQU     08000h
MEM_FREE                EQU     010000h
MEM_PRIVATE             EQU     020000h
MEM_MAPPED              EQU     040000h
MEM_RESET               EQU     080000h
MEM_TOP_DOWN            EQU     0100000h
MEM_4MB_PAGES           EQU     080000000h
SEC_FILE                EQU     0800000h
SEC_IMAGE               EQU     01000000h
SEC_VLM                 EQU     02000000h
SEC_RESERVE             EQU     04000000h
SEC_COMMIT              EQU     08000000h
SEC_NOCACHE             EQU     010000000h
MEM_IMAGE               EQU     SEC_IMAGE

;------------------------------------------------------------------------------
INVALID_FILE_SIZE   EQU     0FFFFFFFFh
        
FILE_BEGIN              EQU     0
FILE_CURRENT            EQU     1
FILE_END                EQU     2


;-----------------------------------------------------------------------------
IMAGE_DOS_SIGNATURE                     EQU     05A4Dh
IMAGE_OS2_SIGNATURE                     EQU     0454Eh
IMAGE_OS2_SIGNATURE_LE                  EQU     0454Ch
IMAGE_VXD_SIGNATURE                     EQU     0454Ch
IMAGE_NT_SIGNATURE                      EQU     000004550h

IMAGE_SIZEOF_FILE_HEADER                EQU     20

IMAGE_FILE_RELOCS_STRIPPED              EQU     00001h
IMAGE_FILE_EXECUTABLE_IMAGE             EQU     00002h
IMAGE_FILE_LINE_NUMS_STRIPPED           EQU     00004h
IMAGE_FILE_LOCAL_SYMS_STRIPPED          EQU     00008h
IMAGE_FILE_AGGRESIVE_WS_TRIM            EQU     00010h
IMAGE_FILE_BYTES_REVERSED_LO            EQU     00080h
IMAGE_FILE_32BIT_MACHINE                EQU     00100h
IMAGE_FILE_DEBUG_STRIPPED               EQU     00200h
IMAGE_FILE_REMOVABLE_RUN_FROM_SW        EQU     00400h
IMAGE_FILE_NET_RUN_FROM_SWAP            EQU     00800h
IMAGE_FILE_SYSTEM                       EQU     01000h
IMAGE_FILE_DLL                          EQU     02000h
IMAGE_FILE_UP_SYSTEM_ONLY               EQU     04000h
IMAGE_FILE_BYTES_REVERSED_HI            EQU     08000h

IMAGE_FILE_MACHINE_UNKNOWN      EQU       0
IMAGE_FILE_MACHINE_I386         EQU       014ch
IMAGE_FILE_MACHINE_R3000        EQU       0162h
IMAGE_FILE_MACHINE_R4000        EQU       0166h
IMAGE_FILE_MACHINE_R10000       EQU       0168h
IMAGE_FILE_MACHINE_ALPHA        EQU       0184h
IMAGE_FILE_MACHINE_POWERPC      EQU       01F0h


IMAGE_NUMBEROF_DIRECTORY_ENTRIES        EQU     16

IMAGE_SIZEOF_ROM_OPTIONAL_HEADER        EQU     56
IMAGE_SIZEOF_STD_OPTIONAL_HEADER        EQU     28
IMAGE_SIZEOF_NT_OPTIONAL_HEADER         EQU     224

IMAGE_NT_OPTIONAL_HDR_MAGIC             EQU     010bh
IMAGE_ROM_OPTIONAL_HDR_MAGIC            EQU     0107h


IMAGE_SUBSYSTEM_UNKNOWN			EQU	0
IMAGE_SUBSYSTEM_NATIVE			EQU	1
IMAGE_SUBSYSTEM_WINDOWS_GUI		EQU	2
IMAGE_SUBSYSTEM_WINDOWS_CUI		EQU	3
IMAGE_SUBSYSTEM_OS2_CUI			EQU	5
IMAGE_SUBSYSTEM_POSIX_CUI		EQU	6
IMAGE_SUBSYSTEM_RESERVED8		EQU	8

IMAGE_DIRECTORY_ENTRY_EXPORT		EQU	0
IMAGE_DIRECTORY_ENTRY_IMPORT		EQU	1
IMAGE_DIRECTORY_ENTRY_RESOURCE		EQU	2
IMAGE_DIRECTORY_ENTRY_EXCEPTION		EQU	3
IMAGE_DIRECTORY_ENTRY_SECURITY		EQU	4
IMAGE_DIRECTORY_ENTRY_BASERELOC		EQU	5
IMAGE_DIRECTORY_ENTRY_DEBUG		EQU	6
IMAGE_DIRECTORY_ENTRY_COPYRIGHT		EQU	7
IMAGE_DIRECTORY_ENTRY_GLOBALPTR		EQU	8
IMAGE_DIRECTORY_ENTRY_TLS		EQU	9
IMAGE_DIRECTORY_ENTRY_LOAD_CONFI	EQU	10
IMAGE_DIRECTORY_ENTRY_BOUND_IMPO	EQU	11
IMAGE_DIRECTORY_ENTRY_IAT		EQU	12

WFILETIME       STRUC
		wft_dwLowDateTime        dd ?
		wft_dwHighDateTime       dd ?
WFILETIME       ENDS

WFF             STRUC
		wff_FileAttributes      dd      ?
		wff_wftCreationTime     WFILETIME ?
		wff_wftLastAccessTime   WFILETIME ?
		wff_wftLastWriteTime    WFILETIME ?
		wff_FileSizeHigh        dd      ?
		wff_FileSizeLow         dd      ?
		wff_Reserved0           dd      ?
		wff_Reserved1           dd      ?
		wff_FileName            dw      MAX_PATH dup(?)
		wff_AlternateFileName   dw      14 dup(?)
		align 4
WFF             ENDS

IMAGE_SCN_TYPE_NO_PAD                   EQU     000000008h
IMAGE_SCN_CNT_CODE                      EQU     000000020h
IMAGE_SCN_CNT_INITIALIZED_DATA          EQU     000000040h
IMAGE_SCN_CNT_UNINITIALIZED_DATA        EQU     000000080h
IMAGE_SCN_LNK_OTHER                     EQU     000000100h
IMAGE_SCN_LNK_INFO                      EQU     000000200h
IMAGE_SCN_LNK_REMOVE                    EQU     000000800h
IMAGE_SCN_LNK_COMDAT                    EQU     000001000h
IMAGE_SCN_MEM_FARDATA                   EQU     000008000h
IMAGE_SCN_MEM_PURGEABLE                 EQU     000020000h
IMAGE_SCN_MEM_16BIT                     EQU     000020000h
IMAGE_SCN_MEM_LOCKED                    EQU     000040000h
IMAGE_SCN_MEM_PRELOAD                   EQU     000080000h
IMAGE_SCN_ALIGN_1BYTES                  EQU     000100000h
IMAGE_SCN_ALIGN_2BYTES                  EQU     000200000h
IMAGE_SCN_ALIGN_4BYTES                  EQU     000300000h
IMAGE_SCN_ALIGN_8BYTES                  EQU     000400000h
IMAGE_SCN_ALIGN_16BYTES                 EQU     000500000h
IMAGE_SCN_ALIGN_32BYTES                 EQU     000600000h
IMAGE_SCN_ALIGN_64BYTES                 EQU     000700000h
IMAGE_SCN_LNK_NRELOC_OVFL               EQU     001000000h
IMAGE_SCN_MEM_DISCARDABLE               EQU     002000000h
IMAGE_SCN_MEM_NOT_CACHED                EQU     004000000h
IMAGE_SCN_MEM_NOT_PAGED                 EQU     008000000h
IMAGE_SCN_MEM_SHARED                    EQU     010000000h
IMAGE_SCN_MEM_EXECUTE                   EQU     020000000h
IMAGE_SCN_MEM_READ                      EQU     040000000h
IMAGE_SCN_MEM_WRITE                     EQU     080000000h

;=============================================================================
.list
