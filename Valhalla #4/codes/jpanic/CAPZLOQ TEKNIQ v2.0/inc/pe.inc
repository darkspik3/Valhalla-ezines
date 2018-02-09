 .xlist
IMAGE_FILE_MACHINE_I386			EQU		014Ch

IMAGE_FILE_EXECUTABLE_IMAGE		EQU		0002h
IMAGE_FILE_32BIT_MACHINE		EQU		0100h
IMAGE_FILE_SYSTEM			EQU		1000h
IMAGE_FILE_DLL				EQU		2000h
IMAGE_FILE_UP_SYSTEM_ONLY		EQU		4000h

;-----------------------------------------------------------------------------
PE_DirEntry     STRUC
		pedir_VA                dd      ?
		pedir_Size              dd      ?
PE_DirEntry     ENDS

;-----------------------------------------------------------------------------
PE_Hdr          STRUC
		; PE File Header.
		peh_Marker              dd      ?
		peh_Machine             dw      ?
		peh_SectionCount        dw      ?
		peh_TimeDateStamp       dd      ?
		peh_SymbTable_Ptr       dd      ?
		peh_SymbTable_Count     dd      ?
		peh_NTHdrSize           dw      ?
		peh_Flags               dw      ?
		; NT Optional Header.
		; Standard Fields.
		peh_Magic               dw      ?
		peh_LinkMajor           db      ?
		peh_LinkMinor           db      ?
		peh_CodeSize            dd      ?
		peh_DataSize            dd      ?
		peh_BSSSize             dd      ?
		peh_EntryPointRVA       dd      ?
		peh_CodeBase            dd      ?
		peh_DataBase            dd      ?
		; NT Additional Fields.
		peh_ImageBase           dd      ?
		peh_SectionAlign        dd      ?
		peh_FileAlign           dd      ?
		peh_OSMajor             dw      ?
		peh_OSMinor             dw      ?
		peh_UserMajor           dw      ?
		peh_UserMinor           dw      ?
		peh_SubSysMajor         dw      ?
		peh_SubSysMinor         dw      ?
		peh_Win32_Version       dd      ?
		peh_ImageSize           dd      ?
		peh_HeaderSize          dd      ?
		peh_FileChecksum        dd      ?
		peh_SubSystem           dw      ?
		peh_DLLFlags            dw      ?
		peh_StackReserveSize    dd      ?
		peh_StackCommitSize     dd      ?
		peh_HeapReserveSize     dd      ?
		peh_HeapCommitSize      dd      ?
		peh_LoaderFlags         dd      ?
		peh_RVATableCount       dd      ?
		;Data Directory
		peh_ExportDirectory	PE_DirEntry<>
		peh_ImportDirectory	PE_DirEntry<>
		peh_ResourceDirectory	PE_DirEntry<>
		peh_ExceptionDirectoy	PE_DirEntry<>
		peh_SecurityDirectory	PE_DirEntry<>
		peh_BaseRelocDirectory	PE_DirEntry<>
		peh_DebugDirectoy	PE_DirEntry<>
		peh_CopyrightDirectory	PE_DirEntry<>
		peh_MIPSGP_Directory	PE_DirEntry<>
		peh_TLSDirectory	PE_DirEntry<>
		peh_LoadConfigDirectory	PE_DirEntry<>
PE_Hdr          ENDS

;-----------------------------------------------------------------------------
PE_Export       STRUC
		peexp_Flags             dd      ?	; 00
		peexp_TimeDateStamp     dd      ?	; 04	
		peexp_MajorVersion      dw      ?	; 08
		peexp_MinorVersion      dw      ?	; 0A
		peexp_ModuleNamePtr     dd      ?	; 0C
		peexp_OrdinalBase       dd      ?	; 10
		peexp_ProcCount         dd      ?	; 14
		peexp_NameCount         dd      ?	; 18
		peexp_ProcListPtr       dd      ?	; 1C
		peexp_NameListPtr       dd      ?	; 20
		peexp_OrdinalListPtr    dd      ?	; 28
PE_Export       ENDS

;-----------------------------------------------------------------------------
PE_Import       STRUC
		peimp_ProcNameListRVA   dd      ?
		peimp_Reserved0         dd      ?
		peimp_Reserved1         dd      ?
		peimp_ModuleNameRVA     dd      ?
		peimp_ProcAddrListRVA   dd      ?
PE_Import       ENDS

;-----------------------------------------------------------------------------
IMAGE_SIZEOF_SHORT_NAME = 8

PE_Sec          STRUC
		pesec_Name              db      IMAGE_SIZEOF_SHORT_NAME dup(?)
		UNION
			pesec_PhysicalAddress   dd      ?
			pesec_VirtualSize       dd      ?
		ENDS
		pesec_VirtualAddress    dd      ?
		pesec_RawDataSize       dd      ?
		pesec_RawDataPtr        dd      ?
		pesec_RelocationsPtr    dd      ?
		pesec_LineNumbersPtr    dd      ?
		pesec_nRelocations      dw      ?
		pesec_nLineNumbers      dw      ?
		pesec_Flags             dd      ?
PE_Sec          ENDS
.list