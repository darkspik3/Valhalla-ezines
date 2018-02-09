.xlist
;-----------------------------------------------------------------------------

; e_ident
EI_NIDENT	EQU	16
EI_MAG0		EQU	0
EI_MAG1		EQU 	1
EI_MAG2		EQU	2
EI_MAG3		EQU	3
EI_CLASS	EQU	4
EI_DATA		EQU	5
EI_VERSION	EQU	6
EI_PAD		EQU	7

ELF_MAGIC = 464C457Fh

; Elf Types
ET_NONE		EQU	0
ET_REL		EQU	1
ET_EXEC		EQU	2
ET_DYN		EQU	3
ET_CORE		EQU	4
ET_LOPROC	EQU	0FF00h
ET_HIPROC	EQU	0FFFFh

; Elf Machines
EM_NONE		EQU	0
EM_M32		EQU	1
EM_SPARC	EQU	2
EM_386		EQU	3
EM_68K		EQU	4
EM_88K		EQU	5
EM_486		EQU	6
EM_860		EQU	7
EM_MIPS		EQU	8

; Elf Version
EV_NONE		EQU 	0
EV_CURRENT	EQU	1

Elf32_Ehdr	STRUC
		e_ident		db 	EI_NIDENT dup(?)
		e_type		dw	?
		e_machine	dw	?
		e_version	dd	?
		e_entry		dd	?
		e_phoff		dd	?
		e_shoff		dd	?
		e_flags		dd	?
		e_ehsize	dw	?
		e_phentsize	dw	?
		e_phnum		dw	?
		e_shentsize	dw	?
		e_shnum		dw	?
		e_shstrndx	dw	?		
Elf32_Ehdr	ENDS

;-----------------------------------------------------------------------------

; Section Types
SHT_NULL 	EQU	0
SHT_PROGBITS 	EQU	1
SHT_SYMTAB 	EQU	2
SHT_STRTAB 	EQU	3
SHT_RELA 	EQU	4
SHT_HASH 	EQU	5
SHT_DYNAMIC 	EQU	6
SHT_NOTE 	EQU	7
SHT_NOBITS 	EQU	8
SHT_REL 	EQU	9
SHT_SHLIB 	EQU	10
SHT_DYNSYM 	EQU	11
SHT_LOPROC 	EQU	0x70000000
SHT_HIPROC 	EQU	0x7fffffff
SHT_LOUSER 	EQU	0x80000000
SHT_HIUSER 	EQU	0xffffffff

; Section Attributes
SHF_WRITE 	EQU	1
SHF_ALLOC	EQU	2
SHF_EXECINSTR	EQU	4
SHF_MASKPROC	EQU	0F0000000h

; Reserved Section Header Indexes
SHN_UNDEF 	EQU	00
SHN_LORESERVE 	EQU 	0FF00h
SHN_HIRESERVE 	EQU	0FFFFh

Elf32_Shdr	STRUC
		sh_name		dd	?
		sh_type		dd	?
		sh_flags	dd	?
		sh_addr		dd	?
		sh_offset	dd	?
		sh_size		dd	?
		sh_link		dd	?
		sh_info		dd	?
		sh_addralign	dd	?
		sh_entsize	dd	?		
Elf32_Shdr	ENDS

;-----------------------------------------------------------------------------

; Segment Types
PT_NULL 	EQU	0
PT_LOAD 	EQU	1
PT_DYNAMIC 	EQU	2
PT_INTERP 	EQU	3
PT_NOTE 	EQU	4
PT_SHLIB 	EQU	5
PT_PHDR 	EQU	6
PT_LOPROC 	EQU	070000000h
PT_HIPROC 	EQU	07fffffffh

Elf32_Phdr	STRUC
		p_type		dd	?
		p_offset	dd	?
		p_vaddr		dd	?
		p_paddr		dd	?
		p_filesz	dd	?
		p_memsz		dd	?
		p_flags		dd	?
		p_align		dd	?		
Elf32_Phdr	ENDS

.list