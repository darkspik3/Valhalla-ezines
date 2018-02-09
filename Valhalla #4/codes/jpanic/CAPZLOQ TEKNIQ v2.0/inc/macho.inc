.xlist
;-----------------------------------------------------------------------------
mach_MH_MAGIC				EQU	0FEEDFACEh
mach_CPU_TYPE_I386			EQU	7
mach_MH_EXECUTE	        		EQU	2
mach_LC_SEGMENT				EQU	1
mach_LC_UNIXTHREAD			EQU	5
mach_i386_NEW_THREAD_STATE	        EQU	1

FAT_CIGAM				EQU	0BEBAFECAh

;-----------------------------------------------------------------------------
mach_header		STRUC
		mach_magic		dd		?
		mach_cputype		dd		?
		mach_cpusubtype		dd		?
		mach_filetype		dd		?
		mach_ncmds		dd		?
		mach_sizeofcmds		dd		?
		mach_flags		dd		?
mach_header		ENDS

;-----------------------------------------------------------------------------
mach_load_command	STRUC
		mach_ldcmd_cmd		dd		?
		mach_ldcmd_cmdsize	dd		?
mach_load_command	ENDS

;-----------------------------------------------------------------------------
mach_segment_command	STRUC
		mach_segcmd_segname	db		16 dup(?)
		mach_segcmd_vmaddr	dd		?
		mach_segcmd_vmsize	dd		?
		mach_segcmd_fileoff	dd		?
		mach_segcmd_filesize	dd		?
		mach_segcmd_maxprot	dd		?
		mach_segcmd_initprot	dd		?
mach_segment_command	ENDS

;-----------------------------------------------------------------------------
mach_section_command	STRUC
		mach_sectcmd_sectname	db		16 dup(?)
		mach_sectcmd_segname	db		16 dup(?)
		mach_sectcmd_addr	dd		?
		mach_sectcmd_size	dd		?
		mach_sectcmd_offset	dd		?
		mach_sectcmd_align	dd		?
		mach_sectcmd_reloff	dd		?
		mach_sectcmd_nreloc	dd		?
		mach_sectcmd_flags	dd		?
		mach_sectcmd_reserved1	dd		?
		mach_sectcmd_reserved2	dd		?
mach_section_command	ENDS

;-----------------------------------------------------------------------------
mach_thread_command		STRUC
		mach_threadcmd_flavor	dd		?
		mach_threadcmd_count	dd		?
mach_thread_command		ENDS

;------------------------------------------------------------------------------
mach_i386_thread_state_t	STRUC
		mach_1386_eax		dd		?
		mach_1386_ebx		dd		?
		mach_1386_ecx		dd		?
		mach_1386_edx		dd		?
		mach_1386_edi		dd		?
		mach_1386_esi		dd		?
		mach_1386_ebp		dd		?
		mach_1386_esp		dd		?
		mach_i386_ss		dd		?
		mach_i386_eflags	dd		?
		mach_i386_eip		dd		?
		mach_i386_cs		dd		?		
		mach_i386_ds		dd		?
		mach_i386_es		dd		?
		mach_i386_fs		dd		?
		mach_i386_gs		dd		?		
mach_i386_thread_state_t	ENDS
;-----------------------------------------------------------------------------
fat_header			STRUC
		fathdr_magic		dd		?
		fathdr_nfat_arch	dd		?
fat_header			ENDS

;-----------------------------------------------------------------------------
fat_arch			STRUC
		fat_cputype		dd		?	; 7
		fat_cpusubtype		dd		?
		fat_offset		dd		?
		fat_size		dd		?
		fat_align		dd		?	; 12
fat_arch			ENDS
;-----------------------------------------------------------------------------
.list