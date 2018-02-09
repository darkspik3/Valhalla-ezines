;= Process list of OS Specific functions (c) 2013 JPanic ==================
;
; Supported OS Functions:
;	Init, FindFirst, FindNext, FindClose, OpenFile, CloseFile
;
;- Declaration Warez ------------------------------------------------------
IFNDEF _OSPROCS_ASM
	extrn OS_Proc_Switch:BYTE
	extrn Fill_Proc_Table:PROC
ENDIF ;_OSPROCS_ASM

;- OS Procedure Processing Macro ------------------------------------------
OS_PROC_LIST	MACRO	_code		
		IRP	_procname,<Init,FindFirst,FindNext,FindClose,OpenFile,CloseFile,Exit,DirSetup,Chdir>
			IRP	_codeline, <_code>
				&_codeline&
			ENDM
			purge	_codeline
		ENDM
		purge	_procname
ENDM

;- Set OS Proc Count ------------------------------------------------------
OSProcCount	=	0
OS_PROC_LIST	<<OSProcCount = OSProcCount + 1>>

;- Set OS_Proc_Switch Selectors -------------------------------------------
OS_Proc_Use_Win32	=       0
OS_Proc_Use_Linux	=       (OSProcCount * 2)
OS_Proc_Use_OSX		=       OS_Proc_Use_Linux+(OSProcCount * 2)
;==========================================================================