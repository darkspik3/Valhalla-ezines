;= Virus Host Stub (c) 2013 JPanic ========================================
;
; The host to which the virus returns. Must be linked last.
;
; PUBLICS:
;	VHost()
;
;= Directive Warez ========================================================
	
	.486	
	locals @@
	.model flat

_VHOST_ASM	EQU 	TRUE

include inc\short.inc
include vmain.ash

extrn MessageBoxA:PROC
extrn ExitProcess:PROC
	
;= Code Warez =============================================================
        include codeseg.ash
;= VHost ==================================================================
; Outputs:
;	None.
;
;--------------------------------------------------------------------------
PUBLIC VHost
VHost			PROC

			push	L 0
			push	ofs szCaption
			push	ofs szMsg
			push	L 0
			call	MessageBoxA
			push	L 0
			call	ExitProcess

VHost			ENDP

;--------------------------------------------------------------------------
        .data
szCaption:	db	VName," VIRUS DROPPER (c) 2013 JPanic",0
szMsg:		db	VName," VIRUS SUCCESFULLY EXECUTED!",0

;==========================================================================
                        ENDS
			END
;==========================================================================
