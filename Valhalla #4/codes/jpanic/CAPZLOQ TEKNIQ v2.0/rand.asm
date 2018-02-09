;= 32-Bit LSFR PRNG (c) 2013 JPanic ======================================
;
; Provides Sub-Procedures to calculate a RAND32:
;
;	GetRAND32	- Return CRC32 of ECX bytes at *ESI in EAX.
;
;= Directive Warez ========================================================

	.486
	.model flat
	locals @@

	_RAND_ASM	EQU 	TRUE
	include vheap.ash
        include rand.ash

;= Code Warez =============================================================
        include codeseg.ash
;= GetRand32 ==============================================================
;
; Inputs: nil

; Outputs:
;	EAX = Rand.
;
;--------------------------------------------------------------------------
PUBLIC GetRand32
GetRand32 		PROC
			push	ecx
			push	32
			pop	ecx
			mov	eax,[vheap.dwRandSeed]
		@@loop:		test	eax,RAND_POLY
				jpe	@@nc
					stc
			@@nc:	rcr	eax,1
			loop	@@loop
			mov	[vheap.dwRandSeed],eax
			pop	ecx
			ret
GetRand32		ENDP		

;==========================================================================
                ENDS
		END
;==========================================================================
