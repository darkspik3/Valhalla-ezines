;= String Hash32 Sub-Procedures (c) 2013 JPanic ============================
;
; Provides Small 32-Bit String Hash.
;
; Provides Sub-Procedure to calculate a 32-bit String Hash:
;
;	StringHash32	- Return Hash of ASCIIZ String in EAX.
;
;= Directive Warez ========================================================

	.486
	.model flat
	locals @@

	_STRHASH32_ASM	EQU 	TRUE
        include strhash32.ash

;= Code Warez =============================================================
        include codeseg.ash
;=  StrHash32 =============================================================
;
; Inputs:
;	ESI = Offset of asciiz string to hash.
;
; Outputs:
;	EAX = 32-bit hash of input.
;
;--------------------------------------------------------------------------
PUBLIC StringHash32
StringHash32 	PROC	NEAR
		push edx
		xor	eax,eax
		cdq
        @@l:	        
                lodsb
		or	al,al
		jz	@@exit
			imul	edx,edx,STRHASH_MUL
			add		edx,eax
		jmp	@@l
        @@exit: xchg eax,edx
		pop edx
		ret
StringHash32 	ENDP
;==========================================================================
ENDS
END
;==========================================================================
