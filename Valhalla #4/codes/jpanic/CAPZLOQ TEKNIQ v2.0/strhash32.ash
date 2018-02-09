;= String Hash32 Sub-Procedures (c) 2013 JPanic ============================
;
; Provides Small 32-Bit String Hash.;
;
; Note: Tasm doesnt support '!' in ascii strings.
;
; Provides macro to emulate String Hash instructions:
;
; strhash32_laz		- set 'strhash32' to hash of asciiz string.
;
; Examples:
;	strhash32_laz	CreateFileA
;	dd	strhash32
;
;- Procedure Definitions --------------------------------------------------
.model flat
.486

IFNDEF	_STRHASH32_ASM
	extrn StringHash32:PROC
ENDIF	;_STRHASH32_ASM

;- String Hash -------------------------------------------------------------

strhash32 = 0

STRHASH_MUL	EQU	37

;= String Hash INSTRUCTIONS ===============================================

;- lcrcaz -----------------------------------------------------------------
	strhash32_laz MACRO data
		LOCAL u,l,c
		.xlist
		strhash32 = 0
		IRPC x, <data>
			u = (strhash32 SHR 16) AND 0FFFFh
			l = (strhash32 and 0FFFFh)
			l = l * STRHASH_MUL
			u = u * STRHASH_MUL			
			l = l + ('&x&' AND 0FFh)
			c = (l SHR 16)
			u = (u + c)
			u = u SHL 16
			u = u AND 0FFFF0000h
			l = l AND 0FFFFh
			strhash32 = u OR l			
		ENDM
		.list		
	ENDM

;= END FILE ===============================================================	