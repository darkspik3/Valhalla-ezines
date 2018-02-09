;= 32-Bit LSFR RNG (c) 2013 JPanic ========================================

;- Procedure Definitions --------------------------------------------------
.model flat
.486

IFNDEF _RAND_ASM	
	extrn GetRand32:PROC
ENDIF

;- Polynomial -------------------------------------------------------------
RAND_POLY 	=	(1\
		OR	(1 SHL 1)\
		OR	(1 SHL 2)\
		OR	(1 SHL 4)\
		OR	(1 SHL 6)\
		OR	(1 SHL 31))

;= END FILE ===============================================================	
