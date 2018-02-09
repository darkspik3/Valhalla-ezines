;= Macho Infection Routine Definitions (c) 2013 JPanic ====================
;
; Provides routines for infection of Macho executables.
;
; Defined:
;	InfectFAT()
;	InfectMACHO()
;
;- Procedure Definitions --------------------------------------------------

.model flat
.486

extrn InfectFAT:PROC
extrn InfectMACHO:PROC

;= END FILE ===============================================================	