;=============================================================================
.xlist
;-----------------------------------------------------------------------------
dwo             equ     dword ptr
qwo             equ     qword ptr
wo              equ     word ptr
by              equ     byte ptr
ofs             equ     offset
L               equ     <large>
S               equ     <small>
W?              equ     1111h

;-----------------------------------------------------------------------------
stQWORD         STRUC
		dwLO    dd      ?
		dwHI    dd      ?
stQWORD         ENDS

stDWORD         STRUC
		wLO     dw      ?
		wHI     dw      ?
stDWORD         ENDS

stWORD          STRUC
		bLO     db      ?
		bHI     db      ?
stWORD          ENDS

;-----------------------------------------------------------------------------
PLABEL          MACRO   name
		&name   LABEL
		PUBLIC  &name
		ENDM

;-----------------------------------------------------------------------------
.list
;=============================================================================

