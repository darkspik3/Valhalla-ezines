;= Process list of Win32 Imported Kernel32 functions (c) 2013 JPanic ======
;
; Imported Functions:
;	FindFirstFileW, FindNextFileW, FindClose, CreateFileW,
;	SetFilePointer, CloseHandle, CreateFileMappingW, MapViewOfFile
;	UnmapViewOfFile, SetEndOfFile, SetFileTime, SetFileAttributesW.
;	GlobalAlloc, GlobalFree, LoadLibraryA, GetProcAddress, GetFullPathNameW,
;	GetCurrentDirectoryW,GetWindowsDirectoryW,GetSystemDirectoryW,SetCurrentDirectoryW.
;
;- Import List Processing Macro -------------------------------------------
W32_IMP_LIST	MACRO	_code
		IRP     _impname,<FindFirstFileW,FindNextFileW,FindClose,CreateFileW,SetFilePointer,CloseHandle,CreateFileMappingW,MapViewOfFile,UnmapViewOfFile,SetEndOfFile,SetFileTime,SetFileAttributesW,GlobalAlloc,GlobalFree,LoadLibraryA,GetProcAddress,GetFullPathNameW,GetCurrentDirectoryW,GetWindowsDirectoryW,GetSystemDirectoryW,SetCurrentDirectoryW>
			IRP	_codeline, <_code>
				&_codeline&
			ENDM
			purge	_codeline
		ENDM
		purge	_impname
ENDM

;- Set Imported Proc Count ------------------------------------------------
K32ProcCount	=	0
W32_IMP_LIST	<<K32ProcCount = K32ProcCount + 1>>

;==========================================================================