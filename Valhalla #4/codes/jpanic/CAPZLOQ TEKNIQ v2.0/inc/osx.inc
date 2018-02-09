.xlist

osx$MAXNAMLEN 			EQU	255

osx$DT_REG			EQU	8

osx$O_RDONLY 			EQU	0
osx$O_WRONLY 			EQU	1
osx$O_RDWR			EQU	2

osx$O_EXLOCK			EQU	20h

osx$SEEK_BEGIN                  EQU     0
osx$SEEK_CURRENT                EQU     1
osx$SEEK_END                    EQU     2

osx$S_IFMT			EQU	0F000h
osx$S_IFREG 			EQU	08000h

osx$S_IRUSR 			EQU	100h
osx$S_IWUSR 			EQU	80h

osx$UF_NODUMP 			EQU	00001h
osx$UF_IMMUTABLE		EQU	00002h
osx$UF_APPEND			EQU	00004h
osx$UF_OPAQUE			EQU	00008h
osx$UF_HIDDEN			EQU	08000h
osx$SF_IMMUTABLE		EQU	20000h
osx$SF_APPEND			EQU	40000h

osx$BAD_STFLAGS			=	(osx$UF_IMMUTABLE	OR\
					osx$UF_APPEND		OR\
					osx$UF_OPAQUE		OR\
					osx$UF_HIDDEN		OR\
					osx$SF_IMMUTABLE	OR\
					osx$SF_APPEND)
					
osx$PROT_READ 			EQU	1h
osx$PROT_WRITE			EQU	2h

osx$MAP_FILE			EQU	0h
osx$MAP_ANON			EQU	1000h
osx$MAP_SHARED			EQU	1h
osx$MAP_PRIVATE			EQU	2h

;==========================================================================
osx$dirent			STRUC
	osx$d_fileno		dd	?
	osx$d_reclen		dw 	?
	osx$d_type		db	?
	osx$d_namelen		db	?
	osx$d_name		db osx$MAXNAMLEN+1 dup(?)	
osx$dirent			ENDS

;--------------------------------------------------------------------------
osx$stat                        STRUC

        osx$st_dev              dd      ?       ; 0
        osx$st_mode             dw      ?       ; 4
        osx$st_nlink            dw      ?       ; 6
        osx$st_ino              dq      ?       ; 8
        osx$st_uid              dd      ?       ; 16
        osx$st_gid              dd      ?       ; 20
        osx$st_rdev             dd      ?       ; 24
        osx$st_atimespec        dq      ?       ; 28
        osx$st_mtimespec        dq      ?       ; 36
        osx$st_ctimespec        dq      ?       ; 44
        osx$st_birthtimespec    dq      ?       ; 52
        osx$st_size             dq      ?       ; 60
        osx$st_blocks           dq      ?       ; 68
        osx$st_blksize          dd      ?       ; 76
        osx$st_flags            dd      ?       ; 80
        osx$st_gen              dd      ?       ; 84
        osx$st_lspare           dd      ?       ; 88
        osx$st_qspare           dq 2 dup (?)    ; 92
                                                ; size = 108
osx$stat                        ENDS
;==========================================================================
.list