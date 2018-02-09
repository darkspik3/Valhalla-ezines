pebImageBaseAddress             equ     8
pebLdr                          equ     0ch

ldrInLoadOrderModuleList        equ     0ch

mlDllBase                       equ     18h

N               equ     16
texSize         equ     2   ;sqrt(N/4.0), where N is power-of-2 array size
MODE_ATI        equ     0   ;set non-zero to enable

outpid          equ     0
codeid          equ     4
xlatid          equ     8

texta           equ     0
textb           equ     4

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

align           1                               ;byte-packed structures
krncrcstk       struct
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
        uRegisterClassA         dd      ?
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
        wglctxhnd                       dd      ? ;pushed from other location
        wglwndhnd                       dd      ? ;pushed from other location
wglcrcstk       ends

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
align
