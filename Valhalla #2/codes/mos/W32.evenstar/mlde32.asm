;*******************************************
;* (X) uNdErX 2003 - underx@antisocial.com *
;*******************************************
;* Micro Length-Disassembler Engine 32     *
;*                                         *
;* release v1.0             05/01/2003     *
;*                                         *
;*******************************************

       ;p386
       ;locals @@

       ;****************
       ;* Opcode types *
       ;****************
       O_UNIQUE      equ     0
       O_PREFIX      equ     1
       O_IMM8        equ     2
       O_IMM16       equ     3
       O_IMM24       equ     4
       O_IMM32       equ     5
       O_IMM48       equ     6
       O_MODRM       equ     7
       O_MODRM8      equ     8
       O_MODRM32     equ     9
       O_EXTENDED    equ    10
       O_WEIRD       equ    11
       O_ERROR       equ    12

       .code

       public C mlde32
       ; int __cdecl mlde32(void *codeptr);
mlde32:
       pushad

       cld
       xor  edx, edx

       mov  esi, [esp+(8*4)+4]
       mov  ebp, esp

       ; 256 bytes, index-compressed opcode type table
       push 01097F71Ch
       push 0F71C6780h
       push 017389718h
       push 0101CB718h
       push 017302C17h
       push 018173017h
       push 0F715F547h
       push 04C103748h
       push 0272CE7F7h
       push 0F7AC6087h
       push 01C121C52h
       push 07C10871Ch
       push 0201C701Ch
       push 04767602Bh
       push 020211011h
       push 040121625h
       push 082872022h
       push 047201220h
       push 013101419h
       push 018271013h
       push 028858260h
       push 015124045h       
       push 05016A0C7h
       push 028191812h
       push 0F2401812h
       push 019154127h
       push 050F0F011h
       mov  ecx, 015124710h
       push ecx
       push 011151247h
       push 010111512h
       push 047101115h
       mov  eax, 012472015h
       push eax
       push eax
       push 012471A10h
       add  cl, 10h
       push ecx
       sub  cl, 20h
       push ecx

       xor  ecx, ecx
       dec  ecx

       ; code starts
@@ps:  inc  ecx
       mov  edi, esp
@@go:  lodsb
       mov  bh, al
@@ft:  mov  ah, [edi]
       inc  edi
       shr  ah, 4
       sub  al, ah
       jnc  @@ft

       mov  al, [edi-1]
       and  al, 0Fh

       cmp  al, O_ERROR
       jnz  @@i7
       
       pop  edx
       not  edx

@@i7:  inc  edx
       cmp  al, O_UNIQUE
       jz   @@t_exit

       cmp  al, O_PREFIX
       jz   @@ps

       add  edi, 51h          ;(@@_ettbl - @@_ttbl)

       cmp  al, O_EXTENDED
       jz   @@go

       mov  edi, [ebp+(8*4)+4]

@@i6:  inc  edx
       cmp  al, O_IMM8
       jz   @@t_exit
       cmp  al, O_MODRM
       jz   @@t_modrm
       cmp  al, O_WEIRD
       jz   @@t_weird

@@i5:  inc  edx
       cmp  al, O_IMM16
       jz   @@t_exit
       cmp  al, O_MODRM8
       jz   @@t_modrm

@@i4:  inc  edx
       cmp  al, O_IMM24
       jz   @@t_exit

@@i3:  inc  edx
@@i2:  inc  edx

       pushad
       mov  al, 66h
       repnz scasb
       popad
       jnz  @@c32

@@d2:  dec  edx
       dec  edx

@@c32: cmp  al, O_MODRM32
       jz   @@t_modrm
       sub  al, O_IMM32
       jz   @@t_imm32

@@i1:  inc  edx

@@t_exit:
       mov  esp, ebp
       mov  [esp+(7*4)], edx
       popad
       ret

;*********************************
;* PROCESS THE MOD/RM BYTE       *
;*                               *
;*   7    6 5          3 2    0  *
;*   | MOD | Reg/Opcode | R/M |  *
;*                               *
;*********************************
@@t_modrm:
       lodsb
       mov  ah, al
       shr  al, 7
       jb   @@prmk
       jz   @@prm

       add  dl, 4

       pushad
       mov  al, 67h
       repnz scasb
       popad
       jnz  @@prm

@@d3:  sub  dl, 3

       dec  al
@@prmk:jnz  @@t_exit
       inc  edx
       inc  eax
@@prm:
       and  ah, 00000111b

       pushad
       mov  al, 67h
       repnz scasb
       popad
       jz   @@prm67chk

       cmp  ah, 04h
       jz   @@prmsib

       cmp  ah, 05h
       jnz  @@t_exit

@@prm5chk:
       dec  al
       jz   @@t_exit
@@i42: add  dl, 4
       jmp  @@t_exit

@@prm67chk:
       cmp  ax, 0600h
       jnz  @@t_exit
       inc  edx
       jmp  @@i1

@@prmsib:
       cmp  al, 00h
       jnz  @@i1
       lodsb
       and  al, 00000111b
       sub  al, 05h
       jnz  @@i1
       inc  edx
       jmp  @@i42

;****************************
;* PROCESS WEIRD OPCODES    *
;*                          *
;* Fucking test (F6h/F7h)   *
;*                          *
;****************************
@@t_weird:
       test byte ptr [esi], 00111000b
       jnz  @@t_modrm

       mov  al, O_MODRM8

       shr  bh, 1
       adc  al, 0
       jmp  @@i5

;*********************************
;* PROCESS SOME OTHER SHIT       *
;*                               *
;* Fucking mov (A0h/A1h/A2h/A3h) *
;*                               *
;*********************************
@@t_imm32:
       sub  bh, 0A0h

       cmp  bh, 04h
       jae  @@d2

       pushad
       mov  al, 67h
       repnz scasb
       popad
       jnz  @@chk66t

@@d4:  dec  edx
       dec  edx

@@chk66t:
       pushad
       mov  al, 66h
       repnz scasb
       popad
       jz   @@i1
       jnz  @@d2

