;   Encryption/Decryption routines - nothing special here :P
;   some basic xor crap. 

vm_enc:
;   esi = ptr to instruction length counter
;   edi = ptr to buffer to be encrypted


;   Generate encryption keys
    pusha
    rdtsc
    mov     ebx, eax
    mov     ecx, eax
    and     ecx, 00ffffffh
@vm_enc_key:
    nop
    loop    @vm_enc_key
    rdtsc   
    xor     eax, ebx                                    ; Contains key
    xor     eax, 0ffffffffh                             ; No byte can be zero
    ;mov     eax, 0                                     ; This will override the key to be 0, so no encryption
    mov     vm_key, eax

;   Main encryption loop
    mov     ebx, eax
    xor     ecx, ecx
    cld
    lodsb                                               ; Load instruction length
    mov     cl, al                                      ; Loop counter
@vm_enc:

;   Check if the key has been fully shifted
    test    ebx, ebx
    jne     vm_enc_key_ok
    mov     ebx, vm_key                                 ; Restore key
vm_enc_key_ok:
    xchg    esi, edi
    lodsb                                               ; Load byte to be encrypted
    xor     al, bl                                      ; Xor
    xchg    esi, edi
    dec     edi
    stosb                                               ; Store encrypted byte
    shr     ebx, 8                                      ; Shift to next byte
    loop    @vm_enc

    mov     ebx, vm_key
    lodsb                                               ; Load instruction length
    mov     cl, al                                      ; Loop counter
    cmp     al, 0efh                                    ; Have we reached the end?
    jne     @vm_enc                                     ; Encrypt next instruction

vm_exit:
    popa
    ret

;   Per instruction decryption routine
; vm_dec


    nop
    nop
    nop
    popa
    ret






