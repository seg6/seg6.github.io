VIDEO = $fd
TICK  = $10
T1    = $11
T2    = $12
T3    = $13
ROW   = $14
ROWV  = $15
DIAG  = $16
PTR   = $17
COL   = $0200

.org $8000
reset:
    cld
    ldx #$ff
    txs
    lda #$01
    sta VIDEO
    lda #$00
    sta T1
    sta T2
    sta T3

frame:
    lda TICK
wait:
    cmp TICK
    beq wait

    lda T1
    clc
    adc #$03
    sta T1
    dec T2
    dec T2
    inc T3

    ldx #$3f
columns:
    txa
    asl
    asl
    clc
    adc T1
    tay
    lda sine,y
    sta COL,x
    txa
    asl
    clc
    adc T3
    tay
    lda sine,y
    clc
    adc COL,x
    sta COL,x
    dex
    bpl columns

    lda #$00
    sta PTR
    sta ROW
    lda #$10
    sta PTR+1
row:
    lda ROW
    asl
    clc
    adc ROW
    adc T2
    tay
    lda sine,y
    sta ROWV
    lda ROW
    asl
    asl
    clc
    adc T3
    sta DIAG

    ldy #$3f
pixel:
    ldx DIAG
    lda sine,x
    clc
    adc COL,y
    adc ROWV
    lsr
    lsr
    tax
    lda ramp,x
    sta (PTR),y
    lda DIAG
    sec
    sbc #$05
    sta DIAG
    dey
    bpl pixel

    lda PTR
    clc
    adc #$40
    sta PTR
    bcc same_page
    inc PTR+1
same_page:
    inc ROW
    lda ROW
    cmp #$40
    bne row
    jmp frame

vblank:
    inc TICK
    rti

sine:
    .byte $20, $20, $21, $22, $23, $23, $24, $25, $26, $26, $27, $28, $29, $29, $2a, $2b
    .byte $2c, $2c, $2d, $2e, $2e, $2f, $30, $30, $31, $32, $32, $33, $33, $34, $35, $35
    .byte $36, $36, $37, $37, $38, $38, $39, $39, $3a, $3a, $3b, $3b, $3b, $3c, $3c, $3c
    .byte $3d, $3d, $3d, $3d, $3e, $3e, $3e, $3e, $3e, $3f, $3f, $3f, $3f, $3f, $3f, $3f
    .byte $3f, $3f, $3f, $3f, $3f, $3f, $3f, $3f, $3e, $3e, $3e, $3e, $3e, $3d, $3d, $3d
    .byte $3d, $3c, $3c, $3c, $3b, $3b, $3b, $3a, $3a, $39, $39, $38, $38, $37, $37, $36
    .byte $36, $35, $35, $34, $33, $33, $32, $32, $31, $30, $30, $2f, $2e, $2e, $2d, $2c
    .byte $2c, $2b, $2a, $29, $29, $28, $27, $26, $26, $25, $24, $23, $23, $22, $21, $20
    .byte $20, $1f, $1e, $1d, $1c, $1c, $1b, $1a, $19, $19, $18, $17, $16, $16, $15, $14
    .byte $13, $13, $12, $11, $11, $10, $0f, $0f, $0e, $0d, $0d, $0c, $0c, $0b, $0a, $0a
    .byte $09, $09, $08, $08, $07, $07, $06, $06, $05, $05, $04, $04, $04, $03, $03, $03
    .byte $02, $02, $02, $02, $01, $01, $01, $01, $01, $00, $00, $00, $00, $00, $00, $00
    .byte $00, $00, $00, $00, $00, $00, $00, $00, $01, $01, $01, $01, $01, $02, $02, $02
    .byte $02, $03, $03, $03, $04, $04, $04, $05, $05, $06, $06, $07, $07, $08, $08, $09
    .byte $09, $0a, $0a, $0b, $0c, $0c, $0d, $0d, $0e, $0f, $0f, $10, $11, $11, $12, $13
    .byte $13, $14, $15, $16, $16, $17, $18, $19, $19, $1a, $1b, $1c, $1c, $1d, $1e, $1f

ramp:
    .byte $00, $00, $00, $06, $06, $06, $0d, $0d, $0d, $03, $03, $03, $01, $01, $01, $07
    .byte $07, $07, $0c, $0c, $0c, $05, $05, $05, $0a, $0a, $0a, $00, $00, $00, $08, $08
    .byte $02, $02, $02, $09, $09, $09, $04, $04, $04, $06, $06, $06, $0d, $0d, $0d, $03
    .byte $03, $03, $01, $01, $01, $07, $07, $07, $09, $09, $09, $02, $02, $02, $04, $04

.org $fffa
    .word vblank
    .word reset
    .word vblank
