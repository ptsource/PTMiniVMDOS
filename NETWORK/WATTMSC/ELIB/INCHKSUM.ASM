; File: inchksum.asm
;
; 16-Jun-92 lr
;
;  Usage :
;	 unsigned inchksum( unsigned far *buf, unsigned cnt)
;
;  Internet compatible 1's complement checksum
;
;  (c) 1990 University of Waterloo,
;           Faculty of Engineering,
;           Engineering Microcomputer Network Development Office
;
;  version
;
;    0.1    17 Dec -1990   E. P. Engelke
;  modified 
;
;    10 Feb - 1992  G. Mercaldo
;
        include masmdefs.hsm
        include model.hsm

codedef INCHKSUM
datadef

cstart  INCHKSUM
cpublic inchksum
        ; Compute 1's-complement sum of data buffer
        ;
        ; unsigned lcsum( unsigned far *buf, unsigned cnt)
	push	DS
        lds     SI, +@AB + 0 [BP]
	mov     CX, +@AB + 4 [BP]       ; cx = cnt in bytes

        mov     BL, CL

	shr     CX, 1			; group into words
	xor	DX, DX			; set checksum to 0
	
	shr	CX, 1			; 10-feb-92 gm to use prefetch
	jnc	deloop			; decrease number of cycles
        cld				; increasing number of statements
        clc				; inside the cycle
	lodsw
	adc	DX, AX
	
deloop:
	jc	deloop1
        cld
        clc
deloop1:lodsw
	adc	DX, AX
	lodsw
	adc	DX, AX
	loop	deloop1

        adc     DX, 0                   ; only two necessary
        adc     DX, 0

remain: and     BL, 1
        jz      done
;
        xor     AH, AH
        lodsb
        add     DX, AX
        adc     DX, 0
        adc     DX, 0

done:   mov	AX,DX		; result into ax
        or      AX,AX
ok:     pop     DS
creturn inchksum
cend    INCHKSUM
        end
; end of file inchksum.asm
