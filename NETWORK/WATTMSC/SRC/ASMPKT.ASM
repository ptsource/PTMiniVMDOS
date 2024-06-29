;
; File: asmpkt.asm
;
; 16-Jun-92 lr
;
; C-to-assembly interface for the packet driver
;
; First, _pktasminit must be called to initialize the
; packet driver. Then, _pktentry is called back from the packet driver
; whenever it requires attention. _pktentry is currently an assembler
; routines that puts the new packet into a circular buffer, and marks
; the buffer as used. The C counterpart is in pcpkt.c
;
;  Usage :
;	    _pktentry
;           _pktasminit( void far * buffers, int maxbufs, int buflen, long far *lost_packets)
;
;  (c) 1991 University of Waterloo,
;           Faculty of Engineering,
;           Engineering Microcomputer Network Development Office
;
;  version
;
;    0.1    22-May-1991   E. P. Engelke
;    0.2    22-Mar-1992   Luigi Rizzo
;
; Each data buffer is preceded by 2 bytes, the first should be
; 0 when the buffer is empty, 1 otherwise.
;
; Buffers are handled as a circular queue.
;
        include masmdefs.hsm
        include model.hsm

codedef ASMPKT
datadef

cstart  ASMPKT

maxbufs	dw	0	; # of data buffer
maxlen	dw	0	; size of each buffer (there are 2 more bytes each)
bufs	dw	0	; offset/
bufseg	dw	0	; segment of buffer

bufptr	dw	0	; 19-dec-91 lr used to do round robin on buffer.
			; points to the next buffer to be used. If not free,
			; then no buffers are available.
bufcnt	dw	0	; free buffer index. easier to use as a limit.

lost_pkt_ofs	dw 0
lost_pkt_seg	dw 0

cproc	_pktentry
	pushf

;
; called with AL=0 to request a buffer, AL=1 when the buffer has been filled
;
	cli		; no interrupts now

	or	AL, AL
	jnz	encue	; branch if was a 1 and must enqueue packet now

	; otherwise it is a buffer request operation
	; to check our buffers we will need the same DS seg, set it now
	;
        push    CX
	push	DS
        mov     DI, CS:bufseg
        mov     DS, DI

	;
	; check the packet length
	;
	cmp	CX, CS:maxlen
	jg	no_fnd		; too big. Pretend none were found

	mov	DI, CS:bufptr	; current buffer
	mov	AL, 0ffh
	test    AL, DS:[DI]	; is it empty ?
	jnz	no_fnd		; no.
;
;	here it is found: simply update pointers.
;
	mov	SI, DI
	add	SI, CS:maxlen
	add	SI, 2		; SI points to the next avail. buffer
	mov	AX, CS:bufcnt
	add	AX, 1
	cmp	AX, CS:maxbufs
	jne	found_1		; wrap around after last buffer
	mov	AX,0
	mov	SI, CS:bufs
found_1:
	mov	CS:bufptr,SI	; save pointers
	mov	CS:bufcnt,AX
	jmp	short found
	
no_fnd:	; not found. Increase the lost pkt counter.
	mov	AX, CS:lost_pkt_seg
	mov	DS, AX
	mov	DI, CS:lost_pkt_ofs
	add	word ptr [DI],1
	adc	word ptr [DI+2],0
	xor	DI, DI		; for whatever error, throw away the buffer
	mov	DS, DI		; by returning 0000:0000
	sub	DI, 2

found:  push	DS
	pop	ES
	add	DI, 2
	pop	DS
	pop	CX
	popf
	retf

	; enqueue packet
	;
encue:	or	SI, SI
	jz	no_enqu		; not a valid pointer, cannot encue
	push	SI
	sub	SI, 2
	mov	AL, 1		; mark as busy
        mov     DS:[SI], AL;	byte ptr DS:SI, AL
	pop	SI
no_enqu:popf
	retf
cendp	_pktentry

cpublic _pktasminit		; bufptr, maxbufs, buflen
	mov	AX, +@AB + 0 [BP]	; bufptr
	mov	BX, +@AB + 2 [BP]	; bufptr segment
	mov	CX, +@AB + 4 [BP]	; maxbufs
	mov	DX, +@AB + 6 [BP]	; buflen
	mov	CS:bufs, AX
	mov	CS:bufseg, BX
	mov	CS:maxbufs, CX
	mov	CS:maxlen, DX
	mov	CS:bufptr, AX		; 19-dec-91 lr
	mov	CS:bufcnt, 0		; 19-dec-91 lr
	mov	AX, +@AB + 8 [BP]	; bufptr
	mov	BX, +@AB + 10 [BP]	; bufptr segment
	mov	CS:lost_pkt_ofs,AX
	mov	CS:lost_pkt_seg,BX
	
creturn _pktasminit
cend    ASMPKT
        end
