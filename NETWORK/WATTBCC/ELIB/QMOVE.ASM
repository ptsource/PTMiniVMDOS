PAGE    66,132
;
;
;
;
;
;
;
;
;  qmove.asm
;
;  Efficient move operation.  Does not handle segment wraps!!!!
;
;
;  Usage :
;	    move( soff, sseg, doff, dseg, count )
;	    unsigned int soff;		/* source offset */
;	    unsigned int sseg;		/* source segment */
;	    unsigned int doff;		/* destination offset */
;	    unsigned int dseg;		/* destination segment */
;	    unsigned int count;		/* byte count */
;
;  (c) 1984 University of Waterloo,
;           Faculty of Engineering,
;           Engineering Microcomputer Network Development Office
;
;  version
;
;    0.2    31-Oct-1990   E. P. Engelke  - brief version
;    0.1    8-June-1984   B. T. Campbell - handle segment wraps
;    0.0    01-May-1984   B. T. Campbell 
;
;
	include masmdefs.hsm
	include	model.hsm

codedef QMOVE
datadef

cstart  QMOVE
cpublic qmove
	mov	DX,DS
	mov	BX,ES			;save segment registers
        lds     SI, +@AB+0[BP]
        les     DI, +@AB+4[BP]
        mov     CX, +@AB+8[BP]          ;byte count

        shr     CX, 1
        cld

        rep     movsw
        jnc     @1
        movsb
@1:
	mov	DS,DX
	mov	ES,BX
creturn qmove

cend    QMOVE

        end

