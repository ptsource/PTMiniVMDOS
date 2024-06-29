; File: intel.asm
;
; 16-Jun-92 lr
;
PAGE    66,132
;
;
;  intel - convert intel <--> bigendian
;
;
;  (c) 1990 University of Waterloo,
;           Faculty of Engineering,
;           Engineering Microcomputer Network Development Office
;
;
;
	include masmdefs.hsm
	include model.hsm

codedef intel
datadef

cstart  intel

;*************************************************************************
;  USAGE:  ULONG intel( ULONG val )
;          - convert to intel format
;*************************************************************************
cpublic intel
;clabel  ntohl
;clabel  htonl
	mov     AX, +@AB + 2 [BP]
	mov     DX, +@AB + 0 [BP]
	xchg    AL, AH
	xchg    DL, DH
creturn intel
;*************************************************************************
;  USAGE:  UINT intel16( UINT val )
;          - convert to intel format
;*************************************************************************
cpublic intel16
;clabel  ntohs
;clabel  htons
	mov     AX, +@AB [BP]
	xchg    AL, AH
creturn intel16
cend    intel
	end
; end of file intel.asm
