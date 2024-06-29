/***
 *
 * File: pcpkt.c - packet driver interface for wattcp
 *
 * 27-Aug-93 fr	final cleanup
 * 21-Sep-92 lr	cleanup
 * 18-Jun-92 lr
 *
 * modified by Luigi Rizzo for use with Microsoft C 6.0
 * Dec. 1991
 *
 * The packet driver invokes a routine in asmpkt.asm to load
 * new packet into a circular buffer. pkt_received() returns
 * a non-null pointer if a new packet is arrived.
 *
 */

#define WATTCP_KERNEL
#define PCPKT
#include <tcp.h>

#ifdef debug
	void stampa_regs(char *s,struct REGPACK *r);
	void print_pkt(byte *p);
#else /* !debug */
#define stampa_regs(x,y)
#endif /* !debug */


#define INT_FIRST	0x60
#define INT_LAST	0x80
#define PKT_LINE	"PKT DRVR"
#define PD_DRIVER_INFO	0x1ff
#define PD_ACCESS 	0x200
#define PD_RELEASE	0x300
#define PD_SEND		0x400
#define PD_GET_ADDRESS	0x600
#define CARRY 		1	     /* carry bit in flags register */

#ifdef COMMENT

The structure of a buffer is as follows:
 
struct _pktbuf {
	short busy;	/* 1 if busy, 0 if free */
	char et_header[14];
	char data[...];
} _pktbuf[MAXBUFS];

#endif /* COMMENT */
 
int
farcmp(char far *f, char *d, int len)
{
	while (len--)
		if (*f++ != *d++) {
			return(1);
		}
	return(0);
}

int
pkt_init(void)
{
    struct REGPACK regs, regs2;
    char far *temp;
    int pd_type;	/* packet driver type */
    int class;

    _pktasminit( (char far *)pktbuf, MAXBUFS, BUFSIZE, &lost_packets);
    for (pkt_interrupt=INT_FIRST;pkt_interrupt<=INT_LAST;++pkt_interrupt ) {
	getvect( pkt_interrupt );
	temp = (char far *)(interrupts[ pkt_interrupt ] +3);
	
	if ( !farcmp( temp, PKT_LINE, strlen( PKT_LINE ))) {
	    break; /* found */
	}
    }
    if ( pkt_interrupt > INT_LAST ) {
	outs("NO PACKET DRIVER FOUND");
	return( 1 );
    }
    DB3((stderr,"packet driver found at interrupt 0x%2x\n",pkt_interrupt));
    /* lets find out about the driver */
    segread(&(regs.s));
    regs.r_ax = PD_DRIVER_INFO;
    stampa_regs("before driver_info",&regs); 
    intr( pkt_interrupt, &regs );
    stampa_regs("after driver_info",&regs); 

    /* handle old versions, assume a class and just keep trying */
    if (regs.r_flags & CARRY ) { /* old version */
	for ( class = 0; class < 2; ++class ) {
	    _pktdevclass = (class) ? PD_SLIP : PD_ETHER;

	    for (pd_type = 1; pd_type < 128; ++pd_type ) {
		regs.r_ax = PD_ACCESS | _pktdevclass;  /* ETH, SLIP */
		regs.r_bx = pd_type;		/* type */
		regs.r_dx = 0;			/* if number */
		regs.r_cx = sizeof( pkt_ip_type );
		{  word far *fp= &pkt_ip_type;
		   regs.r_ds = FP_SEG( fp );
		   regs.r_si = FP_OFF( fp );
		}
		{
		   void far *s= (char far *)_pktentry;
	           regs.r_es = FP_SEG( s );
		   regs.r_di = FP_OFF( s );
		}
		stampa_regs("before access (old) type",&regs); 
		intr( pkt_interrupt, &regs );
		stampa_regs("after access (old) type",&regs); 
		if ( ! (regs.r_flags & CARRY) ) break;
	    }

	    if (pd_type == 128 ) {
		outs("ERROR initializing packet driver\n\r");
		return( 1 );
	    }
	    /* we have found a working type, so kill it */
	    regs.r_bx = regs.r_ax;	/* handle */
	    regs.r_ax = PD_RELEASE;
	    stampa_regs("before release",&regs); 
	    intr( pkt_interrupt, &regs );
	    stampa_regs("after release",&regs); 
	}
    } else {
	pd_type = regs.r_dx;
	switch ( _pktdevclass = (regs.r_cx >> 8)) {
	    case PD_ETHER : _pktipofs = 14;

	    case PD_SLIP  : break;
	    default 	  : outs("ERROR: only ethernet packet drivers allowed\n\r");
			    return( 1 );
	}
    }
    regs.r_ax = PD_ACCESS | _pktdevclass;
    regs.r_bx = 0xffff;  /* any type - was pd_type  type */
    regs.r_dx = 0;			/* if number */
    regs.r_cx = sizeof( pkt_ip_type );
    {	word far *fp= &pkt_ip_type;
	regs.r_ds = FP_SEG( fp );
	regs.r_si = FP_OFF( fp );
    }
    {
	void far *s= (char far *)_pktentry;
	regs.r_es = FP_SEG( s );
	regs.r_di = FP_OFF( s );
    }
    memcpy( &regs2, &regs, sizeof( regs ));
    {	word far *fp= &pkt_arp_type;
	regs2.r_si = FP_OFF( fp );
	regs2.r_ds = FP_SEG( fp );
    }
    stampa_regs("before access IP type",&regs); 
    intr( pkt_interrupt, &regs );
    stampa_regs("after access IP type",&regs); 
    if ( regs.r_flags & CARRY ) {
	outs("ERROR # 0x");
	outhex( (unsigned char)(regs.r_dx >> 8) );
	outs(" accessing IP type on packet driver\n\r" );
	return( 1 );
    }
    pkt_ip_handle = regs.r_ax;

    if (_pktdevclass != PD_SLIP) {
	stampa_regs("before access ARP type on regs2",&regs2); 
	intr( pkt_interrupt, &regs2 );
	stampa_regs("after access ARP type on regs2",&regs2); 
	if ( regs2.r_flags & CARRY ) {
	    regs.r_ax = PD_RELEASE;
	    regs.r_bx = pkt_ip_handle;
	    stampa_regs("failed ARP - before release IP type",&regs); 
	    intr( pkt_interrupt, &regs );
	    stampa_regs("failed ARP - after release IP type",&regs); 

	    outs("ERROR # 0x");
	    outhex( (unsigned char)(regs2.r_dx >> 8) );
	    outs(" accessing ARP type on packet driver\n\r" );
	    return( 1 );
	}
	pkt_arp_handle = regs2.r_ax;
    }

    /* get ethernet address */
    regs.r_ax = PD_GET_ADDRESS;
    regs.r_bx = pkt_ip_handle;
    {	char far *fp= eth_addr;
	regs.r_es = FP_SEG( fp );
	regs.r_di = FP_OFF( fp );
    }
    regs.r_cx = sizeof( eth_addr );
    stampa_regs("before get_addr",&regs); 
    intr( pkt_interrupt, &regs );
    stampa_regs("after get_addr",&regs); 
    if ( regs.r_flags & CARRY ) {
	outs("ERROR # reading ethernet address\n\r" );
	return( 1 );
    }

    return( 0 );
}

int
pkt_release(void)
{
    struct REGPACK regs;
    int error;

    error = 0;

    segread(&(regs.s));
    if ( _pktdevclass != PD_SLIP ) {
	regs.r_ax = PD_RELEASE;
	regs.r_bx = pkt_arp_handle;
	stampa_regs("before release ARP in pkt_release",&regs); 
	intr( pkt_interrupt, &regs );
	stampa_regs("after release ARP in pkt_release",&regs); 
	if (regs.r_flags & CARRY ) {
	    outs("ERROR releasing packet driver for ARP\n\r");
	    error = 1;
	}
    }

    regs.r_ax = PD_RELEASE;
    regs.r_bx = pkt_ip_handle;
    stampa_regs("before release IP in pkt_release",&regs); 
    intr( pkt_interrupt, &regs );
    stampa_regs("after release IP in pkt_release",&regs); 
    if (regs.r_flags & CARRY ) {
	outs("ERROR releasing packet driver for IP\n\r");
	error = 1;
    }

    return( error );
}

int
pkt_send( char *buffer, int length )
{
    struct REGPACK regs;
    int retries;

    segread(&(regs.s));
    retries = 5;
    while (retries--) {
        regs.r_ax = PD_SEND;
	{	char far *fp= buffer;
        	regs.r_ds = FP_SEG( fp );
        	regs.r_si = FP_OFF( fp );
	}
        regs.r_cx = length;
	stampa_regs("before send in pkt_send",&regs); 
	DB2((stderr, "Sending PKT:\n"));
#ifdef debug
	print_pkt(buffer);
#endif /* debug */
        intr( pkt_interrupt, &regs );
	stampa_regs("after send in pkt_send",&regs); 
        if ( regs.r_flags & CARRY )
            continue;
        return( 0 );
    }
    return( 1 );
}

void
pkt_buf_wipe(void )
{
    memset( pktbuf, 0, sizeof( pktbuf ));
}

/* return a buffer to the pool */
void
pkt_buf_release( char *ptr )
{
    DB2((stderr,"called pkt_buf_release()\r\n"));
    *(ptr - (2 + 14)) = 0; /* 14 is ip offset, 2 is busy word */
}

void *
pkt_received(void)
{
	static word i=0; /* index of the current free buffer */
	word j;
	if (pktbuf[i][0] != 1) return NULL; /* not found */
        if (debug_on) {
		DB2((stderr, "Received PKT:\n"));
	#ifdef debug
		print_pkt(pktbuf[i]+2);
	#endif
	}
	j=i;	/* temporary */
        if (++i == MAXBUFS ) i=0; /* update pointer */
	return( &pktbuf[j][2] );
}

void *
_pkt_eth_init(void)
{
    if ( pkt_init() ) {
	outs("Program halted");
	exit( 1 );
    }
    return( eth_addr );
}
#ifdef debug
void
stampa_regs(char *s,struct REGPACK *r)
{
    DB2((stderr,"%s\n",s));
    DB2((stderr,"AX: %4x, BX: %4x, CX: %4x, DX: %4x, SI: %4x, DI: %4x\n",
	(*r).x.ax, (*r).x.bx, (*r).x.cx, (*r).x.dx, (*r).x.si, (*r).x.di));
    DB2((stderr,"CS: %4x, SS: %4x, DS: %4x, ES: %4x, FLAGS: %4x\n",
	(*r).s.cs, (*r).s.ss, (*r).s.ds, (*r).s.es, (*r).r_flags));
    getch();
}


void
print_ip(byte *p)
{
	in_Header *in= (in_Header *)p;
	byte *s;
	DB2((stderr,"Hdrlen: %2d  ver: %2d  tos: %3d len: %5d\n",
		in->hdrlen, in->ver, in->tos, intel16(in->length)));
	switch (in->proto) {
	case 0x11:s="UDP"; break;
	case 0x06:s="TCP"; break;
	case 0x01:s="ICMP"; break;
	default: s="unknown";
	}
	DB2((stderr,"id: %5d  frag: %5d  ttl: %3d  proto: %d (%s)\n",
		intel16(in->identification), intel16(in->frag), in->ttl, in->proto,s));
	s= (char *)(&in->source);
	DB2((stderr,"chk: %4x, src: %d.%d.%d.%d",
		intel16(in->checksum), s[0],s[1],s[2],s[3]));
	s= (char *)(&in->destination);
	DB2((stderr," dst: %d.%d.%d.%d\n", s[0],s[1],s[2],s[3]));
}

void
print_arp(byte *p)
{
	arp_Header *a= (arp_Header *)p;
	byte *s;
	DB2((stderr,"hwtype: %4x  protType: %4x hwProtAddrLen: %4x opcode: %4x\n",
		intel16(a->hwType),intel16(a->protType),
		intel16(a->hwProtAddrLen), intel16(a->opcode) ));
	s= (byte *)(&a->srcEthAddr);
	DB2((stderr,"src_eth: %2x %2x %2x %2x %2x %2x",
		s[0],s[1],s[2],s[3],s[4],s[5]));
	s= (byte *)(&a->srcIPAddr);
	DB2((stderr," src_ip: %d.%d.%d.%d\n", s[0],s[1],s[2],s[3]));
	s= (byte *)(&a->dstEthAddr);
	DB2((stderr,"dst_eth: %2x %2x %2x %2x %2x %2x",
		s[0],s[1],s[2],s[3],s[4],s[5]));
	s= (byte *)(&a->dstIPAddr);
	DB2((stderr," dst_ip: %d.%d.%d.%d\n", s[0],s[1],s[2],s[3]));
}

void
print_pkt(byte *p)
{
	DB2((stderr,"eth_dest: %2x %2x %2x %2x %2x %2x ",
		p[0],p[1],p[2],p[3],p[4],p[5]));
	p +=6;
	DB2((stderr,"eth_src: %2x %2x %2x %2x %2x %2x ",
		p[0],p[1],p[2],p[3],p[4],p[5]));
	p +=6;
	DB2((stderr,"mac_type: %2x %2x", p[0],p[1]));
	switch ( *( (word *)p) ) { /* use intelled values */
	case 0x08: /* IP */
		DB2((stderr," IP\n"));
		print_ip(p+2);
		break;
	case 0x608: /* ARP */
		DB2((stderr," ARP\n"));
		print_arp(p+2);
		break;
	default: /* unknown */
		DB2((stderr," unknown\n"));
		break;
	}
	getch();
}
#endif
