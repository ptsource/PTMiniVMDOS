/***
 *
 * File: pcarp.c
 *
 * 27-Aug-93 fr
 *	removed diagnostic comments
 * 18-Jun-92 lr
 *
 *
 * Address Resolution Protocol
 *
 *  Externals:
 *  _arp_handler( pb ) - returns 1 on handled correctly, 0 on problems
 *  _arp_resolve - rets 1 on success, 0 on fail
 *               - does not return hardware address if passed NULL for buffer
 *
 */

#define WATTCP_KERNEL
#define PCARP
#include <tcp.h>
#include <string.h>

#define MAX_ARP_ALIVE  300 /* five minutes */
#define MAX_ARP_GRACE  100 /* additional grace upon expiration */


typedef struct {
    longword            ip;
    eth_address         hardware;
    byte                flags;
    byte                bits;           /* bits in network */
    longword            expiry;
} arp_tables;

typedef struct {
    longword            gate_ip;
    longword            subnet;
    longword            mask;
} gate_tables;

#define ARP_FLAG_NEED   0
#define ARP_FLAG_FOUND  1
#define ARP_FLAG_FIXED  255     /* cannot be removed */


/*************************** STATICS ******************************/

static void _arp_request( longword ip );
static arp_tables *_arp_search( longword ip, int create );

/*
 * arp resolution cache - we zero fill it to save an initialization routine
 */
static arp_tables arp_data[] =
 {      {0,{0,0,0},0,0,0}, {0,{0,0,0},0,0,0},
	{0,{0,0,0},0,0,0}, {0,{0,0,0},0,0,0},
	{0,{0,0,0},0,0,0}, {0,{0,0,0},0,0,0},
	{0,{0,0,0},0,0,0}, {0,{0,0,0},0,0,0},
	{0,{0,0,0},0,0,0}, {0,{0,0,0},0,0,0},
	{0,{0,0,0},0,0,0}, {0,{0,0,0},0,0,0},
	{0,{0,0,0},0,0,0}, {0,{0,0,0},0,0,0},
	{0,{0,0,0},0,0,0}, {0,{0,0,0},0,0,0},
	{0,{0,0,0},0,0,0}, {0,{0,0,0},0,0,0},
	{0,{0,0,0},0,0,0}, {0,{0,0,0},0,0,0},
	{0,{0,0,0},0,0,0}, {0,{0,0,0},0,0,0},
	{0,{0,0,0},0,0,0}, {0,{0,0,0},0,0,0},
	{0,{0,0,0},0,0,0}, {0,{0,0,0},0,0,0},
	{0,{0,0,0},0,0,0}, {0,{0,0,0},0,0,0},
	{0,{0,0,0},0,0,0}, {0,{0,0,0},0,0,0},
	{0,{0,0,0},0,0,0}, {0,{0,0,0},0,0,0},
	{0,{0,0,0},0,0,0}, {0,{0,0,0},0,0,0},
	{0,{0,0,0},0,0,0}, {0,{0,0,0},0,0,0},
	{0,{0,0,0},0,0,0}, {0,{0,0,0},0,0,0},
	{0,{0,0,0},0,0,0}, {0,{0,0,0},0,0,0}};

#define MAX_ARP_DATA (sizeof(arp_data) /sizeof(arp_tables) )

static gate_tables _arp_gate_data[ MAX_GATE_DATA ];
static word arp_index = 0;              /* rotates round-robin */
/************************ END OF STATICS ******************************/

/*
 * disp_gate_table  added by fr for tcpinfo
 */
void 
disp_gate_table()
{
    int i;
    char buf[80];

    for ( i=0; i< _arp_last_gateway; i++ ) {
	printf("%-18s",w_inet_ntoa(buf,_arp_gate_data[i].gate_ip) );
	printf("%-18s",w_inet_ntoa(buf,_arp_gate_data[i].subnet) );
	printf("%-18s\n",w_inet_ntoa(buf,_arp_gate_data[i].mask) );
    }
}

/*
 * _arp_add_gateway - if data is NULL, don't use string
 */

void
_arp_add_gateway( char *data , longword ip )
{
    int i;
    char *subnetp, *maskp;
    longword subnet, mask;

    subnet = mask = 0;
    if ( data ) {
	maskp = NULL;
	if ( subnetp = strchr( data, ',' ) ) {
	    *subnetp++ = 0;
	    if ( maskp = strchr( subnetp, ',' )) {
		*maskp++ = 0;
		mask = aton( maskp );
		subnet = aton( subnetp );
	    } else {
		subnet = aton( subnetp );
		switch ( subnet >> 30 ) {
		    case 0 :
		    case 1 : mask = 0xff000000L; break;
		    case 2 : mask = 0xfffffe00L; break; /* minimal class b */
		    case 3 : mask = 0xffffff00L; break;
		}
	    }
	}
    }
    ip = aton( data );

    if ( _arp_last_gateway < MAX_GATE_DATA ) {
	for ( i = 0 ; i < _arp_last_gateway ; ++i ) {
	    if ( _arp_gate_data[i].mask < mask ) {
		movmem( &_arp_gate_data[i], &_arp_gate_data[i+1],
		    (_arp_last_gateway - i) * sizeof( gate_tables ));
		break;
	    }
	}
	_arp_gate_data[i].gate_ip = ip;
	_arp_gate_data[i].subnet = subnet;
	_arp_gate_data[i].mask = mask;
	++_arp_last_gateway;    /* used up another one */
    }
}

static void _arp_request( longword ip )
{
    register arp_Header *op;
DB2((FDB,"_arp_request():\n"));
    op = (arp_Header *)_eth_formatpacket(&_eth_brdcast[0], 0x608);
    op->hwType = arp_TypeEther;
    op->protType = 0x008;               /* IP */
    op->hwProtAddrLen = sizeof(eth_address) + (sizeof(longword)<<8);
    op->opcode = ARP_REQUEST;
    op->srcIPAddr = intel( my_ip_addr );
    movmem(_eth_addr, op->srcEthAddr, sizeof(eth_address));
    op->dstIPAddr = intel( ip );

    /* ...and send the packet */
    _eth_send( sizeof(arp_Header) );
}



static arp_tables *_arp_search( longword ip, int create )
{
    int i;
    register arp_tables *arp_ptr;

DB2((FDB,"_arp_search():\n"));
    for ( i = 0; i < MAX_ARP_DATA; ++i ) {
	if ( ip == arp_data[i].ip )
	    return( &arp_data[i] );
    }

    /* didn't find any */
    if ( create ) {
	/* pick an old or empty one */
	for ( i = 0; i < MAX_ARP_DATA ; ++i ) {
	    arp_ptr = &arp_data[i];
	    if ( ! arp_ptr->ip || chk_timeout(arp_ptr->expiry+MAX_ARP_GRACE))
		return( arp_ptr );
	}

	/* pick one at pseudo-random */
	return( &arp_data[ arp_index = ( arp_index + 1 ) % MAX_ARP_DATA ] );
    }
    return( NULL );
}

void _arp_register( longword use, longword instead_of )
{
    register arp_tables *arp_ptr;

DB2((FDB,"_arp_register():\n"));
    if ( arp_ptr = _arp_search( instead_of, 0 )) {
	/* now insert the address of the new guy */
	arp_ptr->flags = ARP_FLAG_NEED;
	_arp_resolve( use, &(arp_ptr->hardware));
	arp_ptr->expiry = set_timeout( MAX_ARP_ALIVE );
	return;
    }

    arp_ptr = _arp_search( use , 1 );   /* create a new one */
    arp_ptr->flags = ARP_FLAG_NEED;
    arp_ptr->ip = instead_of;
    _arp_resolve( use, &(arp_ptr->hardware));
    arp_ptr->expiry = set_timeout( MAX_ARP_ALIVE );
}

void _arp_tick( longword ip )
/* _arp_tick( longword ip ) */
{
    arp_tables *arp_ptr;

DB2((FDB,"_arp_tick():\n"));
    if ( arp_ptr = _arp_search( ip , 0))
	arp_ptr->expiry = set_timeout( MAX_ARP_ALIVE );
}
/*
 * _arp_handler - handle incomming ARP packets
 */
void _arp_handler( arp_Header *in)
{
    arp_Header *op;
    longword his_ip;
    arp_tables *arp_ptr;

DB2((FDB,"_arp_handler():\n"));
    if ( in->hwType != arp_TypeEther ||      /* have ethernet hardware, */
	in->protType != 8 )                  /* and internet software, */
	return;

    /* continuously accept data - but only for people we talk to */
    his_ip = intel( in->srcIPAddr );

    if ( arp_ptr = _arp_search( his_ip, 0)) {
	arp_ptr->expiry = set_timeout( MAX_ARP_ALIVE );
	movmem( in->srcEthAddr, arp_ptr->hardware, sizeof( eth_address ));
	arp_ptr->flags = ARP_FLAG_FOUND;
    }

    /* does someone else want our Ethernet address ? */
    if ( in->opcode == ARP_REQUEST &&        /* and be a resolution req. */
	 in->dstIPAddr == intel( my_ip_addr )/* for my addr. */
       )  {
	op = (arp_Header *)_eth_formatpacket(in->srcEthAddr, 0x0608);
	op->hwType = arp_TypeEther;
	op->protType = 0x008;                   /* intel for ip */
	op->hwProtAddrLen = sizeof(eth_address) + (sizeof(longword) << 8 );
	op->opcode = ARP_REPLY;

	op->dstIPAddr = in->srcIPAddr;
	op->srcIPAddr = in->dstIPAddr;
	movmem(_eth_addr, op->srcEthAddr, sizeof(eth_address));
	movmem(in->srcEthAddr, op->dstEthAddr, sizeof(eth_address));
	_eth_send(sizeof(arp_Header));
	return;
    }
}


/*
 * _arp_resolve - resolve IP address to hardware address
 */
int _arp_resolve( longword ina, eth_address *ethap)
{
    static arp_tables *arp_ptr;
    int i, oldhndlcbrk;
    longword timeout, resend;
    char buf[30];
    /* int packettype; */

    DB2((stderr,"_arp_resolve():\n"));
    DB3( (stderr,"Calling _arp_resolve for eth. address of %s\n\n",
			w_inet_ntoa(buf,ina) ) ); /* fr */
    if ( _pktdevclass == PD_SLIP ) {
	/* running slip or something which does not use addresses */
	return( 1 );
    }

    if ( ina == my_ip_addr ) {
	if (ethap)
	    movmem( _eth_addr, ethap, sizeof( eth_address ));
	return( 1 );
    }

    /* attempt to solve with ARP cache */
    /* fake while loop */
    while ( arp_ptr = _arp_search( ina, 0)) {
	if ( arp_ptr->flags != ARP_FLAG_NEED ) {
	    /* has been resolved */
#ifdef NEW_EXPIRY
	    if ( chk_timeout( arp_ptr->timeout ) {
		if ( ! chk_timeout( arp_ptr->timeout + MAX_ARP_GRACE ) {
		    /* we wish to refresh it asynchronously */
		    _arp_request( ina );
		else
		    break;      /* must do full fledged arp */
#endif /* NEW_EXPIRY */
	    if (ethap)
		movmem( arp_ptr->hardware, ethap, sizeof(eth_address));
	    return( 1 );
	}
	break;
    }

    /* make a new one if necessary */
    if (! arp_ptr )
	arp_ptr = _arp_search( ina, 1 );

    /* we must look elsewhere - but is it on our subnet??? */
    if (( ina ^ my_ip_addr ) & sin_mask ) {
	/* not of this network */
	for ( i = 0; i < _arp_last_gateway ; ++i ) {
	    /* compare the various subnet bits */
	    if ( (_arp_gate_data[i].mask & ina ) == _arp_gate_data[i].subnet ) {
		if ( _arp_resolve( _arp_gate_data[i].gate_ip , ethap ))
		    return( 1 );
	    }
	}
	return( 0 );
    }

    /* return if no host, or no gateway */
    if (! ina )
	return( 0 );

    /* is on our subnet, we must resolve */
    timeout = set_timeout( 5 );         /* five seconds is long for ARP */
    oldhndlcbrk = wathndlcbrk;
    wathndlcbrk = 1;
    watcbroke = 0;
    while ( !chk_timeout( timeout )) {
	/* do the request */
	_arp_request( arp_ptr->ip = ina );
	resend = set_timeout( 1 ) - 14L;        /* 250 ms */
	while (!chk_timeout( resend )) {
	    if (watcbroke) goto fail;
	    tcp_tick( NULL );
	    if ( arp_ptr->flags) {
		if (ethap)
		    movmem( arp_ptr->hardware, ethap, sizeof(eth_address));
		arp_ptr->expiry = set_timeout( MAX_ARP_ALIVE );
		watcbroke = 0;
		wathndlcbrk = oldhndlcbrk;
		return ( 1 );
	    }
	}
    }
fail:
    watcbroke = 0;
    wathndlcbrk = oldhndlcbrk;
    return ( 0 );
}
