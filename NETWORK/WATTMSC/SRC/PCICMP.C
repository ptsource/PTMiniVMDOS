/***
 *
 * File: pcicmp.c
 *
 * 27-Aug-93 fr
 *	final cleanup
 * 18-Jun-92 lr
 *
 * ICMP - RFC 792
 *
 */

#define WATTCP_KERNEL
#define PCICMP
#include <tcp.h>

/*********************** STATICS *************************/

static char *unreach[] = {
	"Network Unreachable",
	"Host Unreachable",
	"Protocol Unreachable",
	"Port Unreachable",
	"Fragmentation needed and DF set",
	"Source Route Failed" };
	
static char *exceed[] = {
	"TTL exceeded in transit",
	"Frag ReAsm time exceeded" };

static char *redirect[] = {
	"Redirect for Network",
	"Redirect for Host",
	"Redirect for TOS and Network",
	"Redirect for TOS and Host" };

/* constants */


struct icmp_unused {
    byte        type;
    byte        code;
    word        checksum;
    longword    unused;
    in_Header   ip;
    byte        spares[ 8 ];
};

struct icmp_pointer {
    byte        type;
    byte        code;
    word        checksum;
    byte        pointer;
    byte        unused[ 3 ];
    in_Header   ip;
};

struct icmp_ip {
    byte        type;
    byte        code;
    word        checksum;
    longword    ipaddr;
    in_Header   ip;
};

struct icmp_echo {
    byte        type;
    byte        code;
    word        checksum;
    word        identifier;
    word        sequence;
};

struct icmp_timestamp {
    byte        type;
    byte        code;
    word        checksum;
    word        identifier;
    word        sequence;
    longword    original;       /* original timestamp */
    longword    receive;        /* receive timestamp */
    longword    transmit;       /* transmit timestamp */
};

struct icmp_info {
    byte        type;
    byte        code;
    word        checksum;
    word        identifier;
    word        sequence;
};

typedef union  {
	struct icmp_unused      unused;
	struct icmp_pointer     pointer;
	struct icmp_ip          ip;
	struct icmp_echo        echo;
	struct icmp_timestamp   timestamp;
	struct icmp_info        info;
} icmp_pkt;

struct _pkt {
    in_Header   in;
    icmp_pkt    icmp;
    in_Header   data;
};

static void icmp_print( icmp_pkt *icmp, char *msg);
static void icmp_Reply( register struct _pkt *p,
	longword src, longword dest, int icmp_length );

static word icmp_id = 0;

static longword ping_hcache = 0;        /* host */
static longword ping_tcache = 0;        /* time */
static longword ping_number = 0;

/*************************** END OF STATICS *****************/
longword
_chk_ping( longword host, longword *ptr )
{
    if ( ping_hcache == host ) {
	ping_hcache = 0xffffffffL;
	*ptr = ping_number;
	return( ping_tcache );
    }
    return( 0xffffffffL );
}


static void
icmp_print( icmp_pkt *icmp, char *msg)
{
    outs("\n\rICMP: ");
    outs( msg );
}

/*
 *
 */
struct _pkt *
icmp_Format( longword destip )
{
    eth_address dest;
    /* char *temp; */

    /* we use arp rather than supplied hardware address */
    /* after first ping this will still be in cache */

    if ( !_arp_resolve( destip , &dest ))
	return( NULL );	/* unable to find address */
    return( (struct _pkt*)_eth_formatpacket( &dest, 8 ));
}

/*
 * icmp_Reply - format a reply packet
 *            - note that src and dest are NETWORK order not host!!!!
 */
static void
icmp_Reply( register struct _pkt *p,
	longword src, longword dest, int icmp_length )
{
    in_Header *ip;
    icmp_pkt *icmp;

    ip = &p->in;
    icmp = &p->icmp;

    /* finish the icmp checksum portion */
    icmp->unused.checksum = 0;
    icmp->unused.checksum = ~inchksum( icmp, icmp_length );

    /* encapsulate into a nice ip packet */
    ip->ver = 4;
    ip->hdrlen = 5;
    ip->length = intel16( sizeof( in_Header ) + icmp_length);
    ip->tos = 0;
    ip->identification = intel16( icmp_id ++);  /* not using ip id */
    ip->frag = 0;
    ip->ttl = 250;
    ip->proto = ICMP_PROTO;
    ip->checksum = 0;
    ip->source = src;
    ip->destination = dest;
    ip->checksum = ~ inchksum( ip, sizeof( in_Header ));

    _eth_send( intel16( ip->length ));
}

void
icmp_handler( in_Header *ip )
{
    register icmp_pkt *icmp, *newicmp;
    struct _pkt *pkt;
    int len, code;
    in_Header *ret;
    char buf[255];

    len = ip->hdrlen << 2;
    icmp = (icmp_pkt*)((byte *)ip + len);
    len = intel16( ip->length ) - len;
    if ( inchksum( icmp, len ) != 0xffff ) {
	outs("ICMP received with bad checksum\n\r");
	return;
    }

    code = icmp->unused.code;
    switch ( icmp->unused.type) {
	default:
		icmp_print( icmp,"bad message");
		break;
	case 0 : /* icmp echo reply received */
		icmp_print( icmp, "received icmp echo receipt");

		/* check if we were waiting for it */
		ping_hcache = intel( ip->source );
		ping_tcache = set_timeout( 1 ) - *(longword *)(&icmp->echo.identifier );
		if (ping_tcache > 0xffffffffL)
		    ping_tcache += 0x1800b0L;
		ping_number = *(longword*)( ((byte*)(&icmp->echo.identifier)) + 4 );
		/* do more */
		break;

	case 3 : /* destination unreachable message */
		if (code < 6) {
		    icmp_print( icmp, unreach[ code ]);

		    /* handle udp or tcp socket */
		    ret =(in_Header *)( (byte*)(icmp) + sizeof( icmp_pkt ));
		    if (ret->proto == TCP_PROTO)
			_tcp_cancel( ret );
		    if (ret->proto == UDP_PROTO)
			_udp_cancel( ret );
		}
		break;

	case 4  : /* source quench */
		icmp_print( icmp, "Source Quench");
		break;

	case 5  : /* redirect */
		if (code < 4) {
		    _arp_register( intel( icmp->ip.ipaddr ),
			intel( icmp->ip.ip.destination ));

		    icmp_print( icmp, redirect[ code ]);
		    /* do it to some socket guy */
		}
		break;

	case 8  : /* icmp echo request */
		if (print_icmp) {
			fprintf(stderr,"PING request from : %s\n",
			w_inet_ntoa( buf,intel(ip->source) ) );
		}

		/* do arp and create packet */
#ifdef OLD
		if (!(pkt = icmp_Format( intel( ip->source ))))
		    break;
#else /* !OLD */
	/* format the packet with the request's hardware address */
	pkt = (struct _pkt*)(_eth_formatpacket( _eth_hardware((byte *)ip), 8));
#endif /* !OLD */
		newicmp = &pkt->icmp;

		movmem( icmp, newicmp, len );
		newicmp->echo.type = 0;
		newicmp->echo.code = (byte)code;

		/* use supplied ip values in case we ever multi-home */
		/* note that ip values are still in network order */
		icmp_Reply( pkt,ip->destination, ip->source, len );
		
		if (print_icmp) {
			fprintf(stderr,"PING reply sent to: %s\n\n",
			w_inet_ntoa( buf,intel(ip->source) ) );
		}
		break;

	case 11 : /* time exceeded message */
		if (code < 2 ) {
		    icmp_print( icmp, exceed[ code ]);
		}
		break;

	case 12 : /* parameter problem message */
		icmp_print( icmp, "IP Parameter problem");
		break;

	case 13 : /* timestamp message */
		icmp_print( icmp, "Timestamp message");
		/* send reply */
		break;

	case 14 : /* timestamp reply */
		icmp_print( icmp, "Timestamp reply");
		/* should store */
		break;

	case 15 : /* info request */
		icmp_print( icmp,"Info requested");
		/* send reply */
		break;

	case 16 : /* info reply */
		icmp_print( icmp,"Info reply");
		break;

    }
}
