#include <copyright.h>
#include <wattcp.h>
#include <mem.h>
#include <dos.h>

/*
 * ICMP - RFC 792
 */

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

#include <icmp.h>

static word icmp_id = 0;

static longword ping_hcache = 0;	/* host */
static longword ping_tcache = 0;	/* time */
static longword ping_number = 0;
extern word multihomes;

/* handler called in icmp_handler if this isn't null */
static icmp_handler_type user_icmp_handler = NULL;

longword _chk_ping( longword host, longword *ptr )
{
    if ( ping_hcache == host ) {
	ping_hcache = 0xffffffffL;
	*ptr = ping_number;
	return( ping_tcache );
    }
    return( 0xffffffffL );
}


void icmp_print( icmp_pkt *icmp, char *msg)
{
    outs("\n\rICMP: ");
    outs( msg );
    outs("\n\r");
}

/*
 *
 */
struct _pkt *icmp_Format( longword destip )
{
    eth_address dest;
    char *temp;

    /* we use arp rather than supplied hardware address */
    /* after first ping this will still be in cache */

    if ( !_arp_resolve( destip , &dest, 0 ))
	return( NULL );				/* unable to find address */
    return( (struct _pkt*)_eth_formatpacket( &dest, 8 ));
}
/*
 * icmp_Reply - format a reply packet
 *  	      - note that src and dest are NETWORK order not host!!!!
 */
void *icmp_Reply( struct _pkt *p, longword src, longword dest, int icmp_length )
{
    in_Header *ip;
    icmp_pkt *icmp;

    ip = &p->in;
    memset( ip, 0, sizeof( in_Header ));
    icmp = &p->icmp;

    /* finish the icmp checksum portion */
    icmp->unused.checksum = 0;
    icmp->unused.checksum = ~checksum( icmp, icmp_length );

    /* encapsulate into a nice ip packet */
    ip->ver = 4;
    ip->hdrlen = 5;
    ip->length = intel16( sizeof( in_Header ) + icmp_length);
    ip->tos = 0;
    ip->identification = intel16( icmp_id ++);	/* not using ip id */
//    ip->frag = 0;
    ip->ttl = 250;
    ip->proto = ICMP_PROTO;
    ip->checksum = 0;
    ip->source = src;
    ip->destination = dest;
    ip->checksum = ~ checksum( ip, sizeof( in_Header ));

    _eth_send( intel16( ip->length ));
}


/*
 * Register the user ICMP handler.  Only one at a time...
 * To disable user handler, call  set_icmp_handler(NULL);
 */
void set_icmp_handler( icmp_handler_type user_handler )
{
   _disable();
   user_icmp_handler = user_handler;
   _enable();
}


icmp_handler( in_Header *ip )
{
    icmp_pkt *icmp, *newicmp;
    struct _pkt *pkt;
    int len, code;
    in_Header *ret;

    len = in_GetHdrlenBytes( ip );
    icmp = (icmp_pkt*)((byte *)ip + len);
    len = intel16( ip->length ) - len;
    if ( checksum( icmp, len ) != 0xffff ) {
	outs("ICMP received with bad checksum\n\r");
	return( 1 );
    }

   /*
    * If there's a user handler installed, call the user's handler;
    *     return of anything but 0 and this handler will continue
    *     processing the message after the user is done with it.
    * Otherwise, stop processing it now.
    */
    if( user_icmp_handler )
    {
        if( (user_icmp_handler)( ip ) == 0 )   /* don't continue processing? */
                return( 1 );
    }

    code = icmp->unused.code;
    ret = & (icmp->ip.ip);

    switch ( icmp->unused.type) {
	case 0 : /* icmp echo reply received */
		/* icmp_print( icmp, "received icmp echo receipt"); */

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
		    if (ret->proto == TCP_PROTO)
                        _tcp_cancel( ret, 1, unreach[ code ], 0 );
		    if (ret->proto == UDP_PROTO)
			_udp_cancel( ret );
		}
		break;

	case 4  : /* source quench */
                if (debug_on > 0 ) icmp_print( icmp, "Source Quench");
                if (ret->proto == TCP_PROTO)
                    _tcp_cancel( ret, 2, NULL, 0 );
		break;

	case 5  : /* redirect */
		if (code < 4) {
                    if (ret->proto == TCP_PROTO)
                        /* do it to some socket guy */
                        _tcp_cancel( ret, 5, NULL, icmp->ip.ipaddr );

                    if (debug_on > 0 ) icmp_print( icmp, redirect[ code ]);
		}
		break;

	case 8  : /* icmp echo request */
		/* icmp_print( icmp, "PING requested of us"); */

                // don't reply if the request was made by ourselves
                // such as a problem with Etherslip pktdrvr
                if  ( (longword) (ip->destination - intel( my_ip_addr)) > multihomes )
                    return( 1 );

                // do arp and create packet
                /* format the packet with the request's hardware address */
                pkt = (struct _pkt*)(_eth_formatpacket( _eth_hardware(ip), 8));

		newicmp = &pkt->icmp;

		movmem( icmp, newicmp, len );
		newicmp->echo.type = 0;
		newicmp->echo.code = code;

		/* use supplied ip values in case we ever multi-home */
		/* note that ip values are still in network order */
		icmp_Reply( pkt,ip->destination, ip->source, len );

		/* icmp_print( newicmp, "PING reply sent"); */

		break;

	case 11 : /* time exceeded message */
		if (code < 2 ) {
		    icmp_print( icmp, exceed[ code ]);
                    if ((ret->proto == TCP_PROTO) && (code != 1))
                        _tcp_cancel( ret, 1, NULL, 0 );
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
    return( 1 );
}


