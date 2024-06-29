/***
 *
 * File: pcping.c
 *
 * 18-Jun-92 lr
 *
 */

#define WATTCP_KERNEL
#include <tcp.h>

struct icmp_echo {
    byte	type;
    byte	code;
    word	checksum;
    word	identifier;
    word	sequence;
    longword	index;
};

struct _pkt {
    in_Header 	in;
    struct icmp_echo icmp;
    in_Header	data;
};



int
_ping( longword host, longword countnum )
{
    eth_address dest;
    struct _pkt *p;
    in_Header *ip;
    struct icmp_echo *icmp;
    static word icmp_id = 0;

    if ((host & 0xff) == 0xff ) {
	outs( "Cannot ping a network!\n\r");
	return( -1 );
    }
    if ( ! _arp_resolve( host, &dest )) {
	outs( "Cannot resolve host's hardware address\n\r");
	return( -1 );
    }

    if (debug_on) {
	outs("\n\rDEBUG: destination hardware :");
	outhexes((char *)&dest, 6 );
	outs("\n\r");
    }
    p = (struct _pkt*)_eth_formatpacket( &dest, 8 );

    ip = &p->in;
    icmp = &p->icmp;

    icmp->type = 8;
    icmp->code = 0;
    icmp->index = countnum;
    *(longword *)(&icmp->identifier) = set_timeout( 1 );
/*
    icmp->identifier = ++icmp_id;
    icmp->sequence = icmp_id;
*/
    /* finish the icmp checksum portion */
    icmp->checksum = 0;
    icmp->checksum = ~inchksum( icmp, sizeof( struct icmp_echo));

    /* encapsulate into a nice ip packet */
    ip->ver = 4;
    ip->hdrlen = 5;
    ip->length = intel16( sizeof( in_Header ) + sizeof( struct icmp_echo));
    ip->tos = 0;
    ip->identification = intel16( icmp_id ++);	/* not using ip id */
    ip->frag = 0;
    ip->ttl = 250;
    ip->proto = ICMP_PROTO;
    ip->checksum = 0;
    ip->source = intel( my_ip_addr );
    ip->destination = intel( host );
    ip->checksum = ~ inchksum( ip, sizeof( in_Header ));

    return( _eth_send( intel16( ip->length )));
}
/*** end of file pcping.c ***/
