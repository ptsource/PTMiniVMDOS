/*
 *
 *   BOOTP - Boot Protocol (RFC 854)
 *
 *   These extensions get called if _bootphost is set to an IP address or
 *   to 0xffffffff.
 *
 *   Version
 *
 *   0.3 : Feb  1, 1992 : J. Dent - patched up various things
 *   0.2 : May 22, 1991 : E.J. Sutcliffe - added RFC_1048 vendor fields
 *   0.1 : May  9, 1991 : E. Engelke - made part of the library
 *   0.0 : May  3, 1991 : E. Engelke - original program as an application
 *
 */

#include <copyright.h>
#include <stdio.h>
#include <wattcp.h>
#include <mem.h>
#include <bootp.h>
#include <conio.h>

/* global variables */
longword _bootphost = 0xffffffffL;
word _bootptimeout = 30;
word _bootpon = 0;

extern longword set_timeout();

#define VM_RFC1048 0x63825363L		/* I think this is correct */

/*
 * _dobootpc - Checks global variables _bootptimeout, _bootphost
 *             if no host specified, the broadcast address
 *             returns 0 on success and sets ip address
 */
int _dobootp()
{
    udp_Socket bsock;
    longword sendtimeout, bootptimeout;
    word magictimeout;
    word len, templen;
    struct bootp sendbootp;     /* outgoing data */
    struct bootp _bootp;        /* incoming data */
    int status;
    longword xid;
    unsigned char *p,*t;

//    if ( _pktdevclass == PD_SLIP ) return( -1 );


    /* We must get Waterloo TCP to use IP address 0 for sending */
    xid = my_ip_addr;   /* a unique value coming from the ethernet card */
    my_ip_addr = 0;

    if (!udp_open( &bsock, IPPORT_BOOTPC, _bootphost, IPPORT_BOOTPS, NULL )) {
        outs("\n\rUnable to resolve bootp server\n\r");
        return( -1 );
    }

    bootptimeout = set_timeout( _bootptimeout );
    magictimeout = (xid & 7) + 7;  /* between 7 and 14 seconds */

    memset( &sendbootp, 0, sizeof( struct bootp ));
    sendbootp.bp_op = BOOTREQUEST;
    sendbootp.bp_htype = _pktdevclass;
    /* Copy into position the Magic Number used by Bootp */
    /* avoid static storage and pushf/call assembler instructions */
    *(longword *)(&sendbootp.bp_vend) = intel(VM_RFC1048);

    if (_pktdevclass == PD_ETHER) sendbootp.bp_hlen = 6;

    sendbootp.bp_xid = xid;
    sendbootp.bp_secs = intel16( 1 );

    movmem( _eth_addr, &sendbootp.bp_chaddr, sizeof(eth_address));

    while ( 1 ) {
	sock_fastwrite( (sock_type*)&bsock, (byte *)&sendbootp, sizeof( struct bootp ));
        sendbootp.bp_secs = intel16( intel16( sendbootp.bp_secs ) + magictimeout );      /* for next time */
        sendtimeout = set_timeout( magictimeout += (xid >> 5) & 7 );

        while ( !chk_timeout( sendtimeout )) {

            if (chk_timeout( bootptimeout))
                goto give_up;
            kbhit();
	    sock_tick( (sock_type*)&bsock, &status );
	    if ((len = sock_dataready( (sock_type*)&bsock)) != 0 ) {

                /* got a response, lets consider it */
		templen = sock_fastread( (sock_type*)&bsock, (byte *)&_bootp, sizeof( struct bootp ));
                if ( templen < sizeof( struct bootp )) {
                    /* too small, not a bootp packet */
		    memset( &_bootp, 0, sizeof( struct bootp ));
                    continue;
                }

                /* we must see if this is for us */
		if (_bootp.bp_xid != sendbootp.bp_xid) {
		    memset( &_bootp, 0, sizeof( struct bootp ));
                    continue;
                }

                /* we must have found it */
		my_ip_addr = intel( _bootp.bp_yiaddr );


		if ( intel( *(longword*)(&_bootp.bp_vend)) == VM_RFC1048 ) {
		    /*RFC1048 complient BOOTP vendor field */
		    /* Based heavily on NCSA Telnet BOOTP */

		    p = &_bootp.bp_vend[4]; /* Point just after vendor field */

                    while ((*p!=255) && (p <= &_bootp.bp_vend[63])) {
			switch(*p) {
                          case 0: /* Nop Pad character */
                                 p++;
                                 break;
                          case 1: /* Subnet Mask */
				 sin_mask = intel( *(longword *)( &p[2] ));
				 /* and fall through */
			  case 2: /* Time offset */
				 p += *(p+1) + 2;
				 break;
			  case 3: /* gateways */
				  /* only add first */
				  _arp_add_gateway( NULL,
				     intel( *(longword*)(&p[2])));
                                  p +=*(p+1)+2;
                                  break;
				  /* and fall through */
			  case 4: /*time servers */
				  /* fall through */
                          case 5: /* IEN=116 name server */
                                 p +=*(p+1)+2;
                                 break;
			  case 6: /* Domain Name Servers (BIND) */
				for ( len = 0; len < *(p+1) ; len += 4 )
				    _add_server( &_last_nameserver,
					MAX_NAMESERVERS, def_nameservers,
					    intel( *(longword*)(&p[2+len])));
				/* and fall through */
			  case 7: /* log server */
				 p += *(p+1)+2;
				 break;
			  case 8: /* cookie server */
				 for ( len = 0; len < *(p+1) ; len += 4 )
				     _add_server( &_last_cookie, MAX_COOKIES,
					_cookie, intel( *(longword*)(&p[2+len])));
                                  /* and fall through */
                                  p +=*(p+1)+2;
                                  break;
                          case 9: /* lpr server */
                          case 10: /* impress server */
                          case 11: /* rlp server */
                                   p +=*(p+1)+2;
                                   break;
			  case 12: /* Client Hostname */
				  movmem( &p[2] , _hostname, MAX_STRING );
				  _hostname[ MAX_STRING - 1 ] = 0;
				  p += *(p+1)+2;
                                  break;
                          case 255:
                                   break;
                          default:
                                   p +=*(p+1)+2;
                                   break;
                        } /* end of switch */
                     } /* end of while */
                }/* end of RFC_1048 if */
                goto give_up;
            }
        }
    }
give_up:

    sock_close( (sock_type *)&bsock );

    return (my_ip_addr == 0 );  /* return 0 on success */

sock_err:
    /* major network error if UDP fails */
    sock_close( (sock_type *)&bsock );
    return( -1 );
}
