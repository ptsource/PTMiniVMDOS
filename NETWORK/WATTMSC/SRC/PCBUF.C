/****
 *
 * File: pcbuf.c
 *
 * 18-Jun-92 lr
 *
 *
 */

#define WATTCP_KERNEL
#include <tcp.h>

int
sock_rbsize( tcp_Socket *s )
{
    switch( _chk_socket( s )) {
	default: return( 0 );
	case 1 :
	case 2 : return( s->rxbufsize );
    }
}

int
sock_rbused( tcp_Socket *s )
{
    switch( _chk_socket( s )) {
	default: return( 0 );
	case 1 :
	case 2 : return( s->rdatalen );
    }
}

int
sock_rbleft( tcp_Socket *s )
{
    switch( _chk_socket( s )) {
	default: return( 0 );
	case 1 :
	case 2 : return( s->rxbufsize - s->rdatalen );
    }
}

int
sock_tbsize( tcp_Socket *s )
{
    switch( _chk_socket( s )) {
	case 2 : return( s->txbufsize );
	default: return( 0 );
    }
}

int
sock_tbused( tcp_Socket *s )
{
    switch( _chk_socket( s )) {
    case 2 : return( s->datalen );
	default: return( 0 );
    }
}

int
sock_tbleft( tcp_Socket *s )
{
    switch( _chk_socket( s )) {
    case 2 : return( s->txbufsize - s->datalen );
	default: return( 0 );
    }
}

int
sock_preread( sock_type *s, byte *dp, int len )
{
    int count;

    if ( !(count = s->udp.rdatalen) < 1)    /* 0 : no data, -1 : error */
	return( count );

    if ( count > len ) count = len;
    movmem( s->udp.rdata, dp, count );
    return( count );
}
