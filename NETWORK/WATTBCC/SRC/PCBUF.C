#include <copyright.h>
#include <wattcp.h>
#include <mem.h>

int sock_rbsize( tcp_Socket *s )
{
    switch( _chk_socket( s )) {
	case 0 : return( 0 );
	case 1 : return( tcp_MaxBufSize );
	case 2 : return( tcp_MaxBufSize );
    }
}
int sock_rbused( tcp_Socket *s )
{
    switch( _chk_socket( s )) {
	case 0 : return( 0 );
	case 1 : return( s->rdatalen );
	case 2 : return( s->rdatalen );
    }
}
int sock_rbleft( tcp_Socket *s )
{
    switch( _chk_socket( s )) {
	case 0 : return( 0 );
	case 1 : return( tcp_MaxBufSize - s->rdatalen );
	case 2 : return( tcp_MaxBufSize - s->rdatalen );
    }
}

int sock_tbsize( tcp_Socket *s )
{
    switch( _chk_socket( s )) {
	case 2 : return( tcp_MaxBufSize );
	default: return( 0 );
    }
}
int sock_tbused( tcp_Socket *s )
{
    switch( _chk_socket( s )) {
    case 2 : return( s->datalen );
	default: return( 0 );
    }
}
int sock_tbleft( tcp_Socket *s )
{
    switch( _chk_socket( s )) {
    case 2 : return( tcp_MaxBufSize - s->datalen );
	default: return( 0 );
    }
}

sock_preread( sock_type *s, byte *dp, int len )
{
    int count;

    if ( (count = s->udp.rdatalen) < 1)    /* 0 : no data, -1 : error */
	return( count );

    if ( count > len ) count = len;
    movmem( s->udp.rdata, dp, count );
    return( count );
}
