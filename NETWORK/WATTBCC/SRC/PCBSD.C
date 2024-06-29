#include <copyright.h>
#include <stdio.h>
#include <wattcp.h>
#include <stdlib.h>    /* itoa */
#include <string.h>
#include <elib.h>

/*
 * PCBSD - provide some typical BSD UNIX functionality
 * Erick Engelke, Feb 22, 1991
 */

/*
 * chk_socket - determine whether a real socket or not
 *
 */
_chk_socket( tcp_Socket *s )
{
    if ( s->ip_type == TCP_PROTO ) {
	if ( s->state <= tcp_StateCLOSED)	/* skips invalid data */
	    return( 2 );
    }
    if ( s->ip_type == UDP_PROTO ) return( 1 );
    return( 0 );
}

char *inet_ntoa( char *s, longword x )
{

    itoa( x >> 24, s, 10 );
    strcat( s, ".");
    itoa( (x >> 16) & 0xff, strchr( s, 0), 10);
    strcat( s, ".");
    itoa( (x >> 8) & 0xff, strchr( s, 0), 10);
    strcat( s, ".");
    itoa( (x) & 0xff, strchr( s, 0), 10);
    return( s );
}

longword inet_addr( char *s )
{
    return( isaddr( s ) ? aton( s ) : 0 );
}

char *sockerr( tcp_Socket *s )
{
    if ( strlen( s->err_msg ) < 80 )
	return( s->err_msg );
    return( NULL );
}

static char *sock_states[] = {
    "Listen","SynSent","SynRec","Established","FinWt1","FinWt2","ClosWt","LastAck"
    "TmWt","Closed"};

char *sockstate( tcp_Socket *s )
{
    switch ( _chk_socket( s )) {
       case  1 : return( "UDP Socket" );
       case  2 : return( sock_states[ s->state ] );
       default : return( "Not an active socket");
    }
}
longword gethostid()
{
    return( my_ip_addr );
}

longword sethostid( longword ip )
{
    return( my_ip_addr = ip );
}

word ntohs( word a )
{
    return( intel16(a) );
}
word htons( word a )
{
    return( intel16(a) );
}
longword ntohl( longword x )
{
    return( intel( x ));
}
longword htonl( longword x )
{
    return( intel( x ));
}

