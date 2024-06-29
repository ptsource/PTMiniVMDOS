/****
 *
 * File: pcbsd.c
 *
 * 18-Jun-92 lr
 *
 * PCBSD - provide some typical BSD UNIX functionality
 * Erick Engelke, Feb 22, 1991
 *
 ***/
#define WATTCP_KERNEL
#include <tcp.h>

/*
 * chk_socket - determine whether a real socket or not
 *
 */
int
_chk_socket( tcp_Socket *s )
{
    if ( s->ip_type == TCP_PROTO ) {
	if ( s->state <= tcp_StateCLOSED)       /* skips invalid data */
	    return( 2 );
    }
    if ( s->ip_type == UDP_PROTO ) return( 1 );
    return( 0 );
}

char *
w_inet_ntoa( char *s, longword x )
{
    *s='\0';
    itoa((int) (x >> 24), s, 10 );
    strcat( s, ".");
    itoa((int)(( x >> 16) & 0xff), strchr( s, 0), 10);
    strcat( s, ".");
    itoa((int)( x >> 8) & 0xff, strchr( s, 0), 10);
    strcat( s, ".");
    itoa((int)(x) & 0xff, strchr( s, 0), 10);
    return( s );
}

void
psocket( tcp_Socket *s )
{
    char buffer[255];

    outch( '[' );
    outs( w_inet_ntoa( buffer, s->hisaddr) );
    outch( ':' );
    itoa( s->hisport, buffer, 10 );
    outs( buffer );
    outch( ']' );
}

longword
inet_addr( char *s )
{
    if ( isaddr( s )) return( aton( s ));
    else return( 0 );
}

char *
sockerr( tcp_Socket *s )
{
    if ( strlen( s->err_msg ) < 80 ) return( s->err_msg );
    else return(NULL);
}

#ifdef unused /* new names are in newpctcp.c */
static char *sock_states[] = {
    "Listen",   "SynSent",      "SynRec",       "Established",
    "FinWt1",   "FinWt2",       "ClosWt",       "LastAck"
    "TmWt",     "Closed"};
#endif /* OLD */

char *
sockstate( tcp_Socket *s )
{
    switch ( _chk_socket( s )) {
       case  1 : return( "UDP Socket" );
       case  2 : return( state_names[ s->state ] );
       default : return( "Not an active socket");
    }
}

int
getpeername( tcp_Socket *s, void *dest, int *len )
{
    struct wat_sockaddr temp;
    int ltemp;

    memset( &temp, 0, sizeof( struct wat_sockaddr ));
    temp.s_ip = s->hisaddr;
    temp.s_port = s->hisport;

    if (!s->hisaddr || !s->hisport || ! _chk_socket( s )) {
	if (len) *len = 0;
	return( -1 );
    }

    /* how much do we move */
    ltemp = (len) ? *len : sizeof( struct wat_sockaddr );
    if (ltemp > sizeof( struct wat_sockaddr)) ltemp = sizeof( struct wat_sockaddr );
    memcpy(dest, &temp, ltemp );

    if (len) *len = ltemp;
    return( 0 );
}

int
wat_getsockname(tcp_Socket *s, void *dest, int *len)
{
    struct wat_sockaddr temp;
    int ltemp;

    memset( &temp, 0, sizeof( struct wat_sockaddr ));
    temp.s_ip = my_ip_addr;
    temp.s_port = s->myport;

    if (!s->hisaddr || !s->hisport || ! _chk_socket( s )) {
	if (len) *len = 0;
	return( -1 );
    }

    /* how much do we move */
    ltemp = (len) ? *len : sizeof( struct wat_sockaddr );
    if (ltemp > sizeof( struct wat_sockaddr)) ltemp = sizeof( struct wat_sockaddr );
    memcpy(dest, &temp, ltemp );

    if (len) *len = ltemp;
    return( 0 );
}

longword
gethostid(void)
{
    return( my_ip_addr );
}

longword
sethostid( longword ip )
{
    return( my_ip_addr = ip );
}

char *
getdomainname( char *name, int length )
{
    if ( length ) {
	if ( length < strlen( def_domain ))
	    *name = 0;
	else
	    strcpy( name, def_domain );
	return( name );
    }
    return( ( def_domain && *def_domain ) ? def_domain : NULL );
}

char *
setdomainname( char *string )
{
    return( def_domain = string );
}

char *
wat_gethostname( char *name, int len )
{
    if ( len ) {
	if (len < strlen( _hostname )) *name = 0;
	else strcpy( name, _hostname );
	return( name );
    }
    return( ( _hostname && *_hostname ) ?  _hostname  : NULL );
}

char *
sethostname( char *name )
{
    return( _hostname = name );
}
