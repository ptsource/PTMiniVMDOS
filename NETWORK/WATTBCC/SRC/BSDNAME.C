#include <copyright.h>
#include <stdio.h>
#include <wattcp.h>
#include <stdlib.h>    /* itoa */
#include <string.h>
#include <elib.h>


getpeername( tcp_Socket *s, void *dest, int *len )
{
    struct sockaddr temp;
    int ltemp;

    memset( &temp, 0, sizeof( struct sockaddr ));
    temp.s_ip = s->hisaddr;
    temp.s_port = s->hisport;

    if (!s->hisaddr || !s->hisport || ! _chk_socket( s )) {
        if (len) *len = 0;
        return( -1 );
    }

    /* how much do we move */
    ltemp = (len) ? *len : sizeof( struct sockaddr );
    if (ltemp > sizeof( struct sockaddr)) ltemp = sizeof( struct sockaddr );
    qmove( &temp, dest, ltemp );

    if (len) *len = ltemp;
    return( 0 );
}

getsockname(  tcp_Socket *s, void *dest, int *len )
{
    struct sockaddr temp;
    int ltemp;

    memset( &temp, 0, sizeof( struct sockaddr ));
    temp.s_ip = s->myaddr;
    temp.s_port = s->myport;

    if (!s->hisaddr || !s->hisport || ! _chk_socket( s )) {
        if (len) *len = 0;
        return( -1 );
    }

    /* how much do we move */
    ltemp = (len) ? *len : sizeof( struct sockaddr );
    if (ltemp > sizeof( struct sockaddr)) ltemp = sizeof( struct sockaddr );
    qmove( &temp, dest, ltemp );

    if (len) *len = ltemp;
    return( 0 );
}

char *getdomainname( char *name, int length )
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

char *setdomainname( char *string )
{
    return( def_domain = string );
}

char *gethostname( char *name, int len )
{
    if ( len ) {
	if (len < strlen( _hostname ))
	    *name = 0;
	else
	    strcpy( name, _hostname );
	return( name );
    }
    return( ( _hostname && *_hostname ) ?  _hostname  : NULL );
}
char *sethostname( char *name )
{
    return( _hostname = name );
}
void psocket( tcp_Socket *s )
{
    char buffer[255];

    outch( '[' );
    outs( inet_ntoa( buffer, s->hisaddr) );
    outch( ':' );
    itoa( s->hisport, buffer, 10 );
    outs( buffer );
    outch( ']' );

}
