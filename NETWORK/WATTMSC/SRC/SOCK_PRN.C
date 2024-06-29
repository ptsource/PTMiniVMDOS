/***
 *
 * File: sock_prn
 *
 * 27-Aug-93 lr	- final cleanup
 * 18-Jun-92 lr
 *
 */

#define WATTCP_KERNEL
#include <tcp.h>

#include <stdarg.h>
#include <string.h>

/* socket based stuff */


int
sock_printf( sock_type *s, char *format, ... )
{
    va_list argptr;
    static char buffer[ DEFAULT_BUFSIZE ];
    int length;

    va_start( argptr, format );
    vsprintf( buffer, format, argptr );
    va_end( argptr );

    if ( (length = strlen( buffer )) > DEFAULT_BUFSIZE ) {
	outs("ERROR: tcp sock_Printf overrun\n\r");
	return( 0 );
    }
    sock_puts( s, buffer );
    return( length );
}

/*
 * sock_scanf - return number of fields returned
 */
int
sock_scanf( sock_type *s, char *format, ... )
{
    va_list argptr;
    static char buffer[ DEFAULT_BUFSIZE ];
    int fields;
    int status;

    fields = 0;
    while (!( status = sock_dataready( s ))) {
	if (status == -1) return( -1 );
    if ( fields = sock_gets( s, buffer, DEFAULT_BUFSIZE )) {
	    va_start( format, argptr );
	    fields = vsscanf( buffer, format, argptr );
	    va_end( argptr );
	}
    }
    return( fields );
}
