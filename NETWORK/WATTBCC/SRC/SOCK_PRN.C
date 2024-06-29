#include <copyright.h>
#include <wattcp.h>

#include <stdio.h>
#include <stdarg.h>
#include <string.h>

/* socket based stuff */

static char buffer[ tcp_MaxBufSize ];

sock_printf( sock_type *s, char *format, ... )
{
    va_list argptr;
    int length;

    va_start( argptr, format );
    vsprintf( buffer, format, argptr );
    va_end( argptr );

    if ( (length = strlen( buffer )) > tcp_MaxBufSize ) {
	outs("ERROR: tcp sock_Printf overrun\n\r");
	return( 0 );
    }
    sock_puts( s, buffer );
    return( length );
}

/*
 * sock_scanf - return number of fields returned
 */
sock_scanf( sock_type *s, char *format, ... )
{
    va_list argptr;
    char buffer[ tcp_MaxBufSize ];
    int fields;
    int status;

    fields = 0;
    while (!( status = sock_dataready( s ))) {
	if (status == -1) return( -1 );
    if ( fields = sock_gets( s, buffer, tcp_MaxBufSize )) {
            va_start( argptr, format );
	    fields = vsscanf( buffer, format, argptr );
	    va_end( argptr );
	}
    }
    return( fields );
}
