/****
 *
 * File: udp_nds.c
 *
 * 18-Jun-92 lr
 *
 */

#include <tcp.h>
#include <string.h>
#include <ctype.h>

/*
 * Name Domain Service
 *
 * V
 *  0.0 : Jan 11, 1991 : E. Engelke
 */

/*
 * aton()
 *	- converts [a.b.c.d] or a.b.c.d to 32 bit long
 *	- returns 0 on error (safer than -1)
 */

longword
aton( char *text )
{
    int i, cur;
    longword ip=0;

    if ( *text == '[' ) ++text;
    for ( i = 24; i >= 0; i -= 8 ) {
	cur = atoi( text );
	ip |= (longword)(cur & 0xff) << i;
	if (!i) return( ip );

	if (!(text = strchr( text, '.')))
	    return( 0 );	/* return 0 on error */
	++text;
    }
    return(ip); /* NOTREACHED */
}

/*
 * isaddr
 *	- returns nonzero if text is simply ip address
 */
word
isaddr( char *text )
{
    char ch;
    while ( ch = *text++ ) {
	if ( isdigit(ch) ) continue;
	if ( ch == '.' || ch == ' ' || ch == '[' || ch == ']' )
	    continue;
	return( 0 );
    }
    return( 1 );
}
