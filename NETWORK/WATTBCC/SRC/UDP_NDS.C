#include <copyright.h>
#include <wattcp.h>
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

longword aton( text )
char *text;
{
    char *p;
    int i, cur;
    longword ip;

    ip = 0;

    if ( *text == '[' )
	++text;
    for ( i = 24; i >= 0; i -= 8 ) {
	cur = atoi( text );
	ip |= (longword)(cur & 0xff) << i;
	if (!i) return( ip );

	if (!(text = strchr( text, '.')))
	    return( 0 );	/* return 0 on error */
	++text;
    }
}

/*
 * isaddr
 *	- returns nonzero if text is simply ip address
 */
word isaddr( text )
char *text;
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

