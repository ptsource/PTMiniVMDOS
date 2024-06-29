/***
 * Filke: cout.c
 *
 * 16-Jun-92 lr
 * various output functions used for debugging and error messages
 ***/

#include <stdio.h>
void outch( unsigned char ch )
{
	putchar(ch);
}

void outs( unsigned char *s)
{
	puts(s);
}       

void outsn( unsigned char *s,unsigned n)
{
	while (n--) outch(*s++);
}

void outhex( unsigned char ch )
{
	unsigned char c;
		
	outch( (unsigned char) ((c=(unsigned char)(ch/16)) >9 ?
					c + 'A' - 10: c + '0'));
	outch( (unsigned char) ((c=(ch%16)) >9 ? c + 'A' - 10: c + '0'));
}

/*
 * outhexes - dump n hex bytes to stdio
 *
 */
void outhexes( unsigned char *p, unsigned n )
{
    while ( n-- > 0) {
	outhex( *p++);
	outch(' ');
    }
}
/*** end of file cout.c ***/
