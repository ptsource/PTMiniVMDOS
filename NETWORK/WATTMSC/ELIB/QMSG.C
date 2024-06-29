/***
 *
 * File: qmsg.c
 *
 * 18-Jun-92 lr
 *
 * debugging messages... can be used inside interrupts
 *
 * I suspect it is not used anywhere - lr
 */

static int far *screenptr = (int far *)0xB8000000L;
void dputch( char x )
{
    if (x == '\n') screenptr = (int far *)0xb8000000L;
    else *(screenptr++) = (x&0xff) | 0x700;
}
void dmsg( char *s )
{
    dputch('\n');
    while ( *s )
	dputch( *s++ );
}

void dhex1int( int x )
{
    x &= 0x0f;
    if ( x > 9 ) x = 'A' + x - 0xa;
    else x += '0';
    dputch( (char)x );
}
void dhex2int( int x )
{
    dhex1int( x>>4 );
    dhex1int( x );
    dputch(' ');
}
void dhex4int( int x )
{
    dhex2int( x >> 8 );
    dhex2int( x );
}
