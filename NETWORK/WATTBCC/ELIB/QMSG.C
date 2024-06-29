/*
 * debugging messages... can be used inside interrupts
 *
 */

static int far *screenptr = 0xB8000000L;
dputch( x )
char x;
{
    if (x == '\n') screenptr = 0xb8000000L;
    else *(screenptr++) = (x&0xff) | 0x700;
}
dmsg( s )
char *s;
{
    dputch('\n');
    while ( *s )
	dputch( *s++ );
}

dhex1int( x )
int x;
{
    x &= 0x0f;
    if ( x > 9 ) x = 'A' + x - 0xa;
    else x += '0';
    dputch( x );
}
dhex2int( x )
int x;
{
    dhex1int( x>>4 );
    dhex1int( x );
    dputch(' ');
}
dhex4int( x )
int x;
{
    dhex2int( x >> 8 );
    dhex2int( x );
}
