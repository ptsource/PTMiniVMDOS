/*
 * outhexes - dump n hex bytes to stdio
 *
 */

outhexes( p, n )
char far *p;
int n;
{
    while ( n-- > 0) {
        outhex( *p++);
        outch(' ');
    }
}
