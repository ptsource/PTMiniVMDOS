#include <stdlib.h>
#include <wattcp.h>


extern void (*wattcpd)();

#define MAXD = 50;

static void (**backd)() = NULL;
word lastd;

static dowattcpd()
{
    void (**p)() = backd;
    int count = lastd;
    do {
        if ( *p ) (**p)();
    } while ( count-- );
}

int addwattcpd( void (*p)() )
{
    int i;
    if ( wattcpd == NULL ) {
        backd = calloc( MAXD, sizeof( void (*)()));
        if ( backd ) wattcpd = dowattcpd;
    }
    for ( i = 0; i < MAXD ; ++i ) {
        if ( backd[i] == NULL ) {
            backd[i] = p;
            break;
        }
    }
    if ( i < MAXD ) {
        if ( lastd <= i ) lastd = i+1;
        return( 0 );
    }
    return( -1 );
}
int delwattcpd( void (*p)() )
{
    int i, j;
    for ( i = 0; i < MAXD; ++i )
        if ( backd[i] == p ) {
            backd[i] = NULL;
            break;
        }
    for ( j = i+1 ; j < lastd ; ++j )
        if ( backd[j] ) i = j;
    lastd = i+1;
}
