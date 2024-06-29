/***
 *
 * File: pcdbug.c
 *
 * 19-Jun-92 lr
 *
 */

#define WATTCP_KERNEL
#define PCDBUG
#include <tcp.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <ctype.h>

#define DEBUGNAME "WATTCP.DBG"

/************************** STATICS **********************/

static void db_msg( char *msg, tcp_Socket *sock, in_Header *ip, tcp_Header *tp);
static void _dbxmit( void *sock, void *ip, void *prot /*, void *data */);
static void _dbrecv( void *sock, void *ip, void *prot /*, void *data */);
static void ourinit(char *name, char *value );

static char localbuf[ 128 ];
static int localhandle = 0;
static char *tcpflag[] =
    /*  7  ,   6 ,  5  ,   4 ,   3 ,   2 ,   1 ,   0 */
      {"??7","??6","URG","ACK","PSH","RST","SYN","FIN" };

static void (*otherinit)();
/*********************** END OF STATICS ******************/

void
db_write( char *msg )
{
    write( localhandle, msg, strlen(msg));
}

static void
db_msg( char *msg, tcp_Socket *sock, in_Header *ip, tcp_Header *tp )
{
    int i,j,datalen, protocol;
    char ch, *data;
    udp_Header *up;

    switch ( protocol = ip->proto ) {
	case UDP_PROTO :if (!debugudp) return;
			up = (udp_Header*)(tp);
			datalen = intel16(up->length);
			data = (char *)(up) + sizeof( udp_Header );
			break;
	case TCP_PROTO :if (!debugtcp) return;
			i = (tcp_GetDataOffset(tp) << 2); /* qwords to bytes */
			j = ip->hdrlen << 2;
			data = (char*)(tp) + i;
			datalen = intel16(ip->length) - j - i;
			break;
	default	       : return;
    }
    if (!localhandle) {
    localhandle = creat( debugname, 0 );
	if (localhandle < 0 ) {
	    outs("ERROR:unable to open debug file!\n");
	    exit(3);
	}
    }
    /* skip packet if no data and that was all we were looking for */
    if (!debugheaders && !datalen) return;
    db_write( msg );
    if (!sock) {
        db_write( "NO SOCKET\n\n");
/*
        return;
*/
    }
    db_write( w_inet_ntoa( localbuf, sock->hisaddr ));
    db_write( ":" );
    db_write( itoa( sock->hisport, localbuf, 10));
    db_write( "   0.0.0.0:");
    db_write( itoa( sock->myport,  localbuf, 10));
    db_write("\n");
    if (debugheaders) {
	switch (protocol) {
	    case UDP_PROTO : db_write("UDP PACKET");
			     break;
	    case TCP_PROTO :
		db_write("    TCP : ");
		db_write( state_names[ sock->state ] );
		db_write("  (LSEQ: 0x");
		db_write(ltoa(sock->seqnum,localbuf,16));
		db_write("  LACK: 0x");
		db_write(ltoa(sock->acknum,localbuf,16));
                db_write(") NOW: ");
                db_write( ltoa( set_timeout(0), localbuf,10));
                db_write("\n    TCP FLAGS : ");
		for ( i = 0; i < 8 ; ++i ) {
			if ( intel16(tp->flags) & ( 0x80 >> i )) {
				db_write( tcpflag[i] );
				db_write(" ");
			}
		}

		db_write("  SEQ : 0x");
		db_write(ltoa(intel(tp->seqnum),localbuf,16));
		db_write("  ACK : 0x");
		db_write(ltoa(intel(tp->acknum),localbuf,16));
		db_write("  WINDOW : ");
		db_write(itoa(intel16(tp->window),localbuf,10));
                db_write("\n VJ_SA : ");
                db_write(itoa(sock->vj_sa ,localbuf,10 ) );
                db_write("  VJ_SD : ");
                db_write(itoa(sock->vj_sd,localbuf,10 ) );
                db_write("  RTO : ");
                db_write(itoa(sock->rto ,localbuf,10 ));
                db_write(" RTT : ");
                db_write(ltoa(sock->rtt_time ,localbuf,10 ));
                db_write(" RTTDIFF : ");
                db_write(ltoa(sock->rtt_time - set_ttimeout(0),localbuf,10 ));

		break;
	}
    db_write("\n");
    }
    if (debugdump) {
	for (i = 0; i < datalen ; i+= 16 ) {
	    sprintf(localbuf,"%04x : ", i );
	    db_write( localbuf );
	    for (j = 0 ; (j < 16) && (j +i < datalen) ; ++j ) {
                sprintf( localbuf, "%02x%c", data[j+i], (j==7)?'-':' ');
		db_write( localbuf );
	    }
	    for ( ; j < 16 ; ++j )
		db_write("   ");

	    memset( localbuf, 0, 17 );
	    for ( j = 0; (j<16) && (j+i<datalen) ; ++j ) {
		ch = data[j+i];
                if ( !isprint(ch) ) ch = '.';
                localbuf[j] = ch;
            }
            db_write( localbuf);
            db_write("\n");
        }
    }
    db_write("\n");
    if ( (i = dup( localhandle )) != -1 )
        close(i);
}

static void
_dbxmit( void *sock, void *ip, void *prot )
{
    db_msg("Transmitted:",sock,ip,prot);
}

static void
_dbrecv( void *sock, void *ip, void *prot )
{
    db_msg("Received:",sock,ip,prot);
}



static void
ourinit(char *name, char *value )
{
    if (!strcmp(name,"DEBUG.FILE")) {
        strncpy(debugname, value, sizeof(debugname)-2);
        debugname[sizeof(debugname) -1] = 0;
    } else if (!strcmp(name,"DEBUG.MODE")) {
        if (!stricmp( value, "DUMP" )) debugdump = 1;
	if (!stricmp( value, "HEADERS")) debugheaders =1;
        if (!stricmp( value, "ALL")) debugheaders = debugdump = 1;
    } else if (!strcmp(name,"DEBUG.PROTO")) {
        if (!stricmp( value, "TCP")) debugtcp = 1;
	if (!stricmp( value, "UDP")) debugudp =1;
        if (!stricmp( value, "ALL")) debugudp = debugtcp = 1;
    } else if (otherinit)
	(*otherinit)(name,value);
}

void
dbuginit(void)
{
    strcpy(debugname,DEBUGNAME );
    otherinit = usr_init;
    usr_init = ourinit;
    _dbugxmit = _dbxmit;
    _dbugrecv = _dbrecv;
    debugheaders = debugdump = debugudp = debugtcp = 0;
}
