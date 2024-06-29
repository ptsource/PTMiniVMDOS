/* DEBUG flag may be set for my internal playing */

/*
#define DEBUG
*/

/*
 *  PCTCP - the true worker of Waterloo TCP
 *   	  - contains all opens, closes, major read/write routines and
 *	    basic IP handler for incomming packets
 *	  - NOTE: much of the TCP/UDP/IP layering is done at the data structure
 *	    level, not in separate routines or tasks
 *
 */



#include <copyright.h>
#include <time.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <conio.h>
#include <string.h>
#include <mem.h>
#include <dos.h>
#include <values.h>

#include "wattcp.h"
#include "elib.h"

static void udp_handler(in_Header *ip);
static udp_write(udp_Socket *s, byte *datap, int len, word offset);
static int udp_read(udp_Socket *s, byte *datap, int maxlen);
static void tcp_Retransmitter(void);


#define TCP_LOCAL 0x4000

/* statics */
static tcp_ProcessData(tcp_Socket *s, tcp_Header *tp, int len);

static char far *mono = (char far *)0xb0000000L;
static char far *colour = (char far *)0xb8000000L;

static initialized = 0;
static void (*system_yield)() = NULL;
extern int multihomes;
extern word _pktipofs;
void (*_dbugxmit)() = NULL;
void (*_dbugrecv)() = NULL;
void (*wattcpd)() = NULL;

char *_hostname = "012345678901234567890123456789012345678901234567890";

word _mss = ETH_MSS;

char *_wattcp = WATTCP_C;

static void tcp_handler(in_Header *ip);
static void udp_handler(in_Header *ip);
extern void icmp_handler(in_Header *ip );

static void tcp_unthread(tcp_Socket *ds);
static void tcp_abort(tcp_Socket *s);
void tcp_sendsoon(tcp_Socket *s );
static tcp_send(tcp_Socket *s, int line);
tcp_rst( in_Header *his_ip, tcp_Header *oldtcpp);
static udp_close(udp_Socket *ds);


/*
 * sock_yield - enable user defined yield function
 */
sock_yield( tcp_Socket *s, void (*fn)())
{
    if ( s )
	s->usr_yield = fn;
    else
	system_yield = fn;
    return( 0 );
}

/*
 * sock_mode - set binary or ascii - affects sock_gets, sock_dataready
 *	     - set udp checksums
 */
word sock_mode( sock_type *s, word mode )
{
     return( s->tcp.sock_mode = (s->tcp.sock_mode & 0xfffc) | mode);
}

/*
 * ip user level timer stuff
 *   void ip_timer_init( void *s, int delayseconds )
 *   int  ip_timer_expired( void *s )
 *	- 0 if not expired
 */
static unsigned long far *realclock = (unsigned long far *)0x000046cL;
#define MAXTICKS 0x1800b0L

void ip_timer_init( udp_Socket *s , int delayseconds )
{
    if (delayseconds)
	s->usertimer = set_timeout( delayseconds );
    else
	s->usertimer = 0;
}

int ip_timer_expired( udp_Socket *s )
{
    if (! s->usertimer)	/* cannot expire */
	return( 0 );
    return( chk_timeout( s->usertimer));
}
longword MsecClock()
{
    return( (*realclock) * 055L);
}
static long make_timeout( word timeout )
{
    if ( timeout ) return( set_timeout( timeout ));
    return( 0 );
}
/*
 * check_timeout - test agains timeout clock - account for overflow
 */
static int check_timeout( unsigned long timeout )
{
    if (timeout) return( chk_timeout( timeout ));
    return( 0 );
}

/*
 * Local IP address
 */
longword my_ip_addr = 0L;	/* for external references */
longword sin_mask = 0xfffffe00L;
longword sin_gate = 0x0;


/*
 * IP identification numbers
 */

static int ip_id = 0;			/* packet number */
static int next_tcp_port = 1024;	/* auto incremented */
static int next_udp_port = 1024;
static tcp_Socket *tcp_allsocs = NULL;
static udp_Socket *udp_allsocs = NULL;

/* Timer definitions */
#define RETRAN_STRAT_TIME  1     /* in ticks - how often do we check retransmitter tables*/
#define tcp_RETRANSMITTIME 3     /* interval at which retransmitter is called */
#define tcp_LONGTIMEOUT 31       /* timeout for opens */
#define tcp_TIMEOUT 13           /* timeout during a connection */

word debug_on = 0;

/*
 * look for bugs
 */
tcp_checkfor( tcp_Socket *t )
{
    tcp_Socket *p;

    for ( p = tcp_allsocs ; p ; p = p->next )
        if ( p == t ) return( 1 );
    return( 0 );
}

/*
 * Shut down the card and all services
 */
void tcp_shutdown()
{
    while (tcp_allsocs)
	tcp_abort( tcp_allsocs );
    _eth_release();
    initialized = 0;
}

/*
 * tcp_Init - Initialize the tcp implementation
 *	    - may be called more than once without hurting
 */
void tcp_init()
{
    extern int _arp_last_gateway;
    extern int _last_nameserver;

    if (!initialized) {
	/* initialize ethernet interface */
	initialized = 1;
	_eth_init();

	/* reset the various tables */
	_arp_last_gateway = 0;	/* reset the gateway table */
	_last_nameserver = 0;	/* reset the nameserver table */
	_last_cookie = 0;	/* eat all remaining crumbs */
	*_hostname = 0;		/* reset the host's name */

	_eth_free( 0 );
	next_udp_port = next_tcp_port = 1024 + ((*realclock >> 7 )& 0x1ff);
    }
}

/*
 * Checks for bugs when compiling in large model C compiler
 *
 * Borland C uses a 4K stack by default.  In all memory models the
 * stack grows down toward the heap.
 *
 * If you accidentally place tcp_Socket onto the stack (like by making
 * it an automatic variable), then you will have already used up that
 * whole 4K and then some!
 *
 * In large model, this will mess up the data space in a major way
 * because the stack starts at SS:_stklen, or SS:1000, so you will
 * wrap the SP pointer back around to FFFE and start writing over
 * the far heap.  Yuck.
 *
 * In small model it usually doesn't kill your application because
 * you would have to be down to your last 4K of memory and this is
 * not as common.
 *
 * The solutions: declare your sockets as static, or put them on the
 * heap, or bump up your stack size by using the global special variable:
 *
 * unsigned _stklen = 16536;    // set stack to 16 k
 */
static void largecheck( void *s, int size )
{
#ifdef __TURBOC__
    if ( (word)(FP_OFF(s)) > (word)(-size)) {
        outs("ERROR: user stack size error\n");
        exit( 3 );
    }
#endif
}

/*
 * findfreeport - return unused local port
 *              - oldport = 0:normal port, 1:special port (513-1023)
 *              - we need not be this picky, but it doesn't hurt
 */
static word findfreeport( word oldport )
{
    word temp;
    tcp_Socket *s;

    if (( oldport > 0 ) && (oldport < 0xffff))
        return( oldport );

    if ( oldport == 0 ) oldport = 1025;
    else oldport = 513;

    for ( temp = oldport ; temp < oldport + 510 ; ++temp ) {
        if (( s = (tcp_Socket*)udp_allsocs) != NULL ) {
            while ( s->next && (s->myport != temp))
                s = (tcp_Socket*)s->next;
            if ( s->myport == temp ) continue;
        }
        if ( (s = tcp_allsocs ) != NULL ) {
            while ( s->next && (s->myport != temp ))
                s = s->next;
            if ( s->myport == temp ) continue;
        }
        break;
    }
    return( temp );
}

/* socket, localport, destaddress */
int udp_open(udp_Socket *s, word lport, longword ina, word port, procref datahandler)
{
    udp_close( s );
    largecheck( s, sizeof( udp_Socket ));
    memset( s, 0, sizeof( udp_Socket ));
    s->rdata = s->rddata;
    s->maxrdatalen = tcp_MaxBufSize;
    s->ip_type = UDP_PROTO;

    lport = findfreeport(lport);

    s->myport = lport;
    s->myaddr = my_ip_addr;

    /* check for broadcast */
    if ( (long)(ina) == -1 || !ina )
	memset( s->hisethaddr, 0xff, sizeof( eth_address ));
    else if ( ! _arp_resolve(ina, (eth_address *) &s->hisethaddr[0], 0) )
	return( 0 );

    s->hisaddr = ina;
    s->hisport = port;
    s->dataHandler = datahandler;
    s->usr_yield = system_yield;
    s->safetysig = SAFETYUDP;
    s->next = udp_allsocs;
    udp_allsocs = s;
    return( 1 );
}

/*
 * Actively open a TCP connection to a particular destination.
 *	- 0 on error
 */
int tcp_open(tcp_Socket *s, word lport, longword ina, word port, procref datahandler)
{
    largecheck( s, sizeof( tcp_Socket ));   /* stack space warnings */
    tcp_unthread(s);                        /* just in case not totally closed */

    memset( s, 0, sizeof( tcp_Socket));
    s->rdata = s->rddata;
    s->maxrdatalen = tcp_MaxBufSize;
    s->ip_type = TCP_PROTO;
    s->mss = _mss;
    s->state = tcp_StateSYNSENT;
    s->timeout = set_timeout( tcp_LONGTIMEOUT );
    s->cwindow = 1;
    s->wwindow = 0;     /* slow start VJ algorithm */
    s->vj_sa = 4;      /* about 250 ms */
    lport = findfreeport( lport );  /* get a nonzero port val */
    s->myaddr = my_ip_addr;
    s->myport = lport;

    if ( ina - my_ip_addr <= multihomes ) return( 0 );
    if ( ! _arp_resolve(ina, (eth_address *) &s->hisethaddr[0], 0) )
	return( 0 );

    s->hisaddr = ina;
    s->hisport = port;
    s->seqnum = intel( set_timeout( 1 )) & 0xffff0000;
    s->datalen = 0;
    s->flags = tcp_FlagSYN;
    s->unhappy = true;
    s->dataHandler = datahandler;
    s->usr_yield = system_yield;

    s->safetysig = SAFETYTCP;       /* insert into chain */
    s->next = tcp_allsocs;
    tcp_allsocs = s;

    s->rtt_delay = s->rtt_smooth = 18;	/* one second startup */
    tcp_send(s, __LINE__ );
    s->rtt_time = set_timeout( 1 );
    return( 1 );
}

/*
 * Passive open: listen for a connection on a particular port
 */
int tcp_listen(tcp_Socket *s, word lport, longword ina, word port, procref datahandler, word timeout)
{
    largecheck( s, sizeof( tcp_Socket ));
    tcp_unthread(s);                        /* just in case not totally closed */
    memset( s, 0, sizeof( tcp_Socket));
    s->rdata = s->rddata;
    s->maxrdatalen = tcp_MaxBufSize;
    s->ip_type = TCP_PROTO;
    s->mss = _mss;
    s->cwindow = 1;
    s->wwindow = 0;     /* slow start VJ algorithm */
    s->vj_sa = 36;      /* about 250 ms */

    s->state = tcp_StateLISTEN;
    if ( !timeout ) s->timeout = 0; /* forever... */
    else s->timeout = set_timeout( timeout );
    lport = findfreeport( lport );  /* get a nonzero port val */
    s->myport = lport;
    s->hisport = port;
    s->hisaddr = ina;
    s->seqnum = intel( (word)(s));
    s->datalen = 0;
    s->flags = 0;
    s->unhappy = false;
    s->dataHandler = datahandler;
    s->usr_yield = system_yield;

    s->safetysig = SAFETYTCP;       /* insert into chain */
    s->next = tcp_allsocs;
    tcp_allsocs = s;

    return( 1 );
}


static udp_close(udp_Socket *ds)
{
    udp_Socket *s, **sp;

    sp = &udp_allsocs;
    for (;;) {
        s = *sp;
        if ( s == ds ) {
            *sp = s->next;
            break;
        }
	if ( !s ) break;
	if ( ! s->err_msg ) s->err_msg = "UDP Close called";
	sp = &s->next;
    }
    return( 0 );
}

/*
 * Send a FIN on a particular port -- only works if it is open
 *   Must still allow receives
 */
static void tcp_close(tcp_Socket *s)
{
    if ( s->ip_type != TCP_PROTO )
	return;
    if ( s->state == tcp_StateESTAB ||
         s->state == tcp_StateESTCL ||
         s->state == tcp_StateSYNREC ) {

       if ( s->datalen ) {     /* must first flush all data */
            s->flags |= tcp_FlagPUSH | tcp_FlagACK;
            if ( s->state < tcp_StateESTCL ) {
                s->state = tcp_StateESTCL;
		tcp_sendsoon( s );
            }
        } else { /* really closing */
            s->flags = tcp_FlagACK | tcp_FlagFIN;
            if (!s->err_msg)
                s->err_msg = "Connection closed normally";
            s->state = tcp_StateFINWT1;
            s->timeout = set_timeout( 4 ); /* should be a pretty lengthy time */
            tcp_send( s, __LINE__ );
        }
        s->unhappy = true;
    } else if (s->state == tcp_StateCLOSWT ) {
        /* need to ack the fin and get on with it */
        s->state = tcp_StateLASTACK;
        s->flags |= tcp_FlagFIN;
        tcp_send( s, __LINE__ );
        s->unhappy = true;
    }
}

/*
 * Abort a tcp connection
 */
static void tcp_abort(tcp_Socket *s)
{
    if (!s->err_msg) s->err_msg = "TCP_ABORT";
    if ( s->state != tcp_StateLISTEN && s->state != tcp_StateCLOSED ) {
        s->flags = tcp_FlagRST  | tcp_FlagACK ;
        s->unhappy = true;
        tcp_send(s, __LINE__);
    }
    s->unhappy = false;
    s->datalen = 0;
    s->ip_type = 0;
    s->state = tcp_StateCLOSED;
/*    if (s->dataHandler) s->dataHandler(s, 0, -1); */
    tcp_unthread(s);
}

void sock_abort(tcp_Socket *s )
{
    if ( s->ip_type == TCP_PROTO )
	tcp_abort( s );
    else
        udp_close( (udp_Socket *)s );
}
/*
 * tcp_sendsoon - schedule a transmission pretty soon
 *		- this one has an imperfection at midnight, but it
 *		  is not significant to the connection performance
 */
void tcp_sendsoon(tcp_Socket *s )
{
    longword temp;
    if (s->ip_type == TCP_PROTO ) {
	temp = set_ttimeout( 1 );
        if ( temp == s->rtt_time && s->rto < 2 && s->recent == 0 ) {
            s->karn_count = 0;
            tcp_send( s, __LINE__ );
            s->recent = 1;
            return;
        }
        if ((s->unhappy || s->datalen > 0 || s->karn_count == 1)
          && (s->rtt_time < temp ))
            return;

        s->rtt_time = set_ttimeout( 1 + (s->rto >> 4) );
	s->karn_count = 1;
    }
}

/*
 * Retransmitter - called periodically to perform tcp retransmissions
 */
static longword retran_strat = 0L; /* timeout retran strategy */
static void tcp_Retransmitter(void)
{
    tcp_Socket *s;

    /* only do this once per RETRAN_STRAT_TIME milliseconds */
    if ( !chk_timeout( retran_strat ))
	return;
    retran_strat = set_ttimeout( RETRAN_STRAT_TIME );

    for ( s = tcp_allsocs; s; s = s->next ) {
        if ( s->datalen > 0 || s->unhappy || s->karn_count == 1 ) {
	    /* retransmission strategy */
	    if ( chk_timeout( s->rtt_time)) {

#ifdef DEBUG
    if(debug_on >1) printf("regular retran TO set unacked back to 0 from %u\n", s->unacked);
#endif DEBUG
                /* strategy handles closed windows   J.D. + E.E. */
               if (s->window == 0 && s->karn_count == 2)
                  s->window = 1;
 
                if ( s->karn_count == 0 ) {
                    /* if really did timeout */

 
                    s->karn_count = 2;

                    s->unacked = 0;
                    /* use the backed off rto - implied, no code necessary */
                    /* reduce the transmit window */
                    s->cwindow =  ((s->cwindow + 1) * 3) >> 2;
                    if ( s->cwindow == 0 ) s->cwindow = 1;
                    s->wwindow = 0;
                }
                if (s->datalen)
                    s->flags |= tcp_FlagPUSH | tcp_FlagACK;
                tcp_send(s, __LINE__);
	    }
	}
        /* handle inactive tcp timeouts */
        if ( sock_inactive && s->inactive_to ) {
            if ( chk_timeout( s->inactive_to)) {
                /* this baby has timed out */
                s->err_msg = "Connection timed out - no activity";
                sock_close( (sock_type *) s );
            }
        }
        if ( s->timeout && chk_timeout( s->timeout)) {
	    if ( s->state == tcp_StateTIMEWT ) {
		s->state = tcp_StateCLOSED;
		tcp_unthread(s);
                break;
            } else if (s->state != tcp_StateESTAB && s->state != tcp_StateESTCL ) {
		s->err_msg = "Timeout, aborting";
		tcp_abort(s);
                break;
	    }
	}
    }
    /* do our various daemons */
    if ( wattcpd ) (*wattcpd)();
}


/*
 * Unthread a socket from the tcp socket list, if it's there
 */
static void tcp_unthread(tcp_Socket *ds)
{
    tcp_Socket *s, **sp;

    if (!ds->rdatalen || (ds->state > tcp_StateESTCL))
        ds->ip_type = 0;                /* fail io */
    ds->state = tcp_StateCLOSED;   /* tcp_tick needs this */
    sp = &tcp_allsocs;
    for (;;) {
	s = *sp;
	if ( s == ds ) {
	    *sp = s->next;
            continue;           /* unthread multiple copies if necessary */
	}
	if ( !s ) break;
	sp = &s->next;
    }
}

/*
 * tcp_tick - called periodically by user application
 *	    - returns 1 when our socket closes
 *	    - called with socket parameter or NULL
 */
tcp_tick( sock_type *s )
{
    in_Header *ip;
    static longword timeout = 0;
    static longword start = 0;

    int x;
    int packettype;

    /* finish off dead sockets */
    if ( s ) {
        if (( s->tcp.ip_type == TCP_PROTO ) &&
            ( s->tcp.state == tcp_StateCLOSED ) &&
            ( s->tcp.rdatalen == 0 )) {
                tcp_unthread( & s->tcp );
		s->tcp.ip_type = 0;
        }
    }


    /* plan our next retransmit */

    if ( !timeout )
	timeout = make_timeout( tcp_RETRANSMITTIME );

    while ( ip = (in_Header *)_eth_arrived( (word *) &packettype ) ) {
	start = *realclock;

	switch ( packettype ) {
	case /*0x800*/ 0x008 :
	    /* do IP */
	    if ( checksum(ip, in_GetHdrlenBytes(ip)) == 0xffff ) {
		switch ( ip->proto ) {
		    case TCP_PROTO :
			tcp_handler(ip);
			break;
		    case UDP_PROTO :
			udp_handler(ip);
			break;
		    case ICMP_PROTO :
			icmp_handler(ip);
			break;
		}
	    } else  {
		if (debug_on)
		    outs("IP Received BAD Checksum \n\r");
	    }
	    break;
	case /*0x806*/ 0x608 :
            /* do arp */
	    _arp_handler(ip);
	    break;
	}
	if (ip) _eth_free(ip);

	continue;
    }
    /* check for our outstanding packets */
	tcp_Retransmitter();

    return( s->udp.ip_type );
}

void tcp_set_debug_state( x )
int x;
{
    debug_on = x;
}

/* returns 1 if connection is established */
int tcp_established(tcp_Socket *s)
{
    return( s->state >= tcp_StateESTAB );
}

/*
 * udp_write() handles fragmented UDP by assuming it'll be called
 *     once for all fragments with no intervening calls.  This is
 *     the case in sock_write().
 * Handles upto a hair-under 32K datagrams.  Could be made to handle
 *     upto a hair-under 64K easily...  wanna Erick?
 * Might be possible to test 'offset' for non/zero fewer times to be
 *     more efficient.  Might also be more efficient to use the old
 *     UDP checksum() call when more_frags is false in the first frag
 *     (i.e., not a fragmented dgram).
 * Uses _mss to decide splits which defaults to 1400.  Could pack
 *     more into an Ethernet packet.
 */
#define IP_MF 0x0020               // more fragments, net byte order

static udp_write(udp_Socket *s, byte *datap, int len, word offset)
{
    struct {                    // special pseudo header because need to
        tcp_PseudoHeader ph;    //    compute checksum in two parts (may not
        word checksum2;         //    have all of datagram built at once).
    } ph;
    struct _pkt {
	in_Header  in;
	udp_Header udp;
	int	   data;
/*	longword maxsegopt; */
    } *pkt;
    byte *dp;
    in_Header *inp;
    udp_Header *udpp;

    word maxlen;
    int more_frags;
    word origlen = len;

    pkt = (struct _pkt *)_eth_formatpacket(&s->hisethaddr[0], /*0x800*/ 8);

    if( offset ) {              // this is not the first fragment
        dp = (byte *) &pkt->udp;    // data goes right after IP header
    } else {
        dp = (byte *) &pkt->data;
        udpp = &pkt->udp;

        /* udp header */
        udpp->srcPort = intel16( s->myport );
        udpp->dstPort = intel16( s->hisport );
        udpp->checksum = 0;
        udpp->length = intel16( UDP_LENGTH + len );
    }
    inp = &pkt->in;

    memset( inp, 0, sizeof( in_Header ));

    maxlen = _mss & 0xFFF8;             // make a multiple of 8
    if( !offset ) maxlen -= UDP_LENGTH; // note UDP_LENGTH is 8, so ok

    if( len > maxlen ) {
        len = maxlen;
        more_frags = 1;
    } else more_frags = 0;

    inp->length = intel16( sizeof(in_Header) +
                                     (offset ? 0 : UDP_LENGTH) + len );
    movmem(datap, dp, len );

    /* internet header */
    inp->ver = 4;
    inp->hdrlen = 5;
    inp->tos = 0;
/* inp->vht = 0x4500;*/   /* version 4, hdrlen 5, tos 0 */
 /* if offset non-zero, then is part of a prev datagram so don't incr ID */
    inp->identification = intel16( offset ? ip_id : ++ip_id );   /* was post inc */
//    inp->frag = 0;
    inp->frags = (offset ? intel16((offset + UDP_LENGTH) >> 3) : 0);
    if(more_frags) inp->frags |= IP_MF;
    inp->ttl = 254;
    inp->proto = UDP_PROTO;	/* udp */
/* inp->ttlProtocol = (250<<8) + 6; */
    inp->checksum = 0;
    inp->source = intel( s->myaddr );
    inp->destination = intel( s->hisaddr );
    inp->checksum = ~checksum( inp, sizeof(in_Header));


    /* compute udp checksum if desired */
    if(!offset) {  // only first of frags has UDP header for entire UDP dgram
        if ( s->sock_mode & UDP_MODE_NOCHK )
	    udpp->checksum = 0;
        else {
	    ph.ph.src = inp->source;	/* already INTELled */
	    ph.ph.dst = inp->destination;
	    ph.ph.mbz = 0;
	    ph.ph.protocol = UDP_PROTO;	/* udp */
	    ph.ph.length = udpp->length;	/* already INTELled */

          /* can't use since may not have the whole dgram built at once */
//	    ph.checksum = checksum(&pkt->udp, intel16(ph.length));
          /* this way handles it */
            ph.ph.checksum = checksum(&pkt->udp, UDP_LENGTH);
            ph.checksum2 = checksum(datap, origlen);

	    udpp->checksum =  ~checksum(&ph, sizeof(ph));
        }
    }
    
    if (_dbugxmit) (*_dbugxmit)(s,inp,udpp,0);
    _eth_send( intel16( inp->length ));

    return ( len );
}

/*
 * udp_read - read data from buffer, does large buffering
 */
static int udp_read(udp_Socket *s, byte *datap, int maxlen)
{
    int x;

    if (maxlen < 0) maxlen = MAXINT;
    if (( x = s->rdatalen ) > 0) {
	if ( x > maxlen ) x = maxlen;
	if ( x > 0 ) {
            if (datap) movmem( s->rdata, datap, x );
	    if ( s->rdatalen -= x )
                movmem( s->rdata + x, s->rdata, s->rdatalen);
	}
    }
    return( x );
}

void _udp_cancel( in_Header *ip )
{
    int len;
    udp_Header *up;
    udp_Socket *s;

    /* match to a udp socket */
    len = in_GetHdrlenBytes(ip);
    up = (udp_Header *)((byte *)ip + len);	/* udp frame pointer */

    /* demux to active sockets */
    for ( s = udp_allsocs; s; s = s->next )
        if ( s->hisport != 0 &&
             intel16( up->dstPort ) == s->hisport &&
             intel16( up->srcPort ) == s->myport &&
             intel( ip->destination ) == s->hisaddr ) break;
    if ( !s ) {
	/* demux to passive sockets */
	for ( s = udp_allsocs; s; s = s->next )
	    if ( s->hisport == 0 && intel16( up->dstPort ) == s->myport ) break;
    }
    if (s) {
        s->rdatalen = 0;
	s->ip_type = 0;
    }
}

void *_tcp_lookup( longword hisip, word hisport, word myport )
{
    tcp_Socket *s;
    for ( s = tcp_allsocs; s; s = s->next ) {
        if ( ( myport == s->myport ) &&         /* always unique under WATTCP */
             ( hisport == s->hisport ) &&
             ( hisip == s->hisaddr ))
                return( s );
    }
    return( NULL );
}


void _tcp_cancel(in_Header *ip, int code, char *msg, longword dummyip )
{
    static int in_icmp_redirect = 0;            // smart@actrix.gen.nz
    int len;
    tcp_Socket *s;
    tcp_Header *tp;

    len = in_GetHdrlenBytes(ip);	/* check work */

    tp = (tcp_Header *)((byte *)ip + len);	/* tcp frame pointer */

    /* demux to active sockets */
    for ( s = tcp_allsocs; s; s = s->next ) {
        if ( intel16( tp->srcPort) == s->myport &&
             intel16( tp->dstPort ) == s->hisport &&
             intel( ip->destination ) == s->hisaddr ) {
                switch (code) {
                    /* halt it */
                    case  1 : if (( s->stress ++ > s->rigid ) &&
                                  ( s->rigid < 100 )) {
                                  s->err_msg = (msg) ?
                                    msg : "ICMP closed connection";
                                  s->rdatalen = s->datalen = 0;
                                  s->unhappy = false;
                                  tcp_abort( s );
                /*      if (s->dataHandler) s->dataHandler(s, 0, -1); */
                                  break;
                              }
                              // follow through to next case

                    /* slow it down */
                    case  2 : s->cwindow = 1;
                              s->wwindow = 1;
                              s->rto <<= 2;
                              s->vj_sa <<= 2;
                              s->vj_sd <<= 2;
                              break;
                    /* icmp redirect for host */
                    case  5 : /* save his NEW network address */
                        /* Dummy is passed in NW form need to intel! */
                        /* This was a bug fixed QVS - smart@actrix.gen.nz */
                              if (!in_icmp_redirect)
                              {
                                  in_icmp_redirect = 1;
                                  _arp_resolve(intel(dummyip), (eth_address*)&s->hisethaddr[0], 0);
                                  in_icmp_redirect = 0;
                              }
                              break;
                }
        }
    }
}

static int tcp_read(tcp_Socket *s, byte *datap, int maxlen)
{
    int x;

    if (maxlen < 0 ) maxlen = MAXINT;
    if (( x = s->rdatalen) > 0) {
	if ( x > maxlen ) x = maxlen;
        if ( x > 0 ) {
            if (datap) movmem( s->rdata, datap, x );
            if (( s->rdatalen -= x ) > 0 ) {
                movmem( s->rdata + x, s->rdata, s->rdatalen );
                tcp_sendsoon( s );   /* update the window */
            } else
                tcp_send( s, __LINE__ );      /* update window el-pronto */
	}
    } else if ( s->state == tcp_StateCLOSWT )
        tcp_close( s );
    return( x );
}

/*
 * Write data to a connection.
 * Returns number of bytes written, == 0 when connection is not in
 * established state.
 */
static tcp_write(tcp_Socket *s, byte *dp, int len)
{
    int x;

    if (len < 0 ) len = MAXINT;
    /* no longer uses tcp_MaxData */
    if ( s->state != tcp_StateESTAB ) len = 0;
    if ( len > (x = s->maxrdatalen - s->datalen) ) len = x;
    if ( len > 0 ) {
        movmem( dp, s->data + s->datalen, len );

	s->datalen += len;
	s->unhappy = true;	/* redundant because we have outstanding data */

        if ( s->sock_mode & TCP_LOCAL )
            s->sock_mode &= ~TCP_LOCAL;
        else {
            if ( s->sock_mode & TCP_MODE_NONAGLE ) {
                tcp_send( s, __LINE__ );
            } else {
                /* transmit if first data or reached MTU */
                /* not true MTU, but better than nothing */
                if (( s->datalen == len ) || ( s->datalen > (s->mss)/2 ))
                    tcp_send( s, __LINE__ );
                else
                    tcp_sendsoon( s );
            }
	}
    }

    return ( len );
}

/*
 * Send pending data
 */
static void tcp_Flush(tcp_Socket *s)
{
    if ( s->datalen > 0 ) {
        s->flags |= tcp_FlagPUSH;
        tcp_send(s, __LINE__);
    }
}

/*
 * Handler for incoming packets.
 */
static void udp_handler(in_Header *ip)
{
    udp_Header *up;
    tcp_PseudoHeader ph;
    word len;
    byte *dp;
    longword temp;
    udp_Socket *s;

    temp = intel( ip->destination );

    // temp = ip number
    //     or 255.255.255.255
    //     or sin_mask.255.255

    if ( ((~temp & ~sin_mask) != 0) &&  /* not a broadcast packet*/
        ((( temp - my_ip_addr) > multihomes )   /* not my address */
        && my_ip_addr))                 /* and I know my address */
          return;


    len = in_GetHdrlenBytes(ip);
    up = (udp_Header *)((byte *)ip + len);	/* udp segment pointer */
    len = intel16( up->length );

    /* demux to active sockets */
    for ( s = udp_allsocs; s; s = s->next ) {
        if ( s->safetysig != SAFETYUDP ) {
            if (debug_on) outs("chain error in udp\r\n");
        }
        if ( (s->hisport != 0) &&
             (intel16( up->dstPort ) == s->myport) &&
             (intel16( up->srcPort ) == s->hisport) &&
             ((intel( ip->destination ) & sin_mask)  == (s->myaddr & sin_mask)) &&
             (intel( ip->source ) == s->hisaddr )) break;
    }
    if (_dbugrecv) (*_dbugrecv)(s,ip,up,0);
    if ( !s ) {
        /* demux to passive sockets */
	for ( s = udp_allsocs; s; s = s->next )
            if ( ((s->hisaddr == 0) || (s->hisaddr == 0xffffffff))
              && intel16( up->dstPort ) == s->myport ) {

                // do we record this information ???
                if ( s->hisaddr == 0 ) {
                    s->hisaddr = intel( ip->source );
                    s->hisport = intel16( up->srcPort );
                    _arp_resolve(intel(ip->source), &s->hisethaddr[0], 0);
                    // take on value of expected destination unless it
                    // is broadcast
                    if ( (~ip->destination & ~sin_mask) != 0 )
                        s->myaddr = intel( ip->destination );
                }
		break;
	    }
    }
    if ( !s ) {
	/* demux to broadcast sockets */
	for ( s = udp_allsocs; s; s = s->next )
            if ( (s->hisaddr == 0xffffffff) &&
                 (intel16( up->dstPort ) == s->myport )) break;
    }

    if ( !s ) {
	if (debug_on) outs("discarding...");
	return;
    }

    // these parameters are used for things other than just checksums
    ph.src = ip->source;    /* already INTELled */
    ph.dst = ip->destination;
    ph.mbz = 0;
    ph.protocol = UDP_PROTO;
    ph.length = up->length;
    if ( up->checksum ) {
	ph.checksum =  checksum(up, len);
	if (checksum(&ph, sizeof( tcp_PseudoHeader)) != 0xffff)
	    return;
    }

    /* process user data */
    if ( (len -= UDP_LENGTH ) > 0) {
	dp = (byte *)( up );
        if (s->dataHandler) s->dataHandler( s, &dp[ UDP_LENGTH ], len , &ph, up);
	else {
            if (len > s->maxrdatalen ) len = s->maxrdatalen;
	    movmem( &dp[ UDP_LENGTH ], s->rdata, len );
	    s->rdatalen = len;
	}
    }
}

static void tcp_handler(in_Header *ip)
{
    tcp_Header *tp;
    tcp_PseudoHeader ph;
    int len;
    byte *dp;
    int diff;
    tcp_Socket *s;
    word flags;
    long diffticks, ldiff;	/* must be signed */
    long scheduleto;


    if ( (longword)(intel( ip->destination ) - my_ip_addr) > multihomes )
        return;

    len = in_GetHdrlenBytes(ip);
    len = intel16( ip->length ) - len;		/* len of tcp data */

    len = in_GetHdrlenBytes(ip);
    tp = (tcp_Header *)((byte *)ip + len);	/* tcp frame pointer */
    len = intel16( ip->length ) - len;		/* len of tcp data */
    flags = intel16( tp->flags );

    if (debug_on > 1) {
            mono[160]++;
            colour[160]++;
            mono[162] = colour[162] = (flags & tcp_FlagSYN) ? 'S' : ' ';
            mono[164] = colour[164] = (flags & tcp_FlagACK) ? 'A' : ' ';
            mono[166] = colour[166] = (flags & tcp_FlagFIN) ? 'F' : ' ';
            mono[168] = colour[168] = (flags & tcp_FlagRST) ? 'R' : ' ';
        }

    /* demux to active sockets */
    for ( s = tcp_allsocs; s; s = s->next ) {
        if ( s->safetysig != SAFETYTCP ) {
            if (debug_on) outs("chain error in tcp\r\n");
        }
	if ( s->hisport != 0 &&
	     intel16( tp->dstPort ) == s->myport &&
	     intel16( tp->srcPort ) == s->hisport &&
             intel( ip->destination )   == s->myaddr     &&
	     intel( ip->source ) == s->hisaddr ) break;
    }
    if ( !s && (flags & tcp_FlagSYN)) {
	/* demux to passive sockets, must be a new session */
	for ( s = tcp_allsocs; s; s = s->next )
            if ((s->hisport == 0) && (intel16( tp->dstPort ) == s->myport )) {
                s->myaddr = intel( ip->destination );
		break;
            }
    }


    if (_dbugrecv) (*_dbugrecv)(s,ip,tp,0);
    if ( !s ) {
        if (!(flags & tcp_FlagRST)) tcp_rst( ip, tp );
	return;
    }

    ph.src = ip->source;	/* already INTELled */
    ph.dst = ip->destination;
    ph.mbz = 0;
    ph.protocol = TCP_PROTO;
    ph.length = intel16( len );
    ph.checksum =  checksum(tp, len);
    if ( checksum(&ph, sizeof(ph)) != 0xffff ) {
	 if (debug_on) outs("bad tcp checksum \n\r");

         /* tester */
         ph.checksum =  checksum(tp, len);
         checksum(&ph, sizeof(ph));

         tcp_sendsoon( s );
	 return;
    }

/* reset code */
    if ( flags & tcp_FlagRST ) {
	if (debug_on) outs("\7\7\7\7\7\7\7connection reset\n");
        s->rdatalen = s->datalen = 0;
        s->err_msg = "Remote reset connection";
	s->state = tcp_StateCLOSED;
/*	if (s->dataHandler) s->dataHandler(s, 0, -1); */
	tcp_unthread(s);
	return;
    }

    if ( sock_inactive )
        s->inactive_to = set_timeout( sock_inactive );


    /* update our retransmission stuff */
    /* new algorithms */
    if (s->karn_count == 2) {
        s->karn_count = 0;
#ifdef DEBUG
        if (debug_on > 1 ) printf("finally got it safely zapped from %u to ????\n\r",s->unacked);
#endif /* DEBUG */
    } else {
        if ( s->vj_last ) {
            /* unnecessary to use unhappy || s->datalen ) */
            if ((diffticks = set_ttimeout( 0 ) - s->vj_last) >= 0 ) {
                /* we ignore the overnight case */
                diffticks -= (longword)( s->vj_sa >> 3 );
                s->vj_sa += (int)diffticks;
                if (diffticks < 0)
                    diffticks = - diffticks;
                diffticks -= (s->vj_sd >> 2);
                s->vj_sd += (int)diffticks;
                if (s->vj_sa > MAXVJSA) s->vj_sa = MAXVJSA;
                if (s->vj_sd > MAXVJSD) s->vj_sd = MAXVJSD;
            }
            /* only recompute rtt hence rto after success */
            s->rto = 1 + ((s->vj_sa >> 2) + (s->vj_sd)) >> 1 ;
#ifdef DEBUG
            if (debug_on > 1 ) printf("rto  %u  sa  %u  sd  %u   cwindow %u  wwindow %u  unacked %u\n",
                s->rto, s->vj_sa, s->vj_sd, s->cwindow, s->wwindow, s->unacked );
#endif /* DEBUG */
	}
        s->karn_count = 0;
        if ( s->wwindow != 255 ) {
            if ( s->wwindow++ >= s->cwindow ) {
                if ( s->cwindow != 255 )
                    s->cwindow ++;
            }
            s->wwindow = 0;
        }
    }
    /* all new */
    scheduleto = set_ttimeout( s->rto + 2 );
    if ( s->rtt_time < scheduleto ) s->rtt_time = scheduleto;


    switch ( s->state ) {

	case tcp_StateLISTEN:	/* accepting SYNs */
            /* save his ethernet address */
            if ( _pktipofs )
                movmem(&((((eth_Header *)ip) - 1)->source[0]), &s->hisethaddr[0], sizeof(eth_address));
            if ( flags & tcp_FlagSYN ) {

                if ( ip->tos > s->tos )
                    s->tos = ip->tos;
                else if ( ip->tos < s->tos ) {
                    /* RFC 793 says we should close connection */
                    /* we best not do that while SunOS ignores TOS */
                }

                s->acknum = intel( tp->seqnum ) + 1;
		s->hisport = intel16( tp->srcPort );
		s->hisaddr = intel( ip->source );
		s->flags = tcp_FlagSYN | tcp_FlagACK;
                s->state = tcp_StateSYNREC;
		s->unhappy = true;
                tcp_send(s, __LINE__);    /* we must respond immediately */

		s->timeout = set_timeout( tcp_TIMEOUT );
	    } else
		tcp_rst( ip , tp );  /* send a reset */

            return;

    case tcp_StateSYNSENT:  /* added ACK Section */
	    if ( flags & tcp_FlagSYN ) {

                if ( ip->tos > s->tos )
                    s->tos = ip->tos;
                else if ( ip->tos < s->tos ) {
                    /* RFC 793 says we should close connection */
                    /* we best not do that while SunOS ignores TOS */
                }

                s->flags = tcp_FlagACK;
		s->timeout = set_timeout( tcp_TIMEOUT );

		/* FlagACK means connection established, else SYNREC */
		if ( flags & tcp_FlagACK) {
		    /* but is it for the correct session ? */
                if (tp->acknum == intel(s->seqnum + 1)) {
                s->state = tcp_StateESTAB;
                s->seqnum++;    /* good increment */
                s->acknum = intel( tp->seqnum  ) + 1;   /* 32 bits */
                tcp_ProcessData(s, tp, len);    /* someone may try it */
                s->unhappy = true;             /* rely on their attempts */
                tcp_send( s, __LINE__ );
            } else {
                /* wrong ack, force a RST and resend SYN soon*/
                s->flags = tcp_FlagRST;
                s->unhappy = true;
                tcp_send( s, __LINE__ );
                s->flags = tcp_FlagSYN;
                tcp_send( s, __LINE__ );
		    }
		} else {
		    s->acknum++;
		    s->state = tcp_StateSYNREC;
                    return;
		}
            } else
                tcp_rst( ip, tp );
	    break;

	case tcp_StateSYNREC:	/* recSYNSENT, sentACK, waiting  EST */
	    if ( flags & tcp_FlagSYN ) {
		s->flags = tcp_FlagSYN | tcp_FlagACK;
		s->unhappy = true;
                tcp_send(s, __LINE__);
		s->timeout = set_timeout( tcp_TIMEOUT );
                return;
	    }
	    if ( (flags & tcp_FlagACK) && (intel( tp->acknum ) == (s->seqnum + 1))) {
                if ( (s->window = intel16( tp->window )) > 0x7fff )
                    s->window = 0x7fff;
		s->flags = tcp_FlagACK;
                s->state = tcp_StateESTAB;
                s->seqnum++;
                s->timeout = 0;     /* never timeout */
                s->unhappy = false;
                return;
	    }

	    break;
	case tcp_StateESTAB:
        case tcp_StateESTCL:
        case tcp_StateCLOSWT:

            /* handle lost SYN */
            if ((flags & tcp_FlagSYN) && (flags & tcp_FlagACK)) {
                tcp_send( s, __LINE__ );
                return;
            }

	    if ( !(flags & tcp_FlagACK)) return;  /* must ack somthing */
            if ( flags & tcp_FlagSYN ) {
                tcp_rst( ip , tp );
                return;
            }
	    s->timeout = 0l;	/* we do not timeout at this point */

	    /* process ack value in packet - but only if it falls
	     * within current window */

	    ldiff = intel( tp->acknum ) - s->seqnum;
	    diff = (int) ldiff;

            if ( ldiff >= 0 && diff <= s->datalen ) {
		s->datalen -= diff;
                s->unacked -= diff;
                if (s->datalen < 0) s->datalen = 0; /* remote proto error */
                if ( s->queuelen ) {
                    s->queue += diff;
                    s->queuelen -= diff;
                } else
                    movmem(s->data + diff, s->data, s->datalen );
		s->seqnum += ldiff;
            } else {
#ifdef DEBUG
    if(debug_on >1) printf("tcphandler confused so set unacked back to 0 from %u\n",s->unacked);
#endif DEBUG
                s->unacked = 0;
            }
            if (s->unacked < 0) s->unacked = 0;

	    s->flags = tcp_FlagACK;
	    tcp_ProcessData(s, tp, len);

            if (( flags & tcp_FlagFIN ) && (s->state != tcp_StateCLOSWT )
                && ( s->acknum == intel( tp->seqnum ))) {
                s->acknum ++;
                if ( ! s->err_msg ) s->err_msg = "Connection closed";
                s->state = tcp_StateCLOSWT;
                tcp_send( s, __LINE__ );
                s->state = tcp_StateLASTACK;
                s->flags |= tcp_FlagFIN;
                s->unhappy = true;
            }

            if ( diff > 0 || len > 0 ) {
                /* need to update window, but how urgent ??? */
                if ( diff > 0 || (len > (s->mss >> 1))) {
                    tcp_send( s, __LINE__ );
                } else
                    tcp_sendsoon( s );

            }
            if ( s->state == tcp_StateESTCL )
                tcp_close( s );
            return;

	case tcp_StateFINWT1:
	    /* They have not necessarily read all the data yet, we must
	       still supply it as requested */

	    ldiff = intel( tp->acknum ) - s->seqnum;
	    diff = (int) ldiff;
	    if ( ldiff >= 0 && diff <= s->datalen ) {
		s->datalen -= diff;
                s->unacked -= diff;
                if (s->datalen < 0) s->datalen = 0;
                if ( s->queuelen ) {
                    s->queue += diff;
                    s->queuelen -= diff;
                } else
                    movmem(s->data + diff, s->data, s->datalen );
		s->seqnum += ldiff;
                if (ldiff == 0 || s->unacked < 0) s->unacked = 0;

	    }

	    /* they may still be transmitting data, we must read it */

	    tcp_ProcessData(s, tp, len);

	    /* check if other tcp has acked all sent data and is ready
	       to change states */

            if ( (flags & (tcp_FlagFIN|tcp_FlagACK) ) == (tcp_FlagFIN|tcp_FlagACK)) {
		/* trying to do similtaneous close */
		if (( intel( tp->acknum ) >= s->seqnum + 1 ) &&
		    ( intel( tp->seqnum) == s->acknum )) {
		    s->seqnum++;
// we shouldn't be inc'ing the ack
//                  s->acknum++;
                    s->flags = tcp_FlagACK;
                    tcp_send( s, __LINE__ );
                    s->unhappy = false;
                    s->timeout = set_timeout( 2 );
                    s->state = tcp_StateCLOSED;
		}
	    } else if ( flags & tcp_FlagACK ) {
		/* other side is legitimately acking our fin */
		if (( intel( tp->acknum ) == s->seqnum + 1 ) &&
		    ( intel( tp->seqnum ) == s->acknum ) &&
		    (  s->datalen == 0 )) {
                        s->seqnum++;
// they are just acking our seq num, not sending more data for us to ack
//                      s->acknum++;
                        s->state = tcp_StateFINWT2;
                        s->timeout = set_timeout( 3 );
                        s->unhappy = false; /* we don't send anything */
		}
	    }
	    break;

	case tcp_StateFINWT2:

	    /* they may still be transmitting data, we must read it */
	    tcp_ProcessData(s, tp, len);

            if ((flags & (tcp_FlagACK | tcp_FlagFIN)) ==
                  (tcp_FlagACK | tcp_FlagFIN)) {
                if (( intel( tp->acknum ) == s->seqnum) &&
		    ( intel( tp->seqnum ) == s->acknum )) {
		    s->acknum++;
		    s->flags = tcp_FlagACK;
                    tcp_send( s, __LINE__ );
		    s->unhappy = false;	/* we don't send anything */
		    s->timeout = set_timeout( 2 );
                    s->state = tcp_StateCLOSED;
                    return;
                }
	    }
	    break;

	case tcp_StateCLOSING:
	    if ((flags & (tcp_FlagACK | tcp_FlagFIN)) == tcp_FlagACK ) {
		if (( tp->acknum == intel(s->seqnum) ) &&
		    ( tp->seqnum == intel(s->acknum))) {
		    s->state = tcp_StateTIMEWT;
		    s->timeout = set_timeout( tcp_TIMEOUT );
		    s->unhappy = false;
		}
	    }
	    break;

	case tcp_StateLASTACK:
	    if ( flags & tcp_FlagFIN ) {
		/* they lost our two packets, back up */
		s->flags = tcp_FlagACK | tcp_FlagFIN;
                tcp_send( s, __LINE__ );
                s->unhappy = TRUE;  /* FALSE; */
                return;
	    } else {
		if (( intel( tp->acknum ) == (s->seqnum + 1 )) &&
		    ( intel( tp->seqnum ) == s->acknum )) {
			s->state = tcp_StateCLOSED;     /* no 2msl necessary */
			s->unhappy = false;             /* we're done */
                        return;
		    }
	    }
	    break;

	case tcp_StateTIMEWT:
            if ( flags & (tcp_FlagACK | tcp_FlagFIN) == (tcp_FlagACK | tcp_FlagFIN)) {
                /* he needs an ack */
                s->flags = tcp_FlagACK;
                tcp_send( s, __LINE__ );
                s->unhappy = false;
                s->state = tcp_StateCLOSED;     /* support 2 msl in rst code */
            }
            break;
	}
    if (s->unhappy) tcp_sendsoon(s);
}

/*
 * Process the data in an incoming packet.
 * Called from all states where incoming data can be received: established,
 * fin-wait-1, fin-wait-2
 */
static tcp_ProcessData(tcp_Socket *s, tcp_Header *tp, int len)
{
    long ldiff;
    int diff, x;
    word flags;
    byte *dp;

    word *options, numoptions, opt_temp;

    if ( s->stress > 0 ) s->stress--;

    if ( (s->window = intel16( tp->window )) > 0x7fff )
        s->window = 0x7fff;

    flags = intel16( tp->flags );
    ldiff = s->acknum - intel( tp->seqnum );

    if ( flags & tcp_FlagSYN ) ldiff--;  /* back up to 0 */
    diff = (int) ldiff;

    /* find the data portion */
    x = tcp_GetDataOffset(tp) << 2;	/* quadword to byte format */
    dp = (byte *)tp + x;

    /* process those options */
    if ( (numoptions = x - sizeof( tcp_Header )) != 0 ) {
	options = (word *)((byte *)(tp) + sizeof( tcp_Header));
	while ( numoptions-- > 0 ) {
	    switch ( *options++ ) {
		case  0 : numoptions = 0;	/* end of options */
			  break;
		case  1 : break;		/* nop */

			  /* we are very liberal on MSS stuff */
		case  2 : if (*options == 2) {
			      opt_temp = intel16( *(word*)(&options[1]));
			      if (opt_temp < s->mss )
				  s->mss = opt_temp;
			  }
			  numoptions -= 2 + *options;
			  options += *options;
			  break;
	    }
	}
    }
    /* done option processing */

    len -= x;		/* remove the header length */
    if ( ldiff >= 0 ) {  /* skip already received bytes */
	dp += diff;
	len -= diff;

	if (s->dataHandler) {
	    s->acknum += s->dataHandler(s, dp, len);
	} else {
	    /* no handler, just dump to buffer, should be indexed, handles goofs */
	    /* limit receive size to our window */
	    if ( s->rdatalen >= 0 ) {
                if ( len > ( x = s->maxrdatalen - s->rdatalen )) {
		    len = x;
                }
		if ( len > 0 ) {
		    s->acknum += len;	/* our new ack begins at end of data */
                    movmem(dp, s->rdata + s->rdatalen, len );
		    s->rdatalen += len;
/*
                    s->karn_count = 3;
*/
		}
	    }
        }
        s->unhappy = (s->datalen) ? true : false;
        if (ldiff == 0 && s->unacked && chk_timeout( s->rtt_lasttran )) {
#ifdef DEBUG
            if(debug_on >1) printf("data process timeout so set unacked back to 0 from %u\n",s->unacked);
#endif DEBUG
            s->unacked = 0;
        }
    } else {
        tcp_sendsoon( s );
    }

    s->timeout = set_timeout( tcp_TIMEOUT );
    return;
}

/*
 * Format and send an outgoing segment
 */

static tcp_send(tcp_Socket *s, int line)
{
    tcp_PseudoHeader ph;
    struct _pkt {
	in_Header in;
	tcp_Header tcp;
	word maxsegopt[2];
    } *pkt;
    byte *dp;
    in_Header *inp;
    tcp_Header *tcpp;
    int senddatalen, sendtotlen, sendpktlen, startdata, sendtotdata;

    int ippkt; 		/* 1..s->cwindow */

    s->recent = 0;
    pkt = (struct _pkt *)_eth_formatpacket(&s->hisethaddr[0], /*0x800*/ 8);
    dp = (byte *) &pkt->maxsegopt;  /* dp constant for multi-packet sends */
    inp = &pkt->in;
    tcpp = &pkt->tcp;


    /* this is our total possible send size */
    if ( s->karn_count != 2 ) {
        /* BUG FIX : jason dent found this */
/*      sendtotdata = min( s->datalen - s->unacked, s->window );  */
        sendtotdata = max (min ( s->datalen, s->window ) - s->unacked, 0);
        startdata = s->unacked;
    } else {
        sendtotdata = (s->datalen >= s->window)? s->window : s->datalen;
        startdata = 0;
    }
/*
    if (sendtotdata < 0) sendtotdata = 0;
*/
    sendtotlen = 0;	/* running count of what we've sent */

    /* step through our packets */
    for ( ippkt = 1; ippkt <= s->cwindow; ++ippkt ) {
        /* adjust size for each packet */
        senddatalen = min( sendtotdata, s->mss );

    /*
        sendpktlen = senddatalen + sizeof( tcp_Header ) + sizeof( in_Header );
        inp->length = intel16( sendpktlen );
    */
        /* tcp header */
        tcpp->srcPort = intel16( s->myport );
        tcpp->dstPort = intel16( s->hisport );
        tcpp->seqnum = intel( s->seqnum + startdata ); /* unacked - no longer sendtotlen */
        tcpp->acknum = intel( s->acknum );

        tcpp->window = intel16( s->maxrdatalen - s->rdatalen );
        tcpp->flags = intel16( s->flags | 0x5000 );
        tcpp->checksum = 0;
        tcpp->urgentPointer = 0;

        /* do options if this is our first packet */
        if ( s->flags & tcp_FlagSYN ) {
            sendpktlen = sizeof( tcp_Header ) + sizeof( in_Header ) + 4;
            tcpp->flags = intel16( intel16( tcpp->flags) + 0x1000 );
            pkt->maxsegopt[0] = 0x0402;
            pkt->maxsegopt[1] = intel16( s->mss );
            dp += 4;
        } else {
            /* handle packets with data */
            if (senddatalen > 0) {
                sendpktlen = senddatalen + sizeof( tcp_Header ) + sizeof( in_Header );

                /* get data from appropriate place */
                if (s->queuelen) movmem(s->queue + startdata, dp, senddatalen );
                else movmem(s->data + startdata, dp, senddatalen);
/*                dp[ senddatalen ] = 0; */
            } else {
            /* handle no-data, not-first-SYN packets */
                sendpktlen = sizeof( tcp_Header ) + sizeof( in_Header );
            }
        }

        /* internet header */
        memset( inp, 0, sizeof( in_Header ));
        inp->ver = 4;
        inp->hdrlen = 5;
        inp->tos = s->tos;
        inp->identification = intel16( ++ip_id );   /* was post inc */
//        inp->frag = 0;
        inp->ttl = 254;
        inp->proto = TCP_PROTO;
        inp->checksum = 0;
        inp->source = intel( s->myaddr );
        inp->destination = intel( s->hisaddr );
        inp->length = intel16( sendpktlen );

        inp->checksum = ~checksum( inp, sizeof(in_Header));

        /* compute tcp checksum */
        ph.src = inp->source;   /* already INTELled */
        ph.dst = inp->destination;
        ph.mbz = 0;
        ph.protocol = 6;
        ph.length = intel16( sendpktlen - sizeof(in_Header));
/*
        ph.checksum = checksum(&pkt->tcp, (sendpktlen - sizeof(in_Header) +1) & 0xfffe);
*/
        ph.checksum = checksum(&pkt->tcp, sendpktlen - sizeof(in_Header));

        tcpp->checksum = ~checksum(&ph, sizeof(ph));

        if (_dbugxmit) (*_dbugxmit)(s,inp,tcpp, line);
        if (debug_on > 1) {
            mono[0]++;
            colour[0]++;
            mono[2] = colour[2] = (s->flags & tcp_FlagSYN) ? 'S' : ' ';
            mono[4] = colour[4] = (s->flags & tcp_FlagACK) ? 'A' : ' ';
            mono[6] = colour[6] = (s->flags & tcp_FlagFIN) ? 'F' : ' ';
            mono[8] = colour[8] = (s->flags & tcp_FlagRST) ? 'R' : ' ';
        }
        if ( _eth_send( intel16( inp->length ))) { /* encounterred error */
            tcp_sendsoon( s );
            return;
        }

        /* do next ip pkt */
        sendtotlen += senddatalen;
        startdata += senddatalen;
        sendtotdata -= senddatalen;
        if (sendtotdata <= 0 ) break;
    }
    s->unacked = startdata;
#ifdef DEBUG
if (debug_on) printf(" Sent %u/%u bytes in %u/%u packets  with (%u) unacked  SYN %lu  line %u\n",
        sendtotlen, s->window, ippkt, s->cwindow, s->unacked, s->seqnum, line);
#endif DEBUG
    s->vj_last = 0;
    if ( s->karn_count == 2 ) {
        if (s->rto) s->rto = (s->rto * 3) / 2;
        else s->rto = 4;
    } else {
        /* vj_last nonzero if we expect an immediate response */
        if (s->unhappy || s->datalen)
            s->vj_last = set_ttimeout( 0 );
	s->karn_count = 0;
    }
    s->rtt_time = set_ttimeout( s->rto + 2 );
    if (sendtotlen > 0 ) s->rtt_lasttran =  s->rtt_time + s->rto;
}
/*
 * Format and send a reset tcp packet
 */
tcp_rst( in_Header *his_ip, tcp_Header *oldtcpp)
{
    tcp_PseudoHeader ph;
    struct _pkt {
        in_Header in;
        tcp_Header tcp;
	word maxsegopt[2];
    } *pkt, *his_pkt;

    static longword nextrst = 0L;
    word oldflags;
    in_Header *inp;
    tcp_Header *tcpp;
    eth_Header *eth;
    int sendtotlen;	/* length of packet */
    int temp;
    longword templong;

    /* see RFC 793 page 65 for details */

    if ( !chk_timeout( nextrst )) return;
    nextrst = set_ttimeout( 1 );

    oldflags = intel16( oldtcpp->flags );
    if (oldflags & tcp_FlagRST ) return;
#ifdef NEVER
    if ( (oldflags & (tcp_FlagACK | tcp_FlagFIN)) == (tcp_FlagACK | tcp_FlagFIN) ){
        templong = oldtcpp->seqnum;
        oldtcpp->seqnum = oldtcpp->acknum;
        oldtcpp->acknum = templong;
        oldflags = tcp_FlagACK;
    } else if ((oldflags & (tcp_FlagSYN | tcp_FlagACK)) ==  tcp_FlagSYN ) {
        oldtcpp->acknum = intel( intel( oldtcpp->seqnum ) + 1 );
        oldtcpp->seqnum = 0;
        oldflags = tcp_FlagACK | tcp_FlagRST;
    } else if ( oldflags & tcp_FlagACK ) {
        oldtcpp->seqnum = oldtcpp->acknum;
        oldtcpp->acknum = 0;
    } else {
        oldtcpp->acknum = intel( intel(oldtcpp->seqnum) + 1);
        oldtcpp->seqnum = 0;
    }
    if ( oldflags & ( tcp_FlagFIN | tcp_FlagSYN ) == 0 )
        oldflags ^= tcp_FlagACK | tcp_FlagRST;

    if ( oldflags & tcp_FlagACK ) {
        oldtcpp->seqnum = oldtcpp->acknum;

#else
    /* better strategy - Dean Roth */
    if ( oldflags & tcp_FlagACK ) {
        oldtcpp->seqnum = oldtcpp->acknum;
        oldtcpp->acknum = 0;
        oldflags = tcp_FlagRST;
    } else if ((oldflags & (tcp_FlagSYN | tcp_FlagACK)) ==  tcp_FlagSYN ) {
        oldtcpp->acknum = intel( intel( oldtcpp->seqnum ) + 1 );
        oldtcpp->seqnum = 0;
        oldflags = tcp_FlagACK | tcp_FlagRST;
    } else {
        temp = intel16( his_ip->length) - in_GetHdrlenBytes( his_ip );
        oldtcpp->acknum = intel( intel( oldtcpp->seqnum ) + temp );
        oldtcpp->seqnum = 0;
        oldflags = tcp_FlagRST;
    }
#endif

    his_pkt  = (struct _pkt*)( his_ip );

    /* convoluted mechanism - reads his ethernet address or garbage */
    eth = _eth_hardware( his_ip );

    pkt = (struct _pkt *)_eth_formatpacket( eth, 8);
    inp = &pkt->in;
    tcpp = &pkt->tcp;

    sendtotlen = sizeof( tcp_Header ) + sizeof( in_Header );
    memset( inp, 0, sizeof( in_Header ));
    inp->length = intel16( sendtotlen );

    /* tcp header */
    tcpp->srcPort = oldtcpp->dstPort;
    tcpp->dstPort = oldtcpp->srcPort;
    tcpp->seqnum = oldtcpp->seqnum;
    tcpp->acknum = oldtcpp->acknum;
    tcpp->window = 0;
/*    tcpp->flags = intel16( oldflags ); */
    /* BUG FIX : jason dent found this thanks to SCO */
    tcpp->flags = intel16( (oldflags & 0x0fff ) | 0x5000 );
    tcpp->checksum = 0;
    tcpp->urgentPointer = 0;

    /* internet header */
    inp->ver = 4;
    inp->hdrlen = 5;
    inp->tos = his_ip->tos;
    inp->identification = intel16( ++ip_id );
//    inp->frag = 0;
    inp->ttl = 254;
    inp->proto = TCP_PROTO;
    inp->checksum = 0;
    inp->source = his_ip->destination;
    inp->destination = his_ip->source;

    inp->checksum = ~checksum( inp, sizeof(in_Header))/* 0*/;

    /* compute tcp checksum */
    ph.src = inp->source;	/* already INTELled */
    ph.dst = inp->destination;
    ph.mbz = 0;
    ph.protocol = 6;
    ph.length = intel16( sendtotlen - sizeof(in_Header));

    ph.checksum = checksum(&pkt->tcp, sizeof(tcp_Header));
    tcpp->checksum =  ~checksum(&ph, sizeof(ph));

    if (_dbugxmit) (*_dbugxmit)(NULL,inp,tcpp,__LINE__);
    _eth_send( intel16( inp->length ));
}




/**********************************************************************
 * socket functions
 **********************************************************************/

/* socket based stuff */

/*
 * sock_read - read a socket with maximum n bytes
 *	     - busywaits until buffer is full but calls s->usr_yield
 *	     - returns count also when connection gets closed
 */
sock_read(sock_type *s, byte *dp, int len )
{
    int templen, count;
    count = 0;
    do {
	if ( s->udp.ip_type == UDP_PROTO )
            templen = udp_read( &(s->udp), dp, len );
	else
            templen = tcp_read( &(s->tcp), dp, len);
        if (s->tcp.usr_yield) (s->tcp.usr_yield)();
        if (templen < 1 ) {
            if (!tcp_tick( s )) return( count );
        } else {
            count += templen;
            dp += templen;
            len -= templen;
        }
    } while ( len );
    return( count );
}
/*
 * sock_fead - read a socket with maximum n bytes
 *	     - does not busywait until buffer is full
 */
sock_fastread(sock_type *s, byte *dp, int len )
{
    if ( s->udp.ip_type == UDP_PROTO )
        len = udp_read( &(s->udp), dp, len );
    else
        len = tcp_read( &(s->tcp), dp, len);
    return( len );
}


/*
 * sock_write - writes data and returns length written
 *	      - does not perform flush
 *	      - repeatedly calls s->usr_yield
 */

sock_write(sock_type *s, byte *dp, int len)
{
    int offset, oldlen, oldmode, proto;

    oldlen = len;
    offset = 0;

    proto = (s->udp.ip_type == TCP_PROTO);
    if ( proto ) oldmode = s->tcp.flags & tcp_FlagPUSH;
    while ( len  > 0) {
        if (proto) {
            s->tcp.flags |= oldmode;
            offset += tcp_write( &(s->udp), &dp[ offset ], len);
        } else
            offset += udp_write( &(s->tcp), &dp[ offset ], len, offset );
	len = oldlen - offset;
	if (s->udp.usr_yield)(s->udp.usr_yield)();
	if (!tcp_tick(s)) return( 0 );
    }
    return( oldlen );
}


/* NOTE: for UDP, assumes data fits in one datagram, else only the first
       fragment will be sent!!!!!  Because _mss is used for splits,
       by default the max data size is 1400 - UDP_LENGTH for a non-fragged
       datagram.
 */
sock_fastwrite(sock_type *s, byte *dp, int len)
{
    return( ( s->udp.ip_type == UDP_PROTO ) ?
        udp_write( s, dp, len, 0 ) :
        tcp_write( s, dp, len) );
}

int sock_setbuf( sock_type *s, byte *dp, int len )
{
    if ( len < 0 ) return( 0 );
    if (len == 0 || dp == NULL ) {
        s->tcp.rdata = s->tcp.rddata;
        s->tcp.maxrdatalen = tcp_MaxBufSize;
    } else {
        s->tcp.rdata = dp;
        s->tcp.maxrdatalen = len;
    }
    return( s->tcp.maxrdatalen);
}

int sock_enqueue(sock_type *s, byte *dp, int len )
{
    int written;
    word offset = 0;

    if ( len < 0 ) return( 0 );
    if ( s->udp.ip_type == UDP_PROTO ) {
        do {
            written = udp_write( s, dp, len, offset );
            dp += written;
            offset += written;
        } while (len -= written > 0);
    } else {
        s->tcp.queue = dp;
        s->tcp.queuelen = len;
        s->tcp.datalen = len;
        tcp_send( s, __LINE__ );  /* start sending it */
    }
    return( len );
}

void sock_noflush( sock_type *s )
{
    if ( s->tcp.ip_type == TCP_PROTO ) {
	s->tcp.flags &= ~tcp_FlagPUSH;
	s->tcp.sock_mode |= TCP_LOCAL ;
    }
}
void sock_flush( sock_type *s )
{
    if ( s->tcp.ip_type == TCP_PROTO ) {
        s->tcp.sock_mode &= ~TCP_LOCAL;
	tcp_Flush( s );
    }
}

/*
 * sock_flushnext - cause next transmission to have a flush
 */
void sock_flushnext( sock_type *s)
{
    if (s->tcp.ip_type == TCP_PROTO ) {
        s->tcp.flags |= tcp_FlagPUSH;
        s->tcp.sock_mode &= ~TCP_LOCAL;
    }
}
/*
 * sock_putc - put a character
 *	     - no expansion but flushes on '\n'
 *	     - returns character
 */
byte sock_putc( sock_type *s, byte c )
{
    if (( c == '\n') || ( c == '\r'))
	sock_flushnext( s );
    sock_write( s, &c, 1 );
    return( c );
}

word sock_getc( sock_type *s )
{
    char ch;
    return( sock_read( s, &ch, 1 ) < 1 ? EOF : ch );
}

/*
 * sock_puts - does not append carriage return in binary mode
 *	     - returns length
 */
sock_puts( sock_type *s, byte *dp )
{
    int len, oldmode;

    len = strlen( dp );

    if (s->tcp.sock_mode & TCP_MODE_ASCII ) {
        if (s->tcp.ip_type == TCP_PROTO )
            s->tcp.sock_mode |= TCP_LOCAL;
        sock_noflush( s );
        if (len) sock_write( s, dp, len );
        sock_flushnext( s );
        sock_write( s, "\r\n", 2 );
    } else {
        sock_flushnext( s );
        sock_write( s, dp, len );
    }
    return( len );
}

/*
 * sock_update - update the socket window size to the other guy
 */
static void sock_update( tcp_Socket *s )
{
    if (s->ip_type == TCP_PROTO) {
        if ( !s->rdatalen )
            tcp_send( s, __LINE__ );              /* update the window */
	else
	    tcp_sendsoon( s );
    }
}
/*
 * sock_gets - read a string from any socket
 *	     - return length of returned string
 *           - removes end of line terminator(s)
 *
 *           - Quentin Smart fixed some problems
 */
int sock_gets( sock_type *s, byte *dp, int n )
{
    int len, templen, *np;
    char *src_p, *temp, *temp2;

    if ( s->udp.ip_type == UDP_PROTO ) {
	src_p = s->udp.rdata;
	np = &s->udp.rdatalen;
    } else {
	src_p = s->tcp.rdata;
	np = &s->tcp.rdatalen;
    }
    if ( *np == 0 ) return( 0 );

    // eat trailing \n or \0 from previous line
    if ( *src_p == 0 || *src_p == '\n' ) {
        movmem( src_p + 1, src_p, *np -= 1 );
        if ( !*np ) return( 0 );
    }

    if ( --n > *np ) n = *np;

    // Q.Smart found and fixed a bug here
    memcpy( dp, src_p, n );     // copy everything
    dp[ n ] = 0;                // terminate new string
    temp = memchr( dp, '\n', n);
    temp2= memchr( dp, '\r', n);

    if (temp)  *temp = 0;
    if (temp2) *temp2= 0;

    // skip if there were no crs
    if ( !temp2 ) {
        *dp = 0;
        return( 0 );
    }

//  not: len = strlen( dp );
    len = (int)(( temp ? min( FP_OFF(temp), FP_OFF(temp2)) :
        FP_OFF(temp2)) - FP_OFF(dp));

    // expect \r\n or \r\0 or \n or \r
    // so get first of the two

    if ( temp == NULL ) {       /* handles \r only */
        temp = temp2;
        temp2 = NULL;
    } else if ( FP_OFF( temp ) > FP_OFF( temp2 ))
        temp = temp2;           // handles trailing \n or \0

    n = len + 1;                // account for first \r

    // we check next char if it exists, and skip it if 0, \r, or \n
    if ((*np > n) && !src_p[n] ) n++;
    movmem( &src_p[ n ], src_p, *np -= n );
    if (*np < 0) *np = 0;

    sock_update( s );   /* new window */
    return( len );
}


/*
 * sock_dataready - returns number of bytes waiting to be ready
 *		  - if in ASCII mode, return 0 until a line is present
 *		    or the buffer is full
 */
word sock_dataready( sock_type *s )
{
    int len;
    char *p;

    if (!(len = s->tcp.rdatalen)) return( 0 );

    if ( s->tcp.sock_mode & TCP_MODE_ASCII ) {
        p = s->tcp.rdata;
        if ( *p == '\n' ) {
            movmem( p + 1, p, s->tcp.rdatalen = --len);
            if ( ! len ) return( 0 );
        }
        /* check for terminating \r */
        if ( memchr( p, '\r', len))
            return( len );
        return( 0 );
    } else
        return( len );
}

sock_established( sock_type *s )
{
    switch ( s->tcp.ip_type ) {
	case UDP_PROTO :
		return( 1 );
	case TCP_PROTO :
                return( s->tcp.state == tcp_StateESTAB ||
                        s->tcp.state == tcp_StateESTCL ||
                        s->tcp.state == tcp_StateCLOSWT );
	default :
		return( 0 );
    }
}

sock_close( sock_type *s )
{
    switch (s->udp.ip_type) {
	case UDP_PROTO :
		udp_close( s );
		break;
	case TCP_PROTO :
		tcp_close( s );
		tcp_tick( s );
		break;
    }
}

sock_sturdy( sock_type *s, int level )
{
    s->tcp.rigid = level;
    if ( s->tcp.rigid < s->tcp.stress ) sock_abort( s );
}

/*
 * _ip_delay0 called by macro sock_wait_established()
 * _ip_delay1 called by macro sock_wait_intput()
 * _ip_delay2 called by macro sock_wait_closed();
 *
 */

_ip_delay0( s, timeoutseconds, fn, statusptr )
sock_type *s;
int timeoutseconds;
procref fn;
int *statusptr;
{
    int status;
    ip_timer_init( s , timeoutseconds );
    do {
	if ( s->tcp.ip_type == TCP_PROTO ) {
	    if ( tcp_established( s )) {
		status = 0;
		break;
	    }
	}
	kbhit();	/* permit ^c */
	if ( !tcp_tick( s )) {
             if (!s->tcp.err_msg) s->tcp.err_msg = "Host refused connection";
	     status = -1;	/* get an early reset */
	     break;
	}
	if ( ip_timer_expired( s )) {
            s->tcp.err_msg = "Open timed out";
            sock_close( s );
	    status = -1;
	    break;
	}
	if ( fn ) if (status = fn(s)) break;
	if ( s->tcp.usr_yield ) (*s->tcp.usr_yield)();
	if ( s->tcp.ip_type == UDP_PROTO ) {
	    status = 0;
	    break;
	}
    } while ( 1 );
    if (statusptr) *statusptr = status;
    return( status );
}

_ip_delay1( s, timeoutseconds, fn, statusptr)
sock_type *s;
int timeoutseconds;
procref fn;
int *statusptr;
{
    int status;
    ip_timer_init( s , timeoutseconds );

    sock_flush( s );	/* new enhancement */

    do {
	if ( sock_dataready( s )) {
	    status = 0;
	    break;
	}
	kbhit();	/* permit ^c */

	if ( !tcp_tick( s )) {
	    status = 1;
	    break;
	}
	if ( ip_timer_expired( s )) {
            s->tcp.err_msg = "Connection timed out";
            sock_close( s );
	    status = -1;
	    break;
	}
	if (fn) {
	    if (status = fn(s))
		break;
	}
	if ( s->tcp.usr_yield ) (*s->tcp.usr_yield)();
    } while ( 1 );
    if (statusptr) *statusptr = status;
    return( status );
}

_ip_delay2( s, timeoutseconds, fn, statusptr)
sock_type *s;
int timeoutseconds;
procref fn;
int *statusptr;
{
    int status;
    ip_timer_init( s , timeoutseconds );

    if (s->tcp.ip_type != TCP_PROTO ) {
        if ( statusptr ) * statusptr = 1;
        return( 1 );
    }

    do {
        /* in this situation we KNOW user not planning to read rdata */
        s->tcp.rdatalen = 0;
	kbhit();	/* permit ^c */
	if ( !tcp_tick( s )) {
	    status = 1;
	    break;
	}
	if ( ip_timer_expired( s )) {
            s->tcp.err_msg = "Connection timed out";
	    sock_abort( s );
	    status = -1;
	    break;
	}
	if (fn) {
	    if (status = fn(s))
		break;
	}
	if ( s->tcp.usr_yield ) (*s->tcp.usr_yield)();

    } while ( 1 );
    if (statusptr) *statusptr = status;
    return( status );
}


char *rip( char *s )
{
    char *temp;

    if (temp = (char *)strchr( s, '\n')) *temp = 0;
    if (temp = (char *)strchr( s, '\r')) *temp = 0;
    return( s );
}

                                 
