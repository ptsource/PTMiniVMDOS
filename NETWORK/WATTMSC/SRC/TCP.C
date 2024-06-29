/***
 *
 * File: tcp.c
 *
 * 27-Aug-93 fr	- final cleanup
 * 28-Aug-92 lr
 *      maybe it's worth resetting s->safetysig on closed sockets.
 * 09-Jul-92 lr
 *      sometimes, a connection won't start.
 *      check carefully the udp implementations, it's likely to be
 *      broken by variable-size buffers.
 *
 ***  TCP.C - the true worker of TCP
 ***    contains all opens, closes, major read/write routines and
 ***    basic IP handler for incomming packets
 ***    Much of the TCP/UDP/IP layering is done at the data structure
 ***    level, not in separate routines or tasks
 ***  The network is kept alive by periodically calling tcp_tick(),
 ***  which scans all the sockets. They can be in three 'unhappy'
 ***  states:
 ***    NO      means they don't need any activity.
 ***    YES     means they need attention at next tick.
 ***    VERY    means they need immediate attention.
 ***
 ***/

#define WATTCP_KERNEL
#define NEWPCTCP
#include <tcp.h>
#include <time.h>

#define NO 0            /*** values for the unhappy flag ***/
#define YES 1
#define VERY 2

#define LAZY 1          /** values for inlist field of tcp sockets **/
#define BUSY 2

/***
 *** Debugging stuff
 *** DB4 always prints a message (these are bugs in this program)
 ***     or in the other party
 *** DB3 prints a message if debug_on=1
 *** DB2 only prints a message if debug is #defined
 ***
 ***/

/*
 * DB_W is a fast output routine for debugging the tcp
 * state machine -- is currently unused
 */ 
#ifndef debug1
#       define DB_W(x) 
#else
#       define DB_W(x) _db_w(x)

void _db_w(char *s) {
	static char far *vdu_base=(char far *)0xb8000000L;
	static int vdu_col=0;
	char c;
	while(c= *s++){
		vdu_base[vdu_col]=c; vdu_col +=2;
		if (vdu_col>=3200) vdu_col=0;
	}
}
#endif /* debug1 */

/***
 *** end of debugging stuff
 ***/

/************************** STATICS **********************************/

/* static void largecheck( void *s, int size ); no more static fr */
static void udp_close( udp_Socket *ds );
static void tcp_close( tcp_Socket *ds );
static void tcp_abort( tcp_Socket *ds );
static void tcp_Retransmitter(void);
static void tcp_unthread( tcp_Socket *ds); 
static int udp_write(register udp_Socket *s, byte *datap, int len);
static int udp_read( register udp_Socket *s, byte *datap, int maxlen);
static int tcp_read(register tcp_Socket *s, byte *datap, int maxlen);
static int tcp_write(register tcp_Socket *s, byte *dp, int len);
static void tcp_Flush(tcp_Socket *s);
static void udp_handler(in_Header *ip);
static void tcp_close_sock(register tcp_Socket *s, char *msg);
static void recompute_rto(register tcp_Socket *s);
static int acceptable(tcp_Socket *s, in_Header *ip, tcp_Header *tp);
static void set_UP(int flags, tcp_Socket *s, tcp_Header *tp);
static void tcp_handler1(register tcp_Socket *s,in_Header *ip,tcp_Header *tp,word flags,int len);
static void tcp_handler(in_Header *ip);
static int tcp_ProcessData(register tcp_Socket *s, tcp_Header *tp, int len);
static void tcp_send(register tcp_Socket *s);
static void sock_update( tcp_Socket *s );

/*static void (*system_yield)() = NULL;  fr put into proto.h */
static unsigned long far *realclock = (unsigned long far *)0x000046cL;
static int ip_id = 0;                   /* packet number */
static unsigned next_tcp_port = 1024;   /* auto incremented */
static unsigned next_udp_port = 1024;
static udp_Socket *udp_allsocs = NULL;
/*static tcp_Socket *tcp_allsocs = NULL;  fr traslated to proto.h */
static initialized = 0;

/*************** END OF STATICS *******************************/



/***
 *** ip user level timer stuff
 ***   void ip_timer_init( void *s, int delayseconds )
 ***   int  ip_timer_expired( void *s )
 ***    - 0 if not expired
 ***/

void
ip_timer_init( udp_Socket *s , int delayseconds )
{ s->usertimer = delayseconds ? set_ttimeout( delayseconds*18 ): 0 ; }

int
ip_timer_expired( udp_Socket *s)
{ return( s->usertimer ? chk_timeout( s->usertimer) : 0 ); }

longword
MsecClock(void)
{ return( (set_ttimeout(0))*55L); }

/***
 *** Timer definitions. All of them are in ticks.
 ***/
#define RETRAN_STRAT_TIME 1 /* how often do we check retrans. tables*/
#define tcp_OPENTIMEOUT 31*18  /* timeout for opens */
#define tcp_CLOSETIMEOUT 31*18  /* timeout for close */
#define tcp_FLUSHTIMEOUT 31*18  /* timeout for flushing data after a close */
#define tcp_TTIMEOUT 31*18      /* timeout during a connection */
#define tcpAbortTimeout 18*13   /* about 5 minutes */

/***
 *** Initialization/termination stuff
 ***/
/***
 *** Shut down the card and all services
 ***/
void
tcp_shutdown(void)
{
    while (tcp_allsocs) tcp_abort( tcp_allsocs );
    _eth_release();
    initialized = 0;
}

/***
 *** tcp_Init - Initialize the tcp implementation
 ***        - may be called more than once without hurting
 ***/
void
tcp_init(void)
{
    /* extern int _arp_last_gateway, _last_nameserver; */

    DB2((FDB,"tcp_init():\n"));
    if (!initialized) { /* initialize ethernet interface */
	initialized = 1;
	_eth_init(); /* in pcpkt.c */
	/*ip_id = (int)set_ttimeout( 0 ) ;*/
	/* reset the various tables */
	_arp_last_gateway = 0;  /* reset the gateway table */
	_last_nameserver = 0;   /* reset the nameserver table */
	_last_cookie = 0;       /* eat all remaining crumbs */
	*_hostname = 0;         /* reset the host's name */

	if (!my_ip_addr) {
	    /* using our local reverse ethernet address thingamajig */
	    memcpy( &my_ip_addr, &_eth_addr[2], 4 );
	}
	_eth_free( 0 );
	next_udp_port=next_tcp_port=1024+(unsigned)((*realclock>>7)& 0x1ff);
    }
}

/***
 *** Checks for bugs in large model C compiler
 ***/
void
largecheck( void *s, int size )
{
    DB2((FDB,"largecheck():\n"));
    if ( (FP_OFF(s)) > (-size)) {
	outs("ERROR: C compiler sock size error\n");
	exit( 3 );
    }
}

/*** Setting new default socket's buffers dimensions. 
 ***/
void
set_tcp_rxbufsize(word size)
{
    RxMaxBufSize = size;
}

void
set_tcp_txbufsize(word size)
{
    TxMaxBufSize = size;
}

void
set_udp_bufsize(word size)
{
    MaxBufSize = size;
}

int
udp_open(udp_Socket *s, word lport, longword ina,
	word port, procref datahandler)
{
    DB2((FDB,"udp_open():\n"));
    largecheck( s, sizeof( udp_Socket ));
    udp_close( s );
    memset( s, 0, sizeof( udp_Socket ));
    s->ip_type = UDP_PROTO;
    if (lport == 0) lport= ++next_udp_port; /* get a nonzero port */
    s->myport = lport;

    /* check for broadcast */
    if ( ina == 0xFFFFFFFF || ina == 0 ) {
	DB2((FDB,"udp_open(): found a broadcast\n"));
	memset( s->hisethaddr, 0xff, sizeof( eth_address ));
    } else { 
	DB2((FDB,"udp_open(): calling _arp_resolve \n"));
	if ( ! _arp_resolve(ina, &(s->hisethaddr)) ) return( 0 );
	DB2((FDB,"udp_open(): _arp_resolve succeded.\n"));
    }

    s->hisaddr = ina;
    s->hisport = port;
    s->dataHandler = datahandler;
    s->usr_yield = system_yield;
    s->next = udp_allsocs;

    if ((s->rdata = (byte *) malloc((int)MaxBufSize)) == NULL) {
	DB3((stderr,"Warning: not enough space for rdata buffer"));
	udp_close(s);
	return(0);
    }
    s->rxbufsize=MaxBufSize;

    udp_allsocs = s;
    s->safetysig = SAFETYUDP;
    return( 1 );
}

/***
 *** Actively open a TCP connection to a particular destination.
 *** Return 0 on error
 */
/*** CHECK THIS ***/
int
tcp_open(register tcp_Socket *s, word lport,
	longword ina, word port, procref datahandler)
{
    DB2((FDB,"tcp_open():\n"));
    largecheck( s, sizeof( tcp_Socket ));   /* stack space warnings */
    tcp_unthread(s);       /* just in case not totally closed */

    memset( s, 0, sizeof( tcp_Socket));
    s->ip_type = TCP_PROTO;
    s->mss = _mss;
    s->state = tcp_StateSYNSENT;
    DB2((FDB,"tcp_open(): going to SYNSENT\n"));
    s->timeout = set_ttimeout( tcp_OPENTIMEOUT );
/***
 *** If cannot connect and the timeout expires, the connection
 *** is aborted.
 ***/

    if (lport==0) lport= ++next_tcp_port; /* get a nonzero port val */
    s->myport = lport;
    DB2((FDB,"Calling _arp_resolve():\n"));
    if (! _arp_resolve(ina, &(s->hisethaddr))) return( 0 );
    DB2((FDB,"_arp_resolve() succeeded.\n"));
    s->hisaddr = ina;
    s->hisport = port;

    /* choose a pseudo-random iss */
    /* s->seqnum = intel( set_ttimeout( 0 )) & 0xffff0000 ; */
    s->seqnum =  (set_ttimeout( 0 ) & 0xfff) << 20 ;
    s->unacked = s->datalen = 0; /* redundant */
    s->flags = tcp_FlagSYN;
    s->dataHandler = datahandler;
    s->usr_yield = system_yield;
    s->next = tcp_allsocs;

    s->rxbufsize = RxMaxBufSize;
    if ((s->rdata = (byte *) malloc((int)RxMaxBufSize)) == NULL) {
	DB3((stderr,"Warning: tcp_open(): not enough room for rdata buffer"));
	tcp_unthread(s);
	return(0);
    }

    s->txbufsize = TxMaxBufSize;
    if ((s->data = (byte *) malloc((int)TxMaxBufSize)) == NULL) {
	DB3((stderr,"Warning: tcp_open(): not enough room for tx data buffer"));
	tcp_unthread(s);
	return(0);
    }

    tcp_allsocs = s;
    s->safetysig = SAFETYTCP;
    DB2((FDB,"Sending first SYN from tcp_open\n")); 
    s->rto= 9; /* start 1/2 sec. rto */
    tcp_send(s);
    return( 1 );
}

/***
 *** Passive open: listen for a connection on a particular port
 ***/
/*** CHECK THIS ***/
int
tcp_listen(register tcp_Socket *s, word lport,
	longword ina, word port, procref datahandler, word timeout)
{
    DB2((FDB,"tcp_listen():\n"));
    largecheck( s, sizeof( tcp_Socket ));
    tcp_unthread(s);    /* just in case not totally closed */
    memset( s, 0, sizeof( tcp_Socket));
    s->ip_type = TCP_PROTO;
    s->mss = _mss;


    s->state = tcp_StateLISTEN;
    DB2((FDB,"tcp_listen(): going to LISTEN\n"));
    s->timeout = timeout ? set_timeout( timeout ) : 0;
/***
 *** Here it's my choice to have or not a timeout
 *** If there is, and it expires, the connection is aborted.
 ***/
    s->myport = lport;
    s->hisport = port;
    s->hisaddr = ina;
    s->seqnum = intel( (longword)s ); /* not a good idea, but works */
    s->datalen = 0;
    s->flags = 0;
    s->rto= 9; /* start 1/2 sec. rto */
    s->unhappy = NO; /* this is a PASSIVE open */
    s->dataHandler = datahandler;
    s->usr_yield = system_yield;
    s->safetysig = SAFETYTCP;
    s->next = tcp_allsocs;

    s->rxbufsize = RxMaxBufSize;
    if ((s->rdata = (byte *) malloc((int)RxMaxBufSize)) == NULL) {
	DB3((stderr,"Warning: tcp_listen(): not enough space for rdata buffer"));
	tcp_unthread(s);
	return(0);
    }
    s->txbufsize = TxMaxBufSize;
    if ((s->data = (byte *) malloc((int)TxMaxBufSize)) == NULL) {
	DB3((stderr,"Warning: tcp_listen(): not enough space for Tx data buffer"));
	tcp_unthread(s);
	return(0);
    }
    tcp_allsocs = s;
    return( 1 );
}

/*** added by fr ***/
#ifdef unused
/*
 * multi-listen is superseded by select()
 */
tcp_Socket *
multi_listen(int numsock, word lport, longword ina, word port, 
	procref datahandler, word mode)
{

  tcp_Socket   *s[20], *sret = NULL, *bsp=NULL, *sldp = NULL; 
  int i;

  DB2((FDB,"multi_listen():\n"));
  if ((sldp = (tcp_Socket *) malloc( (int) sizeof( tcp_Socket ) )) == NULL){
	DB4((stderr,"No room for any socket!\n"));
	return(sldp);
	}
  memset( sldp, 0, sizeof( tcp_Socket));
  sldp->myport = lport;
  sldp->hisport = port;
  sldp->hisaddr = ina;
  sldp->sock_mode = (sldp->sock_mode & 0xfffc) |mode;
  sldp->dataHandler = datahandler;
  sldp->next = NULL;

  for( i=0 ; i<numsock ; i++){
    if ( (s[i] = (tcp_Socket *) malloc( (int) sizeof( tcp_Socket ) )) == NULL){
	DB3((stderr,"%d sockets allocated\n",i));
	break;
	}
    
    largecheck( s[i], sizeof( tcp_Socket ));
    memset( s[i], 0, sizeof( tcp_Socket));
    s[i]->ip_type = TCP_PROTO;
    s[i]->mss = _mss;
    s[i]->state = tcp_StateLISTEN;
    DB2((FDB,"tcp_listen(): going to LISTEN\n"));
    s[i]->myport = lport;
    s[i]->hisport = port;
    s[i]->hisaddr = ina;
    s[i]->sock_mode = (s[i]->sock_mode & 0xfffc) | mode;	
    s[i]->seqnum = intel( (longword)s ); /* not a good idea, but works */
    s[i]->datalen = 0;
    s[i]->flags = 0;
    s[i]->rto= 9; /* start 1/2 sec. rto */
    s[i]->unhappy = NO; /* this is a PASSIVE open */
    s[i]->dataHandler = datahandler;
    s[i]->usr_yield = system_yield;
    s[i]->safetysig = SAFETYTCP;
    s[i]->next = tcp_allsocs;
    s[i]->brother = bsp;
    s[i]->father = sldp;
    s[i]->inlist = LAZY;

    s[i]->rxbufsize = RxMaxBufSize;
    if ((s[i]->rdata = (byte *) malloc((int)RxMaxBufSize)) == NULL) {
	DB3((stderr,"Warning: not enough space for rdata buffer\n"));
	DB3((stderr,"%d sockets allocated\n",i));
	tcp_unthread(s[i]);
	break;
        }
    s[i]->txbufsize = TxMaxBufSize;
    if ((s[i]->data = (byte *) malloc((int)TxMaxBufSize)) == NULL) {
	DB3((stderr,"Warning: not enough space for data buffer"));
	DB3((stderr,"%d sockets allocated\n",i));
	tcp_unthread(s[i]);
	break;
        }
    tcp_allsocs = s[i];
    bsp=s[i];
    sret=s[i];
    if( !(sldp->next) ) sldp->next = sret; /* memorizzo */
    }/*end for*/
    (sldp->next)->brother = sret; /* chiudo la lista */
    sldp->next = sret;
    return(sldp);
}
#endif /* unused */

/***
/***
 *** simply unlink from socket list
 *** It's the UDP version of the tcp_unthread 
 ***/
static void
udp_close( udp_Socket *ds )
{
    register udp_Socket *s, **sp;

    DB2((FDB,"udp_close():\n"));
    for (sp = &udp_allsocs;; sp = &s->next) {
	s = *sp;
	if ( s == ds ) {
	    *sp = s->next;
	    if (s->rdata==NULL) {
		DB3((stderr,"udp_close: socket was already closed\n"));
		break;
	    }
	    free(s->rdata); 
	    s->rdata=NULL; /* 28-Aug-92 lr you never know... */
	    break;
	}
	if ( !s ) break;
	if ( ! s->err_msg ) s->err_msg = "UDP Close called";
    }
}

/***
 *** Will queue a FIN on a particular port.
 *** In ESTCL or CLOSWTCL it has already been called.
 *** Must still allow receives. A timeout becomes active so
 *** that, if I cannot flush data in a reasonable time, the
 *** connection is aborted anyway.
 ***/
static void
tcp_close(register tcp_Socket *s){

    DB2((FDB,"tcp_close():"));
    if ( s->ip_type != TCP_PROTO ) return; /* invalid */
    switch(s->state) {
    	default:
           DB3((FDB,"tcp_close(): called in state %s\n",state_names[s->state]));
	   return;
    	case tcp_StateLISTEN:
    	case tcp_StateSYNSENT:
		tcp_unthread(s); /* check this */
		return; /* error: closing */
	case tcp_StateCLOSWT:
		s->state = tcp_StateCLOSWTCL;
		DB2((FDB,"tcp_close(): going from CLOSWT to CLOSWTCL\n"));
		s->timeout=set_ttimeout(tcp_CLOSETIMEOUT);
   	case tcp_StateCLOSWTCL:
		goto tcp_close_1;
    	case tcp_StateSYNRECLIS:
    	case tcp_StateSYNREC:
    	case tcp_StateESTAB:
    		 DB2((FDB,"tcp_close(): going from %s to ESTCL\n",state_names[s->state]));
		s->state = tcp_StateESTCL;
		s->timeout=set_ttimeout(tcp_CLOSETIMEOUT);
    	case tcp_StateESTCL:
    tcp_close_1:
		if ( s->datalen ) {     /* must first flush all data */
			s->flags |= tcp_FlagPUSH | tcp_FlagACK;
	    		if (s->rtt_time==0) {
		 	    DB4((stderr,"pending data and rtt=0. Ouch!!!\n"));
			    }
	    		} 
		else { /* no more outgoing data, really closing */
			s->flags = tcp_FlagACK | tcp_FlagFIN;
	    		if (!s->err_msg)
				s->err_msg = "Connection closed normally";
	    		if ( s->state == tcp_StateESTCL ) {
				DB2((FDB,"tcp_close(): going from %s to FINWT1\n",state_names[s->state]));
				s->state = tcp_StateFINWT1;
	        		}
	    		else {
				DB2((FDB,"tcp_close(): going from %s to LASTACK\n",state_names[s->state]));
				s->state= tcp_StateLASTACK;
			        }
			s->timeout = set_ttimeout(tcp_FLUSHTIMEOUT);
/***
 *** The above timeout is for the upper level protocol, so that
 *** all the data in the buffers can be flushed. I'm not so sure
 *** about the actual value. Should be at least rto.
 ***/
	    		} /* end else */
		tcp_send( s );
		break;
	        } /* end switch */
	} /* tcp_close */

/***
 *** Abort a tcp connection. Correct.
 ***/
static void
tcp_abort(register tcp_Socket *s)
{
    DB2((FDB,"tcp_abort():\n"));
    if (!s->err_msg) s->err_msg = "TCP_ABORT";
    if ( s->state != tcp_StateLISTEN && s->state != tcp_StateCLOSED ) {
	s->flags = tcp_FlagRST  | tcp_FlagACK ;
	tcp_send(s);
    }
    s->unhappy = NO;
    s->datalen = 0;
    s->state = tcp_StateCLOSED;
    tcp_unthread(s);
}

void
sock_abort(tcp_Socket *s )
{
DB2((FDB,"sock_abort():\n"));
    if ( s->ip_type == TCP_PROTO ) tcp_abort( s );
    else udp_close( (udp_Socket *) s );
}


/***
 *** make_in_hdr() prepares an internet header
 ***    parameters are in machine format.
 ***/
void
make_in_hdr(in_Header *inp, byte proto, longword dest, word len)
{
DB2((FDB,"make_in_hdr():\n"));
    inp->ver = 4;
    inp->hdrlen = 5;
    inp->tos = 0;
    inp->identification = intel16( ++ip_id );   /* was post inc */
    inp->frag = 0;
    inp->ttl = 254;
    inp->proto = proto;
    inp->checksum = 0;
    inp->source = intel( my_ip_addr );
    inp->destination = intel( dest );
    inp->length = intel16( len );
    inp->checksum = ~inchksum((void *)inp, sizeof(in_Header));
}


/***
 *** Retransmitter - called periodically to perform tcp retransmissions
 ***/

static void
tcp_Retransmitter(void)
{
    static longword retran_strat = 0L; /* timeout retran strategy */
    register tcp_Socket *s;
    int slow=0;
#ifdef UNDEF
    DB2((FDB,"tcp_Retransmitter():\n"));
    gm_tcp_Retransmitter++;
#endif /* UNDEF */
    if (slow=chk_timeout(retran_strat))
	retran_strat = set_ttimeout( RETRAN_STRAT_TIME );

    for ( s = tcp_allsocs; s; s = s->next ) {
	if (!slow) {
	    if (s->unhappy & VERY) {
		DB2((FDB,"Retransmitting cause of VERY \n")); 
		gm_tcp_send_very++;
		tcp_send(s);
	    }
	} 
	else {
	    DB_W("RT ");
	    /* only do this once per RETRAN_STRAT_TIME milliseconds */
	    if (s->rtt_time && chk_timeout(s->rtt_time)) {
		gm_expire++;
		s->unacked=0; /* have lost some ack, resend */
/***
 *** exponential backoff for rto. Should also upper bound it.
 ***/
		if (s->rto) s->rto = (s->rto * 3) / 2;
		else s->rto = 4;
		DB3((FDB,"rtt expired, rto now= %d\n",s->rto));
		s->unhappy = YES;
	    }
/***
 *** It is agreed that when, due to a send or an incoming ack,
 *** new data can be sent, then unhappy is also set.
 ***/
	    if (s->unhappy) { /* was also s->datalen>0 */
		DB2((FDB,"Sending seqnum %8lx from Retransmitter\n",s->seqnum));
		gm_tcp_send_retr++;
		tcp_send(s);
	    }
/***
 *** handle inactive tcp timeouts
 ***/
	    if ( sock_inactive && s->inactive_to ) {
		if ( chk_timeout( s->inactive_to)) {
		    /* this baby has timed out */
		    s->err_msg = "Connection timed out - no activity";
		    sock_close((sock_type*) s );
		}
	    }
/***
 *** Handle regular timeouts.
 ***/
	    if ( s->timeout && chk_timeout( s->timeout)) {
		if ( s->state == tcp_StateTIMEWT ) {
		    DB2((FDB,"tcp_close(): going from %s to CLOSED\n",state_names[s->state]));
		    s->state=tcp_StateCLOSED;
		    tcp_unthread(s); /* can I still do I/O ? */
		} 
		else if (s->state!=tcp_StateESTAB /* && s->state!=tcp_StateCLOSWT */) {
		    s->err_msg = "Timeout, aborting";
		    DB3((FDB,"Timeout expired for socket in state %s - aborting\n",state_names[s->state]));
		    tcp_abort(s);
		}
		else {
		    DB3((FDB,"Timeout expired for active socket in state %s\n",state_names[s->state]));
		}
	    }
	} /* end if slow */
    }
} /* end Retransmitter */

/***
 *** Unthread a socket from the socket list, if it's there
 ***/
void
tcp_unthread( tcp_Socket *ds)
{
    register tcp_Socket *s, *fs, **sp; /* eventualm. *pp */

    DB2((FDB,"tcp_unthread():\n"));
    gm_tcp_unthread++;
/*    if (!ds->rdatalen || (ds->state > tcp_StateESTCL)) *//*always */
	ds->ip_type = 0;        /* fail io */
    ds->state = tcp_StateCLOSED;   /* tcp_tick needs this */
    
    if (ds->inlist==BUSY){
	fs = ds->father;
	ds->ip_type = TCP_PROTO;
	ds->sock_mode = fs->sock_mode;
	ds->myport = fs->myport;
	ds->hisport = fs->hisport;
	ds->dataHandler = fs->dataHandler;	
	ds->usertimer = 0L;
	memset(&(ds->hisethaddr ),0,sizeof(eth_address));
	ds->hisaddr = fs->hisaddr;	
	ds->state = tcp_StateLISTEN;
	ds->rdatalen = 0;
	ds->acknum = 0L;
	ds->seqnum = intel((longword)s);
	ds->timeout = 0L;
	ds->unhappy = NO;
	ds->usr_yield = system_yield;
	ds->flags = 0;
	ds->window = 0;
	ds->datalen = 0;
	ds->unacked = 0;
	ds->rto = 9;
	ds->inlist = LAZY;
	/* fs->next = ds->brother;  i don't think it would be a good idea */
	}
    else {	
       	 sp = &tcp_allsocs;
   	 for (;;) {
       		s = *sp;
		if ( s == ds ) {
		    *sp = s->next;
		    if (s->rdata==NULL || s->data==NULL) {
			DB3((stderr,"tcp_unthread: socket already closed\n"));
			break;
  		        }
		    free(s->rdata);
		    free(s->data); 
		    s->rdata=s->data=NULL;
		    break;
		    }
		if ( !s ) break;
		sp = &s->next;
        	}
	}

/*  pp = tcp_allsocs;  when multi_listen sockets where discarded at closing
    for (;;) {
	s = pp->next;
	if ( s == ds ) {
	    pp->brother = s->brother;
	    break;
	    }
	if ( !s ) break;
	pp = s;
	}  */

    }


/***
 *** tcp_tick(s) - called periodically by user application
 ***    returns 0 if s is NULL or not TCP socket
 ***/

extern long far lost_packets;

short
tcp_tick(register sock_type *s )
{
    register in_Header *ip;
    word packettype;

#ifdef UNDEF
    DB2((FDB,"tcp_tick():\n"));
    gm_tcp_tick++;
    if (previous_lost_packets != lost_packets) {
	DB2((stderr,"lost packets: %ld\7\n",lost_packets));
	previous_lost_packets = lost_packets;
    }
#endif /* UNDEF */
    /*** finish off dead sockets ***/
    if ( s && ( s->tcp.ip_type == TCP_PROTO ) &&
	( s->tcp.state==tcp_StateCLOSED ) && ( s->tcp.rdatalen==0 )) {
	    DB3((FDB,"tcp_tick(): unthreading socket\n"));
	    tcp_unthread((tcp_Socket *)s);
	    /* s->tcp.ip_type = 0; /* redundant, already in unthread */
    }

/*** handle incoming packets ***/

    DB2((FDB,"tcp_tick(): testing incoming pkts\n"));
    while ( ip = (in_Header *)_eth_arrived( &packettype ) ) {
	DB2((FDB,"tcp_tick(): arrived pkt type %4x\n",packettype));
	switch ( packettype ) {
	case 0x0008 : /* intel16(IP_TYPE) */
	    if ( inchksum((void *)ip, ip->hdrlen <<2) == 0xffff ) {
		DB2((FDB,"checksum is OK\n"));
		if (!my_ip_addr || (intel(ip->destination) == my_ip_addr)
#ifdef LR
		    /* 19-dec-91 lr: what do I do with local broadcasts ? */
		    || (intel(ip->destination)|(~sin_mask) ==
			my_ip_addr| (~sin_mask) ) /* local broadcast */
#endif /* LR */
		    ) {
		    DB2((FDB,"This pkt is for me\n"));
		    switch ( ip->proto ) {
		    case TCP_PROTO :
			DB2((FDB,"received TCP packet\n"));
			tcp_handler(ip);
			break;
		    case UDP_PROTO :
			DB2((FDB,"received UDP packet\n"));
			udp_handler(ip);
			break;
		    case ICMP_PROTO :
			DB2((FDB,"received ICMP packet\n"));
			icmp_handler(ip);
			break;
		    default:
			DB3((stderr,"unknown protocol %d\n",ip->proto));
			break;
		    }
		}
		else {
		    if (intel(ip->destination)|(~sin_mask) ==
			my_ip_addr| (~sin_mask) ) {
			    /* local broadcast */
			    DB2((FDB, "Received local broadcast\7\n"));
		    }
		    else {
			word *s;
			s=(word *)_eth_hardware((byte *)ip);
			if (s[0]!=0xFFFF || s[1]!=0xffff || s[2]!=0xffff) {
			    DB4((FDB, "This packet is not for me, and not ether broadcast\7\n"));
			}
		    }
		}
	    } 
	    else  { /* bad checksum */
		DB2((FDB, "IP packet, bad checksum\7\n"));
	    }
	    break;
	case 0x0608 : /* intel16(ARP_TYPE) */
	    DB2((FDB,"received ARP packet\n"));
	    (void)_arp_handler((arp_Header *)ip);
	    break;
	} /* end switch packettype */
	DB2((FDB,"FREE eth arrived\n"));
	if (ip) _eth_free(ip);
    } /* end while etharrived */

/***
 *** now check for outstanding packets
 ***/
 
    tcp_Retransmitter();
    return( s ? s->tcp.ip_type : 0 );
}

void
tcp_set_debug_state(int x)
{ debug_on = x; }

/* returns 1 if connection is established */
int
tcp_established(tcp_Socket *s)
{
DB2((FDB,"tcp_established():\n"));
    return( s->state==tcp_StateESTAB || s->state==tcp_StateESTCL
	|| s->state==tcp_StateCLOSWT || s->state==tcp_StateCLOSWTCL );
}

static int
udp_write(register udp_Socket *s, byte *datap, int len)
{
    tcp_PseudoHeader ph;
    struct _pkt {
	in_Header  in;
	udp_Header udp;
	int        data;
    } *pkt;
    int *dp;
    register in_Header *inp;
    register udp_Header *udpp;

    DB2((FDB,"udp_write():\n"));
    pkt=(struct _pkt *)_eth_formatpacket(&s->hisethaddr[0],/*0x800*/8);
    dp = &pkt->data;
    inp = &pkt->in;
    udpp = &pkt->udp;

    /* udp header */
    udpp->srcPort = intel16( s->myport );
    udpp->dstPort = intel16( s->hisport );
    udpp->checksum = 0;
    udpp->length = intel16( UDP_LENGTH + len );
    movmem(datap, dp, len );

    /* internet header */
    make_in_hdr(inp, UDP_PROTO, s->hisaddr,
	sizeof(in_Header) + UDP_LENGTH + len );
	DB2((FDB,"udp inp length = %d\n",intel16(inp->length)));

    /* compute udp checksum if desired */
    if ( s->sock_mode & UDP_MODE_NOCHK ) {
	udpp->checksum = 0;
    } 
    else {
	ph.src = inp->source;   /* already INTELled */
	ph.dst = inp->destination;
	ph.mbz = 0;
	ph.protocol = UDP_PROTO;        /* udp */
	ph.length = udpp->length;       /* already INTELled */

	ph.checksum = inchksum((void *)&pkt->udp, intel16(ph.length));
	udpp->checksum =  ~inchksum((void *)&ph, sizeof(ph));
    }

    /* if (_dbugxmit) (*_dbugxmit)(s,inp,udpp); */
    DB2((FDB,"calling _eth_send():\n"));
    gm_udp_write++;
    if(_eth_send( intel16( inp->length ))) {
	gm_udp_sendfailed++; }
    /* eth_send may fail. But this is udp, so who cares. */
    return ( len );
}

/*
 * udp_read - read data from buffer, does large buffering
 */
static int
udp_read( register udp_Socket *s, byte *datap, int maxlen)
{
    int x;

    DB2((FDB,"udp_read():\n"));
    if (( x = s->rdatalen ) > 0) {
    DB2((FDB,"udp_read():datalen = %d  maxlen = %d\n",x,maxlen));
	gm_udp_read++;
	if ( x > maxlen ) x = maxlen;
	if ( x > 0 ) {
    DB2((FDB,"udp_read():before memcpy\n"));
	    memcpy( datap, s->rdata, x );
	    if ( s->rdatalen -= x )
    DB2((FDB,"udp_read():before memmove\n"));
	    movmem(s->rdata+x ,s->rdata, s->rdatalen);
	}
    }
    return( x );
}

void
_udp_cancel( in_Header *ip )
{
    int len;
    udp_Header *up;
    register udp_Socket *s;

    DB2((FDB,"_udp_cancel():\n"));
    /* match to a udp socket */
    len = ip->hdrlen << 2;
    up = (udp_Header *)((byte *)ip + len);      /* udp frame pointer */

    /* demux to active sockets */
    for ( s = udp_allsocs; s; s = s->next )
	if ( s->hisport != 0 &&
	    intel16( up->dstPort ) == s->myport &&
	    intel16( up->srcPort ) == s->hisport &&
	    intel( ip->source ) == s->hisaddr ) break;
    if ( !s ) {
	/* demux to passive sockets */
	for ( s = udp_allsocs; s; s = s->next )
	    if ( s->hisport == 0 && intel16( up->dstPort ) == s->myport ) break;
    }
    if (s) {
	s->rdatalen = -1;
	s->ip_type = 0;
    }
}

void
_tcp_cancel(in_Header *ip)
{
    int len;
    register tcp_Socket *s;
    tcp_Header *tp;

    DB2((FDB,"_tcp_cancel():\n"));
    len = ip->hdrlen;   /* check work */

    tp = (tcp_Header *)((byte *)ip + len);      /* tcp frame pointer */

    /* demux to active sockets */
    for ( s = tcp_allsocs; s; s = s->next ) {
	if ( s->hisport!=0 &&
	    intel16(tp->dstPort) == s->myport &&
	    intel16(tp->srcPort) == s->hisport &&
	    intel(ip->source) == s->hisaddr ) break;
    }
    if ( !s ) {
	/* demux to passive sockets */
	for ( s = tcp_allsocs; s; s = s->next )
	    if ( s->hisport==0 && intel16(tp->dstPort) == s->myport ) break;
    }
    if (s) { /* tcp_unthread should suffice - 27-Jun-92 lr */
	s->rdatalen = -1;
	s->state=tcp_StateCLOSED;
	s->ip_type=0; /* should be in unthread */
	tcp_unthread(s);
    }
} /* end _tcp_cancel */

/***
 *** Can always read, even after my close.
 ***/
int
tcp_read(register tcp_Socket *s, byte *datap, int maxlen)
{
    int x;

    DB2((FDB,"tcp_read(): data pending  %d\n",s->rdatalen));
    if ( s->ip_type != TCP_PROTO ) return(0); /* invalid */
    if (( x = s->rdatalen) > 0) {
	if ( x > maxlen ) x = maxlen;
	if ( x > 0 ) {
	    memcpy( datap, s->rdata, x );
	    if (( s->rdatalen -= x ) > 0 )
		movmem(s->rdata+x , s->rdata, s->rdatalen );
	    /* s->unhappy = VERY ; */
	    DB2((FDB,"Updating window size in tcp_read\n"));
	    tcp_send(s); /* update window size */
	}
    } 
    else if ( s->state == tcp_StateCLOSWT ) {
	tcp_close( s );
    }
    return( x );
}



/***
 *** Write data to a connection.
 *** Returns number of bytes written, == 0 when connection is not in
 *** established state.
 *** Cannot write after my close or other party's FIN.
 ***/
int
tcp_write(register tcp_Socket *s, byte *dp, int len)
{
    int x;

    DB2((FDB,"tcp_write():\n"));
    if ( s->ip_type != TCP_PROTO ) return(0); /* invalid */
    if ( s->state != tcp_StateESTAB && s->state !=tcp_StateCLOSWT ) len = 0;
    if ( len > (x = s->txbufsize - s->datalen) ) len = x; 
    if ( len > 0 ) {
	memcpy(s->data + s->datalen, dp, len );

	s->datalen += len;
	if ( s->sock_mode & TCP_MODE_NONAGLE ) {
	    tcp_send( s );
	} else { /* default mode */
	    /* transmit if first data or reached MTU */
	    /* not true MTU, but better than nothing */
	    if ((s->datalen==len )||( s->datalen > (int)(s->mss)/2)) {
		tcp_send( s );
	    } else {
		s->unhappy = YES ; /*send at next tick */
	    }
	}
    }
    return ( len );
} /* end tcp_write */


/***
 *** Send pending data
 ***/
static void
tcp_Flush(tcp_Socket *s)
{
DB2((FDB,"tcp_flush():\n"));
    if ( s->datalen > 0 ) {
	s->flags |= tcp_FlagPUSH;
	tcp_send(s);
    }
}

/***
 *** Handler for incoming udp packets.
 ***/
static void
udp_handler(in_Header *ip)
{
    register udp_Header *up;
    tcp_PseudoHeader ph;
    word len;
    byte *dp;
    register udp_Socket *s;

    DB2((FDB,"udp_handler():\n"));
    gm_udp_handler++;

    len = ip->hdrlen << 2;
    up = (udp_Header *)((byte *)ip + len);      /* udp segment pointer */
    len = intel16( up->length );
    DB2((FDB,"udp handler = %d\n",len));
    
    /* demux to active sockets */
    for ( s = udp_allsocs; s; s = s->next ) {
	if ( s->safetysig != SAFETYUDP ) {
	    outs("chain error in tcp");
	    exit(3);
	}
	if ( s->hisport != 0 &&
	    intel16( up->dstPort ) == s->myport &&
	    intel16( up->srcPort ) == s->hisport &&
	    intel( ip->source ) == s->hisaddr ) break;
    } /* end for */
    /* if (_dbugrecv) (*_dbugrecv)(s,ip,up); */
    if ( !s ) { 
	/* demux to passive sockets */
	/*  Note: Passive Sockets have their address = 0 */
	for ( s = udp_allsocs; s; s = s->next )
	    if ( s->hisaddr == 0 && intel16( up->dstPort ) == s->myport ) {
		if (_arp_resolve(intel(ip->source), &(s->hisethaddr))) {
		    s->hisaddr = intel( ip->source );
		    s->hisport = intel16( up->srcPort );
		}
		break;
	    }
    }
    if ( !s ) { 
	/* demux to broadcast sockets */
	for ( s = udp_allsocs; s; s = s->next )
	    if ( s->hisaddr == 0xffffffff
		 && intel16( up->dstPort ) == s->myport ) break;
    }

    if ( !s ) {
        /* maybe can send back an ICMP ? */
	DB2((FDB,"Udp_handler: no session seems to exist \n"));
	return;
    }

    if ( up->checksum ) {
	DB2((FDB,"Udp_handler: filling the pseudoheader \n"));
	ph.src = ip->source;    /* already INTELled */
	ph.dst = ip->destination;
	ph.mbz = 0;
	ph.protocol = UDP_PROTO;
	ph.length = up->length;
	ph.checksum =  inchksum((void *)up, len);
	if (inchksum((void *)&ph, sizeof( tcp_PseudoHeader)) != 0xffff)
	    return;
    }

    /* process user data */
    /* Remember: UDP_LENGTH = sizeof(udp_Header) */
    if ( (len -= UDP_LENGTH ) > 0) {
	DB2((FDB,"udp handler: data = %d\n",len));
	DB2((FDB,"Udp_handler: proc. data \n"));
	dp = (byte *)( up );
	if (s->dataHandler) s->dataHandler( s, &dp[ UDP_LENGTH ], len , &ph);
	else {
	    if (len > (word)s->rxbufsize) len = s->rxbufsize; 
	    memmove( s->rdata,&dp[UDP_LENGTH], len );
	    s->rdatalen = len;
	}
    }
}

static void
tcp_close_sock(register tcp_Socket *s, char *msg)
{
    DB2((FDB,"tcp_close_sock():\n"));
    s->err_msg= msg;
    s->state=tcp_StateCLOSED;
    tcp_unthread(s);
}

static void
recompute_rto(register tcp_Socket *s)
{
    long delta;
#define MAXRTO (18*30) /* 30 sec. rto it's a lot */

    if(s->vj_last) {
	if((delta=set_ttimeout(0) - s->vj_last) >=0 ) {
	    /* always enter here apart from midnight case */
	    s->rto = (word)(delta +(9*(s->rto-delta))/10);
	    if(s->rto > MAXRTO) s->rto = MAXRTO;
	    else if (s->rto <=4 ) s->rto = 4;
	}
    }
    DB2((FDB,"recompute_rto(): rto becomes %d\n",s->rto));
}

/***
 *** this makes the tests in RFC793, pg.69, and sends the
 *** ack if needed.
 ***/

static int
acceptable(tcp_Socket *s, in_Header *ip, tcp_Header *tp)
{
    int seglen, good=TRUE;
    longword seglow, seghigh, winlow, winhigh;
    word flags = intel16(tp->flags);

    seglen = intel16( ip->length ) /* IP len including header */
	- (ip->hdrlen << 2)      /* IP header */
	- (tcp_GetDataOffset(tp)<<2); /* TCP header */

/***
 *** seglow and seghigh are the bounds of the incoming segment,
 *** winlow and winhigh are the bounds of the receive window
 ***/
    seglow= intel(tp->seqnum);
    seghigh= seglow+seglen + (flags&(tcp_FlagACK|tcp_FlagFIN|tcp_FlagSYN) ? 1 : 0);
    winlow= s->acknum;
    winhigh= winlow + s->rxbufsize - s->rdatalen;
    if (winlow==winhigh) winhigh++; /* always room for a Flag */
    if ( seghigh<=winlow || winhigh <= seglow ) good=FALSE;
    if (!good) {
	DB2((FDB,
	    "acceptable(): state %s accept %s: seglen= %d seg: %8lx %8lx, win: %8lx %8lx\n",
	    state_names[s->state], good ? "T":"F",seglen,seglow,seghigh,winlow,winhigh));
	DB2((FDB,"	send win: %8lx %8lx, tp->ack=%8lx\7\n",
	    s->seqnum,s->seqnum+s->unacked+
	    (s->flags &(tcp_FlagSYN|tcp_FlagFIN)? 1:0),intel(tp->acknum)));
	/* should send an ack, unless RST is present */
	if (! (intel16(tp->flags) & tcp_FlagRST) ) {
	    s->flags=tcp_FlagACK;
	    s->unhappy=YES ;
	}
    }
    /* else trim packet if needed */
    return(good);
}


static void
set_UP(int flags, tcp_Socket *s, tcp_Header *tp)
{
DB2((FDB,"set_UP():\n"));
    if( (flags & tcp_FlagURG) && (s->state== tcp_StateESTAB) ) {
	s->UP= (s->UP >= intel16(tp->urgentPointer)) ?
		s->UP : intel16(tp->urgentPointer);
	}
}

static void
tcp_handler1(register tcp_Socket *s,in_Header *ip,
	tcp_Header *tp,word flags,int len /* tcp hdr+data */)
{
    int acked;          /* counters for acked bytes */
    long lacked;

    DB2((FDB,"tcp_handler1(): %d bytes (tcp hdr+data)\n",len));
    switch(s->state) {  /* break or return is the same */
    default: /* just to be sure not to forget... */
	DB3((FDB,"Warning: received a segment in state %s\n",state_names[s->state]));
	return;
/***
 *** these states should be:
 ***    CLOSING LASTACK TIMEWT  CLOSEMSL        CLOSED
 ***/

    case tcp_StateLISTEN:
	DB2((FDB,"State = LISTEN \n")); DB_W("LI ");

/***
 *** I know nothing about sequence numbers here.
 *** First check for an RST: incoming RST are ignored
 ***/

	if (flags & tcp_FlagRST) {
	    DB2((FDB,"ignoring incoming RST\n"));
	    return; /* ignore */
	}
/***
 *** Second check for an ack. Any ACK is bad here, an acceptable
 *** RST segment should be formed with:
 ***    s->seqnum= intel(tp->acknum);
 ***    s->flags= tcp_FlagRST;
 *** Send it and return.
 ***/

	if (flags & tcp_FlagACK) {
	    DB2((FDB,"reply RST to incoming ACK\n"));
	    tcp_rst(ip,tp);
	}

/***
 *** Third, check for a SYN. If set, check security. If ok, set
 ***    s->acknum= intel(tp->seqnum)+1;
 ***    s->flags= tcp_FlagSYN | tcp_FlagACK;
 *** and send the segment, changing state to SYNRECLIS.
 ***/
 
	if (flags & tcp_FlagSYN) {
	    DB2((FDB,"good SYN, goto SYNRECLIS\n"));
	    s->acknum= intel(tp->seqnum)+1;
	    s->hisport = intel16(tp->srcPort);
	    s->hisaddr = intel(ip->source);
	    s->window = intel16( tp->window ); /* set new send window size */
	    DB2((FDB,"LISTEN: window = %d \n",s->window));
	    tcp_ProcessData(s,tp,len); /* for options */
	    s->flags= tcp_FlagSYN | tcp_FlagACK;
	    s->state=tcp_StateSYNRECLIS;
	    DB2((FDB,"Sending SYN+ACK to incoming SYN, going to SYNRECLIS\n"));
	    tcp_send(s); /* send right away, no data */
	    s->timeout=set_ttimeout(tcpAbortTimeout);
	    return;
	} 
/***
 *** Should never arrive here, in any case drop the segment
 *** and return.
 ***/
	DB3((FDB,"LISTEN: don't know what to do with a segment\n"));
	return;

    case tcp_StateSYNSENT:
	DB2((FDB,"State = SYNSENT \n")); DB_W("SYs ");
/***
 *** First, check the ACK bit. If set, but not for our SYN,
 *** and is not a RST (discard it) send RST with
 ***    s->seqnum= intel(tp->acknum);
 ***    s->flags= tcp_FlagRST;
 *** discard the segment and return.
 ***/

	if (flags & tcp_FlagACK) {
	    if (intel(tp->acknum) != s->seqnum +1) { 
		DB2((FDB,"bad ACK\n"));
		if (!(flags & tcp_FlagRST)) { 
		    tcp_rst(ip,tp);
		}
		return;
	    }
	    /*** else, my fin has been acked, but it's easier
	     *** to check it later.
	     ***/
	}
	DB2((FDB,"good ACK for a SYNSENT\n"));

/***
 *** Second, check RST bit. If set, and the ACK was acceptable,
 *** signal "error: connection reset", drop the segment and enter
 *** the CLOSED state. Otherwise drop the segment and return.
 ***
 *** NOTE: apparently, NCSA Telnet sends a RST without ACK. Thus,
 *** I do not check the ACK here. This is a deviation from standard.
 ***/

	if (flags & tcp_FlagRST) {
	    DB3((FDB,"whoops, received RST in state %s\n",state_names[s->state]));
	    /* if (flags & tcp_FlagACK) */
		tcp_close_sock(s,"error: connection reset");
	    return;
	}                       

/***
 *** At this point have a good segment (maybe with an ACK).
 *** Third check security.
 *** Fourth, check the SYN bit. If set, then
 ***    s->acknum= intel(tp->seqnum)+1;
 *** If our SYN has been acked, go to state ESTAB, and send an ack
 *** else goto state SYNREC and send SYN,ACK (the SYN is the old one).
 ***/

	if (flags & tcp_FlagSYN) {
	    DB2((FDB,"good SYN in SYNSENT\n"));
	    s->flags=tcp_FlagACK; /* ack remote SYN */
	    s->window = intel16( tp->window ); /* set new send window size */
	    DB2((FDB,"SYNSENT: window = %d\n",s->window));
	    s->acknum=intel(tp->seqnum) +1; 
	    if (flags & tcp_FlagACK) {
		/* seqnum have already been checked */
		s->seqnum++; /* my SYN has been acked */
		s->state=tcp_StateESTAB;
		s->timeout=0; /* no more timeout */
		s->unhappy = YES; /* is it needed */
		DB2((FDB,"going from SYNSENT to ESTAB\n"));
		goto ESTAB_6;
	    } 
	    else {
		/* maybe there are options, should process them */
		s->flags = tcp_FlagSYN | tcp_FlagACK;
		s->state=tcp_StateSYNREC;
		DB2((FDB,"going from SYNSENT to SYNREC\n"));
		tcp_send(s);
		s->timeout=set_ttimeout(tcp_TTIMEOUT); /* why ?? */
		return;
	    }
	} 

/***
 *** Fifth, if neither SYN or RST, drop the segment and return
 ***/
	return;

    case tcp_StateSYNREC:
	DB2((FDB,"State = SYNREC\n")); DB_W("SYr ");
	goto ESTAB_1;
    case tcp_StateSYNRECLIS:
	DB2((FDB,"State = SYNRECLIS\n")); DB_W("SYl ");
	goto ESTAB_1;
    case tcp_StateESTAB:
	DB2((FDB,"State = ESTAB\n")); DB_W("ES ");
	goto ESTAB_1;
    case tcp_StateESTCL:
	DB2((FDB,"State = ESTCL\n")); DB_W("EC ");
	goto ESTAB_1;
    case tcp_StateCLOSWT:
	DB2((FDB,"State = CLOSWT\n")); DB_W("CW ");
	goto ESTAB_1;
    case tcp_StateCLOSWTCL:
	DB2((FDB,"State = CLOSWTCL\n")); DB_W("CWc ");
	goto ESTAB_1;
    case tcp_StateFINWT1:
	DB2((FDB,"State = FINWT1\n")); DB_W("FW1 ");
	goto ESTAB_1;
    case tcp_StateFINWT2:
	DB2((FDB,"State = FINWT2\n")); DB_W("FW2 ");
	goto ESTAB_1;
    case tcp_StateLASTACK:
	DB2((FDB,"State = LASTACK\n")); DB_W("LAk ");
	goto ESTAB_1;
    case tcp_StateTIMEWT:
	DB2((FDB,"State = TIMEWT\n")); DB_W("LAk ");
	goto ESTAB_1;

/***
 *** The folloging states are 'connected' states:
 ***    SYNREC  SYNRECLIS
 ***    ESTAB   ESTCL
 ***    FINWT1  FINWT2
 ***    CLOSWT
 ***    LASTACK
 ***    TIMEWT
 *** There is some common processing here.
 ***/

ESTAB_1:

/***
 *** First an acceptability test to see if any part of the incoming
 *** segment falls inside the current receive window. If not,
 *** RST are ignored, other segments are acked with
 ***    s->flags= tcp_FlagACK;
 *** and other fields as from the socket descriptor.
 ***/

	if (!acceptable(s,ip,tp)) return;

/***
 *** Second, check the RST bit. Here processing differs:
 ***/

	if (flags & tcp_FlagRST) { /* valid RST */
	    DB3((FDB,"oops.. found RST\n"));
	    switch(s->state) {
	    case tcp_StateSYNREC:
		tcp_close_sock(s, "Connection refused");
		return;
	    case tcp_StateSYNRECLIS:
		s->state=tcp_StateLISTEN;
		DB2((FDB,"going from SYNRECLIS to LISTEN\n"));
		s->timeout=0; /* ouch...where's the original timeout! */
		return;
	    case tcp_StateESTAB:
	    case tcp_StateESTCL:
	    case tcp_StateFINWT1:
	    case tcp_StateFINWT2:
	    case tcp_StateCLOSWT:
	    case tcp_StateCLOSWTCL:
		tcp_close_sock(s, "Connection reset");
		return;
	    case tcp_StateCLOSING:
	    case tcp_StateLASTACK:
	    case tcp_StateTIMEWT:
		tcp_close_sock(s,"");
		return;
/***
 *** CLOSEMSL and CLOSED are missing
 ***/
	    } /* end switch */
	    return; /*** of course ***/
	} /* end if, no RST found */

/***
 *** Third, check security.
 *** Fourth, check the SYN bit: a SYN within the window is an error,
 *** so send a reset and signal "connection reset".
 ***/
	if (flags & tcp_FlagSYN) {
	    DB3((FDB,"oops.. found SYN\n"));
	    tcp_rst(ip,tp);
	    tcp_close_sock(s, "Connection reset");
	    return;
	}

/***
 *** Fifth, check the ACK field. If off, drop segment and return.
 *** otherwise, processing differs.
 ***/

	if (!(flags & tcp_FlagACK)) {
	    DB3((FDB,"oops.. missing ACK\n"));
	    return; /* ack is off */
	}
	
	lacked= intel(tp->acknum) - s->seqnum;
	acked = (int)lacked;
	
	switch(s->state) {
	case tcp_StateSYNREC:
	case tcp_StateSYNRECLIS:
/***
 *** if the ack is acceptable, goto ESTAB and continue processing.
 *** otherwise form a RST segment
 ***    s->seqnum= intel(tp->acknum);
 ***    s->flags= tcp_FlagRST;
 *** and send it. I think we can return.
 ***/
	    if (lacked==1) {
		s->seqnum++; /* accept it */
		s->window=intel16(tp->window);
		s->flags= tcp_FlagACK;
		DB2((FDB,"Setting ACK in SYNREC\n"));
		s->unhappy=VERY;
		DB2((FDB,"Setting VERY in SYNREC\n"));
		s->state=tcp_StateESTAB;
		s->timeout=0;
		DB2((FDB,"Received ACK for SYN in SYNRECLIS- going to ESTAB\n"));
		goto ESTAB_6;
	    }
	    else {
		DB3((FDB,"Warning: ack for unsent data/flags\n"));
		tcp_rst(ip,tp);
		return;
	    }

	case tcp_StateESTAB:
	case tcp_StateESTCL:
	case tcp_StateCLOSWT:
	case tcp_StateCLOSWTCL:
/***
 *** If ack is valid, remove data from the retransmission queue.
 *** The send window should be updated.
 *** Duplicate acks are ignored, invalid acks are acked,
 *** then drop segment and return.
 *** An ack also has a new remote window. If it grows,
 *** we try to send our data becoming VERY unhappy.
 ***/

	    if ( lacked <= 0 ) {
		if (lacked==0) {
/***
 *** maybe a window re-opening. Or the other party wants to send
 *** something.
 ***/
		    int oldwindow;
		    oldwindow = (int)s->window;
		    s->window = intel16( tp->window );
/***
 *** DOUBLE CHECK THIS !!!
 ***/
		    if ( (oldwindow < 1 ) &&
			( s->window > (word)s->unacked) &&
			( s->window > (word)oldwindow ) ) {
			   s->unhappy= VERY; 
			   DB2((FDB,"Window reopening lacked == 0\n"));
		    }
		}
		else {
		    DB2((FDB,"duplicate ack, ignore\n"));
		}
	    }
	    else {
		if (lacked <= (long)s-> unacked) {
		    int oldwindow;
		    DB2((FDB,"valid ack\n"));
		    oldwindow = (int)s->window;
		    s->window = intel16( tp->window );
		    DB2((FDB,"State %d: window = %d \n",s->state,s->window));
		    s->datalen -= acked;
		    s->unacked -= acked;

		    s->seqnum += lacked;
		    recompute_rto(s);
		    if (s->datalen) {
			memmove(s->data,s->data+acked,s->datalen);
			if (( s->window > (word)s->unacked) &&
			  (s->window>(word)oldwindow)) { /* window reopening */
			   s->unhappy=VERY;
			   DB2((FDB,"Setting VERY in State %d\n",s->state));
			}
		    }
		    else { /* no more data pending */
			s->unhappy=NO; /* as far as I know... */
			s->vj_last=0;
			s->rtt_time=0; /* and remove timeout. */

/***
 *** If I had a CLOSE pending, send a FIN. Must call tcp_send()
 *** directly because after that I'll be in the new state.
 ***/
			if (s->state== tcp_StateESTCL
			    || s->state==tcp_StateCLOSWTCL) {
			    s->flags= tcp_FlagFIN | tcp_FlagACK;
			    tcp_send(s); /* here or later ? */
			    DB2((FDB,"going from %s",state_names[s->state]));
			    s->state= s->state== tcp_StateESTCL ?
				tcp_StateFINWT1:tcp_StateLASTACK;
			    DB2((FDB,"to %s\n",state_names[s->state]));
			}
		    }
		} else {
		    DB3((FDB,"invalid ack - drop segment\n"));
		    s->flags=tcp_FlagACK;
		    s->unhappy = YES ;
		    return;
		}
	    }
	    break;
/***
 *** FINWT1, FINWT2, CLOSING have a similar processing, plus
 *** something. Checks are simpler, though, because have at
 *** most one FIN still unacked.
 ***
 *** For FINWT1, if FIN is acked, enter FINWT2 and continue
 *** processing from there.
 ***
 *** For FINWT2, if the retransmission queue is empty, the
 *** user's CLOSE can be acknowledged but the TCB cannot be
 *** deleted. Note that I choose to empty out the retran.queue
 *** before sending my FIN.
 ***
 *** For CLOSING, if the ACK is for our FIN then enter TIMEWAIT,
 *** otherwise ignore the segment.
 ***/
	case tcp_StateCLOSING: /***/
	case tcp_StateFINWT1: /***/
	    if (lacked<=0) break; /* old ack, ignore */
	    if (lacked!=1) return; /* unvalid ack, drop segment */
	    s->seqnum++; /* ack my fin */
	    s->flags= tcp_FlagACK;
	    s->rtt_time=0; /* no more timeout */
	    if (s->state==tcp_StateFINWT1) {
		DB2((FDB,"going from FINWT1 to FINWT2\n"));
		s->state=tcp_StateFINWT2;
		goto FINWT_2;
	    }
	    else {
		DB2((FDB,"going from CLOSING to TIMEWT\n"));
		s->state=tcp_StateTIMEWT;
		s->timeout=set_ttimeout(100); /* 2MSL */
	    }
	    break;
	case tcp_StateFINWT2: /***/
	    if (lacked != 0) return; /* unvalid ack, drop */
	    break;
	case tcp_StateLASTACK:
/***
 *** The only thing can arrive is an ack to our FIN. if it is it,
 *** delete TCB, enter CLOSED state and return.
 ***/
	    if (lacked==1) {
		tcp_close_sock(s,"");
	    }
	    return;
	case tcp_StateTIMEWT:
/***
 *** The only thing can arrive is a retransmission of the remote FIN.
 *** Acknowledge it and restart the 2MSL timeout.
 *** To be completed.
 ***/
	    break;
	} /* end switch */

ESTAB_6:

	DB2((FDB,"we are in ESTAB_6:\n"));
/***
 *** Sixth, check the urgent bit:...
 ***/
	/* set_UP(s->flags,ip,tp); */
/***
 *** Seventh, process the segment text.
 ***/
	if (len>sizeof(tcp_Header)) { /* have data or options */
	    switch(s->state) {
	    case tcp_StateESTAB:
	    case tcp_StateESTCL:
	    case tcp_StateFINWT1:
	    case tcp_StateFINWT2:
/***
 *** Text segments can be delivered to user space. I'll ignore
 *** PUSH requests here. If there are too many data, ProcessData
 *** returns 0 so that the subsequent FIN is not processed.
 ***/
FINWT_2:
		if (!tcp_ProcessData(s,tp,len)) return;
		break;
	    default:
/***
 *** data shouldn't arrive. Ignore them.
 ***/
		DB3((FDB,"Unexpected data in state %s\n",state_names[s->state]));
		break;
	    } /* end switch */
	}
/***
 *** Eight: check the FIN bit. Do not process FIN in CLOSED,
 *** LISTEN or SYN_SENT because it cannot be validated (drop
 *** the segment and return in these cases).
 *** If FIN is set, signal "connection closing" to any
 *** pending receive. Advance s->acknum over FIN and ack the FIN.
 *** FIN implies PUSH for any text not yet delivered to the user.
 *** Then...
 *** SYNREC, SYNRECLIS, ESTAB: enter CLOSEWAIT
 *** FINWT1: if our fin has been acked, so enter TIMEWT, start the
 *** timewait timer and turn off the other timers. otherwise enter
 *** the CLOSING state.
 *** FINWT2: as FINWT1 (and assume FIN has been acked).
 *** TIMEWAIT: restart the 2MSL timeout.
 *** other cases, remain in the same state.
 ***/
	if (flags & tcp_FlagFIN) {
	    DB2((FDB,"FIN arrived\n"));
	    s->err_msg="Connection closing";
	    switch(s->state) {
	    case tcp_StateESTAB:
	    case tcp_StateSYNREC:
	    case tcp_StateSYNRECLIS:
		s->acknum++;
		DB2((FDB,"fin arrived, going from state %s to CLOSWT\n",state_names[s->state]));
		s->state=tcp_StateCLOSWT;
		s->timeout= set_ttimeout(100); /* here they should close soon */
		break;
	    case tcp_StateESTCL:
/***
 *** Here, I don't know what to do yet. Ignore the segment until
 *** all data have been flushed (i.e. we have reached FINWT1).
 ***/
		DB3((FDB,"Received CLOSE in ESTCL. Check this.\7\n"));
		return;
#ifdef notdef
		s->acknum++;
		DB2((FDB,"going from ESTCL to CLOSING\n"));
		s->state=tcp_StateCLOSING; /* or somewhere else ??? */
		break;
#endif /* notdef */
	    case tcp_StateFINWT1:
		s->acknum++;
		if (flags & tcp_FlagACK) {
		    DB2((FDB,"going from FINWT1 to TIMEWT\n"));
		    s->state=tcp_StateTIMEWT;
		    s->timeout=set_ttimeout(100);
		} else {
		    DB2((FDB,"going from FINWT1 to CLOSING\n"));
		    s->state=tcp_StateCLOSING;
		}
		break;
	    case tcp_StateFINWT2:
		s->acknum++;
		DB2((FDB,"going from FINWT2 to TIMEWT\n"));
		s->state=tcp_StateTIMEWT;
		s->timeout=set_ttimeout(100);
		break;
	    default:
		DB3((FDB,"Don't want FIN in state %s\n",state_names[ s->state]));
		return;
	    }
	    DB2((FDB,"Sent ACK\n"));
	    s->flags=tcp_FlagACK;
	    tcp_send(s); /* ack the FIN */
	}
    } /* end main switch */
} /* end tcp_handler1 */


static void
tcp_handler(in_Header *ip)
{
    tcp_Header *tp;
    tcp_PseudoHeader ph;
    int i, len, found = 0;
    register tcp_Socket *s, *ps;
    word flags;

DB2((FDB,"tcp_handler():\n"));
    gm_tcp_handler++;
    DB_W("h ");
    len = ip->hdrlen << 2;
    tp = (tcp_Header *)((byte *)ip + len);      /* tcp frame pointer */
    len = intel16( ip->length ) - len;          /* tcp data including TCP hdr*/
    flags = intel16( tp->flags );               /* this saves time later */
    DB2((FDB,"entering tcp_handler: %d bytes (tcp hdr+data)\n",len));

		    /* demux to active sockets */
    for ( s = tcp_allsocs; s; s = s->next ) {
	if ( s->safetysig != SAFETYTCP ) {
	    outs("chain error in tcp");
	    exit(3);
	    }
	if ( s->hisport != 0 &&
	    intel16( tp->dstPort ) == s->myport &&
	    intel16( tp->srcPort ) == s->hisport &&
	    intel( ip->source ) == s->hisaddr ) break;
        } /* end for */

	     /* demux to passive sockets, must be a new session */

    if ( !s && (flags & tcp_FlagSYN)) {
#ifdef unused /* because there is no multi_listen() */
	/* first look at those sockets created with multi_listen */
	for( ps = tcp_allsocs ; ps ; ps = ps->next ){
	    if( ps->father) break;
	}
	if(ps){
	    ps = (ps->father)->next;
	    s = ps;
	    for(;;){
		if ((s->hisport==0)&&(intel16(tp->dstPort)==s->myport)){
		    found = 1;
		    break;
		}
		if ( (s = s->brother) == ps ) break;
	    }
	}
#endif /* unused */
	if(!found){
	    /* then look at those socket created with listen */
	    for( i=0 ; i<MAXSOCK ; i++ ){
		ps = (tcp_Socket *)sockarr[i].sockp;
		if( ps && ps->brother ){
	 	    s = ps;
		    for(;;){	
		        if ((s->hisport==0)&&(intel16(tp->dstPort)==s->myport)){
			     	found = 1;
				break;
			}
			if( (s = s->brother) == ps ) break;
		    }
		}
		if(found) break;
	    }
	}

	if(!found){
	    /* at the end look all the sockets */
	    for ( s = tcp_allsocs; s; s = s->next )
		if ((s->hisport==0)&&(intel16(tp->dstPort)==s->myport))
		    break;
	}
    }
    if ( !s ) { /* no session seems to exist */
	tcp_rst( ip, tp ); 
	return;
    }

    if ( sock_inactive ) s->inactive_to = set_timeout( sock_inactive );

    /* save his ethernet address */
    memcpy( &s->hisethaddr[0], &((((eth_Header *)ip) - 1)->source[0]),
	    sizeof(eth_address));

    /*** test checksum ***/
    ph.src = ip->source;        /* already INTELled */
    ph.dst = ip->destination;
    ph.mbz = 0;
    ph.protocol = TCP_PROTO;
    ph.length = intel16( len );
    ph.checksum =  inchksum((void *)tp, len);
    if ( inchksum((void *)&ph, sizeof(ph)) != 0xffff ) {
	DB3((FDB,"bad checksum! in tcp_handler\n"));
	return;
    }
    tcp_handler1(s,ip,tp,flags,len);
    return;
}

/***
 *** Process the data in an incoming packet.
 *** Called from all states where incoming data can be received:
 *** ESTAB, ESTCL, FINWT1, FINWT2
 ***/
static int
tcp_ProcessData(register tcp_Socket *s, tcp_Header *tp, int len)
{
    int result=TRUE;
    long lacked;
    int acked, x;
    word flags;
    byte *dp;


    DB2((FDB,"Enter tcp_ProcessData for %d bytes\n", len));
    gm_tcp_ProcessData++;

    flags = intel16( tp->flags );
    lacked = s->acknum - intel( tp->seqnum );
/***
 *** s->acknum is the last ack I sent. If all the data have arrived,
 *** this is also the seqnum of the first byte of the incoming segment,
 *** thus lacked==0. If the segment is an old copy, tp->seqnum is lower,
 *** thus lacked>0 (still it might have some good data).
 *** If I have lost some data, lacked<0 (this I cannot accept).
 *** Also, if the segment carries a SYN, it is considered the
 *** first item, so I have to decrease lacked (the first actual data
 *** byte is at tp->seqnum+1).
 ***/
    if ( flags & tcp_FlagSYN ) lacked--;  /* back up to 0 */
    acked = (int) lacked; /* shorthand */

    /*** find the data portion ***/
    x = tcp_GetDataOffset(tp) << 2;     /* quadword to byte format */
    dp = (byte *)tp + x;        /* pointer to data */

    /*** check for options (i.e. a longer header) ***/
    if ( x > sizeof( tcp_Header )) {
	byte *op;
	gm_proc_option++;
	op = (byte *)(tp) + sizeof(tcp_Header);
	DB2((FDB,"have %d bytes of options\n",x-sizeof(tcp_Header)));
	while ( op < dp ) {
	    gm_proc_opt_in++;
	    switch ( *op ) {
	    case  0 : /*** end of options ***/
		op = dp;
		break;
	    case  1 : /*** nop ***/
		op++;
		break;
	    case  2 : /*** we are very liberal on MSS stuff */
		op++; /* pointer to option len */
		if (*op == 4) {
		    word tmp= intel16( *( (word*)(op+1) ) );
		    DB2((stderr,"old mss=%d new mss=%d\n",s->mss, tmp));
		    if (tmp < _mss ) s->mss = tmp;
		}
		op += *op - 1;
		break;
	    default:
		DB3((stderr,"Warning, unrecognized tcp option %x\n",*op));
		op=dp;
		break;
	    }
	} /* end while */
    } /* done option processing */

    len -= x;           /* remove the header length */
    if ( lacked >= 0 && len>0 ) { /* new data (good ones) */
	dp += acked; /* skip already received bytes */
	len -= acked; /* now might be len <= 0 */
	DB2((FDB,"have %d bytes of new data\n", len));

	if (s->dataHandler) {
	    int tmp= s->dataHandler(s, dp, len);
	    s->acknum += tmp;
	    result = (tmp==len);
	} 
	else {
	    /* no handler, just dump to buffer */
	    /* limit receive size to our window */
	    if ( s->rdatalen >= 0 ) { /* fails only after a cancel */
		if ( len > ( x = s->rxbufsize - s->rdatalen )) {
		    len = x;
		    result=FALSE;
		    DB3((FDB,"Warning, can't take all the new data\n"));
		}
		if ( len > 0 ) {
/***
 *** This might fail if the first SYN carries data...
 ***/
		    s->acknum += len;   /* our new ack begins at end of data */
		    memcpy(s->rdata+s->rdatalen ,dp, len );
		    s->rdatalen += len;
/***
 *** Want to send an ack. The strategy to be used may vary.
 *** Either send it right away, or wait for the input buffer to
 *** be sufficiently full.
 ***/
		    s->unhappy |= s->rdatalen < s->rxbufsize/2 ? YES:VERY;
		    DB2((FDB,"Setting VERY in ProcessData\n"));
		}
	    }
	}
	if (s->timeout) s->timeout=set_ttimeout( tcp_TTIMEOUT ); /* check this ??? */
    }
    else { /* else no data in this packet */
	DB2((FDB,"have no new data\n"));
    }
    return(result);
} /* end tcp_ProcessData */

/*
 * Format and send an outgoing segment
 */
static void
tcp_send(register tcp_Socket *s)
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
    word senddatalen,
    sendpktlen,
    maxsend,    /* max offset of data to be sent */
    sentdata;   /* # of bytes actually sent */

    register char *r; /* used as a pointer, for efficiency */

    DB2((FDB,"tcp_send():\n"));
    gm_tcp_send++;
    s->unhappy=FALSE; /* clear it */
    pkt = (struct _pkt *)_eth_formatpacket(&s->hisethaddr[0], 8 /*IP */);
    dp = (byte *)&pkt->maxsegopt;       /* dp points to data */
    inp = &pkt->in;                     /* inp points to ip header */
    tcpp = &pkt->tcp;                   /* tcpp points to tcp header */

    maxsend=min((word)s->datalen, s->window); /* max possible send size */
    if (s->window==0 && s->datalen > s->unacked) {
	s->flags |= tcp_FlagPUSH; 
	DB2((FDB,"tcp_send(): datalen=%d, window=%d\n",s->datalen,s->window));
    }
    if (s->datalen >0 && s->window ==0 ) s->unhappy=YES;
    sentdata=0;
    do {
	DB2((FDB,"looping in tcp_send - sending %d data bytes\n", maxsend));
	/* enter at least once, to send flags */
	/* adjust size for each packet */
	if( maxsend < (word)s->unacked ) {
	    DB4((stderr,"Error - senddatalen<0\7\n"));
	}
	senddatalen= maxsend - (word)s->unacked;
	if (senddatalen > s->mss) senddatalen = s->mss;
	DB2((FDB,"tcp_send - truncate to %d data bytes\n", senddatalen));

	/*** Prepare tcp header ***/
	r=(char *)tcpp;
#define tcpp ((tcp_Header *)r)

	tcpp->srcPort = intel16( s->myport );
	tcpp->dstPort = intel16( s->hisport );
	tcpp->seqnum = intel(s->seqnum + (long)s->unacked);
	tcpp->acknum = intel( s->acknum );
	tcpp->window = intel16( s->rxbufsize - s->rdatalen );

	tcpp->flags = intel16( s->flags | 0x5000 );
		/* 5000 is the tcp_data_offset in the tcp header */
	tcpp->checksum = 0;
	tcpp->urgentPointer = 0;

	if (s->unacked <0 || s->unacked > s->txbufsize) {
	    DB4((FDB,"tcp_send: len=%5d unack=%5d rwin=%5d seq=%10lu\n",
		senddatalen, s->unacked, s->window, intel(tcpp->seqnum)));
	    DB4((FDB,"     rdatalen=%5d          thiswin=%5d ack=%10lu\n",
		s->rdatalen, intel16(tcpp->window), s->acknum));
	}
	if ((s->flags & (tcp_FlagSYN | tcp_FlagACK)) == tcp_FlagSYN) {
	    /* do options if this is our first packet */
	    sendpktlen = sizeof( tcp_Header ) + sizeof( in_Header ) + 4; 
	    tcpp->flags = intel16( intel16( tcpp->flags) + 0x1000 );
		/*** 1000 means there are some options in the tcp header ***/
	    pkt->maxsegopt[0] = 0x0402;
	    pkt->maxsegopt[1] = intel16( s->mss );
	    dp += 4;
	} 
	else { /* handle packets with data */
	    if (senddatalen > 0) {
		memcpy(dp, s->data + s->unacked, senddatalen);
		dp[ senddatalen ] = 0;  /* zero padding is safe */
	    }
	    sendpktlen=senddatalen+sizeof(tcp_Header)+sizeof(in_Header); 
	}

	/*** internet header, build IP header ***/
#undef tcpp
	make_in_hdr(inp, TCP_PROTO, s->hisaddr, sendpktlen);

	/* compute tcp checksum */
#ifdef notdef
	r= &ph;
#define ph (*(tcp_PseudoHeader *)r)
#endif /* notdef  */
	ph.src = inp->source;   /* already INTELled */
	ph.dst = inp->destination;
	ph.mbz = 0;
	ph.protocol = 6;
	ph.length = intel16( sendpktlen - sizeof(in_Header));
	ph.checksum=inchksum((void *)&pkt->tcp,(sendpktlen-sizeof(in_Header)+1)&0xfffe);

	tcpp->checksum = ~inchksum((void *)&ph, sizeof(ph));
#ifdef ph
#undef ph
#endif /* ph */
	if (senddatalen==0) {
		DB2((FDB,"calling _eth_send(): for empty pkt\n"));
		emptyretr++;    
	}
	if (senddatalen==0 && (s->flags & tcp_FlagACK)) {
		DB2((FDB,"Send ACK\n"));
		emptyeack++;
	}

#ifdef debug
	if (s->flags & tcp_FlagFIN) { DB2((FDB,"Sending FIN\n")); }
	if (s->flags & tcp_FlagSYN) { DB2((FDB,"Sending SYN\n")); }
#endif /* debug */
	if ( _eth_send( intel16( inp->length ))) { /* encounterred error */
	    s->unhappy=VERY; /* send failed, try later */
		DB2((FDB,"Setting VERY cause of failure of eth_send\n"));
	    break;
	}
	if (senddatalen==0) break; /* can't send more */

	/* do next ip pkt */
	sentdata += senddatalen;
	s->unacked += (int)senddatalen; /* 03-mar-92 lr-gm */
	if (s->unacked >s->txbufsize) {
	    DB4((stderr,"Wrong value in s->unacked: %d\n",s->unacked));
	}
    } while ( s->unacked < (int)maxsend );
    if (sentdata || (s->flags & (tcp_FlagSYN | tcp_FlagFIN)) ) {
	s->vj_last = set_ttimeout( 0 ); /* mark send time */
	s->rtt_time = set_ttimeout( s->rto );
    } else {
	s->vj_last = 0; /* might be useless */
	s->rtt_time = 0;
    }
} /* end tcp_send */

/*
 * Format and send a reset tcp packet
 */
void
tcp_rst( in_Header *his_ip, tcp_Header *oldtcpp )
{
    tcp_PseudoHeader ph;
    struct _pkt {
	in_Header in;
	tcp_Header tcp;
	word maxsegopt[2];
    } 
    *pkt, *his_pkt;

    static longword nextrst = 0L;
    byte *dp;
    word oldflags;
    in_Header *inp;
    tcp_Header *tcpp;
    eth_Header *eth;
    int sendtotlen;     /* length of packet */
    longword templong;

    /* see RFC 793 page 65 for details */

    DB2((FDB,"tcp_rst():\n"));
    gm_tcp_rst++;
    /*
     * at most one RST per tick
     */
    if ( !chk_timeout( nextrst )) return;
    nextrst = set_ttimeout( 1 );

    oldflags = intel16( oldtcpp->flags );
    if (oldflags & tcp_FlagRST ) return;
    if ( (oldflags & (tcp_FlagACK | tcp_FlagFIN)) == (tcp_FlagACK | tcp_FlagFIN) ){
	templong = oldtcpp->seqnum;
	oldtcpp->seqnum = oldtcpp->acknum;
	oldtcpp->acknum = templong;
	oldflags = tcp_FlagACK;
    } 
    else if ((oldflags & (tcp_FlagSYN | tcp_FlagACK)) ==  tcp_FlagSYN ) {
	oldtcpp->acknum = intel( intel( oldtcpp->seqnum ) + 1 );
	oldtcpp->seqnum = 0;
	oldflags = tcp_FlagACK | tcp_FlagRST;
    } 
    else if ( oldflags & tcp_FlagACK ) {
	oldtcpp->seqnum = oldtcpp->acknum;
	oldtcpp->acknum = 0;
    } 
    else {
	oldtcpp->acknum = intel( intel(oldtcpp->seqnum) + 1);
	oldtcpp->seqnum = 0;
    }
    if ( (oldflags & ( tcp_FlagFIN | tcp_FlagSYN )) == 0 )
	oldflags ^= tcp_FlagACK | tcp_FlagRST;

    his_pkt  = (struct _pkt*)( his_ip );

    /* convoluted mechanism - reads his ethernet address or garbage */
    eth = _eth_hardware( (byte *)his_ip );

    pkt = (struct _pkt *)_eth_formatpacket( eth, 8);
    dp = (byte *)&pkt->maxsegopt;
    inp = &pkt->in;
    tcpp = &pkt->tcp;

    sendtotlen = sizeof( tcp_Header ) + sizeof( in_Header );

    /* tcp header */
    tcpp->srcPort = oldtcpp->dstPort;
    tcpp->dstPort = oldtcpp->srcPort;
    tcpp->seqnum = oldtcpp->seqnum;
    tcpp->acknum = oldtcpp->acknum;
    tcpp->window = 0;
    tcpp->flags = intel16( oldflags );
    tcpp->checksum = 0;
    tcpp->urgentPointer = 0;

    /* internet header */
    make_in_hdr(inp, TCP_PROTO, intel(his_ip->source) , sendtotlen);

    /* compute tcp checksum */
    ph.src = inp->source;       /* already INTELled */
    ph.dst = inp->destination;
    ph.mbz = 0;
    ph.protocol = 6;
    ph.length = intel16( sendtotlen - sizeof(in_Header));

    ph.checksum = inchksum((void *)&pkt->tcp, (sendtotlen - sizeof(in_Header) +1) & 0xfffe);
    /* intel16(ph.length));*/ /* 0; *//* watstar */
    tcpp->checksum =  ~inchksum((void *)&ph, sizeof(ph));
#ifdef DEBUG
    if (_dbugxmit) (*_dbugxmit)(NULL,inp,tcpp);
#endif /* DEBUG */
    DB2((FDB,"tcp_rst(): calling _eth_send():\n"));
    _eth_send( intel16( inp->length ));
} /* end tcp_rst() */



/*************************************************************
 ***                      socket functions                 ***
 *************************************************************/

/***
 *** sock_yield - enable user defined yield function
 ***/
void
sock_yield( tcp_Socket *s, void (*fn)())
{ if ( s ) s->usr_yield = fn; else system_yield = fn; }

/***
 *** sock_mode - set binary or ascii - affects sock_gets, sock_dataready
 ***         - set udp checksums
 ***/
void sock_mode( sock_type *s, word mode )
{ s->tcp.sock_mode = (s->tcp.sock_mode & 0xfffc) | mode; }

/***
 *** sock_read - read a socket with maximum n bytes
 ***         - busywaits until buffer is full but calls s->usr_yield
 ***         - returns count also when connection gets closed
 ***/
int
sock_read(sock_type *s, byte *dp, int len )
{
    int templen, count=0;

    DB2((FDB,"sock_read():\n"));
    while (len) {
	if ( s->udp.ip_type == UDP_PROTO ) {
	    if (len > (int)_mss) len =_mss;
	    templen = udp_read((udp_Socket *) s, dp, len );
	}
	else
	    templen = tcp_read((tcp_Socket *)s, dp, len);
	if (s->tcp.usr_yield) (s->tcp.usr_yield)();
	if (templen < 1 ) { /* couldn't read */
	    if (!tcp_tick( s )) { /* closed, or something */
		/*** should also check for incoming PUSH ***/
		return( count ); 
	    }
	} 
	else {
	    count += templen;
	    dp += templen;
	    len -= templen;
	}
    }
    return( count );
}

/***
 *** sock_fastread - read a socket with maximum n bytes
 ***         - does not busywait until buffer is full
 ***/
int sock_fastread(sock_type *s, byte *dp, int len )
{
DB2((FDB,"sock_fastread():\n"));
    return(s->udp.ip_type==UDP_PROTO ? udp_read((udp_Socket*)s,dp,len)
	: tcp_read((tcp_Socket *)s,dp,len) );
}


/***
 *** sock_write - writes data and returns length written
 ***          - does not perform flush
 ***          - repeatedly calls s->usr_yield
 ***/

int
sock_write(register sock_type *s, byte *dp, int len)
{
    register int offset=0;
    int  oldmode=0, proto;
    int oldlen;
    int len1;
    DB2((FDB,"sock_write():\n"));

    oldlen=len;
    proto = (s->udp.ip_type == TCP_PROTO);
    if ( proto ) oldmode = s->tcp.flags & tcp_FlagPUSH;
    while ( len > 0) {
	len1=len;
	DB2((FDB,"looping in sock_write():\n"));
	if (proto) {
	    s->tcp.flags |= oldmode;
	    offset += tcp_write( (tcp_Socket *)s, &dp[ offset ], len);
	} 
	else {
	/* 31-mar92 gm Added to warn in case of truncation to mss */
		if (len > (int)_mss) {
		     printf("Warning! Transmission truncated to MSS=%d\n",_mss);
		     offset += udp_write(( udp_Socket*)s, &dp[offset], _mss); 
		     oldlen=_mss;
		} else offset += udp_write(( udp_Socket*)s, &dp[offset], len); 
	}
	len=oldlen-offset;
	if (s->udp.usr_yield) {
	    (s->udp.usr_yield)();
	}
	if (!tcp_tick(s)) { 
	    return( 0 );
	} 
	DB2((FDB,"sock_write(): wrote %d, unacked=%d\n",len1,s->tcp.unacked));
	DB2((FDB,"end looping in sock_write():\n"));
    }
    return( oldlen );
}


int
sock_fastwrite(sock_type *s, byte *dp, int len)
{
    DB2((FDB,"sock_fastwrite():\n"));
    tcp_tick(NULL);     /* updates our output buffer */
    return( ( s->udp.ip_type == UDP_PROTO ) ?
	udp_write( (udp_Socket *)s, dp, len ) :
	tcp_write( (tcp_Socket *)s, dp, len) );
}

void
sock_flush( sock_type *s )
{
    if ( s->tcp.ip_type == TCP_PROTO ) tcp_Flush((tcp_Socket *) s );
}

int
sock_waitwrite( sock_type *s, byte *dp, int len )
{
    int templen;
    if ( s->udp.ip_type == UDP_PROTO ) {
	return udp_write( (udp_Socket *)s,dp,len);
    } else if ( (templen = s->tcp.datalen) + len > (int)(s->tcp.mss / 2)) {
	return( tcp_write( (tcp_Socket *)s, dp, len ) - templen );
    } else {
	movmem( dp, &s->tcp.data[s->tcp.datalen], len );
	s->tcp.datalen += len;
	return( len );
    }
}

/***
 *** sock_flushnext - cause next transmission to have a flush
 ***/
void
sock_flushnext( sock_type *s)
{
    if (s->tcp.ip_type == TCP_PROTO )
	s->tcp.flags |= tcp_FlagPUSH;
}

/***
 *** sock_putc - put a character
 ***         - no expansion but flushes on '\n'
 ***         - returns character
 ***/
byte
sock_putc( sock_type *s, byte c )
{
    if (( c == '\n') || ( c == '\r')) sock_flushnext( s );
    sock_write( s, &c, 1 );
    return( c );
}

word
sock_getc( sock_type *s )
{
    char ch;
    sock_read( s, &ch, 1 );
    return( ch );
}

/*
 * sock_puts - does not append carriage return in binary mode
 *           - returns length
 */
int
sock_puts( sock_type *s, byte *dp )
{
    int len;
    len = strlen( dp );
    sock_flushnext( s );
    sock_write( s, dp, len );
    if (s->tcp.sock_mode & TCP_MODE_ASCII ) sock_write( s, "\r\n", 2 );
    return( len );
}

/*
 * sock_update - update the socket window size to the other guy
 */
static void
sock_update( tcp_Socket *s )
{
    if (s->ip_type == TCP_PROTO) {
	if ( s->rdatalen < ( 3 * s->rxbufsize) / 4 ) {
	    tcp_send( s );      /* update the window */
	} 
	else {
	    s->unhappy=YES;
	}
    }
}

/*
 * sock_gets - read a string from any socket
 *           - return length of returned string
 *           - removes end of line terminator
 */
word
sock_gets( sock_type *s, byte *dp, int n )
{
    int len, templen;
    char *src_p, *temp, *temp2;
    word *np;
    short BufSize=0;

    if ( s->udp.ip_type == UDP_PROTO ) {
	src_p = s->udp.rdata;
	np = &s->udp.rdatalen;
	BufSize = s->udp.rxbufsize;
    } 
    else {
	src_p = s->tcp.rdata;
	np = &s->tcp.rdatalen;
	BufSize = s->tcp.rxbufsize;
    }

    if ( n > BufSize) n = BufSize;

    src_p[ *np ] = 0;           /* terminate string */
    strncpy( dp, src_p, n );    /* copy everything */
    dp[ n-1 ] = 0;              /* terminate */

    if (temp = strchr( dp, '\n')) *temp = 0;
    if (temp2= strchr( dp, '\r')) *temp2= 0;
    len = strlen( dp );

    /* skip if there were no crs or lfs ??? */
    if (!temp2 && !temp && ( (int)strlen(dp) < n - 1) ) {

	if ( s->udp.ip_type == TCP_PROTO &&
	    s->tcp.state != tcp_StateESTAB &&
	    s->tcp.state != tcp_StateESTCL &&
	    s->tcp.state != tcp_StateCLOSWT )
	    /* take what we can get from this connection */;
	else {
	    *dp = 0;
	    return( 0 );
	}
    }

    /* skip over \n and \r but stop on end */
#ifndef OLD
    if ( temp ) templen = FP_OFF( temp ) - FP_OFF( dp );
    else if ( temp2 ) templen = FP_OFF( temp2 ) - FP_OFF( dp );
    else templen = len + 1;

    if (templen) {
	++templen;
	movmem( &src_p[ templen ], src_p, *np -= templen);
    } 
    else
	* np = 0;
#else
    temp = &src_p[ len + 1 ];
    while ( *temp && (  ( *temp == '\n' ) || (*temp == '\r')))
	temp++;

    if (*temp)
	movmem( temp, src_p, *np = strlen( temp ));
    else
	*np = 0;
#endif 

    sock_update((tcp_Socket *) s );     /* new window */
    return( len );
}

/*
 * sock_dataready - returns number of bytes waiting to be ready
 *                - if in ASCII mode, return 0 until a line is present
 *                  or the buffer is full
 */
int
sock_dataready( register sock_type *s )
{
    int len;
    char *p;

    len = (s->tcp.ip_type == TCP_PROTO) ? s->tcp.rdatalen : s->udp.rdatalen;
    if (len == -1) return( -1 );  /* correction of fr instead of following 1 */
    /*if ((len = s->tcp.rdatalen) == -1) return( -1 );*/

    if( (s->tcp.ip_type == TCP_PROTO) && (s->tcp.sock_mode & TCP_MODE_ASCII)){
	if ( len == s->tcp.rxbufsize ) return ( s->tcp.rxbufsize );

	/* check for terminating \n \r */
	p = s->tcp.rdata;
	if ( strchr( p , '\n') || strchr( p, '\r')) return( len );
	return( 0 );
    } 
    else
	return( len );
}

int
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

void
sock_close( sock_type *s)
{
    DB2((FDB,"sock_close():\n"));
    DB2((stderr,"Type of socket [%d]\n", s->udp.ip_type));
    switch (s->udp.ip_type) {
    default:
	DB3((stderr,"Warning: calling sock_close on closed socket [%d]\n",
		s->udp.ip_type));
	return;
    case UDP_PROTO :
	udp_close((udp_Socket *) s );
	break;
    case TCP_PROTO :
	tcp_close((tcp_Socket *) s );
	tcp_tick( s );
	break;
    }
}

#ifdef unused
/*
 *  tcp_accept is superseded by accept()
 */
tcp_Socket *
tcp_accept( tcp_Socket *sl )
{

   register tcp_Socket *s;
 
   s=sl->next;
   for(;;){
	if (!tcp_tick((sock_type *)s)){
		DB4((stderr,"Working on non existing socket!\n"));
		exit(4);
		}
	if(!s->brother){
		DB4((stderr,"You are in the wrong place!\n"));
		exit(4);
		}
	if( (s->inlist) == LAZY && ( tcp_established((tcp_Socket *) s)) ){
		s->inlist = BUSY;
		sl->next = s->brother;  /* fair treatment of client calls */
		return(s);
		}
	if((s->brother) == (sl->next)){ 
		DB3((stderr,"\t\t\t\t\tNo new-call detected!\r"));
		return(NULL);
		}
	s=s->brother;
	}
 }		 
 #endif /* unused */

/***
 *** _ip_delay0 called by macro sock_wait_established()
 *** _ip_delay1 called by macro sock_wait_intput()
 *** _ip_delay2 called by macro sock_wait_closed();
 ***
 ***/

int
_ip_delay0(register sock_type *s, int timeoutseconds,
	procref fn, int *statusptr )
{
    int status;
    ip_timer_init((udp_Socket *) s , timeoutseconds );
    for (;;) {
	if ( s->tcp.ip_type == TCP_PROTO ) {
	    if ( tcp_established((tcp_Socket *) s )) {
		status = 0;
		break;
	    }
	}
	kbhit();        /* permit ^c */
	if ( !tcp_tick( s )) {
	    s->tcp.err_msg = "Host refused connection";
	    status = -1;        /* get an early reset */
	    break;
	}
	if ( ip_timer_expired((udp_Socket *) s )) {
	    sock_close( s );
	    status = -1;
	    break;
	}
	if ( fn && (status = fn(s))) break;
	if ( s->tcp.usr_yield ) (*s->tcp.usr_yield)();
	if ( s->tcp.ip_type == UDP_PROTO ) {
	    status = 0;
	    break;
	}
    }
    if (statusptr) *statusptr = status;
    return( status );
}

int
_ip_delay1(register sock_type *s, int timeoutseconds,
	procref fn, int *statusptr)
{
    int status;
    ip_timer_init((udp_Socket *) s , timeoutseconds );

    sock_flush( s );    /* new enhancement */

    for (;;) {
	if ( sock_dataready( s )) {
	    status = 0;
	    break;
	}
	kbhit();        /* permit ^c */
	if ( !tcp_tick( s )) {
	    status = 1;
	    break;
	}
	if ( ip_timer_expired((udp_Socket *) s )) {
	    /* sock_close( s ); */
	    status = -1;
	    break;
	}
	if (s->tcp.state == tcp_StateCLOSWT && s->tcp.rdatalen == 0) {
	    status = 2; /* no more data can arrive */
	    break;
	}
	if (fn && (status = fn(s))) break;
	if ( s->tcp.usr_yield ) (*s->tcp.usr_yield)();
    }
    if (statusptr) *statusptr = status;
    return( status );
}

int
_ip_delay2(register sock_type *s, int timeoutseconds,
	procref fn, int *statusptr)
{
    int status;
    ip_timer_init((udp_Socket *)s , timeoutseconds );

    if (s->tcp.ip_type != TCP_PROTO ) return( 1 );

    for (;;) {
	kbhit();        /* permit ^c */
	if ( (s->tcp.inlist)==LAZY ){
		status=1;
		break;
		}	
	if ( !tcp_tick( s )) {
	    status = 1;
	    break;
	}
	if ( ip_timer_expired((udp_Socket *) s )) {
	    sock_abort((tcp_Socket *) s );
	    status = -1;
	    break;
	}
	if (fn && (status = fn(s))) break;
	if ( s->tcp.usr_yield ) (*s->tcp.usr_yield)();

    };
    if (statusptr) *statusptr = status;
    return( status );
}


char
*rip( char *s )
{
    char *temp;

    if (temp = strchr( s, '\n')) *temp = 0;
    if (temp = strchr( s, '\r')) *temp = 0;
    return( s );
}


extern long gm_eth_send;
void
gm_statistics(void)
{
    printf("           TCP statistics \n");
    printf("tcp_send:        %8ld	(eth_send):    %8ld\n",
	gm_tcp_send, gm_eth_send);
    printf("   from retr:    %8ld	from very:     %8ld\n",
	gm_tcp_send_retr, gm_tcp_send_very);
    printf("   empty:        %8ld	empty and ack: %8ld\n",
	emptyretr, emptyeack);
    printf("rtt expired:     %8ld\n", gm_expire);
    printf("tcp_handler:     %8ld	ProcessData:   %8ld\n",
	gm_tcp_handler, gm_tcp_ProcessData);
    printf("	from SYNSENT:%8ld	from ESTAB:    %8ld\n",
	gm_proces_sent , gm_proces_estab);
    printf("tcp_tick:        %8ld	tcp_Retr.:     %8ld\n",
	gm_tcp_tick,  gm_tcp_Retransmitter);
    printf("tcp_rst:         %8ld\n", gm_tcp_rst);
    printf("tcp_unthread:    %8ld\n", gm_tcp_unthread);
}

void
gm_udp_statistics(void)
{
    printf("           UDP statistics \n");
    printf("udp_write:       %8ld	(eth_send):    %8ld\n",
	gm_udp_write, gm_eth_send);
    printf("eth_send failed:    %8ld\n", gm_udp_sendfailed);
    printf("udp_read of data:   %8ld\n", gm_udp_read);
    printf("udp_handler:     %8ld\n", gm_udp_handler);
    printf("tcp_tick:        %8ld	tcp_Retr.:     %8ld\n",
	gm_tcp_tick,  gm_tcp_Retransmitter);
    printf("tcp_rst:         %8ld\n", gm_tcp_rst);
}
/*** end of file tcp.c ***/
