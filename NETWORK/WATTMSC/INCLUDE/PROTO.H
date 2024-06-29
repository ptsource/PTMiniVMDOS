/*
 * File: proto.h
 *
 * 18-Jun-92 lr
 *
 *    Here are all global function prototypes and variables
 *
 */

#define EXTERN extern

/*** elib/cout.c ***/

EXTERN void outch( unsigned char ch );
EXTERN void outs(char *s);
EXTERN void outsn(char *s,unsigned n);
EXTERN void outhex( unsigned char ch );
EXTERN void outhexes( unsigned char *p, unsigned n );

/*** elib/inchksum.asm ***/

EXTERN word inchksum(void far *buf, short cnt); 


/*** elib/intel.asm ***/

EXTERN longword intel(long);
/*EXTERN long ntohl(long);
  EXTERN long htonl(long);*/

EXTERN word intel16(short);
/*EXTERN short htons(short);
  EXTERN short ntohs(short);*/

/*** elib/timeout.asm ***/

EXTERN long set_timeout( int seconds );
EXTERN long set_ttimeout( int pc_ticks );
EXTERN int chk_timeout( long value );

/*** src/asmpkt.asm ***/

EXTERN _pktentry(); /* only called by the packet driver */

EXTERN void _pktasminit(void far *buffer, int maxbufs, int buflen, long far *lost_packets);

/*** src/tcp.c ***/

#ifdef NEWPCTCP
#undef EXTERN
#define EXTERN
EXTERN sock_desc sockarr[MAXSOCK] = {
		{0,0,0,NULL}, {0,0,0,NULL}, {0,0,0,NULL}, {0,0,0,NULL},
		{0,0,0,NULL}, {0,0,0,NULL}, {0,0,0,NULL}, {0,0,0,NULL},
		{0,0,0,NULL}, {0,0,0,NULL}, {0,0,0,NULL}, {0,0,0,NULL},
		{0,0,0,NULL}, {0,0,0,NULL}, {0,0,0,NULL}, {0,0,0,NULL},
		{0,0,0,NULL}, {0,0,0,NULL}, {0,0,0,NULL}, {0,0,0,NULL},
		{0,0,0,NULL}, {0,0,0,NULL}, {0,0,0,NULL}, {0,0,0,NULL},
		{0,0,0,NULL}, {0,0,0,NULL}, {0,0,0,NULL}, {0,0,0,NULL},
		{0,0,0,NULL}, {0,0,0,NULL}, {0,0,0,NULL}, {0,0,0,NULL}
		};
EXTERN void (*system_yield)() = NULL;
EXTERN tcp_Socket *tcp_allsocs = NULL;  /* fr traslated from tcp.c */
EXTERN void (*_dbugxmit)() = NULL;
EXTERN void (*_dbugrecv)() = NULL;
EXTERN char *_hostname = "012345678901234567890123456789012345678901234567890";
EXTERN word _mss = ETH_MSS;
EXTERN word debug_on = 0;
EXTERN char *_wattcp = WATTCP_C;
EXTERN longword my_ip_addr = 0L;       /* for external references */
EXTERN longword sin_mask = 0xfffffe00L; /* strange number! */
EXTERN longword sin_gate = 0x0;
EXTERN word MaxBufSize=DEFAULT_BUFSIZE;
EXTERN word RxMaxBufSize=DEFAULT_BUFSIZE;
EXTERN word TxMaxBufSize=DEFAULT_BUFSIZE;
EXTERN long gm_tcp_Retransmitter=0L;
EXTERN long gm_tcp_send_retr=0L;
EXTERN long gm_tcp_send_very=0L;
EXTERN long gm_expire=0L;
EXTERN long gm_tcp_unthread=0L;
EXTERN long previous_lost_packets=0;
EXTERN long gm_udp_write=0l;
EXTERN long gm_udp_sendfailed=0l;
EXTERN long gm_udp_read=0l;
EXTERN long gm_udp_handler=0l;
EXTERN long gm_proces_sent=0L;
EXTERN long gm_proces_estab=0L;
EXTERN long gm_proces_finwt1=0L;
EXTERN long gm_proces_finwt2=0L;
EXTERN long gm_tcp_handler=0L;
EXTERN long gm_tcp_ProcessData=0L;
EXTERN long gm_proc_option=0L;
EXTERN long gm_proc_opt_in=0L;
EXTERN long gm_tcp_send=0L;
EXTERN long gm_tcp_tick=0L;
EXTERN long emptyretr=0L;
EXTERN long emptyeack=0L;
EXTERN long gm_tcp_rst=0l;
EXTERN char *state_names[] = {
	"LISTEN",       "SYNSENT",      "SYNREC",       "SYNRECLIS",
	"ESTAB",        "ESTCL",        "FINWT1",       "FINWT2",
	"CLOSWT",       "CLOSWTCL",     "CLOSING",      "LASTACK",
	"TIMEWT",       "CLOSEMSL",     "CLOSED"};

#endif /* NEWPCTCP */

/*** public functions ***/

EXTERN void largecheck( void *s, int size);/*fr made public (used in socket.c)*/
EXTERN void ip_timer_init( udp_Socket *s , int delayseconds );
EXTERN int ip_timer_expired( udp_Socket *s);
EXTERN longword MsecClock(void);
EXTERN void tcp_shutdown(void);
EXTERN void tcp_init(void);
EXTERN void set_tcp_rxbufsize(word size);
EXTERN void set_tcp_txbufsize(word size);
EXTERN void set_udp_bufsize(word size);
EXTERN int set_udp_buffer(udp_Socket *s,int size);
EXTERN int set_tcp_buffers(tcp_Socket *s,int tsize, int rsize);
EXTERN int udp_open(udp_Socket *s, word lport, longword ina,word port, procref datahandler);
EXTERN int tcp_open(register tcp_Socket *s, word lport,longword ina,
word port, procref datahandler);
EXTERN int tcp_listen(register tcp_Socket *s, word lport,longword ina,
word port, procref datahandler, word timeout);
EXTERN void sock_abort(tcp_Socket *s );
EXTERN tcp_Socket *multi_listen(int numsock, word lport,longword ina,
word port, procref datahandler, word mode);
EXTERN void make_in_hdr(in_Header *inp, byte proto, longword dest, word len);
EXTERN short tcp_tick(register sock_type *s );
EXTERN void tcp_set_debug_state(int x);
EXTERN int tcp_established(tcp_Socket *s);
EXTERN void _udp_cancel( in_Header *ip );
EXTERN void _tcp_cancel(in_Header *ip);
EXTERN void tcp_rst( in_Header *his_ip, tcp_Header *oldtcpp );
EXTERN void sock_yield( tcp_Socket *s, void (*fn)());
EXTERN void sock_mode( sock_type *s, word mode );
EXTERN int sock_read(sock_type *s, byte *dp, int len );
EXTERN int sock_fastread(sock_type *s, byte *dp, int len );
EXTERN int sock_write(register sock_type *s, byte *dp, int len);
EXTERN int sock_fastwrite(sock_type *s, byte *dp, int len);
EXTERN void sock_flush( sock_type *s );
EXTERN int sock_waitwrite( sock_type *s, byte *dp, int len );
EXTERN void sock_flushnext( sock_type *s);
EXTERN byte sock_putc( sock_type *s, byte c );
EXTERN word sock_getc( sock_type *s );
EXTERN int sock_puts( sock_type *s, byte *dp );
EXTERN word sock_gets( sock_type *s, byte *dp, int n );
EXTERN int sock_dataready( register sock_type *s );
EXTERN int sock_established( sock_type *s );
EXTERN void sock_close( sock_type *s);
EXTERN tcp_Socket *tcp_accept( tcp_Socket *sl );
EXTERN int _ip_delay0(register sock_type *s, int timeoutseconds,procref fn, int *statusptr );
EXTERN int _ip_delay1(register sock_type *s, int timeoutseconds,procref fn, int *statusptr);
EXTERN int _ip_delay2(register sock_type *s, int timeoutseconds,procref fn, int *statusptr);
EXTERN char *rip( char *s );
EXTERN void gm_statistics(void);
EXTERN void gm_udp_statistics(void);

#undef EXTERN
#define EXTERN extern

/*** global variables declared here ***/

EXTERN sock_desc sockarr[MAXSOCK];
EXTERN void (*system_yield)();
EXTERN tcp_Socket *tcp_allsocs;  /* fr traslated from tcp.c */
EXTERN void (*_dbugxmit)();
EXTERN void (*_dbugrecv)();
EXTERN char *_hostname;
EXTERN word _mss;
EXTERN word debug_on;
EXTERN char *_wattcp;
EXTERN longword my_ip_addr;       /* for external references */
EXTERN longword sin_mask; /* strange number! */
EXTERN longword sin_gate;
EXTERN word MaxBufSize;
EXTERN word RxMaxBufSize;
EXTERN word TxMaxBufSize;
EXTERN long gm_tcp_Retransmitter;
EXTERN long gm_tcp_send_retr;
EXTERN long gm_tcp_send_very;
EXTERN long gm_expire;
EXTERN long gm_tcp_unthread;
EXTERN long previous_lost_packets;
EXTERN long gm_udp_write;
EXTERN long gm_udp_sendfailed;
EXTERN long gm_udp_read;
EXTERN long gm_udp_handler;
EXTERN long gm_proces_sent;
EXTERN long gm_proces_estab;
EXTERN long gm_proces_finwt1;
EXTERN long gm_proces_finwt2;
EXTERN long gm_tcp_handler;
EXTERN long gm_tcp_ProcessData;
EXTERN long gm_proc_option;
EXTERN long gm_proc_opt_in;
EXTERN long gm_tcp_send;
EXTERN long gm_tcp_tick;
EXTERN long emptyretr;
EXTERN long emptyeack;
EXTERN long gm_tcp_rst;
EXTERN char *state_names[];

/*** src/pc_cbrk.c ***/

#ifdef PC_CBRK
#undef EXTERN
#define EXTERN
EXTERN word wathndlcbrk = 0;
	/* changes operation of the break stuff if in resolve or something */
EXTERN word watcbroke = 0; /* set to non-zero if wathndlcbrk happenned */
#endif /* PC_CBRK */

EXTERN void tcp_cbrk( int mode );
EXTERN word wathndlcbrk;
EXTERN word watcbroke;

#undef EXTERN
#define EXTERN extern

/*** src/pcarp.c ***/

#ifdef PCARP
#undef EXTERN
#define EXTERN
#endif /* PCARP */

EXTERN void _arp_add_gateway( char *data , longword ip );
EXTERN void _arp_register( longword use, longword instead_of );
EXTERN void _arp_handler( arp_Header *in);
EXTERN int _arp_resolve( longword ina, eth_address *ethap);

EXTERN short _arp_last_gateway;

#undef EXTERN
#define EXTERN extern

/*** src/pcbootp.c ***/

#ifdef PCBOOTP
#undef EXTERN
#define EXTERN
EXTERN longword _bootphost = 0xffffffffL;
EXTERN word _bootptimeout = 30;
EXTERN word _bootpon = 0;
#endif /* PCBOOTP */

EXTERN int _dobootp(void);

EXTERN longword _bootphost;
EXTERN word _bootptimeout;
EXTERN word _bootpon;

#undef EXTERN
#define EXTERN extern

/*** src/pcbsd.c ***/

EXTERN int _chk_socket( tcp_Socket *s );
EXTERN char *w_inet_ntoa( char *s, longword x );
EXTERN void psocket( tcp_Socket *s );
EXTERN longword inet_addr( char *s );
EXTERN char *sockerr( tcp_Socket *s );
EXTERN char *sockstate( tcp_Socket *s );
EXTERN int getpeername( tcp_Socket *s, void *dest, int *len );
EXTERN int wat_getsockname(  tcp_Socket *s, void *dest, int *len );
EXTERN longword gethostid(void);
EXTERN longword sethostid( longword ip );
EXTERN char *getdomainname( char *name, int length );
EXTERN char *setdomainname( char *string );
EXTERN char *wat_gethostname( char *name, int len );
EXTERN char *sethostname( char *name );

/*** src/pcbuf.c ***/

EXTERN int sock_rbsize( tcp_Socket *s );
EXTERN int sock_rbused( tcp_Socket *s );
EXTERN int sock_rbleft( tcp_Socket *s );
EXTERN int sock_tbsize( tcp_Socket *s );
EXTERN int sock_tbused( tcp_Socket *s );
EXTERN int sock_tbleft( tcp_Socket *s );
EXTERN int sock_preread( sock_type *s, byte *dp, int len );

/*** src/config.c ***/

#ifdef CONFIG
#undef EXTERN
#define EXTERN
EXTERN word sock_delay = 30;
EXTERN word sock_inactive = 0;  /* defaults to forever */
EXTERN void (*usr_init)() = NULL;
#endif /* PCCONFIG */

EXTERN char *_inet_atoeth( char *src, eth_address eth );
EXTERN void _add_server( int *counter, int max, longword *array, longword value);
EXTERN int tcp_config( char *path );

EXTERN word sock_delay;
EXTERN word sock_inactive;
EXTERN void (*usr_init)();
EXTERN char defaultdomain[ 80 ];
EXTERN longword _cookie[ MAX_COOKIES ];
EXTERN int _last_cookie;


#undef EXTERN
#define EXTERN extern


/*** src/pcdbug.c ***/

#ifdef PCDBUG
#undef EXTERN
#define EXTERN
#endif /* PCDBUG */

EXTERN void db_write( char *msg );
EXTERN void dbuginit(void);

EXTERN char debugname[ 128 ];
EXTERN int debugheaders, debugdump, debugudp, debugtcp;
/* extern void (*_dbugxmit)(); */
/* extern void (*_dbugrecv)(); */


#undef EXTERN
#define EXTERN extern

/*** src/pcicmp.c ***/
#ifdef PCICMP
#undef EXTERN
#define EXTERN
EXTERN int print_icmp=0;
#endif /* PCICMP */
EXTERN longword _chk_ping( longword host, longword *ptr );
EXTERN struct _pkt *icmp_Format( longword destip );
EXTERN void icmp_handler( in_Header *ip );
EXTERN int print_icmp;

#undef EXTERN
#define EXTERN extern

/*** src/pcping.c ***/

EXTERN int _ping( longword host, longword countnum );

/*** src/pcpkt.c ***/

#ifdef PCPKT
#undef EXTERN
#define EXTERN
EXTERN word _pktipofs = 0;      /* offset from header to start of pkt */
EXTERN word pkt_ip_type = 0x0008;       /* these are intelled values */
EXTERN word pkt_arp_type = 0x608;
EXTERN longword far *interrupts = 0L;
EXTERN long far lost_packets=0;
#endif /* PCPKT */

EXTERN int farcmp(char far *f, char *d, int len);
EXTERN int pkt_init(void);
EXTERN int pkt_release(void);
EXTERN int pkt_send( char *buffer, int length );
EXTERN void pkt_buf_wipe(void );
EXTERN void pkt_buf_release( char *ptr );
EXTERN void *pkt_received(void);
EXTERN void *_pkt_eth_init(void);

EXTERN word _pktipofs;
EXTERN word pkt_ip_type;
EXTERN word pkt_arp_type;
EXTERN longword far *interrupts;
EXTERN long far lost_packets;

EXTERN word pkt_interrupt;
EXTERN byte pktbuf[MAXBUFS][ BUFSIZE + 2 ];/* char busy, spare, buf[] */
EXTERN word  pkt_ip_handle;
EXTERN word  pkt_arp_handle;
EXTERN byte eth_addr[ 6 ] ;

#undef EXTERN
#define EXTERN extern


#ifdef unused /*** src/pcrecv.c ***/

EXTERN int _recvdaemon( udp_Socket *s, byte *data, int len, tcp_PseudoHeader *ph);
EXTERN void sock_recv_init( udp_Socket *s, void *space, word len );
EXTERN int sock_recv( udp_Socket *s, char *buffer, int len, word flags);

#endif /* unused */ /* src/pcrecv.c */
/*** src/pcsed.c ***/

#ifdef PCSED
#undef EXTERN
#define EXTERN
EXTERN word _pktdevclass = 1;          /* Ethernet = 1, SLIP = 6 */
EXTERN long gm_eth_send=0L;
#endif

EXTERN void _eth_init(void);
EXTERN byte *_eth_formatpacket( void *eth_dest, word eth_type );
EXTERN int _eth_send( word len);
EXTERN void _eth_free( void *buf);
EXTERN byte *_eth_arrived( word *type_ptr);
EXTERN void _eth_release(void);
EXTERN void *_eth_hardware( byte *p );

EXTERN eth_address _eth_addr;          /* local ethernet address */
EXTERN eth_address _eth_brdcast;       /* Ethernet broadcast address */
EXTERN word _pktdevclass;
EXTERN long gm_eth_send;

#undef EXTERN
#define EXTERN extern

/*** src/sock_ini.c ***/

#ifdef SOCK_INI
#undef EXTERN
#define EXTERN
EXTERN word _survivebootp = 0;
#endif

EXTERN void sock_exit(void);
EXTERN void sock_init(void);

#undef EXTERN
#define EXTERN extern
EXTERN word _survivebootp;



/*** src/sock_prn.c ***/

EXTERN int sock_printf( sock_type *s, char *format, ... );
EXTERN int sock_scanf( sock_type *s, char *format, ... );

/*** src/udp_dom.c ***/

#ifdef UDP_DOM
#undef EXTERN
#define EXTERN
EXTERN int _domaintimeout = 0;
#endif /* UDP_DOM */

EXTERN int countpaths(char *pathstring);
EXTERN longword resolve(char *name);
EXTERN void add_hosts_table(char *ip, char *ipname);
EXTERN void disp_hosts_table(void);
	/* these are loaded by config */
EXTERN char *def_domain;
EXTERN char *loc_domain; /* current subname to be used by the domain system */
EXTERN longword def_nameservers[ MAX_NAMESERVERS ];
EXTERN int _last_nameserver;
EXTERN int _domaintimeout;

#undef EXTERN
#define EXTERN extern

/*** src/udp_nds.c ***/

EXTERN longword aton( char *text );
EXTERN word isaddr( char *text );


/*** src/socket.c ***/

#ifdef SOCKET
#undef EXTERN
#define EXTERN
#endif /* SOCKET */

EXTERN int sendto(int sock, char *buf, int nbytes, int flags, 
			      struct sockaddr *to, int addrlen);
EXTERN int recvfrom(int sock, char *buf, int nbytes, int flags, 
			      struct sockaddr *from, int *addrlen);
EXTERN int select(int maxfdp, fd_set *readfds, fd_set *writefds, 
			      fd_set *exceptfds, struct timeval *timeout);
EXTERN int socket(int af, int type, int protocol);
EXTERN int bind(int s, struct sockaddr *name, int namelen);
EXTERN int getsockname(int s, struct sockaddr *name, int *lenp);
EXTERN int gethostname(char *buf, int len);
EXTERN int listen(int sock, int numsock);
EXTERN int accept(int s, struct sockaddr *addr, int *addrlen);
EXTERN char *inet_ntoa(struct in_addr in);
EXTERN int n_write(int fd, char *dp, int len);
EXTERN int n_read(int fd, char *dp, int len);
EXTERN int n_close(int sock);
EXTERN struct hostent *gethostbyname(char *name);
EXTERN int connect(int sock, struct sockaddr *name, int namelen);
EXTERN void sleep(int sec);
/******* end of file proto.h *********/
