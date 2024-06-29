
#ifndef _wattcp_wattcp_h
#define _wattcp_wattcp_h

#define WATTCPH

#define SOCKESTABLISHED 1
#define SOCKDATAREADY   2
#define SOCKCLOSED      4

#define IP_TYPE     0x0008

/*
#define DEBUG
*/
/*
#define MoveW( a , b, c ) movmem( a, b,c )
#define busyouta(c) (putch(c))
*/


#include <stdio.h>
#include <elib.h>

#define set_mstimeout( x ) (set_timeout(0)+ (x / 55))

#define MAX_GATE_DATA 12
#define MAX_NAMESERVERS 10
#define MAX_COOKIES 10
#define MAX_STRING 50	/* most strings are limited */

#define MAXVJSA     1440 /* 10 s */
#define MAXVJSD     360  /* 10 s */
#define SAFETYTCP  0x538f25a3L
#define SAFETYUDP  0x3e45e154L
#define TRUE        1
#define true        TRUE
#define FALSE       0
#define false       FALSE

#define EL_INUSE        0x0001
#define EL_DELAY        0x0002
#define EL_TCP          0x0004
#define EL_SERVER       0x0008
#define EL_ASCII        0x0010
#define EL_NEVER        0x0020

/* These are Ethernet protocol numbers but I use them for other things too */
#define UDP_PROTO  0x11
#define TCP_PROTO  0x06
#define ICMP_PROTO 0x01

#define TCP_MODE_BINARY  0       /* default mode */
#define TCP_MODE_ASCII   1
#define UDP_MODE_CHK     0       /* default to having checksums */
#define UDP_MODE_NOCHK   2       /* turn off checksums */
#define TCP_MODE_NAGLE   0       /* Nagle algorithm */
#define TCP_MODE_NONAGLE 4

typedef int (*procref)();

typedef unsigned long longword;     /* 32 bits */
typedef unsigned short word;        /* 16 bits */
typedef unsigned char byte;         /*  8 bits */
typedef byte eth_address[6];


/* undesirable */
extern longword MsecClock();
#define clock_ValueRough() MsecClock()

#define TICKS_SEC 18

#define checksum( p, len) inchksum( p, len )

#define PD_ETHER 1
#define PD_SLIP  6

extern word sock_inactive;      /* in pcbootp.c */
extern word _pktdevclass;
extern word _mss;
extern word _bootptimeout;	/* in pcbootp.c */
extern longword _bootphost;	/* in pcbootp.c */
extern word _bootpon;

/* The Ethernet header */
typedef struct {
    eth_address     destination;
    eth_address     source;
    word            type;
} eth_Header;

/* The Internet Header: */
typedef struct {
    unsigned	    hdrlen  : 4;
    unsigned	    ver     : 4;
    byte	    tos;
    word            length;
    word            identification;
    word            frags;
//    unsigned        frags : 3;
//    unsigned        fo    : 13;
    byte	    ttl;
    byte	    proto;
    word            checksum;
    longword        source;
    longword        destination;
} in_Header;


#define in_GetVersion(ip) ( (ip)->ver )
#define in_GetHdrlen(ip)  ( (ip)->hdrlen )  /* 32 bit word size */
#define in_GetHdrlenBytes(ip)  ( in_GetHdrlen(ip) << 2 ) /* 8 bit byte size */
#define in_GetTos(ip)      ( (ip)->tos)

#define in_GetTTL(ip)      ((ip)->ttl)
#define in_GetProtocol(ip) ((ip)->proto )

typedef struct {
    word	    srcPort;
    word	    dstPort;
    word	    length;
    word	    checksum;
} udp_Header;

#define UDP_LENGTH ( sizeof( udp_Header ))

typedef struct {
    word            srcPort;
    word            dstPort;
    longword        seqnum;
    longword        acknum;
    word            flags;
    word            window;
    word            checksum;
    word            urgentPointer;
} tcp_Header;

#define tcp_FlagFIN     0x0001
#define tcp_FlagSYN     0x0002
#define tcp_FlagRST     0x0004
#define tcp_FlagPUSH    0x0008
#define tcp_FlagACK     0x0010
#define tcp_FlagURG     0x0020
#define tcp_FlagDO      0xF000
#define tcp_GetDataOffset(tp) (intel16((tp)->flags) >> 12)

/* The TCP/UDP Pseudo Header */
typedef struct {
    longword    src;
    longword    dst;
    byte        mbz;
    byte        protocol;
    word        length;
    word        checksum;
} tcp_PseudoHeader;

/*
 * TCP states, from tcp manual.
 * Note: close-wait state is bypassed by automatically closing a connection
 *       when a FIN is received.  This is easy to undo.
 */
#define tcp_StateLISTEN  0      /* listening for connection */
#define tcp_StateSYNSENT 1      /* syn sent, active open */
#define tcp_StateSYNREC  2      /* syn received, synack+syn sent. */
#define tcp_StateESTAB   3      /* established */
#define tcp_StateESTCL   4      /* established, but will FIN */
#define tcp_StateFINWT1  5      /* sent FIN */
#define tcp_StateFINWT2  6      /* sent FIN, received FINACK */
#define tcp_StateCLOSWT  7      /* received FIN waiting for close */
#define tcp_StateCLOSING 8      /* sent FIN, received FIN (waiting for FINACK) */
#define tcp_StateLASTACK 9      /* fin received, finack+fin sent */
#define tcp_StateTIMEWT  10     /* dally after sending final FINACK */
#define tcp_StateCLOSEMSL 11
#define tcp_StateCLOSED  12     /* finack received */

#define tcp_MaxBufSize 2048         /* maximum bytes to buffer on input */



/*
 * UDP socket definition
 */
typedef struct _udp_socket {
    struct _udp_socket *next;
    word	    ip_type;		/* always set to UDP_PROTO */
    char	   *err_msg;		/* null when all is ok */
    char           *usr_name;
    void	  (*usr_yield)();
    byte            rigid;
    byte            stress;
    word	    sock_mode;	        /* a logical OR of bits */
    longword	    usertimer;		/* ip_timer_set, ip_timer_timeout */
    procref	    dataHandler;
    eth_address     hisethaddr;		/* peer's ethernet address */
    longword        hisaddr;		/* peer's internet address */
    word	    hisport;		/* peer's UDP port */
    longword        myaddr;
    word	    myport;
    word            locflags;

    int             queuelen;
    byte           *queue;

    int             rdatalen;           /* must be signed */
    word            maxrdatalen;
    byte           *rdata;
    byte            rddata[ tcp_MaxBufSize + 1];         /* if dataHandler = 0, len == 512 */
    longword        safetysig;
} udp_Socket;
/*
 * TCP Socket definition
 */


typedef struct _tcp_socket {
    struct _tcp_socket *next;
    word	    ip_type;	    /* always set to TCP_PROTO */
    char 	   *err_msg;
    char           *usr_name;
    void          (*usr_yield)();
    byte            rigid;
    byte            stress;
    word	    sock_mode;	    /* a logical OR of bits */

    longword	    usertimer;	    /* ip_timer_set, ip_timer_timeout */
    procref         dataHandler;    /* called with incoming data */
    eth_address     hisethaddr;     /* ethernet address of peer */
    longword        hisaddr;        /* internet address of peer */
    word            hisport;	    /* tcp ports for this connection */
    longword        myaddr;
    word	    myport;
    word            locflags;

    int             queuelen;
    byte           *queue;

    int             rdatalen;       /* must be signed */
    word            maxrdatalen;
    byte           *rdata;
    byte            rddata[tcp_MaxBufSize+1];    /* received data */
    longword        safetysig;
    word	    state;          /* connection state */

    longword        acknum;
    longword	    seqnum; 	    /* data ack'd and sequence num */
    long            timeout;        /* timeout, in milliseconds */
    byte            unhappy;        /* flag, indicates retransmitting segt's */
    byte            recent;         /* 1 if recently transmitted */
    word            flags;          /* tcp flags word for last packet sent */

    word	    window;	    /* other guy's window */
    int 	    datalen;        /* number of bytes of data to send */
				    /* must be signed */
    int             unacked;        /* unacked data */

    byte	    cwindow;	    /* Van Jacobson's algorithm */
    byte	    wwindow;

    word	    vj_sa;	    /* VJ's alg, standard average */
    word	    vj_sd;	    /* VJ's alg, standard deviation */
    longword	    vj_last;	    /* last transmit time */
    word	    rto;
    byte	    karn_count;	    /* count of packets */
    byte            tos;            /* priority */
    /* retransmission timeout proceedure */
    /* these are in clock ticks */
    longword        rtt_lasttran;       /* last transmission time */
    longword        rtt_smooth;         /* smoothed round trip time */
    longword        rtt_delay;          /* delay for next transmission */
    longword        rtt_time;           /* time of next transmission */

    word            mss;
    longword        inactive_to;           /* for the inactive flag */
    int             sock_delay;

    byte            data[tcp_MaxBufSize+1]; /* data to send */
} tcp_Socket;

/* sock_type used for socket io */
typedef union {
    udp_Socket udp;
    tcp_Socket tcp;
} sock_type;

/* similar to UNIX */
typedef struct sockaddr {
    word        s_type;
    word        s_port;
    longword    s_ip;
    byte        s_spares[6];    /* unused in TCP realm */
};

extern longword my_ip_addr;
extern eth_address _eth_addr;
extern eth_address _eth_brdcast;
extern longword sin_mask;
extern word sock_delay;

/*
 * ARP definitions
 */
#define arp_TypeEther  0x100		/* ARP type of Ethernet address */

/* harp op codes */
#define ARP_REQUEST 0x0100
#define ARP_REPLY   0x0200

/*
 * Arp header
 */
typedef struct {
    word            hwType;
    word            protType;
    word            hwProtAddrLen;  // hw and prot addr len
    word            opcode;
    eth_address     srcEthAddr;
    longword        srcIPAddr;
    eth_address     dstEthAddr;
    longword        dstIPAddr;
} arp_Header;

#define ETH_MSS 1400  // MSS for Ethernet

 // Ethernet interface:

extern void  _eth_init( void );
extern byte *_eth_formatpacket( void *eth_dest, word eth_type );
extern int   _eth_send( word len);
extern void  _eth_free( void *buf);
extern byte *_eth_arrived( word *type_ptr);
extern void  _eth_release( void );

extern void *_eth_hardware(byte *p);

extern void ip_timer_init(udp_Socket *s, int seconds);
extern int  ip_timer_expired(udp_Socket *s);

/*
 * socket macros
 */

/*
 * sock_wait_established()
 *	- waits then aborts if timeout on s connection
 * sock_wait_input()
 *	- waits for received input on s
 *      - may not be valid input for sock_gets... check returned length
 * sock_tick()
 *	- do tick and jump on abort
 * sock_wait_closed();
 *	- discards all received data
 *
 * jump to sock_err with contents of *statusptr set to
 *	 1 on closed
 *	-1 on timeout
 *
 */

extern _ip_delay0( sock_type *s, int timeoutseconds, procref fn, int *statusptr );
extern _ip_delay1( sock_type *s, int timeoutseconds, procref fn, int *statusptr );
extern _ip_delay2( sock_type *s, int timeoutseconds, procref fn, int *statusptr );

#define sock_wait_established( s, seconds, fn, statusptr ) \
    if (_ip_delay0( s, seconds, fn, statusptr )) goto sock_err;
#define sock_wait_input( s, seconds, fn , statusptr ) \
    if (_ip_delay1( s, seconds, fn, statusptr )) goto sock_err;
#define sock_tick( s, statusptr ) \
    if ( !tcp_tick(s)) { *statusptr = 1 ; goto sock_err; }
#define sock_wait_closed(s, seconds, fn, statusptr )\
    if (_ip_delay2( s, seconds, fn, statusptr )) goto sock_err;

// in UDP_NDS.C
extern longword resolve(char *asciiname);
extern int reverse_addr_lookup(longword ipaddr, char *name);

extern int _last_cookie;
extern longword _cookie[MAX_COOKIES];

extern char *def_domain;
extern longword def_nameservers[MAX_NAMESERVERS];
extern int _last_nameserver;
extern char *_hostname;

extern word isaddr( char *string );
extern longword aton( char *string );

/*
 * Send an icmp echo request using specified ttl and tos.
 * if(icmp_id != NULL) store copy of the id there
 */
extern int _send_ping( longword host, longword countnum, byte ttl,
                                            byte tos, longword *theid );
/* backward compatibility */
#define _ping( h, c ) _send_ping( h, c, 250, 0, NULL )
extern longword _chk_ping( longword host , longword *ptr);
extern void _arp_register( longword use, longword instead_of );
extern int _arp_resolve( longword ina, eth_address *ethap, int nowait);

extern void * _pkt_eth_init( void );
extern void pkt_release( void );
extern int pkt_send( char *buffer, int length );
extern void pkt_buf_wipe( void );
extern void pkt_buf_release( char *ptr );
extern void * pkt_received( void );



extern void _add_server( int *counter, int max, longword *array, longword value );
extern word debug_on;
extern char *rip( char *s);
extern _chk_socket( tcp_Socket *s );
extern char *inet_ntoa( char *s, longword x );
extern void psocket( tcp_Socket *s );
extern longword inet_addr( char *s );
extern char *sockerr( tcp_Socket *s );
extern char *sockstate( tcp_Socket *s );
extern getpeername( tcp_Socket *s, void *dest, int *len );
extern getsockname(  tcp_Socket *s, void *dest, int *len );
extern longword gethostid( void );
extern longword sethostid( longword ip );
extern char *getdomainname( char *name, int length );
extern char *setdomainname( char *string );
extern word ntohs( word a );
extern word htons( word a );
extern longword ntohl( longword x );
extern longword htonl( longword x );

extern void * _tcp_lookup( longword hisip, word hisport, word myport );
extern int addwattcpd( void (*p)() );
extern int delwattcpd( void (*p)() );
extern word sock_mode( sock_type *, word);
extern void sock_abort( tcp_Socket *);
extern int sock_fastwrite( sock_type *, byte *, int );
extern int sock_write( sock_type *, byte *, int );
extern int sock_read( sock_type *, byte *, int );
extern int sock_fastread( sock_type *, byte *, int );

extern int tcp_open(tcp_Socket *s, word lport, longword ina, word port, procref datahandler);
extern int udp_open(udp_Socket *s, word lport, longword ina, word port, procref datahandler);
extern int tcp_listen(tcp_Socket *s, word lport, longword ina, word port, procref datahandler, word timeout);
extern int sock_gets(sock_type *, byte *, int );
extern int sock_close(sock_type * );

#endif /* ndef _wattcp_wattcp_h */
