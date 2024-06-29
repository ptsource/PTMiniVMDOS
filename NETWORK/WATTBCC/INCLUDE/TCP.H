
/*
 * Waterloo TCP
 *
 * Copyright (c) 1990, 1991, 1992, 1993 Erick Engelke
 *
 * Portions copyright others, see copyright.h for details.
 *
 * This library is free software; you can use it or redistribute under
 * the terms of the license included in LICENSE.H.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * file LICENSE.H for more details.
 *
 */
#ifndef _wattcp_tcp_h
#define _wattcp_tcp_h

#ifndef WTCP_VER

/* handle some early dumb naming conventions */
#define dbuginit()      dbug_init()

/* Kernal version (major major minor minor) */
#define WTCP_VER 0x0102

/*
 * Typedefs and constants
 */

#ifndef byte
typedef unsigned char byte;
#endif  byte
#ifndef word
typedef unsigned int word;
#endif  word
#ifndef longword
typedef unsigned long longword;
#endif  longword

typedef struct {
    byte undoc[ 4300 ];
} tcp_Socket;

typedef struct {
    byte undoc[ 2200 ];
} udp_Socket;


typedef struct sockaddr {
    word        s_type;
    word        s_port;
    longword    s_ip;
    byte        s_spares[6];    /* unused in TCP realm */
};

#define sockaddr_in sockaddr

typedef struct in_addr {
    longword    s_addr;
};


#define MAX_COOKIES     10
#define MAX_NAMESERVERS 10

#define TCP_MODE_BINARY 0
#define TCP_MODE_ASCII	1
#define UDP_MODE_CHK	0	/*default to checksum */
#define UDP_MODE_NOCHK	2
#define TCP_MODE_NAGLE  0       /* Nagle algorithm */
#define TCP_MODE_NONAGLE 4

extern sock_init();
/*
 *   s is the pointer to a udp or tcp socket
 */
extern sock_read(void  *s, byte *dp, int len );
extern sock_fastread(void  *s, byte *dp, int len );
extern sock_write(void  *s, byte *dp, int len);
extern void sock_enqueue(void  *s, byte *dp, int len);
extern sock_fastwrite(void *s, byte *dp, int len );
extern sock_flush( void  *s );
extern sock_flushnext( void  *s);
extern sock_puts( void  *s, byte *dp );
extern word sock_gets( void  *s, byte *dp, int n );
extern byte sock_putc( void  *s, byte c );
extern byte sock_getc( void  *s );
extern word sock_dataready( void  *s );
extern sock_close( void *s );
extern sock_abort( void *s );
extern sock_printf( void  *s, char *format, ... );
extern sock_scanf( void  *s, char *format, ... );
extern sock_mode( void *s, word mode );        /* see TCP_MODE_... */
extern void db_write( char *msg );
extern void dbug_init();
extern void dbug_printf(char *,... );

/*
 * TCP or UDP specific stuff, must be used for open's and listens, but
 * sock stuff is used for everything else
 */
extern int udp_open(void *s, word lport, longword ina, word port, int (*datahandler)());
extern int tcp_open(void *s, word lport, longword ina, word port, int (*datahandler)());
extern tcp_listen(void *s, word lport, longword ina, word port, int (*datahandler)(), word timeout);
extern int tcp_established(void *s);
extern char *rip( char *s );
extern longword resolve( char *name);
extern int reverse_addr_lookup(longword ipaddr, char *name);
/*
 * less general functions
 */
extern longword aton( char *text );
extern int isaddr( char *text );
extern tcp_cbreak( word mode );
extern longword intel( longword x );
extern word intel16( word x );

/*
 * timers
 */

extern void ip_timer_init( void *s , word delayseconds );
extern word ip_timer_expired( void *s );
        /*
         * TCP/IP system variables - do not change these since they
         *      are not necessarily the source variables, instead use
         *      ip_Init function
         */
extern longword my_ip_addr;
extern longword sin_mask;       /* eg.  0xfffffe00L */
extern word sock_delay;

        /*
         * tcp_init/tcp_shutdown
         *      - init/kill all tcp and lower services
         *      - only call if you do not use sock_init
         * (NOT RECOMMENDED)
         */
extern tcp_shutdown();
extern tcp_Init();

/*
 * things you probably won't need to know about
 */
	/*
	 * sock_debugdump
	 *	- dump some socket control block parameters
	 * used for testing the kernal, not recommended
	 */
extern sock_debugdump( void *s);
        /*
         * tcp_config - read a configuration file
         *            - if special path desired, call after sock_init()
         *            - null reads path from executable
         * see sock_init();
         */
extern tcp_config( char *path );
        /*
         * tcp_tick - called periodically by user application in sock_wait_...
         *          - returns 1 when our socket closes
         */
extern tcp_tick( void *s );
        /*
         * Retransmitter - called periodically to perform tcp retransmissions
         *          - normally called from tcp_tick, you have to be pretty
         *            low down to use this one
         */
extern tcp_Retransmitter();
        /*
         * tcp_set_debug_state - set 1 or reset 0 - depends on what I have done
         */
extern tcp_set_debug_state( word x );


extern int _last_cookie;
extern longword _cookie[MAX_COOKIES];

        /*
         * name domain constants
         */

extern char *def_domain;
extern longword def_nameservers[ MAX_NAMESERVERS ];


extern word wathndlcbrk;
extern word watcbroke;
/*
 * sock_wait_... macros
 */
/*
 * sock_wait_established()
 *	- waits then aborts if timeout on s connection
 * sock_wait_input()
 *	- waits for received input on s
 *	- may not be valid input for sock_Gets... check returned length
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
extern int _ip_delay0( void *s, int seconds, int (*fn)(), void *statusptr );
extern int _ip_delay1( void *s, int seconds, int (*fn)(), void *statusptr );
extern int _ip_delay2( void *s, int seconds, int (*fn)(), void *statusptr );

extern unsigned long set_timeout( unsigned int seconds );
extern unsigned long set_ttimeout( unsigned int ticks );
extern int chk_timeout( unsigned long timeout );



extern int tcp_tick( void *s );

#define sock_wait_established( s, seconds, fn, statusptr ) \
    if (_ip_delay0( s, seconds, fn, statusptr )) goto sock_err;
#define sock_wait_input( s, seconds, fn , statusptr ) \
    if (_ip_delay1( s, seconds, fn, statusptr )) goto sock_err;
#define sock_tick( s, statusptr ) \
    if ( !tcp_tick(s)) { if (statusptr) *statusptr = 1 ; goto sock_err; }
#define sock_wait_closed(s, seconds, fn, statusptr )\
    if (_ip_delay2( s, seconds, fn, statusptr )) goto sock_err;

/* user initialization file */
extern void (*usr_init)();

extern void outs( char far * string );
extern longword aton( char * string);

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



extern void _eth_init();
extern byte *_eth_formatpacket( void *eth_dest, word eth_type );
extern void _eth_send( word len);
extern void _eth_free( void *buf);
extern byte *_eth_arrived( word *type_ptr);
extern void _eth_release();



/* bsd-similar stuff */

extern int sock_rbsize( void *s );
extern int sock_rbused( void *s );
extern int sock_rbleft( void *s );
extern int sock_tbsize( void *s );
extern int sock_tbused( void *s );
extern int sock_tbleft( void *s );


extern _chk_socket( tcp_Socket *s );
extern char *inet_ntoa( char *s, longword x );
extern char *psocket( tcp_Socket *s );
extern longword inet_addr( char *s );
extern char *sockerr( tcp_Socket *s );
extern char *sockstate( tcp_Socket *s );
extern getpeername( tcp_Socket *s, void *dest, int *len );
extern getsockname(  tcp_Socket *s, void *dest, int *len );
extern longword gethostid();
extern longword sethostid( longword ip );
extern char *getdomainname( char *name, int length );
extern char *setdomainname( char *string );
extern char *gethostname( char *name, int length );
extern char *sethostname( char *string );
extern word ntohs( word a );
extern word htons( word a );
extern longword ntohl( longword x );
extern longword htonl( longword x );

extern void _arp_register( longword use, longword instead_of );
extern int _arp_resolve( longword ina, void *ethap, int nowait );

extern _survivebootp;
extern int sock_established( tcp_Socket *s);
extern sock_stats( tcp_Socket *s, word *days, word *inactive, word *cwindow, word *avg, word *sd );
extern int addwattcpd( void (*p)() );
extern int delwattcpd( void (*p)() );
extern int tap_add( void *socket, void *userid );
#endif /* WTCP_VER */

#endif /* ndef _wattcp_tcp_h */
