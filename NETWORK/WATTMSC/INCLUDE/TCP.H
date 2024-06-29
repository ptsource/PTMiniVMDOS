/***********************************************************************
 *
 * File: tcp.h
 *
 * last revised: 06-Jul-92 lr
 *
 * 06-Sep-93 lr,fr
 *	final cleanup, version becomes 0301
 * 19-Jun-92 lr
 *      cleaned up, merged from wattcp.h and tcp.h
 *
 * Waterloo TCP - TCP/IP library routines
 * 
 * Copyright 1992 Universita` di Pisa
 *
 * This network library was originally created by Erick Engelke,
 * of the University of Waterloo, Waterloo, Ontario, Canada.
 * Porting to Microsoft C, and thorough rewriting was done by
 * Luigi Rizzo of the Dip. di Ingegneria dell'Informazione of the
 * Universita` di Pisa, Pisa, ITALY. Also, some parts are taken
 * by previous implementations of TCP-IP.
 *
 *
 * Portions Copyright (C) 1990, 1991, University of Waterloo
 *
 * Portions Copyright (C) 1990, National Center for Supercomputer Applications
 * Portions Copyright (C) 1990, Clarkson University
 * Portions Copyright (C) 1983, 1986, Imagen Corporation
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 *
 * You may freely use this library to produce programs which you may give
 * away or sell in source format, or as compiled executables, or both.
 *
 * You may not sell this library or a portion thereof or distribute modified
 * versions the library code in either source or OBJect or LIBrary format
 * without written permission from the authors.
 *
 * Name resolution services were adapted from sources made available by
 * the National Centre for Supercomputer Applications (NCSA) and Clarkson
 * University.
 *
 *   A programmer's reference for WATTCP is available from:
 *
 *       WATTCP Programmer's Reference
 *       c/o SNSI
 *       P.O. Box 18,
 *       Warsaw, Ont.
 *       Canada
 *       K0L 3A0
 *
 *    or phone 705-652-1572 (does not need a country code from U.S.A.
 *    or Canada)
 *
 *    Credit cards, purchase orders and other forms of payment accepted.
 */

#define WATTCP_C "Copyright 1992, Universita` di Pisa\n"

#include <stdio.h>
#include <io.h>         /* read/write/open/close */
#include <stdlib.h>     /* for malloc(), free() */
#include <string.h>
#include <dos.h>
#include <conio.h>      /* for kbhit() */
#include <socket.h>     /* fr */


#define FDB stderr      /* debug file */

#define DB4(x)	fprintf x
#define DB3(x)	if (debug_on) DB4(x)
#ifdef debug
#	define DB2(x)	DB4(x)
#else
#	define DB2(x)	/* never print anything */
#endif
/* Kernel version (major major minor minor) */
#define WTCP_VER 0x0301

/*
 * Typedefs and constants
 */

#ifndef byte
#define byte unsigned char
#endif  byte

#ifndef word
#define word unsigned short
#endif  word

#ifndef longword
#define longword unsigned long
#endif  longword


typedef int (*procref)();
typedef byte eth_address[6]; /* check this! */

#define WATTCPH

#define MAX_GATE_DATA 12        /* number of gateways */
#define MAX_STRING 50           /* most strings are limited */

#define MAXBUFS         5       /* maximum number of Ethernet buffers */
#define BUFSIZE         1500    /* size of ethernet buffers */

#define MAXVJSA         1440    /* 10 s */
#define MAXVJSD         360     /* 10 s */
#define SAFETYTCP       0x538f25a3L
#define SAFETYUDP       0x3e45e154L

#define TRUE            1
#define FALSE           0
#define TICKS_SEC       18


#define PD_ETHER        1       /* packet driver class */
#define PD_SLIP         6       /* packet driver class */

/* The Ethernet header */
typedef struct {
    eth_address     destination;
    eth_address     source;
    word            type;
} eth_Header;

/* The Internet Header: */
typedef struct {
    unsigned        hdrlen  : 4, ver : 4, tos : 8;
    word            length;
    word            identification;
    word            frag;
    byte            ttl;
    byte            proto;
    word            checksum;
    longword        source;
    longword        destination;
} in_Header;

typedef struct {
    word            srcPort;
    word            dstPort;
    word            length;
    word            checksum;
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

/*** These are Intelled values ***/
#define tcp_FlagFIN     0x0001
#define tcp_FlagSYN     0x0002
#define tcp_FlagRST     0x0004
#define tcp_FlagPUSH    0x0008
#define tcp_FlagACK     0x0010
#define tcp_FlagURG     0x0020
#define tcp_FlagDO      0xF000
#define tcp_GetDataOffset(tp) (intel16((tp)->flags) >> 12)

/*** The TCP/UDP Pseudo Header ***/
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
#define tcp_StateLISTEN  0
	/* listening for connection
	 */
#define tcp_StateSYNSENT 1
	/* active open, syn sent, waiting for SYN
	 */
#define tcp_StateSYNREC  2
	/* active open, syn received, synack+syn sent., waiting ack
	 */
#define tcp_StateSYNRECLIS  3
	/* passive open, syn received, synack+syn sent., waiting ack
	 */
#define tcp_StateESTAB   4
	/* established, can transmit data.
	 */
#define tcp_StateESTCL   5
	/* established+close (will FIN after flushing the retransmit
	 * queue).
	 */
#define tcp_StateFINWT1  6
	/* outgoing data flushed, sent FIN. Can still receive incoming
	 * data from the other party.
	 */
#define tcp_StateFINWT2  7
	/* sent FIN, received FINACK. Can still receive incoming data
	 * from the other party (he might be in CLOSEWT).
	 */
#define tcp_StateCLOSWT  8
	/* was in ESTAB, received FIN, waiting for close. Must still
	 * flush the outgoing queue, while no more data can arrive.
	 */
#define tcp_StateCLOSWTCL 9
	/* was in CLOSWT (received FIN), received close. Must still
	 * flush the outgoing queue but no new data can arrive.
	 */
#define tcp_StateCLOSING 10
	/* sent FIN, received FIN (waiting for FINACK). No more
	 * data can travel in both directions.
	 */
#define tcp_StateLASTACK 11
	/* FIN received, FINack+FIN sent. No more data can
	 * travel in both directions.
	 */
#define tcp_StateTIMEWT  12
	/* (from CLOSING or FINWT2). Delay after sending final FINACK
	 * which the other party might have lost.
	 */
#define tcp_StateCLOSEMSL 13
	/* Don't know what's this for.
	 */
#define tcp_StateCLOSED  14
	/* FINack received. The connection is down.
	 */

#define DEFAULT_BUFSIZE 2048    /* default buffer size for sockets */

/*** 1-apr-92 gm Moving the buffers outside the socket structure ***/
/*
 * UDP socket definition. Here, there is only a receive buffer
 * because send is done on the fly.
 */

typedef struct _udp_socket {
    struct _udp_socket *next;
    word            ip_type;            /* always set to UDP_PROTO */
    char           *err_msg;            /* null when all is ok */
    void          (*usr_yield)();
    word            sock_mode;          /* a logical OR of bits */
    longword        usertimer;          /* ip_timer_set, ip_timer_timeout */
    procref         dataHandler;
    eth_address     hisethaddr;         /* peer's ethernet address */
    longword        hisaddr;            /* peer's internet address */
    word            hisport;            /* peer's UDP port */
    word            myport;

    short           rxbufsize;
    short           rdatalen;           /* must be signed */
    byte            *rdata;             /* if dataHandler==0,len=512 */
    longword        safetysig;
} udp_Socket;


/*
 * TCP Socket definition. We have variable buffer size.
 * Buffers are allocated by new_socket() with default size. Space is
 * only deallocated when necessary for a change in size.
 * become 
 *
 */

typedef struct _tcp_socket {
    struct _tcp_socket *next;       /* link field */
    word            ip_type;        /* always set to TCP_PROTO */
    char           *err_msg;        /* error string, null if OK */
    void          (*usr_yield)();   /* whom to give control when blocked */
    word            sock_mode;      /* a logical OR of bits */

    longword        usertimer;      /* ip_timer_set, ip_timer_timeout */
    eth_address     hisethaddr;     /* ethernet address of peer */
    longword        hisaddr;        /* internet address of peer */
    word            hisport;        /* tcp ports for this connection */
    word            myport;         /* my port of connection */

    word            state;          /* connection state */


    short           rxbufsize;      /* normally defaultbufsize */
    short           rdatalen;       /* must be signed, -1 means error */
    byte            *rdata;         /* received data */
    longword        safetysig;      /* a magic number */
    procref         dataHandler;    /* called with incoming data */

    longword        acknum;         /* last ack sent */
    longword        seqnum;         /* data ack'd and sequence num */
    long            timeout;        /* timeout, in ticks */
    byte            unhappy;        /* flag, indicates retransmitting segt's */
    word            flags;          /* tcp flags word for last packet sent */

    word            window;         /* other guy's window */
    short           txbufsize;      /* normally DEFAULT_BUFSIZE */
    short           datalen;        /* number of bytes of data to send */
    byte            *data;          /* data to send */
				    /* must be signed */
    short           unacked;        /* unacked data */

    /* 6-mar-92 added by lr-gm */
    longword        irs;            /* Initial Receive Sequential number */
    longword        iss;            /* Initial Send Sequential number    */
    word            UP;             /* Urgent Pointer                    */
    /* *********************** */

    word            vj_sa;          /* VJ's alg, standard average */
    word            vj_sd;          /* VJ's alg, standard deviation */
    longword        vj_last;        /* last transmit time */
    word            rto;

    /* retransmission timeout proceedure */
    /* these are in clock ticks */
    longword        rtt_lasttran;       /* last transmission time */
    longword        rtt_smooth;         /* smoothed round trip time */
    longword        rtt_delay;          /* delay for next transmission */
    longword        rtt_time;           /* time of next transmission */

    word            mss;
    longword        inactive_to;        /* for the inactive flag */

    struct _tcp_socket   *father;      /* pointer to sock-list-descriptor*/
    struct _tcp_socket   *brother;     /* link field for multi_listen*/
    word           inlist;             /* 1=LAZY 2=BUSY*/ 
} tcp_Socket;

/* sock_type used for socket io */
typedef union {
    udp_Socket udp;
    tcp_Socket tcp;
} sock_type;

/*
 * ARP definitions
 */
#ifdef WATTCPH
#define arp_TypeEther  0x100    /* ARP type of Eth addr (net format)*/
#else
#define arp_TypeEther  0x1      wrong.../* ARP type of Ethernet address */
#endif /* WATTCPH */

/* harp op codes */
#ifdef WATTCPH
#define ARP_REQUEST 0x0100 /* net format */
#define ARP_REPLY   0x0200 /* net format */
#else
#define ARP_REQUEST 1   wrong ... /* on purpose */
#define ARP_REPLY   2   wrong ... /* on purpose */
#endif  /* WATTCPH */

/*
 * Arp header
 */
typedef struct {
    word            hwType;
    word            protType;
    word            hwProtAddrLen;  /* hw and prot addr len */
    word            opcode;
    eth_address     srcEthAddr;
    longword        srcIPAddr;
    eth_address     dstEthAddr;
    longword        dstIPAddr;
} arp_Header;

#define ETH_MSS 1400  /* MSS for Ethernet */


/**** MS C compatibility ****/

#include <memory.h>

#define movmem(src,dest,len)    memmove((void *)(dest),(void *)(src),(size_t)(len))

struct REGPACK {
	struct WORDREGS x;
	struct SREGS    s;
#define         r_ax    x.ax
#define         r_bx    x.bx
#define         r_cx    x.cx
#define         r_dx    x.dx
#define         r_si    x.si
#define         r_di    x.di
#define         r_flags x.cflag
#define         r_es    s.es
#define         r_cs    s.cs
#define         r_ds    s.ds
#define         r_ss    s.ss
};

#define getvect(x) _dos_getvect(x)
#define intr(intno,r)   int86x(intno,(union REGS *)&((r)->x), \
			(union REGS *)&((r)->x), &((r)->s))
/**** end MS C compatibility ****/
struct wat_sockaddr {
    word        s_type;
    word        s_port;
    longword    s_ip;
    byte        s_spares[6];    /* unused in TCP realm */
};

typedef struct sockdesc{
	int		valid;
	int		type;
	int	 	my_port;
	sock_type	*sockp;
	} sock_desc;

/** those are in socket.h

#define u_short	unsigned short
#define u_long	unsigned long
#define u_char	unsigned char
#define u_int	unsigned int

#define AF_INET      2
#define INADDR_ANY   0L
#define SOCK_STREAM  1
#define SOCK_DGRAM   2
#define IPPROTO_IP   0
#define IPPROTO_ICMP 1
#define IPPROTO_UDP  17
#define IPPROTO_TCP  6
#define MAXSOCK      32
#define MAXFILE      30


struct sockaddr{
	u_short		sa_family;
	char		sa_data[14];
	};

struct in_addr{
	u_long		s_addr;
	};

struct sockaddr_in {
	short		sin_family;
	u_short		sin_port;
	struct in_addr	sin_addr;
	char		sin_zero[8];
	};

 ***** end socket.h */


#define MAX_COOKIES     10
#define MAX_NAMESERVERS 10

#define UDP_PROTO  0x11
#define TCP_PROTO  0x06
#define ICMP_PROTO 0x01

#define TCP_MODE_BINARY 0
#define TCP_MODE_ASCII  1
#define UDP_MODE_CHK    0       /*default to checksum */
#define UDP_MODE_NOCHK  2
#define TCP_MODE_NAGLE  0       /* Nagle algorithm */
#define TCP_MODE_NONAGLE 4


/*
 * sock_wait_... macros
 *
 * sock_wait_established()
 *      - waits then aborts if timeout on s connection
 * sock_wait_input()
 *      - waits for received input on s
 *      - may not be valid input for sock_Gets... check returned length
 * sock_tick()
 *      - do tick and jump on abort
 * sock_wait_closed();
 *      - discards all received data
 *
 * jump to sock_err with contents of *statusptr set to
 *       1 on closed
 *      -1 on timeout
 *
 */


#define sock_wait_established( s, seconds, fn, statusptr ) \
    if (_ip_delay0( s, seconds, fn, statusptr )) goto sock_err;
#define sock_wait_input( s, seconds, fn , statusptr ) \
    if (_ip_delay1( s, seconds, fn, statusptr )) goto sock_err;
#define sock_tick( s, statusptr ) \
    if ( !tcp_tick(s)) { if (statusptr) *statusptr = 1 ; goto sock_err; }
#define sock_wait_closed(s, seconds, fn, statusptr )\
    if (_ip_delay2( s, seconds, fn, statusptr )) goto sock_err;


#define ntohs(x) intel16(x)
#define htons(x) intel16(x)
#define ntohl(x) intel(x)
#define htonl(x) intel(x)

extern char *itoa(int, char *, int);
extern char *ltoa(long, char *, int);

#include <proto.h>      /* function prototypes */

/*** end of file tcp.h ***/
