/***********************************************************************
 *
 * File: socket.h
 *
 * created: 05-Jul-93 fr
 */

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
#define MAXFILE      32

/*typedef struct sockdesc{
	int		valid;
	int		type;
	int	 	my_port;
	sock_type	*sockp;
	} sock_desc; this is in tcp.h */


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

struct hostent {
	char	*h_name;     	/* host name */
	char	**h_aliases;	/* list of host name aliases */
	int	h_addrtype; 	/* this is always AF_INET for us */
	int 	h_length;	/* this is always 4 for us */
	char 	**h_addr_list;	/* these are pointers to in_addr struct */
	};
#define h_addr 	h_addr_list[0]

#define bcopy(src, dst, nbytes) 	memcpy(dst, src, nbytes)
#define bzero(dst, nbytes) 		memset(dst, 0, nbytes)
#define bcmp(ptr1, ptr2, nbytes) 	strncmp(ptr1, ptr2, nbytes)

#define	NBBY	8		/* number of bits in a byte */
/*
 * Select uses bit masks of file descriptors in longs.
 * These macros manipulate such bit fields (the filesystem macros use chars).
 */
#ifndef	FD_SETSIZE
#define	FD_SETSIZE	64
#endif	/* FD_SETSIZE */

/* How many things we'll allow select to use. 0 if unlimited */
#define MAXSELFD	64
typedef long	fd_mask;
#define NFDBITS	(sizeof(fd_mask) * NBBY)	/* bits per mask (power of 2!)*/
#define NFDSHIFT 5				/* Shift based on above */
#ifndef howmany
#define	howmany(x, y)	(((x)+((y)-1))/(y))
#endif /* howmany */

typedef	struct fd_set {
	fd_mask	fds_bits[howmany(FD_SETSIZE, NFDBITS)];
	} fd_set;

#define	FD_SET(n, p)	((p)->fds_bits[(n)/NFDBITS] |= ((long)1 << ((n) % NFDBITS)))
#define	FD_CLR(n, p)	((p)->fds_bits[(n)/NFDBITS] &= ~((long)1 << ((n) % NFDBITS)))
#define	FD_ISSET(n, p)	((p)->fds_bits[(n)/NFDBITS] & ((long)1 << ((n) % NFDBITS)))
#define FD_ZERO(p)	bzero(p, sizeof(fd_set))
/*#define FD_ZERO(p)	memset(p, 0, sizeof(fd_set))*/

struct timeval {
	long	tv_sec;		/* seconds */
	long	tv_usec;	/* microseconds */
	};

