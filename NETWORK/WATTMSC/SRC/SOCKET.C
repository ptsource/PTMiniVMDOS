/***
 *
 * File: socket.c
 *
 * 27-Aug-93 fr
 *	cleanup
 * 16-Jul-93 fr
 *
 ***/


#include <tcp.h>

#define SOCKET


#define MAXPORT      32
#define MAXNUMPORT   2000
#define MAXLISTEN    8	
#define MAXTICKS     32500	/* about 30 minutes */

#define NO      0	/* should move to tcp.h -- also from tcp.c */

static int	ports[MAXPORT] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
				  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};

static int 
get_port(void)
{
	int i;
	for (i=0 ; i<MAXPORT ; i++)
		if(!(ports[i])){
			ports[i] = i+1;
			return(i+1);	
			}
	return(-1);
} /* end get_port */

int 
socket(int af, int type, int protocol) {
    int i;
    udp_Socket *s;

    if(af != AF_INET  || type > SOCK_DGRAM || type < SOCK_STREAM) 
		return(-1);
    if( (type==SOCK_STREAM) && (protocol != 0) && (protocol != IPPROTO_TCP) ) 
		return(-1);
    if( (type==SOCK_DGRAM) && (protocol != 0) && (protocol != IPPROTO_UDP) ) 
		return(-1);
    for(i = 0; i< MAXSOCK ;i++ )
    	if (!(sockarr[i].valid)){
	    sockarr[i].valid = 1;
	    sockarr[i].type = type;
	    if(type == SOCK_DGRAM){   /* must allocate space for UDP socket */
	    	if((s=(udp_Socket *)malloc((int)sizeof(udp_Socket)))==NULL)
		    return(-1);
		if(!udp_open(s, 0, 0, 0, NULL)){
		    DB3((stderr,"socket(): can't open UDP socket\n"));
		    return(-1);
		    }		
		sockarr[i].sockp = (sock_type *)s;
		}
	    return(i+MAXFILE);
	    }
    return(-1);
    } /* end socket */




int 
bind(int s, struct sockaddr *name, int namelen){

	unsigned short j;
	int i;

	if( (name->sa_family)!= AF_INET )
		return(-1);
	if( namelen != sizeof(struct sockaddr) )
		return(-1);
	if( ( ((struct sockaddr_in *)name)->sin_addr.s_addr ) &&
	    ( ((struct sockaddr_in *)name)->sin_addr.s_addr ) != 
						htonl(my_ip_addr) )
		return(-1);	
	
	if( j = ntohs(((struct sockaddr_in *)name)->sin_port) ) {
		if( (j > MAXNUMPORT) || j <= 0 ) 
			return(-1);
		for(i = 0; i < MAXPORT; i++){
			if(ports[i]==(int)j)
				return(-1);
			}
		for(i = 0; i < MAXPORT; i++){
			if(!ports[i]){
				ports[i] = j;
				break;
				}
			}
		if(i==MAXPORT) return(-1);		
		
		sockarr[s-MAXFILE].my_port = j;
		}
	return(0);
	} /* end bind */




int
listen(int sock, int numsock ) {

  tcp_Socket   *s[MAXLISTEN], *sret = NULL, *bsp=NULL; 
  int i;

  if( (numsock > MAXLISTEN) || (numsock < 1 ) )
	return(-1);

  if((sockarr[sock-MAXFILE].type)!=SOCK_STREAM){ 
 	DB3((stderr,"listen(): Can't do it on this type of socket!\n"));
	return(-1);
    }
  if( !(sockarr[sock-MAXFILE].my_port) ){ 
 	DB3((stderr,"listen(): Must execute bind() before!\n"));
	return(-1);
    }

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
    s[i]->myport = sockarr[sock-MAXFILE].my_port;
    s[i]->hisport = 0;    /* you can't choose in BSD */
    s[i]->hisaddr = 0L;    /* the same as above */
    s[i]->sock_mode = (s[i]->sock_mode & 0xfffc) | TCP_MODE_BINARY;	
    s[i]->seqnum = intel( (longword)s[i] ); /* not a good idea, but works */
    s[i]->datalen = 0;
    s[i]->flags = 0;
    s[i]->rto= 9; /* start 1/2 sec. rto */
    s[i]->unhappy = NO; /* this is a PASSIVE open */
    s[i]->dataHandler = NULL;
    s[i]->usr_yield = system_yield;
    s[i]->safetysig = SAFETYTCP;
    s[i]->next = tcp_allsocs;
    s[i]->brother = bsp;
    s[i]->rxbufsize = RxMaxBufSize;
    s[i]->txbufsize = TxMaxBufSize;

    tcp_allsocs = s[i];
    bsp=s[i];
    sret = s[i];
    if(!(sockarr[sock-MAXFILE].sockp))
	   sockarr[sock-MAXFILE].sockp=(sock_type *)s[i]; /* will it work? */
    }	/*end for*/
  ((tcp_Socket *)(sockarr[sock-MAXFILE].sockp))->brother = sret;
					 /* now we have a cyclic list */
  sockarr[sock-MAXFILE].sockp = (sock_type *)sret;
					 /* begin from the beginning */
  return(0);
  } /* end listen */




int 
accept(int s, struct sockaddr *addr, int *addrlen)
{
    tcp_Socket *ws, *ns;
    int i;
    char *cp;

    if(!(sockarr[s-MAXFILE].sockp)){
	DB3((stderr,"accept(): must call listen() first\n"));
	return(-1);
    }
    if( ( *addrlen < 0 ) || ( *addrlen > sizeof(struct sockaddr) ) )
	return(-1);
    ws = (tcp_Socket *)sockarr[s-MAXFILE].sockp;
    for(;;){
	if(!tcp_tick((sock_type *)ws)){
	    DB3((stderr,"accept(): Working on non-existing socket\n"));
	    return( -1 );
	}
	if(!ws->brother){
	    DB4((stderr,"*** PANIC *** accept(): You're in the wrong place!\n"));
	    exit(4);
	}
	kbhit();
	if( tcp_established(ws)){
			
	    for(i = 0; i< MAXSOCK ;i++ ){
		if (!(sockarr[i].valid)) break;
	    }
	    if(i==MAXSOCK){
		DB3((stderr,"accept(): No available sockets\n"));
		return(-1);
	    }
	    if((ns = malloc( (int) sizeof(tcp_Socket) )) == NULL){
		DB3((stderr,"accept(): No room for new socket\n"));
		return(-1);
	    }
	    memcpy(ns, ws, sizeof(tcp_Socket));	
	    ns->next = tcp_allsocs;
	    ns->brother = NULL;

	    if ((ns->rdata = (byte *) malloc((int)RxMaxBufSize)) == NULL) {
	       DB3((stderr,"accept(): not enough space for rdata buffer\n"));
	       return(-1);
	    }

	    if ((ns->data = (byte *) malloc((int)TxMaxBufSize)) == NULL) {
	   	   DB3((stderr,"ACCEPT: not enough space for data buffer\n"));
		   return(-1);
	    }

	    sockarr[i].sockp = (sock_type *)ns;
	    tcp_allsocs=((tcp_Socket *)sockarr[i].sockp);

	    sockarr[i].type = sockarr[s-MAXFILE].type;
	    sockarr[i].my_port = sockarr[s-MAXFILE].my_port;
	    sockarr[s-MAXFILE].sockp=((sock_type *)ws->brother);	
	    sockarr[i].valid = 1;

	    ((struct sockaddr_in *)addr)->sin_family = AF_INET;
				     /* as it's obvious */	
	    ((struct sockaddr_in *)addr)->sin_addr.s_addr = 
					    htonl(ws->hisaddr);
	    ((struct sockaddr_in *)addr)->sin_port = htons(ws->hisport);

	    cp = &(addr->sa_data[*addrlen]);
	    memset( cp, 0, sizeof(struct sockaddr) - *addrlen );
 
	    ws->state = tcp_StateLISTEN; /*   will .... */
	    ws->hisaddr = 0L;	     /* ...these....*/
	    ws->hisport = 0; 	     /*	...suffice? */
		
	    return(i+MAXFILE);
	}
        ws = ws->brother;   /* I loop but it's no use! */			
   }	/* end for(;;) */
}


int 
select(int maxfdp, fd_set *readfds, fd_set *writefds, fd_set *exceptfds,
			struct timeval *timeout){
	fd_set wkread, wkexcept, wkwrite;
	sock_type *s;
	int i, count = 0;
	long endtime = 0L, ttime = 0L;

	if(maxfdp > FD_SETSIZE) return(-1);
	if(timeout){
	    if( (ttime = ( (18 * timeout->tv_sec )
			+(timeout->tv_usec / 55000) )) > MAXTICKS )
			return(-1);
	    endtime = set_ttimeout((int)ttime);	
	    }
	FD_ZERO( &wkread );
	FD_ZERO( &wkwrite );
	FD_ZERO( &wkexcept );
	for(;;){
	    kbhit();	
	    if(exceptfds){
	        for( i=0 ; i < maxfdp ; i++ ){
		    if( ( i>= MAXFILE) && FD_ISSET(i, exceptfds) ){
		    	tcp_tick(NULL);
		        s=sockarr[i-MAXFILE].sockp;
		    	if( (!s) || ( (s->tcp.ip_type == TCP_PROTO) && 
				      (s->tcp.state >= tcp_StateCLOSWT) ) ){
			    count++;
			    FD_SET(i, &wkexcept);
			    if(!timeout) goto end;	
			    }
			}
		    }
		}	
	    if(readfds){	
	    	for( i=0 ; i < maxfdp ; i++ ){
		    tcp_tick(NULL);
		    if( ( i>= MAXFILE) && FD_ISSET(i, readfds) &&
				(sockarr[i-MAXFILE].sockp) ){
			s=sockarr[i-MAXFILE].sockp;
			if( (   (s->tcp.ip_type == TCP_PROTO) && 
				(s->tcp.brother) && 
				(tcp_established((tcp_Socket *)s)) ) ||
			    (   (s->tcp.ip_type == TCP_PROTO) &&
				(!s->tcp.brother) && 
				(sock_dataready(s)) )  ||
			    (   (s->tcp.ip_type == UDP_PROTO)  &&
				(s->udp.rdatalen) ) ){
		/* opened with LISTEN or waiting for data read */
			    count++;
			    FD_SET(i, &wkread);
			    if( !timeout )   goto end; 
			    }
		    	}
		    } /* end for */
		}  /* end readfds */
	    if(writefds){
	        for( i=0 ; i < maxfdp ; i++ ){
		    if( ( i>= MAXFILE) && FD_ISSET(i, writefds) ){
		    	tcp_tick(NULL);
		        s=sockarr[i-MAXFILE].sockp;
		    	if( (s->tcp.ip_type == UDP_PROTO ) ||
			   ((s->tcp.ip_type == TCP_PROTO) && 
			    (s->tcp.datalen < s->tcp.txbufsize)) ){
			    count++;
			    FD_SET(i, &wkwrite);
			    if(!timeout) goto end;	
			    }
			}
		    }
		}
	    if( timeout && ( (ttime == 0) || (chk_timeout(endtime)) ) ){
end:	        if(readfds)
 	        	memcpy(readfds, &wkread, sizeof(fd_set) );
	        if(exceptfds)
			memcpy(exceptfds, &wkexcept, sizeof(fd_set) );
	        if(writefds)
			memcpy(writefds, &wkwrite, sizeof(fd_set) );
		return(count);
		}
	    } /* end for(;;) */
	}	   



int 
connect(int sock, struct sockaddr *name, int namelen){

	int myport;
	longword ina;
	word hisport;
	sock_type *s;

	if ((sockarr[sock-MAXFILE].type)!=SOCK_STREAM){
	    DB3((stderr,"connect(): %d is not a SOCK_STREAM socket\n",sock));
	    return(-1);
	    }
	if( namelen != sizeof(struct sockaddr) )
		return(-1);
	if( (name->sa_family) != AF_INET )
		return(-1);
	if( (myport = get_port()) <0 )
		return(-1);
	
	sockarr[sock-MAXFILE].my_port = myport;

    	if ( (s = (sock_type *)malloc( (int) sizeof( tcp_Socket ) )) == NULL)
		return(-1);

	sockarr[sock-MAXFILE].sockp = s;
	ina = ntohl((longword)((struct sockaddr_in *)name)->sin_addr.s_addr);	
	hisport = ntohs( ((struct sockaddr_in *)name)->sin_port );

	if( !(tcp_open( (tcp_Socket *)s, (word)myport, ina, hisport, NULL) ) ){
		DB3((stderr,"open failed\n"));
		return(-1); 
		}
	return(0);
	} /* end connect */
		


struct hostent *
gethostbyname(char *name) {
	struct hostent *p;
	u_long	ul;

	if ((p = (struct hostent *)malloc((int)sizeof(struct hostent))) == NULL)
		return(NULL);
	p->h_name= (char *)malloc(64);
	strcpy(p->h_name,name);
	p->h_aliases = NULL;
	p->h_addrtype = AF_INET;
	p->h_length = 4;
	p->h_addr_list = ((char **)calloc(3,sizeof(char *)));
	p->h_addr = (char *)malloc(sizeof(struct in_addr));
	if(!(ul = resolve(name)))
		return(NULL);
	ul = htonl(ul);		
	movmem(&ul,p->h_addr,4);
	p->h_addr_list[1] = NULL;
	return(p);
	} /* end gethostbyname */


int 
getsockname(int s, struct sockaddr *name, int *lenp){
	udp_Socket *us;
	char *cp;
	int j;

	if(!(sockarr[s-MAXFILE].valid))
		return(-1);
	if( *lenp < 0 )
		return(-1);
	if(!(((struct sockaddr_in *)name)->sin_port)){
		sockarr[s-MAXFILE].my_port = get_port();
	     	((struct sockaddr_in *)name)->sin_port = 
					htons(sockarr[s-MAXFILE].my_port);
		}	
	if( (sockarr[s-MAXFILE].type) == SOCK_DGRAM ){
		us=((udp_Socket *)sockarr[s-MAXFILE].sockp);
		us->myport = (word)sockarr[s-MAXFILE].my_port;
		}
	if( (j = *lenp) < 2 )
		j = 2;
		cp = &(name->sa_data[j]);
		memset( cp, 0, sizeof(struct sockaddr) - j );
	return(sockarr[s-MAXFILE].my_port);
	} /* end getsockname */


int 
gethostname(char *buf, int len){
	if(!(_hostname) || !(buf) )
		return(-1);
	buf[0]=0;
	if ( (len < 0) || (len > (int)strlen(_hostname) ) )  
		len = 1 + (int)strlen(_hostname); 
	strncpy(buf,_hostname,len);
	return(0);
	} /* end gethostname */


char *
inet_ntoa(struct in_addr in){
	longword x;
	static char s[128];

	x = ntohl((longword)in.s_addr);
    	s[0]='\0';
    	itoa((int) (x >> 24), s, 10 );
   	strcat( s, ".");
    	itoa((int)(( x >> 16) & 0xff), strchr( s, 0), 10);
    	strcat( s, ".");
    	itoa((int)( x >> 8) & 0xff, strchr( s, 0), 10);
    	strcat( s, ".");
    	itoa((int)(x) & 0xff, strchr( s, 0), 10);
    	return( s );
	} /* end inet_ntoa */



int 
n_read(int fd, char *dp, int len){
	tcp_Socket *s;
	int x;
	
	s = ((tcp_Socket *)sockarr[fd-MAXFILE].sockp);
	if ( (sockarr[fd-MAXFILE].type)!=SOCK_STREAM ){
		DB3((stderr,"Error: N_READ applied to a non tcp socket\n"));
		return(-1);
		}
	for(;;){
		kbhit();	
		if(!tcp_tick((sock_type *)s))
			return(0);
		if(x=sock_dataready((sock_type *)s )){
			x = sock_fastread((sock_type *)s,(byte *)dp,len);
			dp[x] = 0;	/* you can't never say.... */
			if( (x > 0) && (x < len) ) 
				x = len;
			return(x);
			}
		if(s->state >= tcp_StateCLOSWT)
			return(0);
		}
	}



int 
n_write(int fd, char *dp, int len){
	tcp_Socket *s;
	
	s = ((tcp_Socket *)sockarr[fd-MAXFILE].sockp);
	if( !(tcp_tick( (sock_type *)s )) )
		return(-1);
	return(sock_fastwrite((sock_type *)s,(byte *)dp,len));
	}


int 
n_close(int sock) {
	tcp_Socket *s, *ps, *ts, *ys, **xs;
	int i, n;

	if(!(sockarr[sock-MAXFILE].valid)){
	    DB3((stderr,"N_CLOSE: socket %d was already closed\n", sock));
	    return(-1);
	    }

	if((sockarr[sock-MAXFILE].type)==SOCK_DGRAM){
		sock_close(sockarr[sock-MAXFILE].sockp);
		free( ((udp_Socket *)sockarr[sock-MAXFILE].sockp) );    	
		goto end;
		}
	
	ps = (tcp_Socket *)sockarr[sock-MAXFILE].sockp;
	if ( (ps->ip_type==TCP_PROTO) && (ps->brother) ){
	    s = ps;
	    for(;;){
		xs = &tcp_allsocs;
		for(;;){
			ys = *xs;
			if (ys == s){
				*xs = ys->next;
				break;
				}
			if(!ys) break;
			xs = &ys->next;
			}
		ts = s;
		s = s->brother;
		free(ts);
		DB3((stderr,"Freeing LISTEN socket\n"));
		if (s == ps) break;
		}	    
	     /* freed all sockets allocated with LISTEN */
	    goto end;
	    } 
	
	/* must be a normal tcp socket */
	sock_close((sock_type *)ps);
	_ip_delay2( (sock_type *)ps, 3, NULL, NULL);
	free(ps);

end:	sockarr[sock-MAXFILE].valid = 0;
	sockarr[sock-MAXFILE].type = 0;
	i = sockarr[sock-MAXFILE].my_port;
	for(n=0; n<MAXPORT; n++){
		if(ports[n] == i){
			ports[n]=0;
			break;
			}
		}
	sockarr[sock-MAXFILE].my_port = 0;
	sockarr[sock-MAXFILE].sockp = NULL;
	return(0);
	} /* end n_close */



int 
sendto(int sock, char *buf, int nbytes, int flags, 
				struct sockaddr *to, int addrlen) {
	udp_Socket *s;

	if( addrlen < sizeof(struct sockaddr) )
		return(-1);
	if( ((sockarr[sock-MAXFILE].type)!=SOCK_DGRAM) || (flags) )
		return(-1);
	s = ((udp_Socket *)sockarr[sock-MAXFILE].sockp);
	kbhit();
	tcp_tick(NULL);
	s->hisaddr = ntohl(((struct sockaddr_in *)to)->sin_addr.s_addr); 
	if(! _arp_resolve(s->hisaddr, &(s->hisethaddr)) )
		return(-1);
	s->hisport = ntohs( ((struct sockaddr_in *)to)->sin_port ); 
	return( sock_fastwrite( (sock_type *)s, buf, nbytes ) );
	} /* end sendto */



int 
recvfrom(int sock, char *buf, int nbytes, int flags, 
				struct sockaddr *from, int *addrlen) {
	udp_Socket *s;
	int num;
	char *cp;

	if( ((sockarr[sock-MAXFILE].type)!=SOCK_DGRAM) || (flags) )
		return(-1);
	if( ( *addrlen < 0 ) || ( *addrlen > sizeof(struct sockaddr) ))
		return(-1);   
	s = ((udp_Socket *)sockarr[sock-MAXFILE].sockp);
	for(;;){
		kbhit();
		tcp_tick(NULL);
		if( s->rdatalen ){
		    num = sock_fastread( (sock_type *)s, buf, nbytes );
		    ((struct sockaddr_in *)from)->sin_family = AF_INET; 
							 /* obviously */
		    ((struct sockaddr_in *)from)->sin_addr.s_addr = 
						htonl(s->hisaddr); 
		    ((struct sockaddr_in *)from)->sin_port = htons(s->hisport);

		    cp = &(from->sa_data[*addrlen]);
		    memset( cp, 0, sizeof(struct sockaddr) - *addrlen );
		    
		    s->hisaddr = 0L;  /* washing! */
		    s->hisport = 0;
		    memset( s->hisethaddr, 0xff, sizeof(eth_address) );	
		    return(num);
		    } 
		}
	} /* end recvfrom */


void
sleep(int sec){
	int ttime;
	long endtime;

	if( (sec > 0) && (sec < 1800) ){
		ttime=(18 * sec);
		endtime = set_ttimeout(ttime);
		while( !(chk_timeout(endtime)) ){
			tcp_tick(NULL);
			}
		}
	}


