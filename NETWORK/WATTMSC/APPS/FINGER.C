
/******************************************************************************

    FINGER - display user/system information

    Copyright (C) 1991, University of Waterloo

    This program is free software; you can redistribute it and/or modify
    it, but you may not sell it.

    This program is distributed in the hope that it will be useful,
    but without any warranty; without even the implied warranty of
    merchantability or fitness for a particular purpose.

	Erick Engelke                   or via E-Mail
	Faculty of Engineering
	University of Waterloo          Erick@development.watstar.uwaterloo.ca
	200 University Ave.,
	Waterloo, Ont., Canada
	N2L 3G1

******************************************************************************/

#include <stdio.h>
#include <string.h>
#include <tcp.h>

#define FINGER_PORT 79

tcp_Socket fingersock;
char buffer[ 513 ];

void finger(char *userid, longword host, char *hoststring)
{
    tcp_Socket *s;
    int status;
    int len;


    s = &fingersock;
    if (!tcp_open( s, 0, host, FINGER_PORT, NULL )) {
	puts("Sorry, unable to connect to that machine right now!");
	return;
    }

    printf("waiting...\r");
    sock_wait_established( (sock_type *)s, sock_delay, NULL, &status );

    if (*userid)
	printf("'%s' is looking for '%s'...\n\n\n", hoststring, userid);

    strcpy( buffer, userid );
    rip( buffer );                      /* kill all \n and \r's */
    strcat( buffer , "\r\n");

    sock_puts( (sock_type *)s, (byte *)buffer );

    while ( 1 ) {
	sock_wait_input( (sock_type *)s, 30, NULL, &status );
	len = sock_fastread( (sock_type *)s, buffer, 512 );
	buffer[ len ] = 0;
	printf( "%s", buffer );
    }

sock_err:
    switch (status) {
	case 1 : /* foreign host closed */
		 break;
	case -1: /* timeout */
		 printf("ERROR: %s\n", sockerr(s));
		 break;
	case 2 : /* CLOSWT and no more data */
		 sock_close( (sock_type *)s );
		 /* printf("Closing case status 2\n"); */
		 break;
    }
    printf("\n");
}

void help(void) {
	puts("   FINGER  [-d|/d] [userid]@server");
	exit(3);
	}

void main(int argc, char **argv )
{
    char *user, *server, buf[30];
    longword host;
    int i, status;

 /*   dbuginit();*/
    sock_init();

    /* process args */
    if ( argc < 2 ) 
	help();

    for ( i = 1; i < argc ; i++ ) {
	if ( !strcmp( argv[i], "-d") || !strcmp( argv[i], "/d") ) {
		if ( argc == 2 ) 
			help();
		puts("Debug is on");
		tcp_set_debug_state( 1 );
		}
	else {                
	    user = argv[i];
	    if (server = strchr( user, '@'))
		break;
	    else 
		help(); 
	    }
       }
	
  /*  do {
	if (argc == 2) {
	    user = argv[1];
	    if (server = strchr( user, '@'))
		break;
	}
	puts("   FINGER  [userid]@server");
	exit( 3 );
    } while ( 0 ); */

    *server ++ = 0;

    if (host = resolve( server )) {
	if (!debug_on) 
		printf("\nResolved %s = %s \n\n",server,w_inet_ntoa(buf,host));
	status = finger( user, host, server);
    } else {
	printf("Could not resolve host '%s'\n", server );
	exit( 3 );
    }
    exit( status );
}
