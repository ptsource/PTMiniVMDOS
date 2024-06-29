
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

finger(userid, host, hoststring)
char *userid, *hoststring;
longword host;
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
    sock_wait_established(s, sock_delay, NULL, &status);

    if (*userid)
	printf("'%s' is looking for '%s'...\n\n\n", hoststring, userid);

    strcpy( buffer, userid );
    rip( buffer );			/* kill all \n and \r's */
    strcat( buffer , "\r\n");

    sock_puts( s, buffer );

    sock_close( s );                    /* close sending side.... */

    while ( 1 ) {
	sock_wait_input( s, 30, NULL, &status );
	len = sock_fastread( s, buffer, 512 );
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
    }
    printf("\n");
}


main(int argc, char **argv )
{
    char *user,*server;
    longword host;
    int status;
    dbug_init();
    sock_init();

    /* process args */
    do {
	if (argc == 2) {
	    user = argv[1];
	    if (server = strchr( user, '@'))
		break;
	}
	puts("   FINGER  [userid]@server");
	exit( 3 );
    } while ( 0 );

    *server ++ = 0;

    if (host = resolve( server )) {
	status = finger( user, host, server);
    } else {
	printf("Could not resolve host '%s'\n", server );
	exit( 3 );
    }
    exit( status );
}
