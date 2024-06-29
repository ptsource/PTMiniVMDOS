/******************************************************************************

    REXEC - remotely execute a UNIX command

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
#include <time.h>             /* for randomize */
#include <stdlib.h>
#include <conio.h>            /* for getpass */
#include <tcp.h>

#define RSH_PORT 512
#define getrandom(min,max) ((rand()% (int)(((max)+1)-(min)))+(min))

char cmdbuf[ 2048 ];
word cmdbuflen;

char lname[ 64 ];               /* local copies if none supplied */
char lpass[ 64 ];
char lcmd[ 255 ];

void makecmdbuf( void *err, char *name, char *pass, char *cmd ) {

	char *p;

	p = cmdbuf;
	*p++ = 0;
	strcpy( p, name );
	p = strchr( p, 0 );
	strcpy( ++p, pass );
	p = strchr( p, 0 );
	strcpy( ++p, cmd );
	p = strchr( p, 0 );

	cmdbuflen = (word)(p - cmdbuf) + 1;
	}

char *getpass(char *s) {

	static char thepass[128];
	char c, *p=thepass;
	
	fprintf(stderr,s);
	
	while ( c= (char)getch() ) {
		switch (c) {
			case 8 : /* backspace */
			case 127: /* DEL */
				if (p>thepass) p--;
				break;
			case 13:
			case 10:
				*p=0;
				fprintf(stderr,"\n");
				return(thepass);
			default: 
				*p++=c;
				if (p-thepass >=sizeof(thepass)-1) p--;
				break;
			}
		}
	
	return(NULL);
	}

rsh( char *hostname, word port, char *name, char *pass, char *cmd ) {

    word lport, jqpublic, count;
    int status;
    longword host;
    char buffer[ 1024 ];
    tcp_Socket rsh_sock;


    /* randomize(); */
    lport = (word)(getrandom(0,512) + 512);  /* return 511 < port < 1024 */
    /*    lport = (rand() & 512) + 512;      /* return 511 < port < 1024 */

    if (!(host = resolve( hostname ))) {
	printf("Unable to resolve '%s'\naborting\n", hostname );
	return( 2 );
	}

    jqpublic = 0;
    if ( !name ) {
	printf(" Userid   : ");
	gets( name = lname );
	if ( !*name ) {
		printf( name = "JQPUBLIC");
		jqpublic = 1;
		}
	}
    
    if ( !pass ) {
	if (jqpublic) pass = "";
	else
	    strcpy( pass = lpass, getpass(" Password : "));
	     /* copy for neatness since getpass overwrites */
	}

    if (!cmd) {
	printf(" Command  : ");
	gets( cmd = lcmd );
	if ( !*cmd ) {
		puts("No command given\n");
		exit( 2 );
		}
	}

    makecmdbuf( NULL, name, pass, cmd);

    if (! tcp_open( &rsh_sock, lport, host, port, NULL )) {
	printf("Remote host unaccessible");
	return( 1 );
	}
    fprintf(stderr, "waiting for remote host to connect...\r");
    sock_wait_established( (sock_type *)&rsh_sock, sock_delay, NULL, &status);

    fprintf(stderr, "remote host connected, waiting verification...\r");

    sock_write( (sock_type *)&rsh_sock, cmdbuf, cmdbuflen );

    while (1) {
	sock_tick( (sock_type *)&rsh_sock, &status );
	if (!sock_dataready( (sock_type *)&rsh_sock ))
	    continue;
	sock_read( (sock_type *)&rsh_sock, buffer, 1 );
	fprintf(stderr, "                                              \r");
	if ( *buffer == 1 )
	    fprintf(stdout, "RSH failed...\n\r");
	break;
	}

    while (1) {
	if (kbhit())
	    sock_putc( (sock_type *)&rsh_sock, (byte)getch());
	sock_tick( (sock_type *)&rsh_sock, &status );
	if (sock_dataready( (sock_type *)&rsh_sock )) {
	       count = sock_read((sock_type *)&rsh_sock,buffer,sizeof(buffer));

/*** 8-apr-92 gm Here we can insert a call to Tar.library 
 *** and make the output in tar form.
 ***/
	       fwrite( buffer , count, 1, stdout );
	       }
	}

sock_err:
    switch (status) {
	case 1 : puts("\nConnection closed");
		 break;
	case-1 : printf("ERROR: %s\n", sockerr( &rsh_sock ));
		 break;
    }
    return( (status == 1) ? 0 : 1 );
}

void help()
{
    puts("RSH host [username [password]] cmdstring");
    puts("The values for cmdstring should be placed inside quotes");
    exit( 3 );
}

void main( int argc, char **argv )
{
    char *hostname, *name, *pass, *cmd;

    dbuginit();
    hostname = name = pass = cmd = NULL;
    sock_init();

    hostname = argv[ 1 ];

    switch ( argc ) {
	case  5 : pass = argv[3];
	case  4 : name = argv[2];
	case  3 : cmd = argv[ argc - 1 ];
		  break;
	case  2 : break;
	default : help();
    }

    exit( rsh( hostname, RSH_PORT, name, pass, cmd ));
}

