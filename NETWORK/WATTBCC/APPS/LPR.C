/*
 * LPR - dump job to printer
 *
 *
 *   Copyright (C) 1991, University of Waterloo
 *
 *   Portions Copyright (C) 1990, National Center for Supercomputer Applications
 *   and portions copyright (c) 1990, Clarkson University
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it, but you may not sell it.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but without any warranty; without even the implied warranty of
 *   merchantability or fitness for a particular purpose.
 *
 *       Erick Engelke                   or via E-Mail
 *       Faculty of Engineering
 *       University of Waterloo          Erick@development.watstar.uwaterloo.ca
 *       200 University Ave.,
 *       Waterloo, Ont., Canada
 *       N2L 3G1
 *
 *
 * The following notes on control and data files were obtained from Clarkson's
 * CUTE project.
 *
 *
 * Control File: format is the first character in the line is a command,
 * the rest of the line is the argument.  Also note lowercase letters
 * denote the data file names (of various types).
 *
 * currently valid commands are:
 *
 *     J -- "job name" on banner page
 *     C -- "class name" on banner page
 *     L -- "literal" user's name to print on banner
 *     T -- "title" for pr
 *     H -- "host name" of machine where lpr was done
 *     P -- "person" user's login name
 *     I -- "indent" amount to indent output
 *     f -- "file name" name of text file to print
 *     l -- "file name" text file with control chars
 *     p -- "file name" text file to print with pr(1)
 *     t -- "file name" troff(1) file to print
 *     n -- "file name" ditroff(1) file to print
 *     d -- "file name" dvi file to print
 *     g -- "file name" plot(1G) file to print
 *     v -- "file name" plain raster file to print (impress)
 *     c -- "file name" cifplot file to print
 *     1 -- "R font file" for troff
 *     2 -- "I font file" for troff
 *     3 -- "B font file" for troff
 *     4 -- "S font file" for troff
 *     N -- "name" of file (used by lpq)
 *     U -- "unlink" name of file to remove
 *           (after we print it. (Pass 2 only)).
 *     M -- "mail" to user when done printing
 *
 * Currently it looks like only a lowercase filename and U command are
 * necessary.  However one should also include J, L, H, and P.
 *
 * In general the lpd program doesn't care what the data file looks like.
 * It should however be of the type specified in the control file
 * otherwise it will probably print incorrectly.
 *
 * The format is ?fA<number><hostname>.  ? is either c for control or d
 * for data files.  Number is a 3 digit number (0 padded) used for job
 * number information.  Hostname is the name of the originating host and
 * had best be equal to whatever shows up in the from field when a
 * connection is opened (ie probably should be the "real" hostname).
 * Currently all of these must be used as the program has them compiled in
 * (by stupid use of pointers).  I may change this in time but currently
 * it is the law if you want everything to work (some things will work
 * just fine without it, queueing a file just wants names, showing the
 * queue expects a number to start in the fourth position, deleting a file
 * expects the hostname to start in the 7th position and go to the end of
 * the filename.
 *
 * default userid = server = "UNKNOWN";
 *
 * get's sequence file from getenv( "SEQUENCE" )
 * else "SEQUENCE.LPR"
 *
 * if ( ( title = getenv( "TITLE" )) ==  NULL )
 *      title = "stdprn";
 * if ( ( jobname = getenv( "JOBNAME" )) == NULL )
 *       jobname = "job_name";
 * if ( (  class = getenv("CLASS")) == NULL )
 *       class = server
 */


#include <stdio.h>
#include <io.h>
#include <tcp.h>

#define SHORT_LIST 3
#define LONG_LIST  4
#define MFCF_COUNT 5
char *mfcf[MFCF_COUNT];


#define LPQ_PORT 515
#define LOCAL_PORT 722

#define SEQFILE "SEQUENCE.LPR"
char *seqwhere;

word getsequence()
{
    static word oldseq = 0;
    FILE *f;

    if ( ! oldseq ) {
        /* must look to disk for an old sequence number */
        if ( f = fopen( seqwhere, "rt" )) {
            fscanf( f, "%u", &oldseq );
            fclose( f );
        }
    }

    oldseq = ( oldseq + 1 ) % 1000;

    if ( f = fopen( seqwhere, "wt" )) {
        fprintf( f, "%u", oldseq );
        fclose( f );
    }
    return( oldseq );
}

lpr( localhostname, printer, rhostname, filename, title, jobname,
    class, username, servername )
char *localhostname;
char *printer;
char *rhostname;
char *filename;
char *title;
char *jobname;
char *class;
char *username;
char *servername;
{
    static tcp_Socket socketdata;
    tcp_Socket *s;
    longword filesize;
    longword host;
    int status = 0;
    int connected = 0;
    int completed = 0;
    int localport;
    word seqnum, i;

    static char buffer[ 1024 ];
    char *b2;
    char remotename[ 80 ];
    static char cmdfile[ 1024 ];
    longword remaining;
    word found;
    FILE *f;

    if (( *class == 0 ) || (*class == ' ')) class = NULL;

    for ( i = 0; i < MFCF_COUNT ; ++i ) {
        if ( mfcf[ i ] )
            printf("Extra option: %s\n", mfcf[i] );
    }

    if (!(f = fopen( filename, "rb"))) {
	printf("Unable to open file '%s'\n", filename );
	return( 3 );
    }

    sock_init();
    s = &socketdata;
    if (!(host = resolve( rhostname ))) {
        printf( "lpq: unknown host %s\n",rhostname);
        return(1);
    }

    localport = 255 + (MsecClock() & 255);
    if ( !tcp_open( s, localport, host, LPQ_PORT, NULL)) {
      printf("Unable to open socket.");
      tcp_shutdown();
      return(1);
   }

   printf( "connecting...\r");
   sock_wait_established( s, sock_delay, NULL, &status );
   connected = 1;
   printf("connection established\n");

   /* is there an opening message - non-standard but possible */

   if (sock_dataready( s )) {
       sock_fastread( s, buffer, sizeof( buffer ));
       sock_tick( s, &status );	/* in case above message closed port */
   }

   /* use ipnumber/time  */
   seqnum = getsequence();
   sprintf(remotename,"fA%03u%s", seqnum, localhostname );
   
   /* we are connected */
   sprintf( buffer, "\2%s\n", printer );	/* select a printer */
   sock_puts( s, buffer );

   /* state #2 */

   sock_wait_input( s, sock_delay, NULL, &status );

   sock_fastread( s, buffer, sizeof( buffer ));

   switch (*buffer) {
       case 0 : break;
       case 1 : printf("Printer '%s' is not available\n", printer);
		goto close_it;
       default: rip( buffer );
                printf("ERROR: %s\n", buffer);
		goto close_it;
   }

   /* printer is accepted, printing file */
   filesize = filelength( fileno( f ));


   sprintf( buffer, "\3%ld d%s\n", filesize, remotename );
   sock_puts( s , buffer );
   sock_wait_input( s, sock_delay, NULL, &status );

   /* state 3, reply from filename */
   sock_fastread( s, buffer, sizeof( buffer ));

   switch (*buffer) {
	case 0: break;
        case 1: printf("remote host complains of bad connection");
		goto close_it;
	case 2: puts("remote host out of storage space");
		goto close_it;
    }

    /* dump file */

    remaining = filesize;
    do {
        cprintf("Transferred: %lu %c  \r",
            ((filesize - remaining + 1L)*100L)/(filesize+1), 37 );
        backgroundon();
        if ( (found = fread( buffer, 1, sizeof(buffer), f)) == 0 )
	    break;
        backgroundoff();

        sock_write( s, buffer, found );
	sock_tick( s , &status );
	if (sock_dataready( s )) {
	    puts("LPR: interrupted on transfer...");
	    goto close_it;
	}
    } while ( (remaining -= (longword)found) > 0 );

    sock_putc( s, 0 );

    /* check on status of this file */

    sock_wait_input( s, sock_delay, NULL, &status );
    sock_fastread( s, buffer, sizeof(buffer));

    switch (*buffer) {
	case 0: break;
	default:puts("file was rejected");
		goto close_it;		/* could retry */
    }

    sprintf( cmdfile,   "H%s\n"  "P%s\n" "C%s\n" "L%s\n",
        servername,     /* eg "development" */
	username,	/* eg "erick", */
        class ? class : servername, /* eg "NDSW or development", */

        username );     /* eg  "erick"       for on banner */

    for ( i = 0 ; i < MFCF_COUNT ; ++i ) {
        if ( mfcf[i] ) {
            strcat( cmdfile, mfcf[i] );
            strcat( cmdfile, "\n" );
        }
    }
    b2 = strchr( cmdfile, 0 );
    sprintf( b2, "T%s\n" "fd%s\n" "N%s\n" "Ud%s\n" "J%s\n",
        title,          /* title */
	remotename,	/* file processor */
        title,          /* name */
	remotename,
        jobname
    );
    printf("Options:\n%s\n", cmdfile );

    sprintf( buffer, "\2%d c%s\n", strlen( cmdfile ), remotename );

    sock_puts( s , buffer );
    sock_flush( s );

    sock_wait_input( s, sock_delay, NULL, &status );
    sock_fastread( s, buffer, sizeof( buffer ));

    switch (*buffer) {
	case 0: break;
        case 1: puts("Bad connection");
		goto close_it;
        case 2: puts("Out of space on host");
                goto close_it;
        default:puts("Unknown error");
                goto close_it;
    }

    sock_puts( s, cmdfile );
    sock_putc( s, 0 );
    sock_flush( s );

    sock_wait_input( s, sock_delay, NULL, &status );
    sock_fastread( s, buffer, sizeof( buffer ));

    switch (*buffer) {
        case 0: puts("Completed - job accepted");
                completed = 1;
		sock_putc( s, 0 );
		sock_flush( s );
		break;
        default:puts("Control file rejected");
                status = 3;
                break;
    }

    /* all roads come here */
close_it:
    sock_tick( s, &status);	/* in case they sent reset */
    sock_close( s );
    sock_wait_closed( s, sock_delay, NULL, &status );

sock_err:
    switch( status ) {
	case 1: break;
        case-1: printf("Remote host reset connection\n\r");
		status = 3;
		break;
    }
    if (!connected)
       printf( "\n\rCould not get connected.  Perhaps you were not in the /etc/hosts.lpd file!\n\r");

    return( !completed );
}


main(argc, argv)
int argc;
char **argv;
{
    char remotename[128];
    char *hostname;
    char *filename;
    char *printer;
    char *userid, *server;
    char *title, *jobname;
    char *rhostname;
    char *class;
    int status, i;

    for ( i = 0 ; i < MFCF_COUNT ; ++i ) {
        sprintf( remotename, "MFCF%u", i );
        mfcf[i] = getenv( remotename );
        if ( *mfcf[i] == 0 ) mfcf[i] = NULL;
    }


    userid = server = "UNKNOWN";
    if ((seqwhere = getenv( "SEQUENCE" )) == NULL )
        seqwhere = SEQFILE;
    if ( ( title = getenv( "TITLE" )) ==  NULL )
        title = "stdprn";
    if ( ( jobname = getenv( "JOBNAME" )) == NULL )
        jobname = "job_name";
    class = getenv("CLASS");

    puts("LPR using Waterloo TCP");
    switch (argc) {
	case 3:
	    /* no printername */
	    rhostname = argv[1];
	    filename = argv[2];
	    printer = "lp";
	    break;
	case 6:
	    /* whole thing */
	    userid = argv[4];
	    server = argv[5];		/* and continue on below */
	case 4:
	    /* Hostname and printer */
	    printer = argv[1];
	    rhostname = argv[2];
	    filename = argv[3];
	    break;
	default:
              printf( "Usage: LPR [printer] host filename [userid server]");
	      exit(1);
   }
    hostname = gethostname( NULL, 0 );
    if ( !hostname || !*hostname ) {
        puts("You must define your hostname in the WATTCP.CFG file!");
        exit( 3 );
    }

    strlwr( hostname );
    strlwr( userid );
    strlwr( server );
    status = lpr( hostname, printer, rhostname, filename, title, jobname,
        class, userid, server, MFCF_COUNT, mfcf );

    return( status ? 3 : 0 );
}
