/******************************************************************************
    COOKIE - read and print a witty saying from internet

    By: Jim Martin                      Internet: jim@dorm.rutgers.edu
        Dormitory Networking Project    UUCP: {backbone}!rutgers!jim
        Rutgers University              Phone: (908) 932-3719

    Uses the Waterloo TCP kernal.
******************************************************************************/

#include <stdio.h>
#include <tcp.h>


#define COOKIE_PORT 17

cookie(host)
longword host;
{
	tcp_Socket telsock;
    	static tcp_Socket *s;
    	char buffer[ 2049 ];
    	int status;
    	int len;
	int i;
	int fortunelen;

    	s = &telsock;
    	status = 0;

	if ( host != 0 )
	{
		status=udp_open( s, 0, host, COOKIE_PORT, NULL );
	}
	else
	{
		if (_last_cookie == 0)
		{
			puts("Sorry, I can't seem to remember where my cookie jars are. ");
			puts("Could you tell me where one is? (Hint: host on the comand line)");
			exit(3);
		}
		for (i=0; i < _last_cookie; i++)
		{
			if (status=udp_open( s, 0, _cookie[i], COOKIE_PORT, NULL ))
			{
				break;
			}
		}
	}

	if ( status == 0 )
	{
		puts("None of the cookie jars are open!");
		return( 1 );
	}

	sock_write( s, "\n", 1 );


    	while ( 1 )
	{
		sock_tick( s, &status );

		if (sock_dataready( s ) )
		{
			fortunelen=sock_fastread( s, buffer, sizeof( buffer ));
			buffer[fortunelen]='\0';
			printf("%s\n", buffer);
			sock_close(s);
			return(0);
		}
    	}

sock_err:
    switch (status)
	{
		case 1 : /* foreign host closed */
			 return(0);
		case -1: /* timeout */
			 printf("\nConnection timed out!");
             printf("ERROR: %s\n\r", sockerr( s ));
			 return(1);
    	}

}


main(int argc, char **argv )
{
	int status;
	longword host;

	if (argc > 2)
	{
		puts("Quote of the Day (Cookie) - retrieves a witty message");
		puts("Usage: COOKIE [server]");
		exit( 3 );
	}

	sock_init();

	if ( argc == 1)
	{
		status = cookie ((longword) NULL);
	}
	else
	{
		if ( host = resolve( argv[1]))
		{
			status = cookie( host );
		}
		else
		{
			printf("Could not resolve host '%s'\n", argv[1]);
			status = 3;
		}
	}

	exit( status );
}

