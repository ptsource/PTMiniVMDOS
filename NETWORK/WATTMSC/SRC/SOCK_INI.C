/***
 *
 * File: sock_ini.c
 *
 * 18-Jun-92 lr
 *
 * sock_init - easy way to guarentee:
 *	- card is ready
 *	- shutdown is handled
 *	- cbreaks are handled
 *      - config file is read
 *	- bootp is run
 *
 * 0.1 : May 2, 1991  Erick - reorganized operations
 */

#define WATTCP_KERNEL
#define SOCK_INI
#include <tcp.h>

void
sock_exit(void)
{
    tcp_shutdown();
}

void
sock_init(void)
{
    tcp_init();		/* must precede tcp_config because we need eth addr */
    atexit(sock_exit);	/* must not precede tcp_init() incase no PD */
    tcp_cbrk( 0x10 );	/* allow control breaks, give message */

    if (tcp_config( NULL )) {	/* if no config file use BOOTP w/broadcast */
	_bootpon = 1;
	outs("Configuring through BOOTP");
    }

    if (_bootpon)	/* non-zero if we use bootp */
	if (_dobootp()) {
	    outs("BOOTP failed\n\r");
	    if ( !_survivebootp )
		exit( 3 );
	}
}
