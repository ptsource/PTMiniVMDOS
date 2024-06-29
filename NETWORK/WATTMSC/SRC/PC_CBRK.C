/***
 *
 * File: pc_cbrk.c
 *
 * 19-Jun-92 lr
 *
 */

#define WATTCP_KERNEL
#define PC_CBRK
#include <tcp.h>
#include <signal.h>

/*************************** STATICS *****************************/
static char *msgs[] = {
	"\n\rTerminating program\n\r",
	"\n\rCtrl-Breaks ignored\n\r" };
static int cbrkmode = 0;

static void handler(int sig);

/************************ END OF STATICS *************************/

/*
 * tcp_cbreak( mode )
 * 	- mode is composed of the following flags
 *	   0x01 - disallow breakouts
 *	   0x10 - display a message upon Cbreak
 *
 * 18-mar-92 gm modified and now running with Microsoft C 6.00
 */

static void
handler(int sig)
{
	signal(SIGINT,SIG_IGN); /* disable interrupt signals */
#ifdef oldversion
	if ( wathndlcbrk ) {
	        watcbroke = 1;
	        if (cbrkmode & 0x10 ) outs("\n\rInterrupting\n\r");
		signal(SIGINT,handler); /* reenable handler*/
	        return;
	}
#endif
	if (cbrkmode & 0x10 ) { 
		outs( msgs[0]);
		tcp_shutdown();  
		signal(SIGINT,SIG_DFL); /* reenable default handler*/
		return;
	}
	signal(SIGINT,handler); /* reenable handler*/
}

void
tcp_cbrk( int mode )
{
    cbrkmode = mode;

	if(cbrkmode & 0x01) {
		signal(SIGINT,SIG_IGN); /* ctrlbrk(ignored); */
		outs( msgs[1]);
		return;
	}
    signal(SIGINT,handler); /* ctrlbrk(handler); */
}
