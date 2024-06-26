/***
 *
 * File: pcsed.c
 *
 * 18-jun-92 lr
 *
 * Ethernet Driver Routines
 *
 *  The TCP code uses Ethernet constants for protocol numbers and 48 bits
 *  for address.  Also, 0xffffffffffff is assumed to be a broadcast.
 *
 *  If you need to write a new driver, implement it at this level and use
 *  the above mentioned constants as this program's constants, not device
 *  dependant constants.
 *
 *  The packet driver code lies below this and really ought to be rewritten
 *  in assembly language.
 *
 *  _eth_addr 	 - Ethernet address of this host.
 *  _eth_brdcast - Ethernet broadcast address.
 */

#define PCSED
#define WATTCP_KERNEL
#include <tcp.h>
#include <ethdev.h>

/********************** STATICS ***********************/
static struct ether outbuf;
/******************* END OF STATICS *******************/

/*
 * Initialize the Ethernet Interface, and this package.
 * Enable input on all packet buffers.
 */

void
_eth_init(void)
{
    movmem( _pkt_eth_init() , _eth_addr, 6 );
    memset( &_eth_brdcast, 0xff, sizeof( _eth_brdcast ));
}

/*
 * _eth_FormatPacket places the next packet into the buffer and uses the
 * type field for protocol determination.  Note, I only maintain a single
 * output buffer, and it gets used quickly then released.  The benefits of
 * non-blocking systems are immense.
 */


byte *
_eth_formatpacket( void *eth_dest, word eth_type )
{
    memset( &outbuf.data, 0, sizeof(in_Header)+sizeof(tcp_Header));
    switch ( _pktdevclass ) {
	case PD_ETHER :
		movmem( eth_dest, outbuf.dest, 6 );
		movmem( _eth_addr, outbuf.src, 6 );
		outbuf.type = eth_type;
		return( outbuf.data );
	case PD_SLIP :
		return( (byte *)&outbuf );	/* no header */
    }
    return NULL; /* can't be, unless errors */
}

/*
 * _eth_send does the actual transmission once we are complete with the
 * buffer.  Do any last minute patches here, like fix the size.
 */
int
_eth_send( word len)
{

    gm_eth_send++;
    if (( _pktdevclass == PD_ETHER ) && ((len += 14) < ETH_MIN ))
	len = ETH_MIN;

    return( pkt_send((char *)&outbuf, len ));   /* send to packet driver */
}

/*
 * _eth_free - free an input buffer once it is no longer needed
 * If pointer to NULL, release all buffers
 */
void
_eth_free( void *buf)
{
    if ( buf )
	pkt_buf_release( buf );
    else
	pkt_buf_wipe();
}

/*
 * _eth_arrived - if a new packet has arrived, read it and fill pointer
 * with type of packet
 */

byte *
_eth_arrived( word *type_ptr)
{
    struct ether * temp;

    if (temp = pkt_received()) {
	switch ( _pktdevclass ) {
	    case PD_ETHER : *type_ptr = temp->type;
			    return( temp->data );
	    case PD_SLIP  : *type_ptr = 0x008; /* IP_TYPE, intel format */
			    return((byte *) temp );
	}
    }
    return( NULL );
}

/*
 * _eth_release - release the hardware
 */
void
_eth_release(void)
{
    pkt_release();
}

/*
 * _eth_hardware - return pointer to hardware address of a packet
 */
void *
_eth_hardware( byte *p )
{
    return( p - 8 );
}
