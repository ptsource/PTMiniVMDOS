/*
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

#include <copyright.h>
#include <wattcp.h>
#include <ethdev.h>
#include <mem.h>

eth_address _eth_addr;		/* local ethernet address */
eth_address _eth_brdcast;	/* Ethernet broadcast address */
word _pktdevclass = 1;		/* Ethernet = 1, SLIP = 6 */

/*
 *  Initialize the Ethernet Interface, and this package.  Enable input on
 *  all packet buffers.
 */
void _eth_init()
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

static struct ether outbuf;

byte *_eth_formatpacket( void *eth_dest, word eth_type )
{
    memset( &outbuf, 0, sizeof(struct ether));
    switch ( _pktdevclass ) {
	case PD_ETHER :
		movmem( eth_dest, outbuf.dest, 6 );
                movmem( _eth_addr, outbuf.src, 6 );
		outbuf.type = eth_type;
                return( (byte *)&outbuf.data );
	case PD_SLIP :
                return( (byte *) &outbuf );      /* no header */
    }
}

/*
 * _eth_send does the actual transmission once we are complete with the
 * buffer.  Do any last minute patches here, like fix the size.
 */
int _eth_send( word len)
{

    if (( _pktdevclass == PD_ETHER ) && ((len += 14) < ETH_MIN ))
	len = ETH_MIN;

    return( pkt_send( &outbuf, len ));   /* send to packet driver */
}

/*
 * _eth_free - free an input buffer once it is no longer needed
 * If pointer to NULL, release all buffers
 */
void _eth_free( void *buf)
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

byte *_eth_arrived( word *type_ptr)
{
    struct ether * temp;

    if ((temp = (struct ether * ) pkt_received()) != NULL ) {
	switch ( _pktdevclass ) {
	    case PD_ETHER : *type_ptr = temp->type;
			    return( temp->data );
	    case PD_SLIP  : *type_ptr = 0x008;
			    return( (byte *) temp );
	}
    }
    return( NULL );
}

/*
 * _eth_release - release the hardware
 */
void _eth_release()
{
    pkt_release();
}

/*
 * _eth_hardware - return pointer to hardware address of a packet
 */
void *_eth_hardware( byte *p )
{
    return( p - 8 );
}

