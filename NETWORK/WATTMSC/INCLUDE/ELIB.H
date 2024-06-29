/***
 *
 * File: elib.h
 *
 * 16-Jun-92 lr
 *
 ***/

extern void outch(unsigned char ch );	/* print character to stdio */
extern void outs(unsigned char *s);	/* print a ASCIIZ string to stdio */
extern void outsn(unsigned char *s,unsigned n);	/* print a string with len max n */
extern void outhex( unsigned char ch );
extern void outhexes( unsigned char *ch, unsigned n );
/* void qmove( void far * src, void far * dest, int len ); */
/* int  qcmp( void far *src, void far *dest, int len ); */
/* void _keep( int status, int paragraphs ); */
/* int  sem_up( void far * ptr ); */

/*** end of file elib.h ***/
