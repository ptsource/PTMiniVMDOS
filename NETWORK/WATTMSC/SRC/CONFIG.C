/***
 *
 * File: config.c
 * 27-Aug-93 fr
 *	removed diagnostic output
 * 25-May-93 fr (Ferruccio Rosellini)
 *      added hostable
 * 28-Aug-92 lr
 *      some cleanup
 * 01-Jul-92 lr
 *      added TXBUFSIZE, RXBUFSIZE, UDPBUFSIZE
 *
 */

#define WATTCP_KERNEL
#define CONFIG
#include <tcp.h>

#include <fcntl.h>      /* open modes */
#include <ctype.h>
#include <stdio.h>      /* for open/close/read/write -- check this */

/**** MS C Compatibility ****/

#define MY_IP           "MY_IP"
#define NETMASK         "NETMASK"
#define COOKIE          "COOKIE"
#define NAMESERVER      "NAMESERVER"
#define GATEWAY         "GATEWAY"
#define DOMAINS         "DOMAINSLIST"
#define HOSTNAME        "HOSTNAME"
#define SOCKDELAY       "SOCKDELAY"
#define ETHIP           "ETHIP"
#define MSS             "MSS"
#define BOOTP           "BOOTP"
#define BOOTPTO         "BOOTPTO"
#define DOMTO           "DOMAINTO"
#define PRINT           "PRINT"
#define INACTIVE        "INACTIVE"
#define INCLUDE         "INCLUDE"
#define TXBUFSIZE       "TXBUFSIZE"
#define RXBUFSIZE       "RXBUFSIZE"
#define UDPBUFSIZE      "UDPBUFSIZE"
#define DEBUG_FLAG      "DEBUG"

#define is_it( x ) if (!strcmp(name,x))

/**************************** STATICS *********************/
static void ethip( char *s );
static void set_values(char *name, char *value );

static char *watname = "WATTCP.CFG";
static char *hostsname = "HOSTS";

/*********************** END OF STATICS *******************/
/*
 * _inet_atoeth - read src, dump to ethernet buffer
 *                and return pointer to end of text string
 */

char *
_inet_atoeth( char *src, eth_address eth )
{
    word count, val;
    char ch;

    val = count = 0;
    while (ch = (char)toupper(*src++)) {
	if (ch == ':') {
	    eth[count++] = (byte)val;
	    if (count > 6)
		break;
	    val = 0;
	}
	if (ch == ',') {
	    eth[count] = (byte)val;
	    break;
	}
	if ((ch -= '0') > 9) ch -= 7;
	val = (val << 4) + ch;
    }
    return( src );
}

static void
ethip( char *s )
{
    eth_address temp_eth;
    char *temp;

    if ( temp = _inet_atoeth( s, temp_eth )) {
	if (!memcmp( &temp_eth, &_eth_addr, sizeof( eth_address ))) {
	    my_ip_addr = inet_addr( temp );
	}
    }
}

void
_add_server( int *counter, int max, longword *array, longword value )
{
    if ( value && ( *counter < max ))
	array[ (*counter)++ ] = value;
}


static void
set_values(char *name, char *value )
{
    char *p;
    /* longword temp; */
    word i;

    strupr(name);
    is_it( MY_IP ) {
	if ( toupper( *value ) == 'B') _bootpon = 1;
	else my_ip_addr = resolve( value );
    }
    else is_it( NETMASK) sin_mask = resolve( value );
    else is_it( GATEWAY) _arp_add_gateway( value , 0L );
	/* accept gateip[,subnet[,mask]]  */
    else is_it( NAMESERVER )  _add_server( &_last_nameserver,
		MAX_NAMESERVERS, def_nameservers, resolve(value));
    else is_it( COOKIE ) _add_server( &_last_cookie, MAX_COOKIES,
		_cookie, resolve( value ));
    else is_it( DOMAINS ) def_domain = strcpy( defaultdomain, value );
    else is_it( HOSTNAME ) strncpy(_hostname, value, (MAX_STRING*2) );
    else is_it( SOCKDELAY ) sock_delay = atoi( value );
    else is_it( ETHIP )  ethip( value );
    else is_it( MSS ) _mss = atoi( value );
    else is_it( TXBUFSIZE ) TxMaxBufSize = atoi( value );
    else is_it( RXBUFSIZE ) RxMaxBufSize = atoi( value );
    else is_it( UDPBUFSIZE ) MaxBufSize = atoi( value );
    else is_it( DEBUG_FLAG ) debug_on = atoi( value );
    else is_it( BOOTP ) _bootphost = resolve( value );
    else is_it( BOOTPTO) _bootptimeout = atoi( value );
    else is_it( DOMTO ) _domaintimeout = atoi( value );
    else is_it( INACTIVE ) sock_inactive = atoi( value );
    else is_it( PRINT ) {
	if(debug_on){
		outs( value ); 
		outs( "\r" );
		}
	}
    else is_it( INCLUDE ) {
	if ( *(p = value) == '?') p++;
	if ((i = open( p, O_RDONLY | O_TEXT )) != -1 ) {
	    close( i );
	    tcp_config( p );
	} else if ( *value != '?' ) {
	    outs("\n\rUnable to open '");
	    outs( p );
	    outs("'\n\r");
	}
    }
    else {
	if ( usr_init )
	    (*usr_init)(name, value);
    }
}


static int
hostable( char *path ) {
	char name[80], ip[80], ipname[80], s[80];
	FILE *fp;

	if (!path) {
		if (path=getenv( hostsname )) {
			path = strcpy( name, path );
			strcat( name, "\\");  
			}
		strcat( name, hostsname );        
		}   
    
	else   strcpy( name, path );           

	if ( !( fp = fopen( name, "r" ) ) ) {
	/* to recover a path parameter error try local subdirectory */
		if ( !( fp = fopen( hostsname, "r" ) ) ){
			DB3((stderr,"%s not found\n\r\n",hostsname));
			return( -1 );
			}
		}
	while ( fgets( s , 80 , fp ) !=NULL ) {
		switch( s[0] ) {
			
			case  '#':
			case  ';': break;

			default  : sscanf( s, "%s %s",ip,ipname );
				   add_hosts_table(ip,ipname);
				   break;
			} /* end switch */
		}/* end while */
	fclose(fp);
	return(0);
	}

int
tcp_config( char *path ) {
	char name[80];
	char value[80], ch[2];
	int  quotemode;
	int f, mode;

	hostable(NULL);        

	if (!path) {
		if (path=getenv( watname )) {
			path = strcpy( name, path );
			strcat( name, "\\");  
			}
	     /* else {
			strcpy( name, "program" !don't have argv[0]! );
			path = ( *name && (name[1] == ':')) ? &name[2] : name;
			if (!(temp = strrchr( path, '\\' ))) {
				temp = path;
				*(temp) = 0;    
				}                
			else *(++temp) = 0;
			strcpy( name , path);   
					
			}      that's all rubbish !    */

		strcat( name, watname );        
		}   /* end if !path */
    
	else   /* there is a path */
		strcpy( name, path );           

	if ( ( f = open( name, O_RDONLY | O_TEXT )) == -1 ) {
	/* to recover a path parameter error try local subdirectory */
		if (( f = open( watname, O_RDONLY | O_TEXT )) == -1 ){
			fprintf(stderr,"%s not found\n\r\n",watname);
			return( -1 );
			}
		}
	*name = *value = ch[1] = mode = quotemode = 0;
	while ( read( f, &ch, 1 ) == 1) {
		switch( *ch ) {
			case  '\"': quotemode ^= 1;
				    break;
			case  ' ' :
			case  '\t': if (quotemode) goto addit;
				    break;

			case  '=' : if (quotemode) goto addit;
				    if (!mode) mode = 1;
				    break;
			case  '#' :
			case  ';' : if (quotemode) goto addit;
				    mode = 2;
				    break;
			case  '\n':
			case  '\r': if (*name && *value)
					    set_values(name, value);
				    *name = *value = quotemode = mode = 0;
				    break;
			default   :
addit:
				switch (mode ) {
					case 0 : strcat(name, ch);
					break;
					case 1 : strcat(value, ch);
					break;
					}
				break;
			} /* end switch */
		}/* end while */
	close(f );
	return( 0 );
	}
