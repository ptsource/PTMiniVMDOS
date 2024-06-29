
#include <stdio.h>
#include <tcp.h>

void main() {

        char buf[20];
        int i;

        sock_init();

        printf("my_ip_addr           = %s \n", w_inet_ntoa(buf,my_ip_addr) );
        printf("_hostname            = %s \n", _hostname );
        printf("sin_mask             = %s \n", w_inet_ntoa(buf,sin_mask) );
        printf("_bootphost           = %s \n", w_inet_ntoa(buf,_bootphost) );
        printf("_bootptimeout        = %d sec.\n", _bootptimeout );
        printf("_last_nameserver     = %d \n", _last_nameserver );
        for(i=0;i<_last_nameserver;i++)
                printf("def_nameservers[%d]   = %s\n",i,\
                        w_inet_ntoa(buf,def_nameservers[i]) );
        printf("_domaintimeout       = %d sec.\n", _domaintimeout );
        printf("def_domain           = %s \n", def_domain );
        /*printf("loc_domain           = %s \n",loc_domain );*/
        printf("_arp_last_gateway    = %d \n", _arp_last_gateway );
        
        printf("sock_delay           = %d sec.\n", sock_delay );
        printf("MaxBufSize           = %d bytes\n", MaxBufSize );
        printf("TxMaxBufSize         = %d bytes\n", TxMaxBufSize );
        printf("RxMaxBufSize         = %d bytes\n", RxMaxBufSize );
        printf("_mss (max lungh. seg. Ether.) = %d bytes\n", _mss );
        printf("_last_cookie         = %d \n", _last_cookie );
        printf("sock_inactive        = %d \n", sock_inactive );
        }
