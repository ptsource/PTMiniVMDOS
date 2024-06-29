#include <wattcp.h>


sock_stats( tcp_Socket *s, word *days, word *inactive, word *cwindow, word *avg, word *sd )
{
    if (s->ip_type == UDP_PROTO )
        return( 0 );

    if (days) *days = (word)(set_timeout(0)/0x1800b0L);
    if (inactive) *inactive = sock_inactive;
    if (cwindow) *cwindow = s->cwindow;
    if (avg)   *avg = s->vj_sa >> 3;
    if (sd)    *sd  = s->vj_sd >> 2;
}
