#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <raims/ev_nats_transport.h>
#include <raims/transport.h>
#include <raims/session.h>

using namespace rai;
using namespace natsmd;
using namespace ms;
using namespace kv;
using namespace md;

EvNatsTransportListen::EvNatsTransportListen( kv::EvPoll &p,
                                              TransportRoute &r ) noexcept
    : EvNatsListen( p, r.sub_route )/*, RouteNotify( r.sub_route )*/, rte( r )
{
  this->notify = &r;
  /*r.sub_route.add_route_notify( *this );*/
}
#if 0
void
EvNatsTransportListen::on_sub( NotifySub &sub ) noexcept
{
  if ( sub.is_start() ) {
    this->rte.mgr.sub_db.external_sub_start( sub, this->rte.tport_id );
  }
  d_nats( "on_sub(%.*s) rcnt=%u src_type=%c\n", (int) sub.subject_len,
         sub.subject, sub.sub_count, sub.src_type );
}

void
EvNatsTransportListen::on_unsub( NotifySub &sub ) noexcept
{
  if ( sub.is_stop() )
    this->rte.mgr.sub_db.external_sub_stop( sub, this->rte.tport_id );
  d_nats( "on_unsub(%.*s) rcnt=%u src_type=%c\n", (int) sub.subject_len,
        sub.subject, sub.sub_count, sub.src_type );
}

void
EvNatsTransportListen::on_psub( NotifyPattern &pat ) noexcept
{
  if ( pat.sub_count == 1 ) {
    this->rte.mgr.sub_db.external_psub_start( pat, this->rte.tport_id );
  }
  d_nats( "on_psub(%.*s) rcnt=%u src_type=%c\n", (int) pat.pattern_len,
        pat.pattern, pat.sub_count, pat.src_type );
}

void
EvNatsTransportListen::on_punsub( NotifyPattern &pat ) noexcept
{
  if ( pat.sub_count == 0 )
    this->rte.mgr.sub_db.external_psub_stop( pat, this->rte.tport_id );
  d_nats( "on_punsub(%.*s) rcnt=%u src_type=%c\n", (int) pat.pattern_len,
        pat.pattern, pat.sub_count, pat.src_type );
}

void
EvNatsTransportListen::on_reassert( uint32_t ,
                                    kv::RouteVec<kv::RouteSub> &,
                                    kv::RouteVec<kv::RouteSub> & ) noexcept
{
  d_nats( "on_reassert()\n" );
}
#endif
