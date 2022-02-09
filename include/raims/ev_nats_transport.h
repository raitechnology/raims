#ifndef __rai_raims__ev_nats_transport_h__
#define __rai_raims__ev_nats_transport_h__

#include <natsmd/ev_nats.h>
#include <raims/msg.h>
#include <raims/sub.h>

namespace rai {
namespace ms {

struct TransportRoute;

struct EvNatsTransportListen : public natsmd::EvNatsListen /*,
                               public kv::RouteNotify*/ {
  TransportRoute & rte;
  EvNatsTransportListen( kv::EvPoll &p,  TransportRoute &r ) noexcept;
#if 0
  /* sub notify */
  virtual void on_sub( kv::NotifySub &sub ) noexcept;
  virtual void on_unsub( kv::NotifySub &sub ) noexcept;
  virtual void on_psub( kv::NotifyPattern &pat ) noexcept;
  virtual void on_punsub( kv::NotifyPattern &pat ) noexcept;
  virtual void on_reassert( uint32_t fd,  kv::RouteVec<kv::RouteSub> &sub_db,
                            kv::RouteVec<kv::RouteSub> &pat_db ) noexcept;
#endif
};

}
}

#endif
