#ifndef __rai_raims__ev_rv_transport_h__
#define __rai_raims__ev_rv_transport_h__

#include <sassrv/ev_rv.h>
#include <raims/msg.h>
#include <raims/sub.h>

namespace rai {
namespace ms {

struct TransportRoute;
struct EvRvTransport : public kv::RouteNotify/*, public SubOnMsg*/ {
  TransportRoute &rte;
  EvRvTransport( TransportRoute &r ) noexcept;

  /* sub notify */
  virtual void on_sub( kv::NotifySub &sub ) noexcept;
  virtual void on_unsub( kv::NotifySub &sub ) noexcept;
  virtual void on_psub( kv::NotifyPattern &pat ) noexcept;
  virtual void on_punsub( kv::NotifyPattern &pat ) noexcept;
  virtual void on_reassert( uint32_t fd,  kv::RouteVec<kv::RouteSub> &sub_db,
                            kv::RouteVec<kv::RouteSub> &pat_db ) noexcept;
  /*virtual void on_data( const SubMsgData &val ) noexcept;*/
};

struct EvRvTransportListen : public sassrv::EvRvListen, public EvRvTransport {
  EvRvTransportListen( kv::EvPoll &p,  TransportRoute &r ) noexcept;
  virtual int start_host( void ) noexcept final;
  virtual int stop_host( void ) noexcept final;
};

}
}

#endif
