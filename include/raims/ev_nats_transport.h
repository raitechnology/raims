#ifndef __rai_raims__ev_nats_transport_h__
#define __rai_raims__ev_nats_transport_h__

#include <natsmd/ev_nats.h>
#include <raims/msg.h>
#include <raims/sub.h>

namespace rai {
namespace sassrv {
struct RvHost;
}
namespace ms {

struct TransportRoute;

struct EvNatsTransportListen : public natsmd::EvNatsListen {
  TransportRoute & rte;
  const char     * service;
  size_t           service_len;
  sassrv::RvHost * rv_host;
  uint16_t         rv_service;

  EvNatsTransportListen( kv::EvPoll &p,  TransportRoute &r ) noexcept;

  virtual EvSocket *accept( void ) noexcept;
  virtual int listen( const char *ip,  int port,  int opts ) noexcept;
};

}
}

#endif
