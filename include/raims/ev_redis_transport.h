#ifndef __rai_raims__ev_redis_transport_h__
#define __rai_raims__ev_redis_transport_h__

#include <raikv/ev_tcp.h>
#include <raids/ev_service.h>
#include <raims/msg.h>
#include <raims/sub.h>

namespace rai {
namespace sassrv {
struct RvHost;
}
namespace ms {

struct TransportRoute;

struct EvRedisTransportListen : public ds::EvRedisListen {
  TransportRoute & rte;
  const char     * service;
  size_t           service_len;
  sassrv::RvHost * rv_host;
  uint16_t         rv_service;

  EvRedisTransportListen( kv::EvPoll &p,  TransportRoute &r ) noexcept;

  virtual kv::EvSocket *accept( void ) noexcept;
  virtual int listen( const char *ip,  int port,  int opts ) noexcept;
  virtual bool get_service( void *host,  uint16_t &svc ) noexcept;
};

}
}

#endif
