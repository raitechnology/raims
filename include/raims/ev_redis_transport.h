#ifndef __rai_raims__ev_redis_transport_h__
#define __rai_raims__ev_redis_transport_h__

#include <raids/ev_service.h>
#include <raims/msg.h>
#include <raims/sub.h>

namespace rai {
namespace ms {

struct TransportRoute;

struct EvRedisTransportListen : public ds::EvRedisListen {
  TransportRoute & rte;
  EvRedisTransportListen( kv::EvPoll &p,  TransportRoute &r ) noexcept;
};

}
}

#endif
