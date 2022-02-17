#ifndef __rai_raims__ev_nats_transport_h__
#define __rai_raims__ev_nats_transport_h__

#include <natsmd/ev_nats.h>
#include <raims/msg.h>
#include <raims/sub.h>

namespace rai {
namespace ms {

struct TransportRoute;

struct EvNatsTransportListen : public natsmd::EvNatsListen {
  TransportRoute & rte;
  EvNatsTransportListen( kv::EvPoll &p,  TransportRoute &r ) noexcept;
};

}
}

#endif
