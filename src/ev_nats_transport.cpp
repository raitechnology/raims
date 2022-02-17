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
    : EvNatsListen( p, r.sub_route ), rte( r )
{
  this->notify = &r;
}
