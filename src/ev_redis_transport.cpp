#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <raims/ev_redis_transport.h>
#include <raims/transport.h>
#include <raims/session.h>

using namespace rai;
using namespace ds;
using namespace ms;
using namespace kv;

EvRedisTransportListen::EvRedisTransportListen( kv::EvPoll &p,
                                                TransportRoute &r ) noexcept
    : EvRedisListen( p, r.sub_route ), rte( r )
{
  this->notify = &r;
}
