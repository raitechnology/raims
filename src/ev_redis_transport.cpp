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

EvSocket *
EvRedisTransportListen::accept( void ) noexcept
{
  EvSocket *c = this->EvRedisListen::accept();
  if ( c != NULL )
    this->rte.set_peer_name( *c, "redis.acc" );
  return c;
}

int
EvRedisTransportListen::listen( const char *ip,  int port,  int opts ) noexcept
{
  int res = this->EvRedisListen::listen( ip, port, opts );
  if ( res == 0 )
    this->rte.set_peer_name( *this, "redis.list" );
  return res;
}

