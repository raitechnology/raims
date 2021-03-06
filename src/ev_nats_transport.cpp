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

EvSocket *
EvNatsTransportListen::accept( void ) noexcept
{
  EvSocket *c = this->EvNatsListen::accept();
  if ( c != NULL )
    this->rte.set_peer_name( *c, "nats.acc" );
  return c;
}

int
EvNatsTransportListen::listen( const char *ip,  int port,  int opts ) noexcept
{
  int res = this->EvNatsListen::listen( ip, port, opts );
  if ( res == 0 )
    this->rte.set_peer_name( *this, "nats.list" );
  return res;
}

