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
    : EvNatsListen( p, r.sub_route ), rte( r ),
      service( "_nats." ), service_len( 6 ), rv_host( 0 ), rv_service( 0 )
{
  this->notify = &r;
}

EvSocket *
EvNatsTransportListen::accept( void ) noexcept
{
  EvSocket *c = this->EvNatsListen::accept();
  if ( c != NULL ) {
    this->rte.set_peer_name( *c, "nats.acc" );
    EvNatsService * svc = (EvNatsService *) c;
    if ( this->service_len <= sizeof( svc->prefix ) ) {
      ::memcpy( svc->prefix, this->service, this->service_len );
      svc->prefix_len = this->service_len;
    }
    svc->notify = this->notify;
  }
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

bool
EvNatsTransportListen::get_service( void *host,  uint16_t &svc ) const noexcept
{
  svc = this->rv_service;
  if ( host != NULL )
    *(void **) host = (void *) &this->rv_host;
  return this->rv_service != 0;
}
