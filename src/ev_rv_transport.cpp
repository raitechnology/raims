#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <raims/ev_rv_transport.h>
#include <raims/transport.h>
#include <raims/session.h>

using namespace rai;
using namespace sassrv;
using namespace ms;
using namespace kv;
using namespace md;

EvRvTransportListen::EvRvTransportListen( kv::EvPoll &p,
                                          TransportRoute &r ) noexcept
    : EvRvListen( p, r.sub_route ), rte( r )
{
  this->notify = &r;
}

EvSocket *
EvRvTransportListen::accept( void ) noexcept
{
  EvSocket *c = this->EvRvListen::accept();
  if ( c != NULL )
    this->rte.set_peer_name( *c, "rv.acc" );
  return c;
}

int
EvRvTransportListen::listen( const char *ip,  int port,  int opts ) noexcept
{
  int res = this->EvRvListen::listen( ip, port, opts );
  if ( res == 0 )
    this->rte.set_peer_name( *this, "rv.list" );
  return res;
}

static void
set_route_string( ConfigTree::Transport *t,  StringTab &stab,
                  const char *parm,  size_t parm_len,
                  const char *value, size_t value_len ) noexcept
{
  ConfigTree::StringPair * sp;
  if ( (sp = t->route.get_pair( parm, parm_len )) == NULL ) {
    sp = stab.make<ConfigTree::StringPair>();
    stab.ref_string( parm, parm_len, sp->name );
    t->route.push_tl( sp );
  }
  stab.reref_string( value, value_len, sp->value );
}

static ConfigTree::Transport *
get_rv_transport( EvRvTransportListen &listen,  RvHost &host ) noexcept
{
  ConfigTree::Transport * t;
  ConfigTree & tree = listen.rte.mgr.tree;
  StringTab  & stab = listen.rte.user_db.string_tab;
  char rv_svc[ RvHost::MAX_SERVICE_LEN + 8 ];
  int  svc_len;

  if ( host.service_len == 0 ) {
    ::strcpy( rv_svc, "rv_7500" );
    svc_len = 7;
  }
  else {
    svc_len = ::snprintf( rv_svc, sizeof( rv_svc ), "rv_%.*s",
                          host.service_len, host.service );
  }
  t = tree.find_transport( rv_svc, svc_len );

  if ( t == NULL ) {
    t = stab.make<ConfigTree::Transport>();
    stab.ref_string( rv_svc, svc_len, t->tport );
    t->tport_id = tree.transport_cnt++;
    tree.transports.push_tl( t );
  }
  return t;
}

int
EvRvTransportListen::start_host( RvHost &host ) noexcept
{
  RvHostRoute           * hr  = this->tab.find( &host );
  TransportRoute        * rte = NULL;
  ConfigTree::Transport * t   = NULL;
  uint32_t                delay_secs = 0;

  if ( hr != NULL ) {
    rte = hr->rte;
    t   = hr->cfg;
  }
  if ( ( rte == NULL || rte->is_set( TPORT_IS_SHUTDOWN ) ) &&
       host.network_len != 0 ) {
    StringTab & stab = this->rte.user_db.string_tab;

    if ( t == NULL )
      t = get_rv_transport( *this, host );
    if ( rte == NULL )
      rte = this->rte.user_db.transport_tab.find_transport( t );

    if ( rte == NULL || rte->is_set( TPORT_IS_SHUTDOWN ) ) {
      stab.reref_string( "pgm", 3, t->type );
      set_route_string( t, stab, "listen", 6, host.network, host.network_len );
      set_route_string( t, stab, "port", 4, host.service, host.service_len );
      set_route_string( t, stab, "mcast_loop", 10, "0", 1 );
      set_route_string( t, stab, "mtu", 3, "16384", 5 );

      bool b;
      if ( rte != NULL )
        b = this->rte.mgr.start_transport( *rte, true );
      else
        b = this->rte.mgr.add_transport2( this->rte.svc, *t, true, rte );
      if ( ! b )
        return -1;
      delay_secs = 1;
    }
  }
  if ( hr == NULL ) {
    if ( rte != NULL )
      this->tab.add( &host, rte, t );
  }
  else {
    hr->rte = rte;
    hr->cfg = t;
  }
  printf( "start_network:        service %.*s, \"%.*s\"\n",
          (int) host.service_len, host.service, (int) host.network_len,
          host.network );
  return this->EvRvListen::start_host2( host, delay_secs );
}

int
EvRvTransportListen::stop_host( RvHost &host ) noexcept
{
  printf( "stop_network:         service %.*s, \"%.*s\"\n",
          (int) host.service_len, host.service, (int) host.network_len,
          host.network );
  return this->EvRvListen::stop_host( host );
}
