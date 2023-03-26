#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <netdb.h>
#include <raims/ev_rv_transport.h>
#include <raims/ev_web.h>
#include <raims/transport.h>
#include <raims/session.h>

using namespace rai;
using namespace sassrv;
using namespace ms;
using namespace kv;
using namespace md;

enum {
  RV_START_TIMER,
  RV_STOP_TIMER,
  RV_QUIT_TIMER
};
static const int RV_TIMEOUT_SECS = 2 * 60 + 10;

EvRvTransportListen::EvRvTransportListen( kv::EvPoll &p,
                                          TransportRoute &r,
                                          RvTransportService &s ) noexcept
    : EvRvListen( p, r.sub_route, s.db, true ), rte( r ), svc( s )
{
  static kv_atom_uint64_t rv_timer_id;
  this->notify = &r;
  this->timer_id = ( (uint64_t) this->sock_type << 56 ) |
                   kv_sync_add( &rv_timer_id, (uint64_t) 1 );
}

RvTransportService::RvTransportService( TransportRoute &r ) noexcept
    : rte( r ), last_active_mono( 0 ), active_cnt( 0 ), start_cnt( 0 ),
      no_mcast( false ), no_permanent( false ), no_fakeip( false )
{
}

EvSocket *
EvRvTransportListen::accept( void ) noexcept
{
  EvSocket *c = this->EvRvListen::accept();
  if ( c != NULL ) {
    this->rte.set_peer_name( *c, "rv.acc" );
    ((EvRvService *) c)->notify = this->notify;
  }
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

int
EvRvTransportListen::start_host( sassrv::RvHost &host,
                                 const sassrv::RvHostNet &hn ) noexcept
{
  uint32_t delay_secs = 0;
  int status = this->svc.start_host( host, hn, delay_secs );
  if ( status != 0 )
    return status;
  return this->EvRvListen::start_host2( host, delay_secs );
}

int
EvRvTransportListen::stop_host( RvHost &host ) noexcept
{
  this->svc.stop_host( host );
  return this->EvRvListen::stop_host( host );
}

void
RvTransportService::start( void ) noexcept
{
  if ( this->no_permanent ) {
    this->rte.poll.timer.add_timer_seconds( *this, RV_TIMEOUT_SECS,
                                            0, RV_START_TIMER );
  }
}

bool
RvTransportService::timer_cb( uint64_t,  uint64_t kind ) noexcept
{
  if ( kind == RV_START_TIMER ) {
    if ( this->start_cnt == 0 ) {
      this->rte.printf( "no client connected, shutting down\n" );
      this->rte.poll.timer.add_timer_seconds( *this, 1, 0, RV_QUIT_TIMER );
    }
  }
  else if ( kind == RV_STOP_TIMER ) {
    if ( this->active_cnt == 0 ) {
      uint64_t cur_mono = this->rte.poll.mono_ns;
      if ( this->last_active_mono +
           sec_to_ns( RV_TIMEOUT_SECS - 1 ) <= cur_mono ) {
        this->rte.printf( "no active clients, shutting down\n" );
        this->rte.poll.timer.add_timer_seconds( *this, 1, 0, RV_QUIT_TIMER );
      }
    }
  }
  else if ( kind == RV_QUIT_TIMER ) {
    this->rte.poll.quit = 1;
  }
  return false;
}

static size_t
make_rv_name( RvHost &host,  char *name,  const char *suf ) noexcept
{
  int x;
  if ( host.service_len == 0 )
    x = ::snprintf( name, 256, "rv_7500%s", suf );
  else
    x = ::snprintf( name, 256, "rv_%.*s%s", host.service_len, host.service,
                    suf );
  return min_int( x, 255 );
}

ConfigTree::Transport *
RvTransportService::get_rv_transport( RvHost &host,  bool create ) noexcept
{
  ConfigTree::Transport * t;
  ConfigTree & tree = this->rte.mgr.tree;
  StringTab  & stab = this->rte.user_db.string_tab;
  char   rv_svc[ 256 ];
  size_t svc_len = make_rv_name( host, rv_svc, "" );

  t = tree.find_transport( rv_svc, svc_len );

  if ( t == NULL && create ) {
    t = stab.make<ConfigTree::Transport>();
    stab.ref_string( rv_svc, svc_len, t->tport );
    t->tport_id = tree.transport_cnt++;
    t->is_temp = true;
    tree.transports.push_tl( t );
  }
  return t;
}

NetTransport
RvMcast2::net_to_transport( const char *net,  size_t &net_len ) noexcept
{
  static const struct {
    const char * name;
    NetTransport type;
  } protos[] = {
   { T_ANY, NET_ANY },
   { T_MESH, NET_MESH }, { T_MESH_LISTEN, NET_MESH_LISTEN },
   { T_MESH_CONNECT, NET_MESH_CONNECT },
   { T_TCP, NET_TCP },   { T_TCP_LISTEN, NET_TCP_LISTEN },
   { T_TCP_CONNECT, NET_TCP_CONNECT } };
  static const size_t nprotos = sizeof( protos ) / sizeof( protos[ 0 ] );

  const char * p;
  if ( net_len == 0 )
    return NET_NONE;
  if ( (p = (const char *) ::memchr( net, ';', net_len )) == NULL )
    return NET_ANY;

  size_t len = &net[ net_len ] - p;
  for ( size_t i = 0; i < nprotos; i++ ) {
    size_t plen = ::strlen( protos[ i ].name );
    if ( len == plen + 1 && ::memcmp( p + 1, protos[ i ].name, plen ) == 0 ) {
      net_len -= plen + 1;
      return protos[ i ].type;
    }
  }
  return NET_MCAST;
}

int
RvMcast2::parse_network2( const char *net,  size_t net_len ) noexcept
{
  this->type = net_to_transport( net, net_len );
  return this->RvMcast::parse_network( net, net_len );
}

static bool
match_route_str( ConfigTree::Transport &t,  const char *name,
                 const char *value,  size_t value_len ) noexcept
{
  const char *tmp = NULL;
  return t.get_route_str( name, tmp ) &&
         ::strlen( tmp ) == value_len &&
         ::memcmp( value, tmp, value_len ) == 0;
}

static bool
net_equals( RvHost &host,  ConfigTree::Transport &t ) noexcept
{
  size_t net_len = host.network_len,
         host_ip_len;
  char   host_ip[ 64 ];

  host_ip_len = host.mcast.ip4_string( host.mcast.host_ip, host_ip );
  switch ( RvMcast2::net_to_transport( host.network, net_len ) ) {
    default:
    case NET_NONE:
      return false;

    case NET_ANY:
      return t.type.equals( T_ANY, T_ANY_SZ ) &&
             match_route_str( t, R_DEVICE, host_ip, host_ip_len );

    case NET_MESH_CONNECT:
    case NET_MESH:
    case NET_MESH_LISTEN:
      return t.type.equals( T_MESH, T_MESH_SZ ) &&
             match_route_str( t, R_DEVICE, host_ip, host_ip_len );

    case NET_TCP_CONNECT:
    case NET_TCP:
    case NET_TCP_LISTEN:
      return t.type.equals( T_TCP, T_TCP_SZ ) &&
             match_route_str( t, R_DEVICE, host_ip, host_ip_len );

    case NET_MCAST:
      return t.type.equals( T_PGM, T_PGM_SZ ) &&
             match_route_str( t, R_LISTEN, host.network, host.network_len ) &&
             match_route_str( t, R_PORT, host.service, host.service_len );
  }
}

void
RvTransportService::make_rv_transport( ConfigTree::Transport *&t,
                                      RvHost &host, bool &is_listener ) noexcept
{
  ConfigTree & tree = this->rte.mgr.tree;
  StringTab  & stab = this->rte.user_db.string_tab;
  size_t       net_len = host.network_len,
               host_ip_len;
  char         host_ip[ 64 ];

  is_listener = true;
  host_ip_len = host.mcast.ip4_string( host.mcast.host_ip, host_ip );
  NetTransport type = RvMcast2::net_to_transport( host.network, net_len );
  if ( type == NET_NONE || ( type == NET_MCAST && this->no_mcast ) ) {
    t = NULL;
    return;
  }
  uint32_t localhost = htonl( ( 127U << 24 ) | 1 );
  if ( type == NET_ANY && host.mcast.host_ip == localhost )
    return;
  char name[ 256 ];
  size_t name_len = make_rv_name( host, name, "_old" );
  for ( ConfigTree::Transport * t = tree.transports.hd; t != NULL;
        t = t->next ) {
    if ( t->tport.equals( name, name_len ) ) {
      if ( net_equals( host, *t ) ) {
        name_len = make_rv_name( host, name, "" );
        stab.ref_string( name, name_len, t->tport );
        break;
      }
    }
  }

  if ( t == NULL )
    t = get_rv_transport( host, true );
  switch ( type ) {
    default: break;
    case NET_ANY:
      stab.reref_string( T_ANY, T_ANY_SZ, t->type );
      tree.set_route_str( *t, stab, R_DEVICE, host_ip, host_ip_len );
      break;

    case NET_MESH_CONNECT:
      is_listener = false; /* FALLTHRU */
    case NET_MESH:
    case NET_MESH_LISTEN:
      stab.reref_string( T_MESH, T_MESH_SZ, t->type );
      tree.set_route_str( *t, stab, R_DEVICE, host_ip, host_ip_len );
      break;

    case NET_TCP_CONNECT:
      is_listener = false; /* FALLTHRU */
    case NET_TCP:
    case NET_TCP_LISTEN:
      stab.reref_string( T_TCP, T_TCP_SZ, t->type );
      tree.set_route_str( *t, stab, R_DEVICE, host_ip, host_ip_len );
      break;

    case NET_MCAST:
      if ( ! this->no_mcast ) {
        stab.reref_string( T_PGM, T_PGM_SZ, t->type );
        tree.set_route_str( *t, stab, R_LISTEN,
                            host.network, host.network_len );
        tree.set_route_str( *t, stab, R_PORT,
                            host.service, host.service_len );
        tree.set_route_str( *t, stab, R_MCAST_LOOP, "2", 1 );
      }
      break;
  }
}

void
RvTransportService::find_host_http( RvHost &host ) noexcept
{
  for ( uint32_t i = 0; i < this->rte.mgr.unrouteable.count; i++ ) {
    Unrouteable & un = this->rte.mgr.unrouteable.ptr[ i ];
    if ( un.web != NULL ) {
      char         tmp[ 256 ];
      const char * addr = un.web->http_url.val;
      size_t       len  = sizeof( tmp );
      int          port = un.tport->get_host_port( addr, tmp, len,
                                               this->rte.mgr.tree.hosts );
      if ( port != 0 && len > 0 ) {
        AddrInfo info;
        if ( info.get_address(addr, port, OPT_AF_INET|OPT_LISTEN) == 0 ) {
          for ( addrinfo * ai = info.ai; ai != NULL; ai = ai->ai_next ) {
            if ( ai->ai_family == AF_INET ) {
              host.http_addr =
                ((struct sockaddr_in *) ai->ai_addr)->sin_addr.s_addr;
              host.http_port =
                ((struct sockaddr_in *) ai->ai_addr)->sin_port;
              return;
            }
          }
        }
      }
    }
  }
}

int
RvTransportService::start_host( RvHost &host,  const RvHostNet &hn,
                                uint32_t &delay_secs ) noexcept
{
  bool not_running = ! host.start_in_progress && ! host.network_started;
  this->start_cnt++;
  if ( hn.has_service_prefix != host.has_service_prefix )
    return ERR_SAME_SVC_TWO_NETS;
  if ( host.network_started ) {
    /* allow clients to attach to existing */
    if ( hn.network_len == 0 || this->no_mcast )
      return HOST_OK;
    if ( host.network_len != 0 ) {
      if ( host.mcast.host_ip == 0 ||
           ! host.is_same_network( hn ) )
        return ERR_SAME_SVC_TWO_NETS;
      return HOST_OK;
    }
  }
  if ( ! host.start_in_progress ) {
    if ( host.mcast.host_ip == 0 ||
         ! host.is_same_network( hn ) ) {
      RvMcast2 mc;
      int status = mc.parse_network2( hn.network, hn.network_len );
      if ( status != HOST_OK )
        return status;

      if ( mc.fake_ip == 0 && ! this->no_fakeip )
        mc.fake_ip = this->rte.mgr.user_db.bridge_nonce_int;
      host.host_id_len = (uint16_t)
        min_int( (size_t) this->rte.mgr.user_db.user.user.len,
                 MAX_RV_HOST_ID_LEN - 1 );
      ::memcpy( host.host_id, this->rte.mgr.user_db.user.user.val,
                host.host_id_len );
      ::memset( &host.host_id[ host.host_id_len ], 0,
                MAX_RV_HOST_ID_LEN - host.host_id_len );

      this->find_host_http( host );

      if ( ! host.network_started )
        status = host.start_network( mc, hn );
      else
        status = host.copy_network( mc, hn );
      if ( status != HOST_OK )
        return status;
    }
    if ( ! host.network_started )
      host.start_in_progress = true;
  }

  RvHostRoute           * hr   = this->tab.find( &host );
  TransportRoute        * rte  = NULL;
  ConfigTree::Transport * t    = NULL;
  bool                    exists = false;

  /* exists -> do not shutdown, do not startup
   * equals -> do not shutdown, do startup
   * not equals -> do shutdown, do startup */
  if ( hr != NULL ) {
    rte    = hr->rte;
    t      = hr->cfg;
    exists = hr->tport_exists;
  }
  if ( t != NULL ) {
    if ( ! exists ) {
      if ( ! net_equals( host, *t ) ) {
        StringTab  & stab = this->rte.user_db.string_tab;
        this->rte.mgr.shutdown_transport( *t );
        char old_name[ 256 ];
        int  name_len = ::snprintf( old_name, sizeof( old_name ), "%s_old",
                                    t->tport.val );
        stab.ref_string( old_name,
          min_int( (int) sizeof( old_name ) - 1, name_len ), t->tport );
        t = NULL;
        rte = NULL;
      }
    }
  }
  else {
    t = this->get_rv_transport( host, false );
    if ( t != NULL && hr == NULL )
      exists = true;
  }
  delay_secs = 0;
  if ( host.network_len == 0 || exists )
    rte = NULL;
  else if ( rte == NULL || rte->is_set( TPORT_IS_SHUTDOWN ) ) {
    if ( t != NULL && rte == NULL )
      rte = this->rte.user_db.transport_tab.find_transport( t );

    if ( rte == NULL || rte->is_set( TPORT_IS_SHUTDOWN ) ) {
      bool b, is_listener;
      this->make_rv_transport( t, host, is_listener );

      if ( t == NULL )
        rte = NULL;
      else {
        if ( rte != NULL )
          b = this->rte.mgr.start_transport( *rte, is_listener );
        else
          b = this->rte.mgr.add_transport2( *t, is_listener, rte );
        if ( ! b )
          return -1;
        delay_secs = 1;
      }
    }
  }
  if ( hr == NULL ) {
    hr = this->tab.add( &host, rte, t );
    hr->tport_exists = exists;
  }
  else {
    hr->rte = rte;
    hr->cfg = t;
    hr->tport_exists = exists;
  }
  if ( not_running ) {
    const char * extra = "";
    if ( host.network_len > 0 && this->no_mcast )
      extra = " (no_mcast)";
    printf( "start network: service %.*s, host %.*s (%.*s), \"%.*s\"%s\n",
            (int) host.service_len, host.service,
            (int) host.session_ip_len, host.session_ip,
            (int) host.sess_ip_len, host.sess_ip,
            (int) host.network_len, host.network, extra );
    this->last_active_mono = this->rte.poll.mono_ns;
    if ( hr != NULL ) {
      hr->last_active_mono = this->last_active_mono;
      hr->is_active = true;
    }
    this->active_cnt++;
    /*this->add_host_inbox_patterns( host.service_num );*/
  }
  return 0;
}

void
RvTransportService::stop_host( RvHost &host ) noexcept
{
  const char * extra = "";
  if ( host.network_len > 0 && this->no_mcast )
    extra = " (no_mcast)";
  printf( "stop network:  service %.*s, host %.*s (%.*s), \"%.*s\"%s\n",
          (int) host.service_len, host.service,
          (int) host.session_ip_len, host.session_ip,
          (int) host.sess_ip_len, host.sess_ip,
          (int) host.network_len, host.network, extra );
  uint64_t cur_mono = this->rte.poll.mono_ns;
  RvHostRoute * hr  = this->tab.find( &host );
  if ( hr != NULL ) {
    hr->last_active_mono = cur_mono;
    hr->is_active = false;
  }
  /*this->del_host_inbox_patterns( host.service_num );*/
  if ( --this->active_cnt == 0 && this->no_permanent ) {
    this->last_active_mono = cur_mono;
    this->rte.poll.timer.add_timer_seconds( *this, RV_TIMEOUT_SECS,
                                            0, RV_STOP_TIMER );
  }
}

void
RvTransportService::outbound_data_loss( uint16_t svc,  uint32_t msg_loss,
                                        uint32_t pub_host,
                                        const char *pub_host_id ) noexcept
{
  printf( "outbound_data_loss svc %u, lost %u, host %x.%s\n", svc, msg_loss,
          pub_host, pub_host_id );
  RvHost *host;
  if ( this->db.get_service( host, svc ) ) {
    host->send_outbound_data_loss( msg_loss, pub_host, pub_host_id );
  }
}

void
RvTransportService::add_host_inbox_patterns( uint16_t svc ) noexcept
{
  char inbox_buf[ 64 ], host_ip[ 16 ];
  UserDB & user_db = this->rte.user_db;
  size_t d = uint16_digits( svc );
  for ( uint32_t uid = 1; uid < user_db.next_uid; uid++ ) {
    if ( user_db.bridge_tab.ptr[ uid ] == NULL )
      continue;
    uint32_t fake_ip = user_db.bridge_tab.ptr[ uid ]->bridge_nonce_int;
    RvMcast::ip4_hex_string( fake_ip, host_ip );
    CatPtr ibx( inbox_buf );
    ibx.c( '_' ).u( svc, d ).s( "._INBOX." ).s( host_ip ).end();
    /*uint32_t n =*/
      this->rte.sub_route.add_pattern_route_str( inbox_buf, ibx.len(),
                                                 this->rte.fd );
    /*printf( "add_pattern %s: %u\n", inbox_buf, n );*/
  }
}

void
RvTransportService::update_host_inbox_patterns( uint32_t uid ) noexcept
{
  char inbox_buf[ 64 ], host_ip[ 16 ];
  UserDB & user_db = this->rte.user_db;
  if ( this->db.host_tab == NULL )
    return;
  if ( user_db.bridge_tab.ptr[ uid ] == NULL )
    return;
  uint32_t fake_ip = user_db.bridge_tab.ptr[ uid ]->bridge_nonce_int;
  RvMcast::ip4_hex_string( fake_ip, host_ip );
  for ( uint32_t k = 0; k < this->db.host_tab->count; k++ ) {
    if ( this->db.host_tab->ptr[ k ] == NULL )
      continue;

    sassrv::RvHost & host = *this->db.host_tab->ptr[ k ];
    if ( host.active_clients > 0 ) {
      uint16_t svc = host.service_num;
      size_t d = uint16_digits( svc );
      CatPtr ibx( inbox_buf );
      ibx.c( '_' ).u( svc, d ).s( "._INBOX." ).s( host_ip ).end();
      /*uint32_t n =*/
        this->rte.sub_route.add_pattern_route_str( inbox_buf, ibx.len(),
                                                   this->rte.fd );
      /*printf( "upd_pattern %s: %u\n", inbox_buf, n );*/
    }
  }
}

void
RvTransportService::del_host_inbox_patterns( uint16_t svc ) noexcept
{
  char inbox_buf[ 64 ], host_ip[ 16 ];
  UserDB & user_db = this->rte.user_db;
  size_t d = uint16_digits( svc );
  for ( uint32_t uid = 1; uid < user_db.next_uid; uid++ ) {
    if ( user_db.bridge_tab.ptr[ uid ] == NULL )
      continue;
    uint32_t fake_ip = user_db.bridge_tab.ptr[ uid ]->bridge_nonce_int;
    RvMcast::ip4_hex_string( fake_ip, host_ip );
    CatPtr ibx( inbox_buf );
    ibx.c( '_' ).u( svc, d ).s( "._INBOX." ).s( host_ip ).end();

    /*uint32_t n =*/
      this->rte.sub_route.del_pattern_route_str( inbox_buf, ibx.len(),
                                                 this->rte.fd );
    /*printf( "del_pattern %s: %u\n", inbox_buf, n );*/
  }
}

