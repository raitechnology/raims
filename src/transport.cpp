#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdarg.h>
#ifndef _MSC_VER
#include <unistd.h>
#else
#include <raikv/win.h>
#endif
#include <raims/transport.h>
#include <raims/session.h>
#include <raims/ev_tcp_transport.h>
#include <raims/ev_pgm_transport.h>
#include <raims/ev_inbox_transport.h>
#include <raims/ev_telnet.h>
#include <raims/ev_web.h>
#include <raims/ev_rv_transport.h>
#include <raims/ev_nats_transport.h>
#include <raims/ev_redis_transport.h>

using namespace rai;
using namespace ms;
using namespace kv;
using namespace md;
#if 0
struct rai::ms::TcpConnectionMgr :
   public ConnectionMgr<EvTcpTransportClient> {
  TcpConnectionMgr( kv::EvPoll &p,  uint8_t type ) : ConnectionMgr( p, type ) {}
};
#endif
bool
UserDB::forward_pub( const MsgFramePublish &pub,  const UserBridge &,
                     const MsgHdrDecoder &dec ) noexcept
{
  bool b = true;
  if ( dec.is_mcast_type() ) {
    size_t count = this->transport_tab.count;
    if ( count > 1 || pub.rte.connect_count > 1 ) {
      kv::EvPublish tmp( pub );
      for ( size_t i = 0; i < count; i++ ) {
        TransportRoute * rte = this->transport_tab.ptr[ i ];
        tmp.pub_type = 'p';
        if ( rte->connect_count > 0 ) {
          if ( rte != &pub.rte )
            b &= rte->forward_to_connected_auth( tmp );
          else if ( rte->connect_count > 1 )
            b &= rte->forward_to_connected_auth_not_fd( tmp, pub.src_route );
        }
      }
    }
  }
  return b;
}

TransportRoute::TransportRoute( kv::EvPoll &p,  SessionMgr &m,
                                ConfigTree::Service &s,
                                ConfigTree::Transport &t,
                                const char *svc_name,  uint32_t svc_id,
                                uint32_t id,  uint32_t f ) noexcept
    : EvSocket( p, p.register_type( "transport_route" ) ),
      poll( p ), mgr( m ), user_db( m.user_db ),
      sub_route( p.sub_route.get_service( svc_name, svc_id, id ) ),
      uid_in_mesh( &this->mesh_connected ),
      mesh_csum( &this->mesh_csum2 ),
      hb_time( 0 ), hb_mono_time( 0 ), hb_seqno( 0 ),
      stats_seqno( 0 ), tport_id( id ), hb_count( 0 ),
      last_hb_count( 0 ), connect_count( 0 ), last_connect_count( 0 ),
      state( f ), mesh_id( 0 ), listener( 0 ), connect_mgr( *this ),
      pgm_tport( 0 ), ibx_tport( 0 ), ucast_url_addr( 0 ),
      mesh_url_addr( 0 ), ucast_url_len( 0 ), mesh_url_len( 0 ), inbox_fd( -1 ),
      mcast_fd( -1 ), mesh_conn_hash( 0 ), oldest_uid( 0 ),
      primary_count( 0 ), ext( 0 ), svc( s ), transport( t )
{
  uint8_t i;
  this->uid_connected.tport      = t.tport;
  this->uid_connected.tport_type = t.type;
  this->uid_connected.tport_id   = id;
  for ( i = 0; i < COST_PATH_COUNT; i++ )
    this->router_rt[ i ] = NULL;
  /* parse config that has cost, cost2 ... */
  ConfigTree::StringPair * el[ COST_PATH_COUNT ] = {
    t.route.get_pair( "cost", 4 ), t.route.get_pair( "cost2", 5 ),
    t.route.get_pair( "cost3", 5 ), t.route.get_pair( "cost4", 5 )
  };
  /* parse config that uses array of cost */
  if ( el[ 0 ] != NULL ) {
    for ( i = 0; i < 3; i++ ) {
      if ( el[ i ]->next == NULL ) break;
      if ( ! el[ i ]->next->name.equals( "cost", 4 ) ) break;
      el[ i + 1 ] = el[ i ]->next;
    }
    this->uid_connected.is_advertised = true;
  }
  int cost, j = 0;
  for ( i = 0; i < COST_PATH_COUNT; i++ ) {
    if ( el[ i ] == NULL || ! el[ i ]->value.get_int( cost ) || cost <= 0 )
      cost = ( i == 0 ? COST_DEFAULT : this->uid_connected.cost[ j++ ] );
    this->uid_connected.cost[ i ] = cost;
  }
  d_tran( "transport.%u(%s, %x, %u,%u,%u,%u) created\n", id, t.tport.val, f,
           this->uid_connected.cost[ 0 ], this->uid_connected.cost[ 1 ],
           this->uid_connected.cost[ 2 ], this->uid_connected.cost[ 3 ] );
  this->sock_opts = OPT_NO_POLL;
  /* external tports do not have protocol for link state routing:
   *   _I.inbox, _X.HB, _Z.ADD, _Z.BLM, _Z.ADJ, _S.JOIN, _P.PSUB, etc */
  /* console_rt causes msgs to flow from tport -> session management */
  if ( ! this->is_set( TPORT_IS_IPC ) ) {
    BloomRoute *rt;
    rt = this->sub_route.create_bloom_route( m.fd, &m.sub_db.console, 0 );
    rt->add_bloom_ref( &m.sys_bloom );
    this->sub_route.create_bloom_route( m.ipc_rt.fd, &m.sub_db.ipc, 0 );
  }
  else {
    this->sub_route.create_bloom_route( m.console_rt.fd, &m.sub_db.console, 0 );
    /* extrenal routes do not have system subjects */
  }
  this->mesh_csum2.zero();
  this->hb_cnonce.zero();
  for ( int i = 0; i < 3; i++ )
    this->auth[ i ].zero();
}

int
TransportRoute::init( void ) noexcept
{
  int pfd = this->poll.get_null_fd();
  d_tran( "tport %s fd %d\n", this->sub_route.service_name, pfd );
  this->PeerData::init_peer( pfd, this->sub_route.route_id, NULL, "tport" );
  this->set_peer_name( *this, "tport" );
  int status = this->poll.add_sock( this );
  if ( status != 0 )
    return status;
  this->mgr.router_set.add( pfd );
  /* router_rt tport causes msgs to flow from tport -> routable user subs */
  for ( uint8_t i = 0; i < COST_PATH_COUNT; i++ )
    this->router_rt[ i ] = this->sub_route.create_bloom_route( pfd, NULL, i );
  return 0;
}

void
TransportRoute::set_peer_name( PeerData &pd,  const char *suff ) noexcept
{
  ConfigTree::Transport & tport = this->transport;
  ConfigTree::Service   & svc   = this->svc;
  char buf[ 256 ];
  int len = ::snprintf( buf, sizeof( buf ), "%s.%s.%s.%u",
                        svc.svc.val, tport.tport.val, suff, this->tport_id );
  pd.set_name( buf, len );
}

int
TransportRoute::printf( const char *fmt,  ... ) const noexcept
{
  va_list ap;
  int n, m;

  n = fprintf( stdout, "%s.%u ", this->transport.tport.val, this->tport_id );
  va_start( ap, fmt );
  m = vfprintf( stdout, fmt, ap );
  va_end( ap );
  return ( n >= 0 && m >= 0 ) ? n + m : -1;
}

void
TransportRoute::update_cost( UserBridge &n,
                             uint32_t cost[ COST_PATH_COUNT ] ) noexcept
{
  uint8_t i;
  for ( i = 0; i < COST_PATH_COUNT; i++ ) {
    if ( cost[ i ] != this->uid_connected.cost[ i ] ) {
      if ( this->uid_connected.is_advertised ) {
        n.printe( "conflicting cost[%u] advertised %u != %u on %s\n",
                   i, cost[ i ], this->uid_connected.cost[ i ], this->name );
      }
      break;
    }
  }
  if ( i == COST_PATH_COUNT )
    return;

  if ( this->uid_connected.is_advertised ) {
    for ( i = 0; i < COST_PATH_COUNT; i++ ) {
      if ( this->uid_connected.cost[ i ] > cost[ i ] )
        cost[ i ] = this->uid_connected.cost[ i ];
    }
  }
  for ( i = 0; i < COST_PATH_COUNT; i++ )
    this->uid_connected.cost[ i ] = cost[ i ];

  this->user_db.peer_dist.invalidate( ADVERTISED_COST_INV );
  this->user_db.adjacency_change.append( n.bridge_id.nonce, n.uid,
             this->tport_id, this->user_db.link_state_seqno + 1, true );

  if ( this->is_set( TPORT_IS_MESH ) ) {
    uint32_t count = (uint32_t) this->user_db.transport_tab.count;
    for ( uint32_t id = 0; id < count; id++ ) {
      if ( id == this->tport_id )
        continue;
      TransportRoute *rte = this->user_db.transport_tab.ptr[ id ];
      if ( ! rte->is_set( TPORT_IS_SHUTDOWN ) ) {
        if ( rte->is_set( TPORT_IS_MESH ) &&
             rte->mesh_id == this->mesh_id ) {
          for ( i = 0; i < COST_PATH_COUNT; i++ )
            rte->uid_connected.cost[ i ] = cost[ i ];
        }
      }
    }
  }
}

bool
SessionMgr::add_startup_transports( ConfigTree::Service &s ) noexcept
{
  ConfigTree::Parameters * p;
  ConfigTree::StringPair * sp;
  ConfigTree::Transport  * tport;
  bool conn;
  for ( p = this->tree.parameters.hd; p != NULL; p = p->next ) {
    for ( sp = p->parms.hd; sp != NULL; sp = sp->next ) {
      if ( sp->name.equals( "listen" ) ) {
        tport = this->tree.find_transport( sp->value.val, sp->value.len,&conn );
        if ( tport == NULL ) {
          fprintf( stderr, "startup listen transport %.*s not found\n",
                   (int) sp->value.len, sp->value.val );
          return false;
        }
        if ( ! this->add_transport( s, *tport, true ) )
          return false;
      }
    }
  }
  for ( p = this->tree.parameters.hd; p != NULL; p = p->next ) {
    for ( sp = p->parms.hd; sp != NULL; sp = sp->next ) {
      if ( sp->name.equals( "connect" ) ) {
        tport = this->tree.find_transport( sp->value.val, sp->value.len,&conn );
        if ( tport == NULL ) {
          fprintf( stderr, "startup connect transport %.*s not found\n",
                   (int) sp->value.len, sp->value.val );
          return false;
        }
        if ( ! this->add_transport( s, *tport, false ) )
          return false;
      }
    }
  }

  return true;
}

bool
SessionMgr::add_transport( ConfigTree::Service &s,
                           ConfigTree::Transport &t,
                           bool is_service ) noexcept
{
  TransportRoute * rte;
  return this->add_transport2( s, t, is_service, rte );
}

bool
SessionMgr::add_ipc_transport( ConfigTree::Service &s,  const char *ipc,
                               const char *map,  uint8_t db ) noexcept
{
  if ( ! this->in_list( IN_ACTIVE_LIST ) ) {
    if ( this->init_sock() != 0 )
      return false;
  }
  ConfigTree::Transport * tptr;
  TransportRoute * rte;
  uint32_t f = TPORT_IS_SVC | TPORT_IS_IPC;
  StringTab & stab = this->user_db.string_tab;

  tptr = this->tree.find_transport( "ipc", 3 );
  if ( tptr == NULL ) {
    tptr = stab.make<ConfigTree::Transport>();
    stab.ref_string( "ipc", 3, tptr->type );
    tptr->tport = tptr->type;
    tptr->tport_id = this->tree.transport_cnt++;
    this->tree.transports.push_tl( tptr );
  }
  uint32_t id = (uint32_t) this->user_db.transport_tab.count;
  void * p = aligned_malloc( sizeof( TransportRoute ) );
  rte = new ( p ) TransportRoute( this->poll, *this, s, *tptr, "ipc", 0, id, f );
  if ( rte->init() != 0 )
    return false;

  this->user_db.transport_tab[ id ] = rte;
  rte->ext = new ( ::malloc( sizeof( IpcRteList ) ) ) IpcRteList( *rte );
  rte->sub_route.add_route_notify( *rte->ext );
  this->user_db.ipc_transport = rte;

  EvShm shm( "ms_server" );
  const char *ipc_name = ipc;
  const char *map_name = map;
  uint32_t    db_num   = db;

  if ( ipc_name == NULL )
    this->tree.find_parameter( "ipc", ipc_name, NULL );
  if ( map_name == NULL )
    this->tree.find_parameter( "map", map_name, NULL );

  shm.ipc_name = ipc_name;
  if ( map_name != NULL )
    shm.open( map_name, db_num );
  else
    shm.open_rdonly();

  rte->sub_route.init_shm( shm );
  this->user_db.add_transport( *rte );
  return true;
}

bool
SessionMgr::add_transport2( ConfigTree::Service &s,
                            ConfigTree::Transport &t,
                            bool is_service,
                            TransportRoute *&rte ) noexcept
{
  if ( ! this->in_list( IN_ACTIVE_LIST ) ) {
    if ( this->init_sock() != 0 )
      return false;
  }
  if ( t.type.equals( "telnet" ) )
    return this->create_telnet( t );
  if ( t.type.equals( "web" ) )
    return this->create_web( t );

  ConfigTree::Transport * tptr = &t;
  uint32_t f = ( is_service ? TPORT_IS_SVC : 0 );
  char svc_name[ 256 ];
  if ( t.type.equals( "rv" ) || t.type.equals( "nats" ) ||
       t.type.equals( "redis" ) ) {
    StringTab & stab = this->user_db.string_tab;
    f |= TPORT_IS_IPC;
    size_t svc_len =
      ::snprintf( svc_name, sizeof( svc_name ), "%s.ipc", s.svc.val );
    tptr = this->tree.find_transport( svc_name, svc_len );
    if ( tptr == NULL ) {
      tptr = stab.make<ConfigTree::Transport>();
      stab.ref_string( "ipc", 3, tptr->type );
      stab.ref_string( svc_name, svc_len, tptr->tport );
      tptr->tport_id = this->tree.transport_cnt++;
      this->tree.transports.push_tl( tptr );
    }
  }
  else {
    ::snprintf( svc_name, sizeof( svc_name ), "%s.%s", s.svc.val, t.tport.val );
  }
  uint32_t id     = (uint32_t) this->user_db.transport_tab.count;
  bool     is_new = false;
  d_tran( "add transport %s tport_id %u\n", svc_name, id );

  rte = NULL;
  if ( ( f & TPORT_IS_IPC ) != 0 )
    rte = this->user_db.ipc_transport;

  if ( rte == NULL ) {
    void * p = aligned_malloc( sizeof( TransportRoute ) );
    rte = new ( p ) TransportRoute( this->poll, *this, s, *tptr, svc_name, 0,
                                    id, f );
    if ( rte->init() != 0 )
      return false;
    this->user_db.transport_tab[ id ] = rte;
    if ( ( f & TPORT_IS_IPC ) != 0 ) {
      rte->ext = new ( ::malloc( sizeof( IpcRteList ) ) ) IpcRteList( *rte );
      rte->sub_route.add_route_notify( *rte->ext );
      this->user_db.ipc_transport = rte;
    }
    is_new = true;
  }

  if ( rte->create_transport( t ) ) {
    if ( is_new )
      this->user_db.add_transport( *rte );
    return true;
  }
  rte->set( TPORT_IS_SHUTDOWN );
  return false;
}

uint32_t
SessionMgr::shutdown_transport( ConfigTree::Service &s,
                                ConfigTree::Transport &t ) noexcept
{
  if ( t.type.equals( "telnet" ) )
    return this->shutdown_telnet();
  if ( t.type.equals( "web" ) )
    return this->shutdown_web();

  uint32_t id,
           count = (uint32_t) this->user_db.transport_tab.count,
           match = 0;
  for ( id = 0; id < count; id++ ) {
    TransportRoute *rte = this->user_db.transport_tab.ptr[ id ];
    if ( &rte->transport == &t && &rte->svc == &s ) {
      match += rte->shutdown( t );
    }
  }
  return match;
}

bool
SessionMgr::start_transport( TransportRoute &rte,
                             bool is_service ) noexcept
{
  if ( rte.transport.type.equals( "tcp" ) ) {
    if ( is_service ) {
      if ( rte.listener != NULL )
        return rte.start_listener( rte.listener, rte.transport );
    }
    else {
      if ( rte.connect_mgr.conn != NULL ) {
        rte.connect_mgr.restart();
        //rte.connect_mgr->is_shutdown = false;
        rte.clear( TPORT_IS_SHUTDOWN );
        rte.connect_mgr.do_connect();
        return true;
      }
    }
  }
  else if ( rte.transport.type.equals( "mesh" ) ) {
    if ( rte.listener != NULL ) {
      if ( rte.is_set( TPORT_IS_SHUTDOWN ) ) {
        if ( ! rte.start_listener( rte.listener, rte.transport ) )
          return false;
        rte.create_listener_mesh_url();
      }
      if ( ! is_service )
        rte.add_mesh_connect( NULL, 0 );
      return true;
    }
  }
  else if ( rte.transport.type.equals( "pgm" ) ) {
    rte.clear( TPORT_IS_LISTEN | TPORT_IS_CONNECT );
    if ( is_service ) {
      rte.set( TPORT_IS_LISTEN );
      if ( rte.create_pgm( TPORT_IS_LISTEN, rte.transport ) )
        return true;
      rte.set( TPORT_IS_SHUTDOWN );
      return false;
    }
    rte.set( TPORT_IS_CONNECT );
    if ( rte.create_pgm( TPORT_IS_CONNECT, rte.transport ) )
      return true;
    rte.set( TPORT_IS_SHUTDOWN );
    return false;
  }
  return false;
}

static size_t
make_mesh_url_from_sock( char buf[ MAX_TCP_HOST_LEN ],
                         EvSocket &sock ) noexcept
{
  ::memcpy( buf, "tcp://", 6 );
  size_t len = get_strlen64( sock.peer_address.buf );
  bool is_ip4_wildcard, is_ip6_wildcard;
  is_ip4_wildcard = ( ::strncmp( sock.peer_address.buf, "0.0.0.0:", 8 ) == 0 );
  is_ip6_wildcard = ( ! is_ip4_wildcard &&
                      ::strncmp( sock.peer_address.buf, "[::]:", 5 ) == 0 );
  if ( is_ip4_wildcard || is_ip6_wildcard ) {
    size_t i = 0, j = 6;
    if ( ::gethostname( &buf[ 6 ], MAX_TCP_HOST_LEN - 6 ) == 0 ) {
      j += ::strlen( &buf[ 6 ] );
      if ( is_ip4_wildcard )
        i = 7;
      else
        i = 4;
    }
    while ( j < MAX_TCP_HOST_LEN - 1 && i < len )
      buf[ j++ ] = sock.peer_address.buf[ i++ ];
    len = j;
  }
  else {
    ::memcpy( &buf[ 6 ], sock.peer_address.buf, len );
    len += 6;
  }
  buf[ len ] = '\0';
  d_tran( "mesh_url_from_sock( \"%s\" )\n", buf );
  return len;
}

bool
SessionMgr::add_mesh_accept( TransportRoute &listen_rte,
                             EvTcpTransport &conn ) noexcept
{
  TransportRoute        * rte;
  ConfigTree::Service   & s = listen_rte.svc;
  ConfigTree::Transport & t = listen_rte.transport;
  const char            * svc_name = listen_rte.sub_route.service_name;

  d_tran( "add transport %s\n", svc_name );
  //uint32_t id = this->user_db.transport_list.tport_count++;
  uint32_t id,
           count = (uint32_t) this->user_db.transport_tab.count;
  for ( id = 0; id < count; id++ ) {
    rte = this->user_db.transport_tab.ptr[ id ];
    if ( rte->all_set( TPORT_IS_SHUTDOWN | TPORT_IS_MESH ) &&
         rte->mesh_id == conn.rte->mesh_id ) {
      if ( rte->connect_mgr.is_shutdown ) {
        rte->clear_all();
        break;
      }
    }
  }
  if ( id == count ) {
    void * p = aligned_malloc( sizeof( TransportRoute ) );
    rte = new ( p ) TransportRoute( this->poll, *this, s, t, svc_name, id, id,
                                    0 );
    if ( rte->init() != 0 )
      return false;
  }
  if ( rte->connect_mgr.conn != NULL )
    rte->connect_mgr.release_conn();

  rte->mesh_url_addr = listen_rte.mesh_url_addr;
  rte->mesh_url_len  = listen_rte.mesh_url_len;
  rte->mesh_id       = listen_rte.mesh_id;
  rte->uid_in_mesh   = listen_rte.uid_in_mesh;
  rte->mesh_csum     = listen_rte.mesh_csum;
  for ( uint8_t i = 0; i < COST_PATH_COUNT; i++ )
    rte->uid_connected.cost[ i ] = listen_rte.uid_connected.cost[ i ];

  rte->set( TPORT_IS_MESH );

  /*char buf[ MAX_TCP_HOST_LEN ];
  make_mesh_url_from_sock( buf, conn );
  rte->mesh_conn_hash = kv_crc_c( buf, ::strlen( buf ), 0 );*/
  rte->mesh_conn_hash = 0;
  conn.rte      = rte;
  conn.notify   = rte;
  conn.route_id = rte->sub_route.route_id;

  printf( "%s.%u add_mesh_accept %s from %s\n",
        rte->transport.tport.val, rte->tport_id, rte->mesh_url_addr,
        conn.peer_address.buf );
  if ( id == count ) {
    this->user_db.transport_tab[ id ] = rte;
    this->user_db.add_transport( *rte );
  }
  this->events.on_connect( rte->tport_id, TPORT_IS_MESH );
  if ( ! rte->connected.test_set( conn.fd ) )
    rte->connect_count++;
  d_tran( "%s connect_count %u\n", rte->name, rte->connect_count );
  return true;
}

void
TransportRoute::clear_mesh( void ) noexcept
{
  this->mesh_url_addr  = NULL;
  this->mesh_url_len   = 0;
  this->mesh_id        = 0;
  this->uid_in_mesh    = &this->mesh_connected;
  this->mesh_csum      = &this->mesh_csum2;
  this->mesh_conn_hash = 0;
}

bool
SessionMgr::add_tcp_accept( TransportRoute &listen_rte,
                            EvTcpTransport &conn ) noexcept
{
  TransportRoute        * rte;
  ConfigTree::Service   & s = listen_rte.svc;
  ConfigTree::Transport & t = listen_rte.transport;
  const char            * svc_name = listen_rte.sub_route.service_name;

  d_tran( "add transport %s\n", svc_name );
  //uint32_t id = this->user_db.transport_list.tport_count++;
  uint32_t id,
           count = (uint32_t) this->user_db.transport_tab.count;
  for ( id = 0; id < count; id++ ) {
    rte = this->user_db.transport_tab.ptr[ id ];
    if ( rte->all_set( TPORT_IS_SHUTDOWN | TPORT_IS_TCP ) ) {
      if ( rte->connect_mgr.is_shutdown ) {
        rte->clear_all();
        rte->clear_mesh();
        break;
      }
    }
  }
  if ( id == count ) {
    void * p = aligned_malloc( sizeof( TransportRoute ) );
    rte = new ( p ) TransportRoute( this->poll, *this, s, t, svc_name, id,id,0);
    if ( rte->init() != 0 )
      return false;
  }
  if ( rte->connect_mgr.conn != NULL )
    rte->connect_mgr.release_conn();

  for ( uint8_t i = 0; i < COST_PATH_COUNT; i++ )
    rte->uid_connected.cost[ i ] = listen_rte.uid_connected.cost[ i ];
  rte->set( TPORT_IS_TCP );

  conn.rte      = rte;
  conn.notify   = rte;
  conn.route_id = rte->sub_route.route_id;

  printf( "%s.%u add_tcp_accept\n", rte->transport.tport.val, rte->tport_id );
  if ( id == count ) {
    this->user_db.transport_tab[ id ] = rte;
    this->user_db.add_transport( *rte );
  }
  this->events.on_connect( rte->tport_id, TPORT_IS_TCP );
  if ( ! rte->connected.test_set( conn.fd ) )
    rte->connect_count++;
  d_tran( "%s connect_count %u\n", rte->name, rte->connect_count );
  return true;
}

static void
parse_tcp_param( EvTcpTransportParameters &parm,  const char *name,
                 ConfigTree::Transport &tport,  bool reuseport,
                 bool nb_connect ) noexcept
{
  char tmp[ MAX_TCP_HOSTS ][ MAX_TCP_HOST_LEN ];
  size_t len[ MAX_TCP_HOSTS ];
  size_t nlen = ::strlen( name );
  const char *host[ MAX_TCP_HOSTS ];
  int port[ MAX_TCP_HOSTS ], port2 = 0;
  char n[ MAX_TCP_HOSTS - 1 ][ 16 ];
  size_t i;

  for ( i = 0; i < MAX_TCP_HOSTS - 1; i++ ) /* connect2, connect3, connect4 */
    ::snprintf( n[ i ], sizeof( n[ i ] ), "%s%d", name, (int) i + 2 );

  ConfigTree::StringPair * el[ MAX_TCP_HOSTS ];
  el[ 0 ] = tport.route.get_pair( name, nlen );
  for ( i = 1; i < MAX_TCP_HOSTS; i++ )
    el[ i ] = tport.route.get_pair( n[ i - 1 ], nlen+1 );

  /* parse config that uses array of cost */
  if ( el[ 0 ] != NULL ) {
    for ( i = 0; i < MAX_TCP_HOSTS - 1; i++ ) {
      if ( el[ i ]->next == NULL ) break;
      if ( ! el[ i ]->next->name.equals( name, nlen ) ) break;
      el[ i + 1 ] = el[ i ]->next;
    }
  }

  tport.get_route_int( "port", port2 );
  for ( i = 0; i < MAX_TCP_HOSTS; i++ ) {
    host[ i ] = ( el[ i ] == NULL ? NULL : el[ i ]->value.val );
    tmp[ i ][ 0 ] = '\0';
    len[ i ] = sizeof( tmp[ i ] );
    port[ i ] = tport.get_host_port( host[ i ], tmp[ i ], len[ i ] );
    if ( port[ i ] == 0 )
      port[ i ] = port2;
    if ( tport.is_wildcard( tmp[ i ] ) ) {
      host[ i ] = NULL;
      tmp[ i ][ 0 ] = '\0';
    }
  }
  parm.set_host_port( host, port );

  if ( ! tport.get_route_int( "timeout", parm.timeout ) )
    parm.timeout = 15;
  if ( ! tport.get_route_bool( "edge", parm.edge ) )
    parm.edge = false;
  if ( reuseport )
    parm.opts |= kv::OPT_REUSEPORT;
  else
    parm.opts &= ~kv::OPT_REUSEPORT;
  if ( nb_connect )
    parm.opts |= kv::OPT_CONNECT_NB;
  else
    parm.opts &= ~kv::OPT_CONNECT_NB;
}

bool
TransportRoute::add_mesh_connect( const char *mesh_url,
                                  uint32_t mesh_hash ) noexcept
{
  if ( mesh_url == NULL )
    return this->mgr.add_mesh_connect( *this );
  return this->mgr.add_mesh_connect( *this, &mesh_url, &mesh_hash, 1 );
}

bool
SessionMgr::add_mesh_connect( TransportRoute &mesh_rte ) noexcept
{
  EvTcpTransportParameters parm;
  char     url_buf[ MAX_TCP_HOSTS ][ MAX_TCP_HOST_LEN ];
  size_t   url_buf_sz[ MAX_TCP_HOSTS ], i, j;
  uint32_t url_hash[ MAX_TCP_HOSTS ];

  parse_tcp_param( parm, "connect", mesh_rte.transport, false, true );

  for ( i = 0; i < MAX_TCP_HOSTS; i++ ) {
    char   * url    = url_buf[ i ];
    size_t & url_sz = url_buf_sz[ i ];
    char     pbuf[ 24 ];
    ::memcpy( url, "tcp://", 6 );
    if ( parm.host[ i ] == NULL ) {
      if ( i > 0 )
        break;
      url_sz = EvTcpTransportParameters::copy_host_buf( url, 6, "127.0.0.1" );
    }
    else {
      url_sz = EvTcpTransportParameters::copy_host_buf( url, 6, parm.host[ i ]);
    }
    if ( parm.port[ i ] != 0 ) {
      j = uint32_to_string( parm.port[ i ], pbuf );
      pbuf[ j ] = '\0';
    }
    else {
      ::strcpy( pbuf, "28989" );
    }
    if ( url_sz < MAX_TCP_HOST_LEN - 1 )
      url[ url_sz++ ] = ':';
    for ( j = 0; pbuf[ j ] != '\0'; j++ ) {
      if ( url_sz < MAX_TCP_HOST_LEN - 1 )
        url[ url_sz++ ] = pbuf[ j ];
    }
    url[ url_sz ] = '\0';
    url_hash[ i ] = kv_crc_c( url_buf[ i ], url_buf_sz[ i ], 0 );
  }

  const char *mesh_url[ MAX_TCP_HOSTS ];
  for ( j = 0; j < i; j++ )
    mesh_url[ j ] = url_buf[ j ];
  return this->add_mesh_connect( mesh_rte, mesh_url, url_hash, i );
}

TransportRoute *
SessionMgr::find_mesh_conn( TransportRoute &mesh_rte,  
                            uint32_t mesh_hash ) noexcept
{
  uint32_t count = (uint32_t) this->user_db.transport_tab.count;
  for ( uint32_t tport_id = 0; tport_id < count; tport_id++ ) {
    TransportRoute *rte = this->user_db.transport_tab.ptr[ tport_id ];
    if ( rte != &mesh_rte && rte->mesh_id == mesh_rte.mesh_id &&
         ! rte->is_set( TPORT_IS_SHUTDOWN ) ) {
      d_tran( "find_mesh %x (%x)%s\n", rte->mesh_conn_hash, mesh_hash,
               rte->mesh_conn_hash == mesh_hash ? " found" : "" );
      if ( rte->mesh_conn_hash == mesh_hash )
        return rte;
    }
  }
  return NULL;
}

bool
SessionMgr::add_mesh_connect( TransportRoute &mesh_rte,  const char **mesh_url,
                              uint32_t *mesh_hash, uint32_t url_count ) noexcept
{
  TransportRoute * rte;
  uint32_t         tport_id,
                   count, i, j, first_hash = 0;

  if ( mesh_rte.mesh_id == NULL )
    return true;
  mesh_rte.printf( "add_mesh_connect" );
  for ( i = 0; i < url_count; i++ )
    printf( " %s (%x)", mesh_url[ i ], mesh_hash[ i ] );
  printf( "\n" );

  for ( i = 0; i < url_count; i++ ) {
    if ( mesh_hash[ i ] == mesh_rte.mesh_conn_hash &&
         mesh_rte.is_set( TPORT_IS_LISTEN ) ) {
      mesh_rte.printf( "not connecting to self (%s)\n", mesh_url[ i ] );
      mesh_url[ i ]  = NULL;
      mesh_hash[ i ] = 0;
      continue;
    }
    rte = this->find_mesh_conn( mesh_rte, mesh_hash[ i ] );
    if ( rte != NULL ) {
      mesh_rte.printf( "already connected (%s)\n", mesh_url[ i ] );
      return true;
    }
    if ( first_hash == 0 )
      first_hash = mesh_hash[ i ];
  }
  if ( first_hash == 0 ) {
    mesh_rte.printf( "no mesh urls to connect\n" );
    return true;
  }
  count = (uint32_t) this->user_db.transport_tab.count;
  for ( tport_id = 0; tport_id < count; tport_id++ ) {
    rte = this->user_db.transport_tab.ptr[ tport_id ];
    if ( rte->all_set( TPORT_IS_SHUTDOWN | TPORT_IS_MESH ) &&
         rte->mesh_id == mesh_rte.mesh_id ) {
      if ( rte->connect_mgr.is_shutdown ) {
        rte->clear( TPORT_IS_SHUTDOWN );
        break;
      }
    }
  }
  if ( tport_id == count ) {
    void * p = aligned_malloc( sizeof( TransportRoute ) );
    ConfigTree::Service &s = mesh_rte.svc;
    ConfigTree::Transport &t = mesh_rte.transport;
    const char * svc_name = mesh_rte.mesh_id->sub_route.service_name;
    d_tran( "add transport %s\n", svc_name );
    rte = new ( p ) TransportRoute( this->poll, *this, s, t, svc_name,
                                    tport_id, tport_id, 0 );
    if ( rte->init() != 0 )
      return false;
  }

  rte->mesh_url_addr  = mesh_rte.mesh_url_addr;
  rte->mesh_url_len   = mesh_rte.mesh_url_len;
  rte->mesh_id        = mesh_rte.mesh_id;
  rte->uid_in_mesh    = mesh_rte.uid_in_mesh;
  rte->mesh_csum      = mesh_rte.mesh_csum;
  rte->mesh_conn_hash = first_hash;
  for ( uint8_t i = 0; i < COST_PATH_COUNT; i++ )
    rte->uid_connected.cost[ i ] = mesh_rte.uid_connected.cost[ i ];

  rte->set( TPORT_IS_MESH | TPORT_IS_CONNECT );
  this->user_db.transport_tab[ tport_id ] = rte;
  this->user_db.add_transport( *rte );

  EvTcpTransportParameters parm;

  j = 0;
  for ( i = 0; i < url_count; i++ ) {
    if ( mesh_url[ i ] != NULL ) {
      char tcp_buf[ MAX_TCP_HOST_LEN ];
      size_t len = sizeof( tcp_buf );
      int port;
      port = ConfigTree::Transport::get_host_port( mesh_url[ i ], tcp_buf, len);
      parm.set_host_port( tcp_buf, port, mesh_hash[ i ], j );
      j++;
    }
  }

  if ( ! mesh_rte.transport.get_route_int( "timeout", parm.timeout ) )
    parm.timeout = 15;

  if ( rte->connect_mgr.conn == NULL ) {
    uint8_t type = this->tcp_connect_sock_type;
    EvTcpTransportClient *c =
      rte->connect_mgr.alloc_conn<EvTcpTransportClient>( this->poll, type );
    c->rte = rte;
    c->route_id = rte->sub_route.route_id;
  }
  rte->connect_mgr.connect_timeout_secs = parm.timeout;
  rte->connect_mgr.set_parm( parm.copy() );
  if ( ! rte->connect_mgr.do_connect() ) {
    rte->set( TPORT_IS_SHUTDOWN );
    return false;
  }
  return true;
}

bool
TransportRoute::on_msg( EvPublish &pub ) noexcept
{
  this->msgs_recv++;
  this->bytes_recv += pub.msg_len;
  if ( pub.src_route == (uint32_t) this->mgr.fd ) {
    d_tran( "xxx discard %s transport_route: on_msg (%.*s)\n",
            ( pub.src_route == (uint32_t) this->fd ? "from tport" : "from mgr" ),
            (int) pub.subject_len, pub.subject );
    return true;
  }
  if ( pub.pub_type != 'X' ) {
    uint32_t id = pub.sub_route.route_id;
    TransportRoute * rte = this->user_db.transport_tab.ptr[ id ];
    if ( rte->is_set( TPORT_IS_IPC ) ) {
      d_tran( "rte(%s) forward external: on_msg (%.*s)\n",
              rte->name, (int) pub.subject_len, pub.subject );
      return this->mgr.forward_ipc( *rte, pub );
    }
    d_tran( "rte(%s) pub_type == (%c) transport_route: on_msg (%.*s)\n",
            rte->name, pub.pub_type, (int) pub.subject_len, pub.subject );
    return true;
  }
  MsgFramePublish & fpub = (MsgFramePublish &) pub;
  MsgHdrDecoder   & dec  = fpub.dec;
  if ( ( fpub.flags & MSG_FRAME_TPORT_CONTROL ) != 0 ) {
    d_tran( "rte(%s) tport_route == true transport_route: on_msg (%.*s)\n",
            fpub.rte.name, (int) pub.subject_len, pub.subject );
    return true;
  }
  fpub.flags |= MSG_FRAME_TPORT_CONTROL;
  if ( fpub.n == NULL ) {
    if ( (fpub.n = this->user_db.lookup_bridge( fpub, dec )) == NULL ) {
      d_tran( "ignore_msg status %d transport_route: on_msg (%.*s)\n",
              fpub.status, (int) pub.subject_len, pub.subject );
      return true;
    }
  }
  UserBridge & n   = *fpub.n;
  uint16_t     opt = dec.msg->caba.get_opt();
  d_tran( "transport_route src %s.%u\n", n.peer.user.val, n.uid );
  if ( ( fpub.flags & MSG_FRAME_ACK_CONTROL ) == 0 ) {
    fpub.flags |= MSG_FRAME_ACK_CONTROL;
    if ( ( opt & CABA_OPT_TRACE ) != 0 ) {
      if ( ! dec.test( FID_SUB ) && dec.decode_msg() != 0 )
        return true;
      this->mgr.send_ack( fpub, n, dec, _TRACE );
    }
  }
  UserBridge * ptp_bridge;
  CabaTypeFlag tflag = dec.msg->caba.get_type();
  bool         b     = true;
  if ( tflag == CABA_INBOX ) {
    if ( (ptp_bridge = this->user_db.is_inbox_sub( pub.subject,
                                                  pub.subject_len )) != NULL ) {
      TransportRoute &rte = ptp_bridge->primary( this->user_db )->rte;
      if ( &rte != this ) {
        d_tran( "transport_route: inbox (%.*s) -> %s\n",
                (int) pub.subject_len, pub.subject, rte.name );
        /*this->msgs_sent++;
        this->bytes_sent += pub.msg_len;*/
        b = this->user_db.forward_to_inbox( *ptp_bridge, pub.subject,
                                      pub.subject_len, pub.subj_hash,
                                      pub.msg, pub.msg_len );
      }
      return b;
    }
  }
  /* cache of the multicast tree for messages originating at n */
  uint8_t path_select = ( opt >> CABA_OPT_MC_SHIFT ) % COST_PATH_COUNT;
  if ( path_select > 0 && n.bloom_rt[ path_select ] == NULL )
    path_select = 0;

  ForwardCache   & forward = n.forward_path[ path_select ];
  TransportRoute * rte;
  uint32_t         tport_id;
  pub.shard = path_select;
  this->user_db.peer_dist.update_forward_cache( forward, n.uid, path_select );
  if ( forward.first( tport_id ) ) {
    do {
      rte = this->user_db.transport_tab.ptr[ tport_id ];
      b  &= rte->sub_route.forward_except( pub, this->mgr.router_set );
    } while ( forward.next( tport_id ) );
  }
  return b;
}

const char *
TransportRoute::connected_names( char *buf,  size_t buflen ) noexcept
{
  return this->user_db.uid_names( this->uid_connected, buf, buflen );
}

const char *
TransportRoute::reachable_names( char *buf,  size_t buflen ) noexcept
{
  this->user_db.peer_dist.calc_reachable( *this );
  return this->user_db.uid_names( this->user_db.peer_dist.reachable,
                                  this->user_db.peer_dist.max_uid,
                                  buf, buflen );
}

const char *
UserDB::uid_names( const BitSpace &uids,  char *buf,
                   size_t buflen ) noexcept
{
  UIntBitSet bits( uids.ptr );
  return this->uid_names( bits, uids.bit_size(), buf, buflen );
}

const char *
UserDB::uid_names( const UIntBitSet &uids,  uint32_t max_uid,
                   char *buf,  size_t buflen ) noexcept
{
  uint32_t uid;
  size_t   off = 0;
  buf[ 0 ] = '\0';
  for ( bool ok = uids.first( uid, max_uid ); ok;
        ok = uids.next( uid, max_uid ) ) {
    if ( this->bridge_tab.ptr[ uid ] == NULL )
      continue;
    const UserBridge &n = *this->bridge_tab.ptr[ uid ];
    off += ::snprintf( &buf[ off ], buflen - off, "%s.%u ",
                       n.peer.user.val, uid );
  }
  if ( off > 0 )
    buf[ off - 1 ] = '\0';
  return buf;
}

size_t
TransportRoute::port_status( char *buf,  size_t buflen ) noexcept
{
  buf[ 0 ] = '\0';
  if ( this->listener != NULL )
    return this->listener->print_sock_error( buf, buflen );
  if ( this->connect_mgr.conn != NULL )
    return this->connect_mgr.conn->print_sock_error( buf, buflen );
  if ( this->pgm_tport != NULL )
    return this->pgm_tport->print_sock_error( buf, buflen );
  return 0;
}

void
TransportRoute::on_connect( kv::EvSocket &conn ) noexcept
{
  printf( "%s connected %s %s using %s fd %u\n", this->transport.tport.val,
          conn.peer_address.buf, conn.type_string(),
          this->sub_route.service_name, conn.fd );
  uint32_t connect_type = 0;
  this->clear( TPORT_IS_SHUTDOWN );
  if ( ! this->is_mcast() ) {
    EvTcpTransport &tcp = (EvTcpTransport &) conn;
    if ( this->is_mesh() ) {
      if ( ! tcp.is_connect ) {
        this->mgr.add_mesh_accept( *this, tcp );
        return;
      }
      connect_type = TPORT_IS_CONNECT | TPORT_IS_MESH;
    }
    else {
      if ( ! tcp.is_connect ) {
        if ( ! this->is_edge() ) {
          this->mgr.add_tcp_accept( *this, tcp );
          return;
        }
        connect_type = TPORT_IS_TCP;
      }
      else {
        connect_type = TPORT_IS_CONNECT | TPORT_IS_TCP;
      }
    }
  }
  else {
    connect_type = TPORT_IS_MCAST;
  }
  this->mgr.events.on_connect( this->tport_id, connect_type );
  if ( ! this->connected.test_set( conn.fd ) )
    this->connect_count++;
}

void
TransportRoute::on_shutdown( EvSocket &conn,  const char *err,
                             size_t errlen ) noexcept
{
  const char *s = "disconnected";
  char errbuf[ 256 ];
  if ( &conn == (EvSocket *) this->listener )
    s = "listener stopped";
  else if ( errlen >= 15 && ::memcmp( err, "already connect", 15 ) == 0 )
    s = "stopped trying";
  if ( errlen == 0 ) {
    errlen = conn.print_sock_error( errbuf, sizeof( errbuf ) );
    if ( errlen > 0 )
      err = errbuf;
  }
  if ( errlen > 0 )
    printf( "%s %s (%.*s)\n", s, conn.peer_address.buf, (int) errlen, err );
  else
    printf( "%s %s (count=%u)\n", s, conn.peer_address.buf,
            this->connect_count );
  this->mgr.events.on_shutdown( this->tport_id, conn.fd >= 0 );
  if ( conn.fd >= 0 ) {
    this->user_db.retire_source( *this, conn.fd );
    if ( this->connected.test_clear( conn.fd ) ) {
      if ( --this->connect_count == 0 )
        if ( ! this->is_set( TPORT_IS_LISTEN ) )
          this->set( TPORT_IS_SHUTDOWN );
    }
    else if ( &conn == (EvSocket *) this->listener )
      this->set( TPORT_IS_SHUTDOWN );
  }
  else if ( this->connect_count == 0 ) {
    this->set( TPORT_IS_SHUTDOWN );
  }
  d_tran( "%s connect_count %u\n", this->name, this->connect_count );
}

void
TransportRoute::create_listener_mesh_url( void ) noexcept
{
  char   tmp[ MAX_TCP_HOST_LEN ];
  size_t len = make_mesh_url_from_sock( tmp, *this->listener );
  char * url = this->mesh_url_addr;
  if ( url == NULL )
    url = (char *) ::malloc( MAX_TCP_HOST_LEN );
  ::memcpy( url, tmp, len + 1 );
  this->mesh_url_addr  = url;
  this->mesh_url_len   = (uint32_t) len;
  this->mesh_conn_hash = kv_crc_c( url, len, 0 );
  d_tran( "%s: %s (%x)\n", this->name, url, this->mesh_conn_hash );
}

bool
TransportRoute::create_transport( ConfigTree::Transport &tport ) noexcept
{
  bool b = false;
  if ( tport.type.equals( "rv" ) ) {
    if ( this->is_svc() )
      return this->create_rv_listener( tport );
    return false;
  }
  if ( tport.type.equals( "nats" ) ) {
    if ( this->is_svc() )
      return this->create_nats_listener( tport );
    return false;
  }
  if ( tport.type.equals( "redis" ) ) {
    if ( this->is_svc() )
      return this->create_redis_listener( tport );
    return false;
  }
  if ( tport.type.equals( "tcp" ) ) {
    if ( this->is_svc() ) {
      this->listener = this->create_tcp_listener( tport );
      goto out_listen;
    }
    b = this->create_tcp_connect( tport );
    goto out_connect;
  }
  if ( tport.type.equals( "pgm" ) ) {
    this->set( TPORT_IS_MCAST );
    if ( this->is_svc() ) {
      if ( this->create_pgm( TPORT_IS_LISTEN, tport ) )
        return true;
      this->set( TPORT_IS_SHUTDOWN );
      return false;
    }
    b = this->create_pgm( TPORT_IS_CONNECT, tport );
    goto out_connect;
  }
  if ( tport.type.equals( "mesh" ) ) {
    EvTcpTransportListen *l;
    this->set( TPORT_IS_MESH );
    this->mesh_id = this;
    if ( this->is_svc() )
      l = this->create_mesh_listener( tport );
    else
      l = this->create_mesh_rendezvous( tport );
    if ( l == NULL ) {
      this->set( TPORT_IS_SHUTDOWN );
      return false;
    }
    this->listener = l;
    this->create_listener_mesh_url();

    if ( ! this->is_svc() )
      this->add_mesh_connect( NULL, 0 );
    return true;
  }
out_connect:;
  if ( ! b )
    this->set( TPORT_IS_SHUTDOWN );
  else
    this->set( TPORT_IS_CONNECT );
  return b;

out_listen:;
  if ( this->listener == NULL )
    this->set( TPORT_IS_SHUTDOWN );
  return this->listener != NULL;
}

uint32_t
TransportRoute::shutdown( ConfigTree::Transport &tport ) noexcept
{
  uint32_t count = 0;
  if ( tport.type.equals( "tcp" ) ||
       tport.type.equals( "mesh" ) ) {
    if ( this->listener != NULL ) {
      uint32_t fd, uid;
      if ( ! this->test_set( TPORT_IS_SHUTDOWN ) ) {
        count++;
        this->listener->idle_push( EV_CLOSE );
      }
      if ( ! this->is_set( TPORT_IS_MESH ) ) {
        if ( this->connect_count > 0 ) {
          for ( bool ok = this->connected.first( fd ); ok;
                ok = this->connected.next( fd ) ) {
            if ( fd < this->poll.maxfd ) {
              EvSocket *s = this->poll.sock[ fd ];
              if ( s != NULL ) {
                s->idle_push( EV_SHUTDOWN );
                count++;
              }
            }
          }
        }
      }
      else {
        uint32_t i,
                 tport_count = (uint32_t) this->user_db.transport_tab.count;
        for ( bool ok = this->uid_in_mesh->first( uid ); ok;
              ok = this->uid_in_mesh->next( uid ) ) {
          UserBridge &n = *this->user_db.bridge_tab.ptr[ uid ];
          for ( i = 0; i < tport_count; i++ ) {
            UserRoute * u_ptr = n.user_route_ptr( this->user_db, i );
            if ( u_ptr->is_valid() && u_ptr->rte.mesh_id == this->mesh_id ) {
              fd = u_ptr->mcast_fd;
              if ( fd < this->poll.maxfd ) {
                EvSocket *s = this->poll.sock[ fd ];
                if ( s != NULL ) {
                  s->idle_push( EV_SHUTDOWN );
                  count++;
                }
                else if ( ! u_ptr->rte.connect_mgr.is_shutdown )
                  count++;
              }
              if ( ! u_ptr->rte.connect_mgr.is_shutdown ) {
                u_ptr->rte.connect_mgr.is_shutdown = true;
                u_ptr->rte.set( TPORT_IS_SHUTDOWN );
              }
            }
          }
        }
      }
    }
    else if ( this->connect_mgr.conn != NULL ) {
      if ( this->connect_mgr.conn->fd >= 0 &&
           (uint32_t) this->connect_mgr.conn->fd < this->poll.maxfd ) {
        this->connect_mgr.conn->idle_push( EV_SHUTDOWN );
        count++;
      }
      else if ( ! this->connect_mgr.is_shutdown )
        count++;
      this->connect_mgr.is_shutdown = true;
      this->set( TPORT_IS_SHUTDOWN );
    }
  }
  else if ( tport.type.equals( "pgm" ) ) {
    if ( ! this->test_set( TPORT_IS_SHUTDOWN ) ) {
      if ( this->pgm_tport != NULL )
        this->pgm_tport->idle_push( EV_SHUTDOWN );
      if ( this->ibx_tport != NULL )
        this->ibx_tport->idle_push( EV_SHUTDOWN );
      count++;
    }
  }
  return count;
}

bool
TransportRoute::start_listener( EvTcpListen *l,
                                ConfigTree::Transport &tport ) noexcept
{
  EvTcpTransportParameters parm;
  parse_tcp_param( parm, "listen", tport, true, false );

  int status = l->listen( parm.host[ 0 ], parm.port[ 0 ], parm.opts );
  if ( status != 0 ) {
    printf( "%s.%u listen %s:%u failed\n", tport.tport.val, this->tport_id,
            ConfigTree::Transport::is_wildcard( parm.host[ 0 ] ) ? "*" :
            parm.host[ 0 ], parm.port[ 0 ] );
    this->mgr.events.on_shutdown( this->tport_id, false );
    this->clear( TPORT_IS_LISTEN );
    this->set( TPORT_IS_SHUTDOWN );
    return false;
  }
  this->mgr.events.on_connect( this->tport_id, TPORT_IS_LISTEN );
  this->set( TPORT_IS_LISTEN );
  if ( parm.edge )
    this->set( TPORT_IS_EDGE );
  else
    this->clear( TPORT_IS_EDGE );
  this->clear( TPORT_IS_SHUTDOWN );
  printf( "%s.%u listening on %s%s\n", tport.tport.val, this->tport_id,
          l->peer_address.buf,
          this->is_set( TPORT_IS_EDGE ) ? " edge is true" : "" );
  return true;
}

EvTcpTransportListen *
TransportRoute::create_tcp_listener( ConfigTree::Transport &tport ) noexcept
{
  EvTcpTransportListen * l =
    new ( aligned_malloc( sizeof( EvTcpTransportListen ) ) )
    EvTcpTransportListen( this->poll, *this );
  this->start_listener( l, tport );
  return l;
}

bool
TransportRoute::create_rv_listener( ConfigTree::Transport &tport ) noexcept
{
  EvRvTransportListen * l =
    new ( aligned_malloc( sizeof( EvRvTransportListen ) ) )
    EvRvTransportListen( this->poll, *this );
  bool pref;
  if ( tport.get_route_bool( "use_service_prefix", pref ) )
    l->has_service_prefix = pref;
  this->start_listener( l, tport );
  if ( l == NULL )
    return false;
  this->ext->list.push_tl(
    new ( ::malloc( sizeof( IpcRte ) ) ) IpcRte( tport, l ) );
  return true;
}

bool
TransportRoute::create_nats_listener( ConfigTree::Transport &tport ) noexcept
{
  EvNatsTransportListen * l =
    new ( aligned_malloc( sizeof( EvNatsTransportListen ) ) )
    EvNatsTransportListen( this->poll, *this );
  this->start_listener( l, tport );
  if ( l == NULL )
    return false;
  this->ext->list.push_tl(
    new ( ::malloc( sizeof( IpcRte ) ) ) IpcRte( tport, l ) );
  return true;
}

bool
TransportRoute::create_redis_listener( ConfigTree::Transport &tport ) noexcept
{
  EvRedisTransportListen * l =
    new ( aligned_malloc( sizeof( EvRedisTransportListen ) ) )
    EvRedisTransportListen( this->poll, *this );
  this->start_listener( l, tport );
  if ( l == NULL )
    return false;
  this->ext->list.push_tl(
    new ( ::malloc( sizeof( IpcRte ) ) ) IpcRte( tport, l ) );
  return true;
}

bool
TransportRoute::create_tcp_connect( ConfigTree::Transport &tport ) noexcept
{
  EvTcpTransportParameters parm;
  parse_tcp_param( parm, "connect", tport, false, true );

  if ( this->connect_mgr.conn == NULL ) {
    uint8_t type = this->mgr.tcp_connect_sock_type;
    EvTcpTransportClient *c =
      this->connect_mgr.alloc_conn<EvTcpTransportClient>( this->poll, type );
    c->rte = this;
    c->route_id = this->sub_route.route_id;
  }
  this->connect_mgr.connect_timeout_secs = parm.timeout;
  this->connect_mgr.set_parm( parm.copy() );
  return this->connect_mgr.do_connect();
}

bool
TransportRoute::create_rv_connect( ConfigTree::Transport & ) noexcept
{
  return /*this->create_tcp_connect();*/ false;
}

bool
TransportRoute::create_nats_connect( ConfigTree::Transport & ) noexcept
{
  return /*this->create_tcp_connect();*/ false;
}

bool
TransportRoute::create_redis_connect( ConfigTree::Transport & ) noexcept
{
  return /*this->create_tcp_connect();*/ false;
}

EvTcpTransportListen *
TransportRoute::create_mesh_listener( ConfigTree::Transport &tport ) noexcept
{
  return this->create_tcp_listener( tport );
}

EvTcpTransportListen *
TransportRoute::create_mesh_rendezvous( ConfigTree::Transport &tport ) noexcept
{
  return this->create_tcp_listener( tport );
}

bool
SessionMgr::create_telnet( ConfigTree::Transport &tport ) noexcept
{
  if ( this->telnet == NULL ) {
    void * p = aligned_malloc( sizeof( TelnetListen ) );
    this->telnet = new ( p ) TelnetListen( this->poll );
  }
  TelnetListen * l = this->telnet;
  EvTcpTransportParameters parm;
  parse_tcp_param( parm, "listen", tport, true, false );
  this->telnet_tport = &tport;

  if ( ! l->in_list( IN_ACTIVE_LIST ) ) {
    if ( l->listen2( parm.host[ 0 ], parm.port[ 0 ], parm.opts,
                     "telnet_listen", -1 ) != 0 ) {
      fprintf( stderr, "failed to start telnet at %s.%d\n",
               parm.host[ 0 ] ? parm.host[ 0 ] : "*", parm.port[ 0 ] );
      return false;
    }
    l->console = &this->console;
    printf( "%s listening on %s\n", tport.tport.val, l->peer_address.buf );
  }
  else {
    printf( "%s is already active on %s\n", tport.tport.val,
            l->peer_address.buf );
  }
  return true;
}

bool
SessionMgr::create_web( ConfigTree::Transport &tport ) noexcept
{
  if ( this->web == NULL ) {
    void * p = aligned_malloc( sizeof( WebListen ) );
    this->web = new ( p ) WebListen( this->poll );
    if ( tport.get_route_str( "http_dir", this->web->http_dir ) &&
         this->web->http_dir != NULL ) {
      this->web->http_dir_len = ::strlen( this->web->http_dir );
    }
  }
  WebListen * l = this->web;
  EvTcpTransportParameters parm;
  parse_tcp_param( parm, "listen", tport, true, false );
  this->web_tport = &tport;

  if ( ! l->in_list( IN_ACTIVE_LIST ) ) {
    if ( l->listen2( parm.host[ 0 ], parm.port[ 0 ], parm.opts, "web_listen",
                     -1 ) != 0 ) {
      fprintf( stderr, "failed to start web at %s.%d\n",
               parm.host[ 0 ] ? parm.host[ 0 ] : "*", parm.port[ 0 ] );
      return false;
    }
    l->console = &this->console;
    printf( "%s listening on %s\n", tport.tport.val, l->peer_address.buf );
  }
  else {
    printf( "%s is already active on %s\n", tport.tport.val,
            l->peer_address.buf );
  }
  return true;
}

uint32_t
SessionMgr::shutdown_telnet( void ) noexcept
{
  if ( this->telnet == NULL )
    return 0;
  TelnetListen * l = this->telnet;
  if ( l->in_list( IN_ACTIVE_LIST ) ) {
    l->idle_push( EV_SHUTDOWN );
    return 1;
  }
  return 0;
}

uint32_t
SessionMgr::shutdown_web( void ) noexcept
{
  if ( this->web == NULL )
    return 0;
  WebListen * l = this->web;
  if ( l->in_list( IN_ACTIVE_LIST ) ) {
    l->idle_push( EV_SHUTDOWN );
    return 1;
  }
  return 0;
}

static void
parse_pgm_param( EvPgmTransportParameters &parm,  const char *name,
                 ConfigTree::Transport &tport,  char net_buf[ 1024 ] ) noexcept
{
  size_t len = 1024;
  int    ival;
  tport.get_route_str( name, parm.network );
  if ( ! tport.get_route_int( "port", parm.port ) )
    parm.port = tport.get_host_port( parm.network, net_buf, len );
  if ( tport.is_wildcard( parm.network ) )
    parm.network = NULL;

  if ( tport.get_route_int( "mtu", ival ) )
    parm.mtu = ival;
  if ( tport.get_route_int( "txw_sqns", ival ) )
    parm.txw_sqns = ival;
  if ( tport.get_route_int( "rxw_sqns", ival ) )
    parm.rxw_sqns = ival;
  if ( tport.get_route_int( "mcast_loop", ival ) )
    parm.mcast_loop = ival;
}

bool
TransportRoute::create_pgm( int kind,  ConfigTree::Transport &tport ) noexcept
{
  EvPgmTransportParameters parm;
  char         net_buf[ 1024 ];
  const char * name = ( kind & TPORT_IS_LISTEN ) ? "listen" : "connect";
  parse_pgm_param( parm, name, tport, net_buf );

  EvPgmTransport * l;
  if ( this->pgm_tport != NULL )
    l = this->pgm_tport;
  else
    l = new ( aligned_malloc( sizeof( EvPgmTransport ) ) )
        EvPgmTransport( this->poll, *this );

  if ( ! l->connect( parm, this ) )
    return false;
  this->pgm_tport = l;
  this->state    |= kind;

  EvInboxTransport * s;
  if ( this->ibx_tport != NULL )
    s = this->ibx_tport;
  else
    s = new ( aligned_malloc( sizeof( EvInboxTransport ) ) )
        EvInboxTransport( this->poll, *this );
  this->ibx_tport = s;

  s->mtu = parm.mtu;
  uint16_t port;
  rand::fill_urandom_bytes( &port, 2 );
  port = ( port % 0xc000 ) + 0x4000U; /* port range 16384 -> 65535 */
  for ( uint32_t i = 0; ; port++ ) {
    if ( port < 0x4000 )
      port = 0x4000;
    if ( s->listen( l->pgm.gsr_addr, port ) ) /* could print error if used */
      break;
    if ( ++i == 0xc000U )
      return false;
  }
  size_t len = ::strlen( l->pgm.gsr_addr ) + sizeof( "inbox://" ) + 8;
  char * url = this->ucast_url_addr;
  if ( url == NULL )
    url = (char *) ::malloc( 256 );
  len = ::snprintf( url, len, "inbox://%s:%u", l->pgm.gsr_addr, port );
  this->ucast_url_addr = url;
  this->ucast_url_len  = (uint32_t) len;
  this->inbox_fd       = s->fd;
  this->mcast_fd       = l->fd;
  d_tran( "set mcast_fd=%u inbox_route=%u\n", l->fd, s->fd );
  return true;
}

void
ConnectionMgr::connect_failed( EvSocket &conn ) noexcept
{
  this->rte.on_shutdown( conn, NULL, 0 );
  if ( ! this->setup_reconnect() ) {
    printf( "reconnected failed (connect_failed)\n" );
  }
  else {
    printf( "reconnect timer running (connect_failed)\n" );
  }
}

void
ConnectionMgr::on_connect( EvSocket &conn ) noexcept
{
  this->connect_time = current_monotonic_time_s();
  this->rte.on_connect( conn );
}

void
ConnectionMgr::on_shutdown( EvSocket &conn,  const char *err,
                           size_t errlen ) noexcept
{
  this->rte.on_shutdown( conn, err, errlen );
  if ( ! this->setup_reconnect() ) {
    printf( "reconnect failed (on_shutdown)\n" );
  }
  else {
    printf( "reconnect timer running (on_shutdown)\n" );
  }
}

bool
ConnectionMgr::setup_reconnect( void ) noexcept
{
  if ( this->is_reconnecting || this->is_shutdown || this->rte.poll.quit )
    return true;

  this->is_reconnecting = true;
  if ( this->connect_count < MAX_TCP_HOSTS &&
       this->parameters->host[ this->connect_count ] != NULL ) {
    this->rte.poll.timer.add_timer_millis( *this, 100, 0, 0 );
    return true;
  }
  double now    = current_monotonic_time_s(),
         period = 60;
  if ( this->connect_timeout_secs > 0 )
    period = this->connect_timeout_secs + 15;
  /* if connected for 1 second, restart timers */
  if ( ( this->connect_time + 1 < now &&
         this->connect_time > this->reconnect_time ) ||
       this->reconnect_time + period < now ) {
    this->reconnect_timeout_secs = 1;
    this->reconnect_time = now;
    this->connect_time = 0;
  }
  else {
    this->reconnect_timeout_secs =
      min_int<uint16_t>( this->reconnect_timeout_secs + 2, 10 );
  }
  if ( this->connect_timeout_secs > 0 ) {
    if ( now - this->reconnect_time > (double) this->connect_timeout_secs ) {
      this->is_reconnecting = false;
      return false;
    }
  }
  printf( "reconnect in %u seconds\n", this->reconnect_timeout_secs );
  this->rte.poll.timer.add_timer_seconds( *this, this->reconnect_timeout_secs,
                                          0, 0 );
  return true;
}

bool
ConnectionMgr::do_connect( void ) noexcept
{
  EvTcpTransportClient     & client = *this->conn;
  EvTcpTransportParameters & parm   = *this->parameters;
  this->is_shutdown = false;
  size_t index;
  for ( index = 0; index < MAX_TCP_HOSTS; index++ ) {
    if ( parm.hash[ index ] != 0 ) {
      if ( this->rte.mgr.find_mesh_conn( this->rte, parm.hash[ index ] ) ) {
        const char s[] = "already connected to mesh";
        this->rte.on_shutdown( client, s, sizeof( s ) - 1 );
        this->is_shutdown = true;
        return false;
      }
    }
  }
  for (;;) {
    index = this->connect_count++ % MAX_TCP_HOSTS;
    if ( index == 0 || parm.host[ index ] != NULL )
      break;
  }
  d_tran( "do_connect index %u host %s:%d (%x)\n",
          (uint32_t) index, parm.host[ index ],
          parm.port[ index ], parm.hash[ index ] );
  /* non-blocking connect should always succeed unless socket error */
  if ( ! client.connect( parm, this, index ) ) {
    this->connect_failed( client );
    this->is_shutdown = true;
    return false;
  }
  return true;
}

bool
ConnectionMgr::timer_cb( uint64_t, uint64_t ) noexcept
{
  if ( this->is_reconnecting ) {
    this->is_reconnecting = false;
    if ( ! this->is_shutdown && ! this->rte.poll.quit )
      this->do_connect();
  }
  return false;
}

void TransportRoute::write( void ) noexcept {}
void TransportRoute::read( void ) noexcept {}
void TransportRoute::process( void ) noexcept {}
void TransportRoute::release( void ) noexcept {}

IpcRteList::IpcRteList( TransportRoute &r ) noexcept
          : RouteNotify( r.sub_route ), rte( r )
{
  r.sub_route.add_route_notify( *this );
}

void
IpcRteList::on_sub( NotifySub &sub ) noexcept
{
  if ( sub.src_type != 'M' ) {
    this->rte.mgr.sub_db.ipc_sub_start( sub, this->rte.tport_id );
    d_tran( "on_sub(%.*s) rcnt=%u src_type=%c\n", (int) sub.subject_len,
           sub.subject, sub.sub_count, sub.src_type );
  }
}

void
IpcRteList::on_unsub( NotifySub &sub ) noexcept
{
  if ( sub.src_type != 'M' ) {
    if ( sub.sub_count == 0 ) {
      this->rte.mgr.sub_db.ipc_sub_stop( sub, this->rte.tport_id );
    }
    d_tran( "on_unsub(%.*s) rcnt=%u src_type=%c\n", (int) sub.subject_len,
          sub.subject, sub.sub_count, sub.src_type );
  }
}

void
IpcRteList::on_psub( NotifyPattern &pat ) noexcept
{
  if ( pat.src_type != 'M' ) {
    this->rte.mgr.sub_db.ipc_psub_start( pat, this->rte.tport_id );
    d_tran( "on_psub(%.*s) rcnt=%u src_type=%c\n", (int) pat.pattern_len,
          pat.pattern, pat.sub_count, pat.src_type );
  }
}

void
IpcRteList::on_punsub( NotifyPattern &pat ) noexcept
{
  if ( pat.src_type != 'M' ) {
    if ( pat.sub_count == 0 )
      this->rte.mgr.sub_db.ipc_psub_stop( pat, this->rte.tport_id );
    d_tran( "on_punsub(%.*s) rcnt=%u src_type=%c\n", (int) pat.pattern_len,
          pat.pattern, pat.sub_count, pat.src_type );
  }
}

void
IpcRteList::on_reassert( uint32_t , kv::RouteVec<kv::RouteSub> &,
                         kv::RouteVec<kv::RouteSub> & ) noexcept
{
  d_tran( "on_reassert()\n" );
}
