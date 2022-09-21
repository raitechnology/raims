#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
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
#include <raims/ev_name_svc.h>

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
      uid_in_device( &this->mesh_connected ),
      mesh_csum( &this->mesh_csum2 ),
      hb_time( 0 ), hb_mono_time( 0 ), hb_seqno( 0 ),
      stats_seqno( 0 ), tport_id( id ), hb_count( 0 ),
      last_hb_count( 0 ), connect_count( 0 ), last_connect_count( 0 ),
      state( f ), mesh_id( 0 ), dev_id( 0 ), listener( 0 ),
      connect_mgr( *this ), pgm_tport( 0 ), ibx_tport( 0 ), inbox_fd( -1 ),
      mcast_fd( -1 ), mesh_conn_hash( 0 ), conn_hash( 0 ), oldest_uid( 0 ),
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
SessionMgr::add_startup_transports( void ) noexcept
{
  ConfigTree::Parameters * p;
  ConfigTree::StringPair * sp;
  ConfigTree::Transport  * tport;
  size_t len;
  for ( p = this->tree.parameters.hd; p != NULL; p = p->next ) {
    for ( sp = p->parms.hd; sp != NULL; sp = sp->next ) {
      if ( sp->name.equals( "listen" ) ) {
        for ( len = sp->value.len; len > 0 && sp->value.val[ len - 1 ] == ' ';
          len-- ) ;
        tport = this->tree.find_transport( sp->value.val, len );
        if ( tport == NULL ) {
          fprintf( stderr, "startup listen transport \"%.*s\" not found\n",
                   (int) sp->value.len, sp->value.val );
          return false;
        }
        if ( ! this->add_transport( *tport, true ) )
          return false;
      }
    }
  }
  for ( p = this->tree.parameters.hd; p != NULL; p = p->next ) {
    for ( sp = p->parms.hd; sp != NULL; sp = sp->next ) {
      if ( sp->name.equals( "connect" ) ) {
        for ( len = sp->value.len; len > 0 && sp->value.val[ len - 1 ] == ' ';
          len-- ) ;
        tport = this->tree.find_transport( sp->value.val, len );
        if ( tport == NULL ) {
          fprintf( stderr, "startup connect transport \"%.*s\" not found\n",
                   (int) sp->value.len, sp->value.val );
          return false;
        }
        if ( ! this->add_transport( *tport, false ) )
          return false;
      }
    }
  }
  return true;
}

bool
SessionMgr::add_rvd_transports( const char *listen,  const char *http,
                                int flags ) noexcept
{
  ConfigTree::Transport * rvd, * web;
  rvd = this->tree.find_transport( "rvd", 3 );
  if ( rvd == NULL ) {
    StringTab & stab = this->user_db.string_tab;
    ConfigTree::StringPair *p;

    rvd = stab.make<ConfigTree::Transport>();
    stab.ref_string( "rv", 2, rvd->type );
    stab.ref_string( "rvd", 3, rvd->tport );

    p = stab.make<ConfigTree::StringPair>();
    stab.ref_string( "listen", 6, p->name );
    if ( listen == NULL )
      listen = "7500";
    stab.ref_string( listen, ::strlen( listen ), p->value );
    rvd->route.push_tl( p );
    if ( ( flags & RV_NO_MCAST ) != 0 ) {
      p = stab.make<ConfigTree::StringPair>();
      stab.ref_string( "no_mcast", 8, p->name );
      stab.ref_string( "true", 4, p->value );
      rvd->route.push_tl( p );
    }
    if ( ( flags & RV_NO_PERMANENT ) != 0 ) {
      p = stab.make<ConfigTree::StringPair>();
      stab.ref_string( "no_permanent", 12, p->name );
      stab.ref_string( "true", 4, p->value );
      rvd->route.push_tl( p );
    }

    rvd->tport_id = this->tree.transport_cnt++;
    this->tree.transports.push_tl( rvd );
  }
  if ( ! this->add_transport( *rvd, true ) )
    return false;
  if ( ( flags & RV_NO_HTTP ) == 0 ) {
    web = this->tree.find_transport( "web", 3 );
    if ( web == NULL ) {
      StringTab & stab = this->user_db.string_tab;
      ConfigTree::StringPair *p;

      web = stab.make<ConfigTree::Transport>();
      stab.ref_string( "web", 3, web->type );
      web->tport = web->type;

      p = stab.make<ConfigTree::StringPair>();
      stab.ref_string( "listen", 6, p->name );

      char   tmp[ MAX_TCP_HOST_LEN ],
             buf[ MAX_TCP_HOST_LEN + 16 ];
      size_t len = sizeof( tmp );
      if ( http == NULL ) {
        const char * addr = NULL;
        if ( rvd->get_route_str( "listen", addr ) ) {
          int port = web->get_host_port( addr, tmp, len );
          if ( port != 0 ) {
            port += 80;
            if ( web->is_wildcard( tmp ) )
              ::snprintf( buf, sizeof( buf ), "*:%d", port );
            else if ( ::strchr( tmp, ':' ) != NULL )
              ::snprintf( buf, sizeof( buf ), "[%s]:%d", tmp, port );
            else
              ::snprintf( buf, sizeof( buf ), "%s:%d", tmp, port );
            http = buf;
          }
        }
        if ( http == NULL )
          http = "7580";
      }
      stab.ref_string( http, ::strlen( http ), p->value );
      web->route.push_tl( p );

      web->tport_id = this->tree.transport_cnt++;
      this->tree.transports.push_tl( web );

      if ( ! this->add_transport( *web, true ) )
        return false;
    }
  }
  return true;
}

bool
SessionMgr::add_ipc_transport( void ) noexcept
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
  rte = new ( p ) TransportRoute( this->poll, *this, this->svc, *tptr,
                                  "ipc", 0, id, f);
  if ( rte->init() != 0 )
    return false;

  this->user_db.transport_tab[ id ] = rte;
  rte->ext = new ( ::malloc( sizeof( IpcRteList ) ) ) IpcRteList( *rte );
  rte->sub_route.add_route_notify( *rte->ext );
  this->user_db.ipc_transport = rte;

  EvShm shm( "ms_server" );
  const char * ipc_name = NULL,
             * map_name = NULL,
             * db_num   = NULL;

  this->tree.find_parameter( "map_file", map_name, NULL );
  this->tree.find_parameter( "ipc_name", ipc_name, NULL );
  this->tree.find_parameter( "db_num", db_num, NULL );

  shm.ipc_name = ipc_name;
  if ( map_name != NULL ) {
    if ( shm.open( map_name, ( db_num ? atoi( db_num ) : 0 ) ) == 0 )
      printf( "shm opened: %s (db=%s)\n", map_name, db_num ? db_num : "0" );
    else {
      fprintf( stderr, "shm failed: %s (db=%s)\n",
               map_name, db_num ? db_num : "0" );
      return false;
    }
  }
  else {
    shm.open_rdonly();
  }
  rte->sub_route.init_shm( shm );
  this->user_db.add_transport( *rte );
  return true;
}

bool
SessionMgr::add_transport( ConfigTree::Transport &t,
                           bool is_listener ) noexcept
{
  TransportRoute * rte = NULL;
  return this->add_transport2( t, is_listener, rte );
}

bool
SessionMgr::add_transport2( ConfigTree::Transport &t,
                            bool is_listener,
                            TransportRoute *&rte ) noexcept
{
  uint32_t f = ( is_listener ? TPORT_IS_SVC : 0 );
  NameSvc * name_svc[ MAX_TCP_HOSTS ];
  uint32_t  name_svc_count = 0;

  if ( ! this->in_list( IN_ACTIVE_LIST ) ) {
    if ( this->init_sock() != 0 )
      return false;
  }
  if ( t.type.equals( "telnet" ) )
    return this->create_telnet( t );
  if ( t.type.equals( "web" ) )
    return this->create_web( t );
  if ( t.type.equals( "name" ) )
    return this->create_name( t );
  if ( t.type.equals( "mesh" ) || t.type.equals( "tcp" ) ||
       t.type.equals( "any" ) ) {
    const char * dev = NULL;
    if ( t.get_route_str( "device", dev ) ) {
      name_svc_count = this->start_name_services( t, name_svc );
      if ( name_svc_count > 0 )
        f |= TPORT_IS_DEVICE;
    }
  }

  ConfigTree::Transport * tptr = &t;
  char svc_name[ 256 ];
  if ( t.type.equals( "rv" ) || t.type.equals( "nats" ) ||
       t.type.equals( "redis" ) ) {
    StringTab & stab = this->user_db.string_tab;
    f |= TPORT_IS_IPC;
    size_t svc_len =
      ::snprintf( svc_name, sizeof( svc_name ), "%s.ipc", this->svc.svc.val );
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
    ::snprintf( svc_name, sizeof( svc_name ), "%s.%s", this->svc.svc.val,
                t.tport.val );
  }
  uint32_t id     = (uint32_t) this->user_db.transport_tab.count;
  bool     is_new = false;
  d_tran( "add transport %s tport_id %u\n", svc_name, id );

  rte = NULL;
  if ( ( f & TPORT_IS_IPC ) != 0 )
    rte = this->user_db.ipc_transport;

  if ( rte == NULL ) {
    void * p = aligned_malloc( sizeof( TransportRoute ) );
    rte = new ( p ) TransportRoute( this->poll, *this, this->svc, *tptr,
                                    svc_name, 0, id, f );
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
    uint32_t i;
    for ( i = 0; i < name_svc_count; i++ )
      name_svc[ i ]->adverts.push( rte );
    if ( this->session_started ) {
      for ( i = 0; i < name_svc_count; i++ )
        this->user_db.mcast_name( *name_svc[ i ] );
    }
    return true;
  }
  rte->set( TPORT_IS_SHUTDOWN );
  return false;
}

uint32_t
SessionMgr::shutdown_transport( ConfigTree::Transport &t ) noexcept
{
  if ( t.type.equals( "telnet" ) )
    return this->shutdown_telnet( t );
  if ( t.type.equals( "web" ) )
    return this->shutdown_web( t );

  uint32_t id,
           count = (uint32_t) this->user_db.transport_tab.count,
           match = 0;
  for ( id = 0; id < count; id++ ) {
    TransportRoute *rte = this->user_db.transport_tab.ptr[ id ];
    if ( &rte->transport == &t ) {
      match += rte->shutdown( t );
    }
  }
  return match;
}

bool
SessionMgr::start_transport( TransportRoute &rte,
                             bool is_listener ) noexcept
{
  if ( rte.transport.type.equals( "tcp" ) ) {
    if ( is_listener ) {
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
      if ( ! is_listener )
        rte.add_mesh_connect( NULL, 0 );
      return true;
    }
  }
  else if ( rte.transport.type.equals( "pgm" ) ) {
    rte.clear( TPORT_IS_LISTEN | TPORT_IS_CONNECT );
    if ( is_listener ) {
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

static void
make_url_from_sock( StringTab &string_tab,  StringVal &url,
                    EvSocket &sock ) noexcept
{
  char   buf[ MAX_TCP_HOST_LEN ];
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
  string_tab.ref_string( buf, len, url );
}

bool
SessionMgr::add_mesh_accept( TransportRoute &listen_rte,
                             EvTcpTransport &conn ) noexcept
{
  TransportRoute        * rte;
  ConfigTree::Service   & s = listen_rte.svc;
  ConfigTree::Transport & t = listen_rte.transport;

  //uint32_t id = this->user_db.transport_list.tport_count++;
  uint32_t id,
           count = (uint32_t) this->user_db.transport_tab.count;
  for ( id = 0; id < count; id++ ) {
    rte = this->user_db.transport_tab.ptr[ id ];
    if ( &t == &rte->transport &&
         rte->all_set( TPORT_IS_SHUTDOWN | TPORT_IS_MESH ) &&
         rte->mesh_id == conn.rte->mesh_id ) {
      if ( rte->connect_mgr.is_shutdown ) {
        rte->clear_all();
        break;
      }
    }
  }
  if ( id == count ) {
    void       * p    = aligned_malloc( sizeof( TransportRoute ) );
    const char * name = listen_rte.sub_route.service_name;
    rte = new ( p ) TransportRoute( this->poll, *this, s, t, name, id, id, 0 );
    if ( rte->init() != 0 )
      return false;
  }
  if ( rte->connect_mgr.conn != NULL )
    rte->connect_mgr.release_conn();

  rte->mesh_url    = listen_rte.mesh_url;
  rte->mesh_id     = listen_rte.mesh_id;
  rte->uid_in_mesh = listen_rte.uid_in_mesh;
  rte->mesh_csum   = listen_rte.mesh_csum;
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

  rte->printf( "add_mesh_accept %s from %s\n",
               rte->mesh_url.val, conn.peer_address.buf );
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
  this->mesh_url.zero();
  this->conn_url.zero();
  this->ucast_url.zero();
  this->mesh_id        = NULL;
  this->dev_id         = NULL;
  this->uid_in_mesh    = &this->mesh_connected;
  this->uid_in_device  = &this->mesh_connected;
  this->mesh_csum      = &this->mesh_csum2;
  this->mesh_conn_hash = 0;
  this->conn_hash      = 0;
}

TransportRoute *
SessionMgr::add_tcp_rte( TransportRoute &src_rte,  uint32_t conn_hash ) noexcept
{
  TransportRoute        * rte;
  ConfigTree::Service   & s = src_rte.svc;
  ConfigTree::Transport & t = src_rte.transport;
  bool is_new = false;

  //uint32_t id = this->user_db.transport_list.tport_count++;
  uint32_t id,
           count = (uint32_t) this->user_db.transport_tab.count;
  if ( conn_hash != 0 ) {
    for ( id = 0; id < count; id++ ) {
      rte = this->user_db.transport_tab.ptr[ id ];
      if ( rte->conn_hash == conn_hash && &t == &rte->transport )
        return rte;
    }
  }
  for ( id = 0; id < count; id++ ) {
    rte = this->user_db.transport_tab.ptr[ id ];
    if ( &t == &rte->transport &&
         rte->all_set( TPORT_IS_SHUTDOWN | TPORT_IS_TCP ) &&
         rte->dev_id == src_rte.dev_id ) {
      if ( rte->connect_mgr.is_shutdown ) {
        rte->clear_all();
        rte->clear_mesh();
        break;
      }
    }
  }
  if ( id == count ) {
    void       * p    = aligned_malloc( sizeof( TransportRoute ) );
    const char * name = src_rte.sub_route.service_name;
    rte = new ( p ) TransportRoute( this->poll, *this, s, t, name, id, id, 0 );
    if ( rte->init() != 0 )
      return NULL;
    is_new = true;
  }
  if ( rte->connect_mgr.conn != NULL )
    rte->connect_mgr.release_conn();
  rte->dev_id        = src_rte.dev_id;
  rte->uid_in_device = src_rte.uid_in_device;

  if ( is_new ) {
    this->user_db.transport_tab.push( rte );
    this->user_db.add_transport( *rte );
  }
  return rte;
}

bool
SessionMgr::add_tcp_accept( TransportRoute &listen_rte,
                            EvTcpTransport &conn ) noexcept
{
  TransportRoute * rte = this->add_tcp_rte( listen_rte, 0 );

  if ( rte == NULL )
    return false;
  for ( uint8_t i = 0; i < COST_PATH_COUNT; i++ )
    rte->uid_connected.cost[ i ] = listen_rte.uid_connected.cost[ i ];
  rte->set( TPORT_IS_TCP );

  conn.rte      = rte;
  conn.notify   = rte;
  conn.route_id = rte->sub_route.route_id;

  rte->printf( "add_tcp_accept\n" );
  this->events.on_connect( rte->tport_id, TPORT_IS_TCP );
  if ( ! rte->connected.test_set( conn.fd ) )
    rte->connect_count++;

  d_tran( "%s connect_count %u\n", rte->name, rte->connect_count );
  return true;
}

enum {
  P_REUSEPORT  = 1,
  P_NB_CONNECT = 2,
  P_LISTEN     = 4
};

static void
parse_tcp_route( const char *name,  ConfigTree::Transport &tport,
                 ConfigTree::StringPair * el[ MAX_TCP_HOSTS ] ) noexcept
{
  size_t i, nlen = ::strlen( name );

  el[ 0 ] = tport.route.get_pair( name, nlen );
  for ( i = 1; i < MAX_TCP_HOSTS; i++ ) {
    char nbuf[ 16 ]; /* try connect2, connect3, ... */
    ::snprintf( nbuf, sizeof( nbuf ), "%s%d", name, (int) i + 1 );
    el[ i ] = tport.route.get_pair( nbuf, nlen+1 );
  }
  /* parse config that uses array of cost */
  if ( el[ 0 ] != NULL ) {
    for ( i = 0; i < MAX_TCP_HOSTS - 1; i++ ) {
      if ( el[ i ]->next == NULL ) break;
      if ( ! el[ i ]->next->name.equals( name, nlen ) ) break;
      el[ i + 1 ] = el[ i ]->next;
    }
  }
}

static void
parse_tcp_param( EvTcpTransportParameters &parm,  ConfigTree::Transport &tport,
                 int ptype ) noexcept
{
  char         tmp[ MAX_TCP_HOSTS ][ MAX_TCP_HOST_LEN ];
  size_t       len[ MAX_TCP_HOSTS ];
  const char * host[ MAX_TCP_HOSTS ];
  int          port[ MAX_TCP_HOSTS ], port2 = 0;
  bool         ip4, ip6, is_device = false;

  ConfigTree::StringPair * el[ MAX_TCP_HOSTS ];
  if ( ( ptype & P_LISTEN ) == 0 )
    parse_tcp_route( "connect", tport, el );
  else {
    parse_tcp_route( "listen", tport, el );
    if ( el[ 0 ] == NULL ) {
      parse_tcp_route( "device", tport, el );
      is_device = true;
    }
  }
  tport.get_route_int( "port", port2 );
  for ( size_t i = 0; i < MAX_TCP_HOSTS; i++ ) {
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
  if ( ! tport.get_route_bool( "ipv4only", ip4 ) )
    if ( ! tport.get_route_bool( "ip4only", ip4 ) )
      ip4 = false;
  if ( ! tport.get_route_bool( "ipv6only", ip6 ) )
    if ( ! tport.get_route_bool( "ip6only", ip6 ) )
      ip6 = false;
  if ( is_device )
    parm.opts |= OPT_NO_DNS;
  if ( ip4 )
    parm.opts = ( parm.opts & ~OPT_AF_INET6 ) | OPT_AF_INET;
  else if ( ip4 )
    parm.opts = ( parm.opts & ~OPT_AF_INET ) | OPT_AF_INET6;
  if ( ( ptype & P_LISTEN ) != 0 )
    parm.opts |= kv::OPT_REUSEADDR;
  if ( ( ptype & P_REUSEPORT ) != 0 )
    parm.opts |= kv::OPT_REUSEPORT;
  else
    parm.opts &= ~kv::OPT_REUSEPORT;
  if ( ( ptype & P_NB_CONNECT ) != 0 )
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

  parse_tcp_param( parm, mesh_rte.transport, P_NB_CONNECT );

  for ( i = 0; i < MAX_TCP_HOSTS; i++ ) {
    char   * url    = url_buf[ i ];
    size_t & url_sz = url_buf_sz[ i ];
    char     pbuf[ 24 ];
    ::memcpy( url, "tcp://", 6 );
    if ( parm.host[ i ] == NULL ) {
      if ( i == 0 ) {
        if ( mesh_rte.is_set( TPORT_IS_DEVICE ) )
          return true;
      }
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

static const uint32_t MAX_DNS_HOST_ADDR = 128;
static bool
match_mesh_host_port( const char *host, int port, uint32_t conn_hash,
                      uint32_t *dns_cache,  uint32_t &addr_count ) noexcept
{
  if ( addr_count != 0 ) {
    for ( uint32_t i = 0; i < addr_count; i++ )
      if ( dns_cache[ i ] == conn_hash )
        return true;
    return false;
  }
  AddrInfo info;
  struct addrinfo * p = NULL;
  bool   matched = false;

  int status = info.get_address( host, port, DEFAULT_TCP_CONNECT_OPTS );
  if ( status != 0 )
    return false;
  for ( p = info.ai; p != NULL; p = p->ai_next ) {
    char url_buf[ MAX_TCP_HOST_LEN ], buf[ MAX_TCP_HOST_LEN ];
    int n = 0;
    if ( p->ai_family == AF_INET ) {
      struct sockaddr_in * p4 = (struct sockaddr_in *) p->ai_addr;
      inet_ntop( AF_INET, &p4->sin_addr, buf, sizeof( buf ) );
      n = ::snprintf( url_buf, sizeof( url_buf ), "tcp://%s:%d", buf, port );
    }
    else if ( p->ai_family == AF_INET6 ) {
      struct sockaddr_in6 * p6 = (struct sockaddr_in6 *) p->ai_addr;
      inet_ntop( AF_INET6, &p6->sin6_addr, buf, sizeof( buf ) );
      n = ::snprintf( url_buf, sizeof( url_buf ), "tcp://[%s]:%d", buf, port );
    }
    if ( n > 0 ) {
      uint32_t h = kv_crc_c( url_buf, n, 0 );
      if ( h == conn_hash )
        matched = true;
      if ( addr_count < MAX_DNS_HOST_ADDR )
        dns_cache[ addr_count++ ] = h;
      d_tran( "match( %s ) %x %s %x\n", url_buf, h,
              h == conn_hash ? "=" : "!=", conn_hash );
    }
  }
  return matched;
}

static bool
match_mesh_hash( const char *url,  uint32_t url_hash,
                 uint32_t conn_hash,  uint32_t *dns_cache,
                 uint32_t &addr_count ) noexcept
{
  if ( url_hash == conn_hash )
    return true;
  if ( url == NULL )
    return false;
  d_tran( "match( %s ) %x != %x\n", url, url_hash, conn_hash );
  if ( addr_count != 0 ) {
    for ( uint32_t i = 0; i < addr_count; i++ )
      if ( dns_cache[ i ] == conn_hash )
        return true;
    return false;
  }
  char tcp_buf[ MAX_TCP_HOST_LEN ];
  size_t len = sizeof( tcp_buf );
  int port;
  port = ConfigTree::Transport::get_host_port( url, tcp_buf, len );
  return match_mesh_host_port( tcp_buf, port, conn_hash, dns_cache, addr_count );
}
#if 0
TransportRoute *
SessionMgr::find_mesh_conn( TransportRoute &mesh_rte,  
                            const char *url,  uint32_t url_hash ) noexcept
{
  uint32_t count = (uint32_t) this->user_db.transport_tab.count;
  uint32_t dns_cache[ MAX_DNS_HOST_ADDR ];
  dns_cache[ 0 ] = 0;
  for ( uint32_t tport_id = 0; tport_id < count; tport_id++ ) {
    TransportRoute *rte = this->user_db.transport_tab.ptr[ tport_id ];
    if ( rte != &mesh_rte && rte->mesh_id == mesh_rte.mesh_id &&
         ! rte->is_set( TPORT_IS_SHUTDOWN ) ) {
      if ( match_mesh_hash( url, url_hash, rte->mesh_conn_hash,
                            dns_cache ) )
        return rte;
    }
  }
  return NULL;
}
#endif
bool
SessionMgr::find_mesh( TransportRoute &mesh_rte,  const char *host,
                       int port,  uint32_t mesh_hash ) noexcept
{
  uint32_t count = (uint32_t) this->user_db.transport_tab.count;
  uint32_t dns_cache[ MAX_DNS_HOST_ADDR ], addr_count = 0;
  for ( uint32_t tport_id = 0; tport_id < count; tport_id++ ) {
    TransportRoute *rte = this->user_db.transport_tab.ptr[ tport_id ];
    if ( rte != &mesh_rte && rte->mesh_id == mesh_rte.mesh_id &&
      ! rte->is_set( TPORT_IS_SHUTDOWN ) && ! rte->is_set( TPORT_IS_LISTEN ) ) {
      if ( rte->mesh_conn_hash == mesh_hash )
        return true;
      if ( match_mesh_host_port( host, port, rte->mesh_conn_hash,
                                 dns_cache, addr_count ) )
        return true;
    }
  }
  return false;
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

  count = (uint32_t) this->user_db.transport_tab.count;
  for ( i = 0; i < url_count; i++ ) {
    uint32_t dns_cache[ MAX_DNS_HOST_ADDR ], addr_count = 0;
    if ( mesh_rte.is_set( TPORT_IS_LISTEN ) &&
         match_mesh_hash( mesh_url[ i ], mesh_hash[ i ],
                          mesh_rte.mesh_conn_hash, dns_cache, addr_count ) ) {
      mesh_rte.printf( "not connecting to self (%s)\n", mesh_url[ i ] );
      mesh_url[ i ]  = NULL;
      mesh_hash[ i ] = 0;
      continue;
    }
    for ( tport_id = 0; tport_id < count; tport_id++ ) {
      rte = this->user_db.transport_tab.ptr[ tport_id ];
      if ( rte != &mesh_rte && rte->mesh_id == mesh_rte.mesh_id &&
           ! rte->is_set( TPORT_IS_SHUTDOWN ) ) {
        if ( match_mesh_hash( mesh_url[ i ], mesh_hash[ i ],
                              rte->mesh_conn_hash, dns_cache, addr_count ) ) {
          mesh_rte.printf( "already connected (%s)\n", mesh_url[ i ] );
          return true;
        }
      }
    }
    if ( first_hash == 0 )
      first_hash = mesh_hash[ i ];
  }
  if ( first_hash == 0 ) {
    mesh_rte.printf( "no mesh urls to connect\n" );
    return true;
  }
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

  rte->mesh_url       = mesh_rte.mesh_url;
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
      d_tran( "mesh_url[ %u ] = %s:%u\n", i, tcp_buf, port );
      j++;
    }
  }
  if ( ! mesh_rte.transport.get_route_int( "timeout", parm.timeout ) )
    parm.timeout = 15;

  EvTcpTransportClient *c = rte->connect_mgr.conn;
  if ( c == NULL ) {
    uint8_t type = this->tcp_connect_sock_type;
    c = rte->connect_mgr.alloc_conn<EvTcpTransportClient>( this->poll, type );
    rte->connect_mgr.conn = c;
  }
  c->rte = rte;
  c->route_id = rte->sub_route.route_id;
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
  this->printf( "connected %s %s using %s fd %u\n",
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
    this->printf( "%s %s (%.*s)\n", s, conn.peer_address.buf,
                  (int) errlen, err );
  else
    this->printf( "%s %s (count=%u)\n", s, conn.peer_address.buf,
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
  make_url_from_sock( this->user_db.string_tab, this->mesh_url,
                      *this->listener );
  this->mesh_conn_hash = kv_crc_c( this->mesh_url.val, this->mesh_url.len, 0 );
  d_tran( "%s: %s (%x)\n", this->name, this->mesh_url.val,
          this->mesh_conn_hash );
}

void
TransportRoute::create_listener_conn_url( void ) noexcept
{
  make_url_from_sock( this->user_db.string_tab, this->conn_url,
                      *this->listener );
  this->conn_hash = kv_crc_c( this->conn_url.val, this->conn_url.len, 0 );
  d_tran( "%s: %s (%x)\n", this->name, this->conn_url.val,
          this->conn_hash );
}

void
TransportRoute::change_any( const char *type,  NameSvc & ) noexcept
{
  StringTab & stab = this->user_db.string_tab;
  stab.ref_string( type, ::strlen( type ), this->transport.type );
  this->create_transport( this->transport );
}

bool
TransportRoute::create_transport( ConfigTree::Transport &tport ) noexcept
{
  bool b = false;
  if ( tport.type.equals( "any" ) ) {
    return true;
  }
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
    if ( this->is_set( TPORT_IS_DEVICE ) )
      this->dev_id = this;
    else
      this->dev_id = NULL;
    if ( this->is_svc() ) {
      this->listener = this->create_tcp_listener( tport );
      this->create_listener_conn_url();
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
    l = this->create_mesh_listener( tport );
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
  parse_tcp_param( parm, tport, /*P_REUSEPORT |*/ P_LISTEN );

  int status = l->listen( parm.host[ 0 ], parm.port[ 0 ], parm.opts );
  if ( status != 0 ) {
    fprintf( stderr, "%s.%u listen %s:%u failed\n", tport.tport.val,
             this->tport_id,
             ConfigTree::Transport::is_wildcard( parm.host[ 0 ] ) ? "*" :
             parm.host[ 0 ], parm.port[ 0 ] );
    this->mgr.events.on_shutdown( this->tport_id, false );
    this->set( TPORT_IS_LISTEN | TPORT_IS_SHUTDOWN );
    return false;
  }
  this->mgr.events.on_connect( this->tport_id, TPORT_IS_LISTEN );
  this->set( TPORT_IS_LISTEN );
  if ( parm.edge )
    this->set( TPORT_IS_EDGE );
  else
    this->clear( TPORT_IS_EDGE );
  this->clear( TPORT_IS_SHUTDOWN );
  this->printf( "%s listening on %s%s\n", tport.tport.val,
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
  bool b;
  if ( tport.get_route_bool( "use_service_prefix", b ) )
    l->has_service_prefix = b;
  if ( tport.get_route_bool( "no_permanent", b ) )
    l->no_permanent = b;
  if ( tport.get_route_bool( "no_mcast", b ) )
    l->no_mcast = b;
  this->start_listener( l, tport );
  if ( l == NULL )
    return false;
  this->ext->list.push_tl(
    new ( ::malloc( sizeof( IpcRte ) ) ) IpcRte( tport, l ) );
  return true;
}

void
TransportRoute::get_tport_service( ConfigTree::Transport &tport,
                                   const char *&service,
                                   size_t &service_len ) noexcept
{
  const char * tmp;
  if ( tport.get_route_str( "service", tmp ) ) {
    size_t tmplen = ::strlen( tmp );
    if ( tmp[ 0 ] != '_' || tmp[ tmplen - 1 ] != '.' ) {
      char * buf = (char *) ::malloc( tmplen + 3 );
      buf[ 0 ] = '_';
      if ( tmp[ 0 ] == '_' ) {
        tmp++;
        tmplen--;
      }
      ::memcpy( &buf[ 1 ], tmp, tmplen );
      if ( tmp[ tmplen - 1 ] != '.' )
        buf[ 1 + tmplen++ ] = '.';
      buf[ 1 + tmplen ] = '\0';
      tmp = buf;
    }
    service     = tmp;
    service_len = ::strlen( tmp );
  }
#if 0
  else {
    service     = NULL;
    service_len = 0;
  }
#endif
  if ( service_len > 0 )
    this->printf( "%s.%s service: %.*s\n", tport.type.val, tport.tport.val,
                  (int) service_len - 2, &service[ 1 ] );
}

bool
TransportRoute::create_nats_listener( ConfigTree::Transport &tport ) noexcept
{
  EvNatsTransportListen * l =
    new ( aligned_malloc( sizeof( EvNatsTransportListen ) ) )
    EvNatsTransportListen( this->poll, *this );
  this->get_tport_service( tport, l->service, l->service_len );
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
  this->get_tport_service( tport, l->service, l->service_len );
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
  const char * tmp, * tmp2;
  parse_tcp_param( parm, tport, P_NB_CONNECT );

  EvTcpTransportClient *c = this->connect_mgr.conn;
  if ( c == NULL ) {
    uint8_t type = this->mgr.tcp_connect_sock_type;
    c = this->connect_mgr.alloc_conn<EvTcpTransportClient>( this->poll, type );
    this->connect_mgr.conn = c;
  }
  c->rte = this;
  c->route_id = this->sub_route.route_id;
  this->connect_mgr.connect_timeout_secs = parm.timeout;
  if ( ! tport.get_route_str( "device", tmp ) ||
       tport.get_route_str( "connect", tmp2 ) ) {
    this->connect_mgr.set_parm( parm.copy() );
    return this->connect_mgr.do_connect();
  }
  return true;
}

bool
TransportRoute::add_tcp_connect( const char *conn_url,
                                 uint32_t conn_hash ) noexcept
{
  d_tran( "add_tcp_connect( %s )\n", conn_url );
  TransportRoute * rte = this;
  if ( ! rte->connect_mgr.is_shutdown ) {
    if ( rte->conn_hash == conn_hash ) {
      if ( ! rte->connect_mgr.is_reconnecting )
        return rte->connect_mgr.do_connect();
      return true;
    }
    rte = NULL;
  }
  if ( rte == NULL ) {
    rte = this->mgr.add_tcp_rte( *this, conn_hash );

    if ( rte == NULL )
      return false;
    EvTcpTransportClient *c = rte->connect_mgr.conn;
    if ( c == NULL ) {
      uint8_t type = this->mgr.tcp_connect_sock_type;
      c = rte->connect_mgr.alloc_conn<EvTcpTransportClient>( this->poll, type );
      rte->connect_mgr.conn = c;
    }
    c->rte = rte;
    c->route_id = rte->sub_route.route_id;
  }
  EvTcpTransportParameters parm;
  char tcp_buf[ MAX_TCP_HOST_LEN ];
  size_t len = sizeof( tcp_buf );
  int port;
  port = ConfigTree::Transport::get_host_port( conn_url, tcp_buf, len );
  parm.set_host_port( tcp_buf, port, 0, 0 );
  d_tran( "tcp_url = %s:%u\n", tcp_buf, port );
  rte->connect_mgr.connect_timeout_secs = 1;
  rte->connect_mgr.set_parm( parm.copy() );
  rte->conn_hash = conn_hash;
  return rte->connect_mgr.do_connect();
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

static bool
do_listen_start( ConfigTree::Transport &tport,  EvTcpListen *l,
                 const char *k ) noexcept
{
  EvTcpTransportParameters parm;
  parse_tcp_param( parm, tport, /*P_REUSEPORT |*/ P_LISTEN );

  if ( ! l->in_list( IN_ACTIVE_LIST ) ) {
    if ( l->listen2( parm.host[ 0 ], parm.port[ 0 ], parm.opts, k, -1 ) != 0 ) {
      fprintf( stderr, "%s: failed to start %s at %s.%d\n", tport.type.val,
       tport.tport.val, parm.host[ 0 ] ? parm.host[ 0 ] : "*", parm.port[ 0 ] );
      return false;
    }
    printf( "%s: %s start listening on %s\n", tport.type.val, tport.tport.val,
             l->peer_address.buf );
  }
  else {
    printf( "%s: %s is already active on %s\n", tport.type.val, tport.tport.val,
            l->peer_address.buf );
  }
  return true;
}

bool
SessionMgr::create_telnet( ConfigTree::Transport &tport ) noexcept
{
  Unrouteable & un = this->unrouteable.upsert( &tport );
  if ( un.telnet == NULL ) {
    void * p = aligned_malloc( sizeof( TelnetListen ) );
    un.telnet = new ( p ) TelnetListen( this->poll, this->console );
  }
  if ( do_listen_start( tport, un.telnet, "telnet_listen" ) ) {
    char buf[ 256 ];
    int len = ::snprintf( buf, sizeof( buf ), "%s.%s", tport.type.val,
                          tport.tport.val );
    un.telnet->set_name( buf, len );
    return true;
  }
  return false;
}

bool
SessionMgr::create_web( ConfigTree::Transport &tport ) noexcept
{
  Unrouteable & un = this->unrouteable.upsert( &tport );
  if ( un.web == NULL ) {
    void * p = aligned_malloc( sizeof( WebListen ) );
    un.web = new ( p ) WebListen( this->poll, this->console );
    if ( tport.get_route_str( "http_dir", un.web->http_dir ) &&
         un.web->http_dir != NULL ) {
      un.web->http_dir_len = ::strlen( un.web->http_dir );
    }
  }
  if ( do_listen_start( tport, un.web, "web_listen" ) ) {
    char buf[ 256 ];
    int len = ::snprintf( buf, sizeof( buf ), "%s.%s", tport.type.val,
                          tport.tport.val );
    un.web->set_name( buf, len );
    return true;
  }
  return false;
}

bool
SessionMgr::create_name( ConfigTree::Transport &tport ) noexcept
{
  Unrouteable & un = this->unrouteable.upsert( &tport );
  if ( un.name == NULL ) {
    void * p = aligned_malloc( sizeof( NameSvc ) );
    un.name = new ( p ) NameSvc( this->poll, *this, this->user_db, tport );
  }
  if ( ! un.name->is_connected ) {
    if ( ! un.name->connect() )
      return false;
  }
  return true;
}

uint32_t
SessionMgr::start_name_services( ConfigTree::Transport &tport,
                                 NameSvc **name_svc ) noexcept
{
  ConfigTree::StringPair * el[ MAX_TCP_HOSTS ];
  uint32_t count   = 0;

  parse_tcp_route( "device", tport, el );
  for ( uint32_t i = 0; i < MAX_TCP_HOSTS; i++ ) {
    if ( el[ i ] == NULL )
      continue;

    const char * dev     = el[ i ]->value.val;
    uint32_t     dev_len = el[ i ]->value.len;

    ConfigTree::Transport *tptr = this->tree.find_transport( dev, dev_len );
    /* tport: lo
       type: name
       route:
         connect: lo;239.23.22.217
         port: 8327 */
    if ( tptr == NULL ) {
      StringTab & stab = this->user_db.string_tab;
      char mcast[ 256 ], port[ 8 ];
      ConfigTree::StringPair *p;

      tptr = stab.make<ConfigTree::Transport>();
      stab.ref_string( "name", 4, tptr->type );
      stab.ref_string( dev, dev_len, tptr->tport );

      p = stab.make<ConfigTree::StringPair>();
      stab.ref_string( "connect", 7, p->name );
      ::snprintf( mcast, sizeof( mcast ), "%.*s%s", dev_len, dev,
                  NameSvc::default_name_mcast() );
      stab.ref_string( mcast, ::strlen( mcast ), p->value );
      tptr->route.push_tl( p );

      p = stab.make<ConfigTree::StringPair>();
      stab.ref_string( "port", 4, p->name );
      ::snprintf( port, sizeof( port ), "%d", NameSvc::default_name_port() );
      stab.ref_string( port, ::strlen( port ), p->value );
      tptr->route.push_tl( p );

      tptr->tport_id = this->tree.transport_cnt++;
      this->tree.transports.push_tl( tptr );
    }
    Unrouteable *un = this->unrouteable.find( tptr );
    if ( un == NULL ) {
      this->create_name( *tptr );
      un = this->unrouteable.find( tptr );
    }
    if ( un != NULL && un->name != NULL )
      name_svc[ count++ ] = un->name;
  }
  return count;
}

uint32_t
SessionMgr::shutdown_telnet( ConfigTree::Transport &tport ) noexcept
{
  Unrouteable * un = this->unrouteable.find( &tport );
  if ( un != NULL && un->telnet != NULL &&
       un->telnet->in_list( IN_ACTIVE_LIST ) ) {
    un->telnet->idle_push( EV_SHUTDOWN );
    return 1;
  }
  return 0;
}

uint32_t
SessionMgr::shutdown_web( ConfigTree::Transport &tport ) noexcept
{
  Unrouteable * un = this->unrouteable.find( &tport );
  if ( un != NULL && un->web != NULL && un->web->in_list( IN_ACTIVE_LIST ) ) {
    un->web->idle_push( EV_SHUTDOWN );
    return 1;
  }
  return 0;
}

uint32_t
SessionMgr::shutdown_name( ConfigTree::Transport &tport ) noexcept
{
  Unrouteable * un = this->unrouteable.find( &tport );
  if ( un != NULL && un->name != NULL && un->name->is_connected ) {
    un->name->close();
    return 1;
  }
  return 0;
}

static void
parse_pgm_param( EvPgmTransportParameters &parm,  const char *name,
                 ConfigTree::Transport &tport,  char net_buf[ 1024 ],
                 UserDB &user_db ) noexcept
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
  if ( tport.get_route_int( "txw_secs", ival ) )
    parm.txw_secs = ival;
  else
    parm.txw_secs = user_db.reliability;
}

bool
TransportRoute::create_pgm( int kind,  ConfigTree::Transport &tport ) noexcept
{
  EvPgmTransportParameters parm;
  char         net_buf[ 1024 ];
  const char * name = ( kind & TPORT_IS_LISTEN ) ? "listen" : "connect";
  parse_pgm_param( parm, name, tport, net_buf, this->user_db );

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
  char tmp[ 256 ];
  int  len = ::snprintf( tmp, sizeof( tmp ), "inbox://%s:%u",
                         l->pgm.gsr_addr, port );
  this->user_db.string_tab.ref_string( tmp, len, this->ucast_url );
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
      this->is_shutdown = true;
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
      if ( this->rte.mgr.find_mesh( this->rte, parm.host[ index ],
                                    parm.port[ index ], parm.hash[ index ] ) ) {
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
