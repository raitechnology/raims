#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdarg.h>
#if ! defined( _MSC_VER ) && ! defined( __MINGW32__ )
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#else
#include <raikv/win.h>
#endif
#include <raims/transport.h>
#include <raims/session.h>
#include <raims/ev_tcp_transport.h>
#include <raims/ev_rv_transport.h>
#include <raims/ev_telnet.h>
#include <raims/ev_name_svc.h>
#include <raims/ev_web.h>

using namespace rai;
using namespace ms;
using namespace kv;
using namespace md;

bool
SessionMgr::add_startup_transports( void ) noexcept
{
  if ( ! this->add_startup_transports( R_LISTEN, R_LISTEN_SZ, true ) )
    return false;
  if ( ! this->add_startup_transports( R_CONNECT, R_CONNECT_SZ, false ) )
    return false;
  return true;
}

bool
SessionMgr::add_startup_transports( const char *name,  size_t name_sz,
                                    bool is_listen ) noexcept
{
  ConfigTree::Parameters * p;
  ConfigTree::StringPair * sp;
  ConfigTree::Transport  * tport;
  TransportRoute * rte;
  size_t len;
  for ( p = this->tree.startup.hd; p != NULL; p = p->next ) {
    for ( sp = p->list.hd; sp != NULL; sp = sp->next ) {
      if ( sp->name.equals( name, name_sz ) ) {
        for ( len = sp->value.len; len > 0 && sp->value.val[ len - 1 ] == ' ';
          len-- ) ;
        tport = this->tree.find_transport( sp->value.val, len );
        rte   = this->user_db.transport_tab.find_transport( tport );
        if ( rte != NULL ) {
          if ( ! rte->is_shutdown() ) {
            fprintf( stderr,
                     "Startup %.*s transport \"%.*s\" already running\n",
                     (int) name_sz, name,
                     (int) len, sp->value.val );
            return true;
          }
        }
        if ( tport == NULL ) {
          fprintf( stderr, "Startup %.*s transport \"%.*s\" not found\n",
                   (int) name_sz, name,
                   (int) len, sp->value.val );
          return false;
        }
        if ( ! this->add_transport( *tport, is_listen ) )
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
    stab.ref_string( T_RV, T_RV_SZ, rvd->type );
    stab.ref_string( "rvd", 3, rvd->tport );

    p = stab.make<ConfigTree::StringPair>();
    stab.ref_string( R_LISTEN, R_LISTEN_SZ, p->name );
    if ( listen == NULL )
      listen = "7500";
    stab.ref_string( listen, ::strlen( listen ), p->value );
    rvd->route.push_tl( p );
    if ( ( flags & RV_NO_MCAST ) != 0 ) {
      p = stab.make<ConfigTree::StringPair>();
      stab.ref_string( R_NO_MCAST, R_NO_MCAST_SZ, p->name );
      stab.ref_string( "true", 4, p->value );
      rvd->route.push_tl( p );
    }
    if ( ( flags & RV_NO_PERMANENT ) != 0 ) {
      p = stab.make<ConfigTree::StringPair>();
      stab.ref_string( R_NO_PERMANENT, R_NO_PERMANENT_SZ, p->name );
      stab.ref_string( "true", 4, p->value );
      rvd->route.push_tl( p );
    }

    rvd->tport_id = this->tree.transport_cnt++;
    rvd->is_temp = true;
    this->tree.transports.push_tl( rvd );
  }
  if ( ! this->add_transport( *rvd, true ) ) {
    ConfigTree::Transport * rv;
    if ( (rv = this->tree.find_transport_type( "rv", 2, false )) != NULL ) {
      IpcRte *el;
      if ( this->user_db.ipc_transport != NULL ) {
        el = this->user_db.ipc_transport->ext->find( *rv );
        if ( el != NULL && el->listener->in_list( IN_ACTIVE_LIST ) ) {
          fprintf( stderr, "rv listener already running\n" );
          return true;
        }
      }
    }
    return false;
  }
  if ( ( flags & RV_NO_HTTP ) == 0 ) {
    web = this->tree.find_transport( T_WEB, T_WEB_SZ );
    if ( web == NULL ) {
      StringTab & stab = this->user_db.string_tab;
      ConfigTree::StringPair *p;

      web = stab.make<ConfigTree::Transport>();
      stab.ref_string( T_WEB, T_WEB_SZ, web->type );
      web->tport = web->type;

      p = stab.make<ConfigTree::StringPair>();
      stab.ref_string( R_LISTEN, R_LISTEN_SZ, p->name );

      char   tmp[ MAX_TCP_HOST_LEN ],
             buf[ MAX_TCP_HOST_LEN + 16 ];
      size_t len = sizeof( tmp );
      if ( http == NULL ) {
        const char * addr = NULL;
        if ( rvd->get_route_str( R_LISTEN, addr ) ) {
          int port = web->get_host_port( addr, tmp, len, this->tree.hosts );
          if ( port != 0 ) {
            port += 80;
            CatPtr p( buf );
            if ( web->is_wildcard( addr ) )
              p.s( "*:" );
            else if ( ::strchr( tmp, ':' ) != NULL )
              p.s( "[" ).s( addr ).s( "]:" );
            else
              p.s( addr ).s( ":" );
            p.i( port ).end();
            http = buf;
          }
        }
        if ( http == NULL )
          http = "7580";
      }
      stab.ref_string( http, ::strlen( http ), p->value );
      web->route.push_tl( p );

      web->tport_id = this->tree.transport_cnt++;
      web->is_temp = true;
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
  uint32_t f = TPORT_IS_IPC;
  StringTab & stab = this->user_db.string_tab;

  tptr = this->tree.find_transport( T_IPC, T_IPC_SZ );
  if ( tptr == NULL ) {
    tptr = stab.make<ConfigTree::Transport>();
    stab.ref_string( T_IPC, T_IPC_SZ, tptr->type );
    tptr->tport = tptr->type;
    tptr->tport_id = this->tree.transport_cnt++;
    tptr->is_temp = true;
    this->tree.transports.push_tl( tptr );
  }
  void * p = aligned_malloc( sizeof( TransportRoute ) );
  rte = new ( p )
    TransportRoute( this->poll, *this, this->svc, *tptr, "ipc", f );
  if ( rte->init() != 0 )
    return false;

  rte->ext = new ( ::malloc( sizeof( IpcRteList ) ) ) IpcRteList( *rte );
  rte->sub_route.add_route_notify( *rte->ext );
  this->user_db.ipc_transport = rte;

  EvShm shm( "ms_server" );
  const char * ipc_name = NULL,
             * map_name = NULL,
             * db_num   = NULL;

  this->tree.parameters.find( P_MAP_FILE, map_name, NULL );
  this->tree.parameters.find( P_IPC_NAME, ipc_name, NULL );
  this->tree.parameters.find( P_DB_NUM, db_num, NULL );

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
SessionMgr::add_network( const char *net,  size_t net_len,
                         const char *svc,  size_t svc_len,
                         bool start_host ) noexcept
{
  ConfigTree::Transport * t;
  ConfigTree & tree = this->tree;
  StringTab  & stab = this->user_db.string_tab;
  RvMcast2     mc;
  CatMalloc    p( 32 + svc_len );
  uint16_t     num;
  bool is_listener = true;

  if ( mc.parse_network2( net, net_len ) != sassrv::HOST_OK )
    return false;
  /*if ( mc.type == NET_NONE )
    return false;*/

  if ( mc.type != NET_NONE ) {
    for ( int i = 0; ; i++ ) {
      if ( i == 0 )
        p.begin().s( "net_" );
      else
        p.begin().s( "net" ).i( i ).s( "_" );
      t = tree.find_transport( p.start, p.x( svc, svc_len ).end() );
      if ( t == NULL )
        break;
    }
    t = stab.make<ConfigTree::Transport>();
    stab.ref_string( p.start, p.len(), t->tport );
    t->tport_id = tree.transport_cnt++;
    t->is_temp = true;
    tree.transports.push_tl( t );

    char host_ip[ 64 ];
    int  host_ip_len;
    host_ip_len = mc.ip4_string( mc.host_ip, host_ip );
    switch ( mc.type ) {
      default: return false;
      case NET_ANY:
        stab.reref_string( T_ANY, T_ANY_SZ, t->type );
        tree.set_route_str( *t, stab, R_DEVICE,
                            host_ip, host_ip_len );
        break;

      case NET_MESH_CONNECT:
        is_listener = false; /* FALLTHRU */
      case NET_MESH:
      case NET_MESH_LISTEN:
        stab.reref_string( T_MESH, T_MESH_SZ, t->type );
        tree.set_route_str( *t, stab, R_DEVICE,
                            host_ip, host_ip_len );
        break;

      case NET_TCP_CONNECT:
        is_listener = false; /* FALLTHRU */
      case NET_TCP:
      case NET_TCP_LISTEN:
        stab.reref_string( T_TCP, T_TCP_SZ, t->type );
        tree.set_route_str( *t, stab, R_DEVICE,
                            host_ip, host_ip_len );
        break;

      case NET_MCAST: {
        size_t i, port_len = 0;
        const char * port = NULL;
        char port_hash[ 16 ];
        for ( i = 0; i < svc_len && svc[ i ] >= '0' && svc[ i ] <= '9'; i++ )
          ;
        if ( i == svc_len ) {
          port     = svc;
          port_len = svc_len;
        }
        else {
          port_len = uint32_to_string(
            ( kv_crc_c( svc, svc_len, 0 ) & 0x7fff ) + 0x8000, port_hash );
          port = port_hash;
          port_hash[ port_len ] = '\0';
        }
        stab.reref_string( "pgm", 3, t->type );
        tree.set_route_str( *t, stab, R_LISTEN, net, net_len );
        if ( port_len > 0 )
          tree.set_route_str( *t, stab, R_PORT, port, port_len );
        tree.set_route_str( *t, stab, R_MCAST_LOOP, "2", 1 );
        break;
      }
    }
    if ( ! this->add_transport( *t, is_listener ) )
      return false;
  }
  if ( (num = SessionMgr::parse_rv_service( svc, svc_len )) != 0 ) {
    RvSvc *rv_svc = this->get_rv_session( num, start_host );
    if ( rv_svc != NULL )
      rv_svc->ref_count++;
  }
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
  uint32_t f = ( is_listener ? TPORT_IS_LISTEN : 0 );
  NameSvcArray name_svc;

  if ( ! this->in_list( IN_ACTIVE_LIST ) ) {
    if ( this->init_sock() != 0 )
      return false;
  }
  rte = this->user_db.transport_tab.find_transport( &t );
  if ( rte != NULL ) {
    fprintf( stderr, "Transport %s already added\n", t.tport.val );
    return false;
  }
  if ( t.type.equals( T_TELNET, T_TELNET_SZ ) )
    return this->create_telnet( t );
  if ( t.type.equals( T_WEB, T_WEB_SZ ) )
    return this->create_web( t );
  if ( t.type.equals( T_NAME, T_NAME_SZ ) )
    return this->create_name( t );
  if ( t.type.equals( T_MESH, T_MESH_SZ ) || t.type.equals( T_TCP, T_TCP_SZ ) ||
       t.type.equals( T_ANY, T_ANY_SZ ) ) {
    const char * dev = NULL;
    if ( t.get_route_str( R_DEVICE, dev ) ) {
      if ( this->start_name_services( t, name_svc ) )
        f |= TPORT_IS_DEVICE;
    }
  }

  ConfigTree::Transport * tptr = &t;
  CatMalloc svc_name( this->svc.svc.len + t.tport.len + 8 );
  if ( t.type.equals( T_RV, T_RV_SZ ) || t.type.equals( T_NATS, T_NATS_SZ ) ||
       t.type.equals( T_REDIS, T_REDIS_SZ ) ) {
    StringTab & stab = this->user_db.string_tab;
    f |= TPORT_IS_IPC;
    svc_name.s( this->svc.svc.val ).s( ".ipc" ).end();
    tptr = this->tree.find_transport( svc_name.start, svc_name.len() );
    if ( tptr == NULL ) {
      tptr = stab.make<ConfigTree::Transport>();
      stab.ref_string( "ipc", 3, tptr->type );
      stab.ref_string( svc_name.start, svc_name.len(), tptr->tport );
      tptr->tport_id = this->tree.transport_cnt++;
      tptr->is_temp = true;
      this->tree.transports.push_tl( tptr );
    }
  }
  else {
    svc_name.s( this->svc.svc.val ).s( "." ).s( t.tport.val ).end();
  }
  bool is_new = false;

  rte = NULL;
  if ( ( f & TPORT_IS_IPC ) != 0 )
    rte = this->user_db.ipc_transport;

  if ( rte == NULL ) {
    void * p = aligned_malloc( sizeof( TransportRoute ) );
    rte = new ( p )
      TransportRoute( this->poll, *this, this->svc, *tptr, svc_name.start, f );
    if ( rte->init() != 0 )
      return false;
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
    for ( i = 0; i < name_svc.count; i++ )
      name_svc[ i ]->adverts.push( rte );
    if ( this->session_started ) {
      for ( i = 0; i < name_svc.count; i++ )
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
  if ( t.type.equals( T_TELNET, T_TELNET_SZ ) )
    return this->shutdown_telnet( t );
  if ( t.type.equals( T_WEB, T_WEB_SZ ) )
    return this->shutdown_web( t );
  if ( t.type.equals( T_NAME, T_NAME_SZ ) )
    return this->shutdown_name( t );

  uint32_t count = (uint32_t) this->user_db.transport_tab.count,
           match = 0;
  for ( uint32_t id = 0; id < count; id++ ) {
    TransportRoute *rte = this->user_db.transport_tab.ptr[ id ];
    if ( &rte->transport == &t || rte->ext != NULL ) {
      match += rte->shutdown( t );
    }
  }
  return match;
}

bool
SessionMgr::start_transport( TransportRoute &rte,
                             bool is_listener ) noexcept
{
  if ( rte.transport.type.equals( T_TCP, T_TCP_SZ ) ) {
    if ( is_listener ) {
      if ( rte.listener != NULL ) {
        if ( ! rte.start_listener( rte.listener, rte.transport ) )
          return false;
        rte.create_listener_conn_url();
      }
    }
    else {
      rte.clear( TPORT_IS_SHUTDOWN );
      if ( rte.connect_ctx != NULL ) {
        EvTcpTransportParameters parm;
        parm.parse_tport( rte.transport, PARAM_NB_CONNECT, *this );
        rte.connect_ctx->connect( parm.host( 0 ), parm.port( 0 ), parm.opts,
                                  parm.timeout );
      }
    }
    if ( rte.is_device() )
      this->name_hb( 0 );
    return true;
  }
  else if ( rte.transport.type.equals( T_MESH, T_MESH_SZ ) ) {
    if ( rte.listener != NULL ) {
      if ( rte.is_shutdown() ) {
        if ( ! rte.start_listener( rte.listener, rte.transport ) )
          return false;
        rte.create_listener_mesh_url();
      }
      if ( ! is_listener )
        rte.add_mesh_connect( NULL, 0 );
      if ( rte.is_device() )
        this->name_hb( 0 );
      return true;
    }
  }
  else if ( rte.transport.type.equals( T_PGM, T_PGM_SZ ) ) {
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

bool
SessionMgr::add_mesh_accept( TransportRoute &listen_rte,
                             EvTcpTransport &conn ) noexcept
{
  TransportRoute        * rte;
  ConfigTree::Service   & s = listen_rte.svc;
  ConfigTree::Transport & t = listen_rte.transport;
  bool is_new = true;

  uint32_t count = (uint32_t) this->user_db.transport_tab.count;
  for ( uint32_t id = 0; id < count; id++ ) {
    rte = this->user_db.transport_tab.ptr[ id ];
    if ( &t == &rte->transport &&
         rte->all_set( TPORT_IS_SHUTDOWN | TPORT_IS_MESH ) &&
         rte->mesh_id == conn.rte->mesh_id ) {
      if ( rte->connect_ctx == NULL && rte->connect_count == 0 ) {
        rte->init_state();
        is_new = false;
        break;
      }
    }
  }
  if ( is_new ) {
    void       * p    = aligned_malloc( sizeof( TransportRoute ) );
    const char * name = listen_rte.sub_route.service_name;
    rte = new ( p ) TransportRoute( this->poll, *this, s, t, name, 0 );
    if ( rte->init() != 0 )
      return false;
  }
  rte->mesh_id     = listen_rte.mesh_id;
  rte->uid_in_mesh = listen_rte.uid_in_mesh;
  rte->mesh_csum   = listen_rte.mesh_csum;
  for ( uint8_t i = 0; i < COST_PATH_COUNT; i++ )
    rte->uid_connected.cost[ i ] = listen_rte.uid_connected.cost[ i ];

  rte->set( TPORT_IS_MESH );
  rte->mesh_url.zero();
  rte->mesh_url_hash = 0; /* don't know this util after auth */
  conn.rte      = rte;
  conn.notify   = rte;
  conn.route_id = rte->sub_route.route_id;
  rte->set_peer_name( conn, "tcp_acc" );

  PeerAddrStr paddr;
  paddr.set_sock_addr( conn.fd );
  rte->printf( "add_mesh_accept(%s) from %s (listen:%s.%u) local(%s)\n",
               is_new ? "new" : "reuse",
               conn.peer_address.buf, listen_rte.transport.tport.val,
               listen_rte.tport_id,
               paddr.buf );
  if ( is_new )
    this->user_db.add_transport( *rte );
  this->events.on_connect( rte->tport_id, TPORT_IS_MESH, conn.encrypt );
  if ( ! rte->connected.test_set( conn.fd ) )
    rte->connect_count++;
  d_tran( "%s connect_count %u\n", rte->name, rte->connect_count );
  return true;
}

TransportRoute *
SessionMgr::add_tcp_rte( TransportRoute &src_rte,  uint32_t conn_hash ) noexcept
{
  TransportRoute        * rte;
  ConfigTree::Service   & s = src_rte.svc;
  ConfigTree::Transport & t = src_rte.transport;
  bool is_new = true;

  uint32_t count = (uint32_t) this->user_db.transport_tab.count, id;
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
      if ( rte->connect_ctx == NULL && rte->connect_count == 0 ) {
        rte->init_state();
        is_new = false;
        break;
      }
    }
  }
  if ( is_new ) {
    void       * p    = aligned_malloc( sizeof( TransportRoute ) );
    const char * name = src_rte.sub_route.service_name;
    rte = new ( p ) TransportRoute( this->poll, *this, s, t, name, 0 );
    if ( rte->init() != 0 )
      return NULL;
  }
  rte->dev_id        = src_rte.dev_id;
  rte->uid_in_device = src_rte.uid_in_device;

  if ( is_new ) {
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
  rte->set_peer_name( conn, "tcp_acc" );

  rte->printf( "add_tcp_accept from %s\n", conn.peer_address.buf );
  this->events.on_connect( rte->tport_id, TPORT_IS_TCP, conn.encrypt );
  if ( ! rte->connected.test_set( conn.fd ) )
    rte->connect_count++;

  d_tran( "%s connect_count %u\n", rte->name, rte->connect_count );
  return true;
}

static size_t
copy_host_buf( char buf[ MAX_TCP_HOST_LEN ],  size_t off,
               const char *str ) noexcept
{
  while ( *str != '\0' && off < MAX_TCP_HOST_LEN - 1 )
    buf[ off++ ] = *str++;
  buf[ off ] = '\0';
  return off;
}

namespace {
struct MeshUrlArray {
  kv::ArrayCount< const char *, 4 > mesh_url;
  kv::ArrayCount< uint32_t, 4 > url_hash;

  ~MeshUrlArray() {
    for ( size_t i = 0; i < this->mesh_url.count; i++ )
      ::free( (void *) this->mesh_url.ptr[ i ] );
  }
  void append( const char *url,  size_t len ) {
    char * p = (char *) ::malloc( len + 1 );
    ::memcpy( p, url, len );
    p[ len ] = '\0';
    this->mesh_url.push( p );
    this->url_hash.push( kv_crc_c( p, len, 0 ) );
  }
};
}

bool
SessionMgr::add_mesh_connect( TransportRoute &mesh_rte ) noexcept
{
  EvTcpTransportParameters parm;
  MeshUrlArray url_array;
  size_t i, j;

  parm.parse_tport( mesh_rte.transport, PARAM_NB_CONNECT, *this );

  for ( i = 0; ; i++ ) {
    char   url[ MAX_TCP_HOST_LEN ];
    size_t url_sz = 0;
    char   pbuf[ 24 ];

    url_sz = copy_host_buf( url, 0, "mesh://" );
    if ( parm.host( i ) == NULL ) {
      if ( i == 0 ) {
        if ( mesh_rte.is_device() )
          return true;
      }
      if ( i > 0 )
        break;
      url_sz = copy_host_buf( url, url_sz, "127.0.0.1" );
    }
    else {
      url_sz = copy_host_buf( url, url_sz, parm.host( i ) );
    }
    if ( parm.port( i ) != 0 ) {
      j = uint32_to_string( parm.port( i ), pbuf );
      pbuf[ j ] = '\0';
    }
    else {
      ::strcpy( pbuf, "28989" );
    }
    url_sz = copy_host_buf( url, url_sz, ":" );
    url_sz = copy_host_buf( url, url_sz, pbuf );
    url_array.append( url, url_sz );
  }

  return this->add_mesh_connect( mesh_rte, url_array.mesh_url.ptr,
                                 url_array.url_hash.ptr,
                                 url_array.mesh_url.count );
}

bool
SessionMgr::add_mesh_connect( TransportRoute &mesh_rte,  const char **mesh_url,
                              uint32_t *mesh_hash, uint32_t url_count ) noexcept
{
  TransportRoute * rte;
  uint32_t         count, i;
  uint64_t         skip = 0;

  if ( mesh_rte.mesh_id == NULL )
    return true;

  count = (uint32_t) this->user_db.transport_tab.count;
  for ( i = 0; i < url_count; i++ ) {
    if ( mesh_rte.is_set( TPORT_IS_LISTEN ) &&
         mesh_rte.mesh_equal( mesh_url[ i ], mesh_hash[ i ] ) ) {
      mesh_rte.printf( "not connecting to self (%s)\n", mesh_url[ i ] );
      mesh_url[ i ]  = NULL;
      mesh_hash[ i ] = 0;
      skip |= 1 << i;
    }
    else {
      for ( uint32_t tport_id = 0; tport_id < count; tport_id++ ) {
        rte = this->user_db.transport_tab.ptr[ tport_id ];
        if ( rte != &mesh_rte && rte->mesh_id == mesh_rte.mesh_id &&
             ! rte->is_set( TPORT_IS_SHUTDOWN ) ) {
          if ( rte->mesh_equal( mesh_url[ i ], mesh_hash[ i ] ) ) {
            if ( debug_tran )
              mesh_rte.printf( "skip, already connected (%s)\n", mesh_url[ i ] );
            skip |= 1 << i;
            break;
          }
        }
      }
    }
  }
  if ( skip == ( (uint64_t) 1 << url_count ) - 1 ) {
    if ( debug_tran )
      mesh_rte.printf( "no mesh urls to connect\n" );
    return true;
  }
  for ( i = 0; i < url_count; i++ ) {
    if ( ( skip & ( 1 << i ) ) == 0 )
      this->add_mesh_connect( mesh_rte, mesh_url[ i ], mesh_hash[ i ] );
  }
  return true;
}

bool
SessionMgr::add_mesh_connect( TransportRoute &mesh_rte,  const char *url,
                              uint32_t url_hash ) noexcept
{
  TransportRoute   * rte;
  EvTcpTransportOpts opts;

  ConfigTree::Transport & t = mesh_rte.transport;
  char         host_buf[ MAX_TCP_HOST_LEN ];
  const char * host = url;
  size_t       len  = sizeof( host_buf );
  int          port;
  uint32_t     count;
  bool         is_new = true;

  port = ConfigTree::Transport::get_host_port( host, host_buf, len,
                                               this->tree.hosts );
  opts.parse( mesh_rte.transport, PARAM_NB_CONNECT, *this );

  count = (uint32_t) this->user_db.transport_tab.count;
  for ( uint32_t tport_id = 0; tport_id < count; tport_id++ ) {
    rte = this->user_db.transport_tab.ptr[ tport_id ];
    if ( &t == &rte->transport &&
         rte->all_set( TPORT_IS_SHUTDOWN | TPORT_IS_MESH ) &&
         rte->mesh_id == mesh_rte.mesh_id &&
         rte->connect_count == 0 &&
         ( rte->connect_ctx == NULL ||
           rte->connect_ctx->state == ConnectCtx::CONN_SHUTDOWN ||
           rte->connect_ctx->state == ConnectCtx::CONN_IDLE ) ) {
      if ( rte->mesh_equal( url, url_hash ) ) {
        rte->init_state();
        is_new = false;
        break;
      }
    }
  }
  if ( is_new ) {
    void * p = aligned_malloc( sizeof( TransportRoute ) );
    ConfigTree::Service &s = mesh_rte.svc;
    ConfigTree::Transport &t = mesh_rte.transport;
    const char * svc_name = mesh_rte.mesh_id->sub_route.service_name;
    rte = new ( p ) TransportRoute( this->poll, *this, s, t, svc_name, 0 );
    if ( rte->init() != 0 )
      return false;
  }

  StringTab & st = this->user_db.string_tab;
  st.ref_string( url, ::strlen( url ), rte->mesh_url );
  rte->mesh_id       = mesh_rte.mesh_id;
  rte->uid_in_mesh   = mesh_rte.uid_in_mesh;
  rte->mesh_csum     = mesh_rte.mesh_csum;
  rte->mesh_url_hash = url_hash;
  for ( uint8_t i = 0; i < COST_PATH_COUNT; i++ )
    rte->uid_connected.cost[ i ] = mesh_rte.uid_connected.cost[ i ];

  rte->set( TPORT_IS_MESH | TPORT_IS_CONNECT );
  rte->printf(
    "add_mesh_connect(%s) timeout=%u encrypt=%s %s (%x) (mesh:%s.%u)\n",
    is_new ? "new" : "reuse",
    opts.timeout, opts.noencrypt ? "false" : "true", url, url_hash,
    mesh_rte.transport.tport.val, mesh_rte.tport_id );

  if ( is_new )
    this->user_db.add_transport( *rte );

  if ( rte->connect_ctx == NULL )
    rte->connect_ctx = this->connect_mgr.create( rte->tport_id );

  rte->connect_ctx->connect( host, port, opts.opts, opts.timeout );
  return true;
}

bool
SessionMgr::listen_start_noencrypt( ConfigTree::Transport &tport,
                                    EvTcpListen *l, const char *k ) noexcept
{
  EvTcpTransportParameters parm;
  parm.parse_tport( tport, PARAM_LISTEN, *this );
  parm.noencrypt = true;
  parm.opts &= ~TCP_OPT_ENCRYPT;

  if ( ! l->in_list( IN_ACTIVE_LIST ) ) {
    if ( l->listen2( parm.host( 0 ), parm.port( 0 ), parm.opts, k, -1 ) != 0 ) {
      fprintf( stderr, "%s: failed to start %s at %s.%d\n", tport.type.val,
       tport.tport.val, parm.host( 0 ) ? parm.host( 0 ) : "*", parm.port( 0 ) );
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
  if ( this->listen_start_noencrypt( tport, un.telnet, "telnet_listen" ) ) {
    CatMalloc p( tport.type.len + tport.tport.len + 1 );
    p.s( tport.type.val ).s( "." ).s( tport.tport.val ).end();
    un.telnet->set_name( p.start, p.len() );
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
    if ( tport.get_route_str( R_HTTP_DIR, un.web->http_dir ) &&
         un.web->http_dir != NULL ) {
      un.web->http_dir_len = ::strlen( un.web->http_dir );
    }
    const char * http_username = NULL,
               * http_password = NULL,
               * http_realm    = NULL,
               * htdigest      = NULL;
    tport.get_route_str( R_HTTP_USERNAME, http_username );
    tport.get_route_str( R_HTTP_PASSWORD, http_password );
    tport.get_route_str( R_HTTP_REALM, http_realm );
    tport.get_route_str( R_HTDIGEST, htdigest );
    if ( http_username != NULL || http_password != NULL || htdigest != NULL ) {
      un.web->init_htdigest( http_username, http_password, http_realm,
                             htdigest );
    }
  }
  if ( this->listen_start_noencrypt( tport, un.web, "web_listen" ) ) {
    CatMalloc p( tport.type.len + tport.tport.len + 1 );
    p.s( tport.type.val ).s( "." ).s( tport.tport.val ).end();
    un.web->set_name( p.start, p.len() );
    TransportRoute::make_url_from_sock( this->user_db.string_tab,
                                        un.web->http_url, *un.web, "http" );
    printf( "http_url %s\n", un.web->http_url.val );
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
    un.name = new ( p ) NameSvc( this->poll, *this, this->user_db,
                                 tport, un.un_id );
  }
  if ( ! un.name->is_connected ) {
    if ( ! un.name->connect() )
      return false;
  }
  return true;
}

bool
SessionMgr::start_name_services( ConfigTree::Transport &tport,
                                 NameSvcArray &name_svc ) noexcept
{
  ConfigTree::StringPairArray el;

  tport.get_route_pairs( R_DEVICE, el );
  for ( uint32_t i = 0; i < el.count; i++ ) {
    const char * dev = el[ i ]->value.val;
    char         tmp[ MAX_TCP_HOST_LEN ];

    tmp[ 0 ] = '\0';
    size_t len  = sizeof( tmp );
    int    port = tport.get_host_port( dev, tmp, len, this->tree.hosts );

    /* tport: lo
       type: name
       route:
         connect: lo;239.23.22.217
         port: 8327 */
    ConfigTree::Transport *tptr = NULL;
    if ( port == 0 )
      tptr = this->tree.find_transport( dev, len );
    if ( tptr == NULL ) {
      StringTab & stab = this->user_db.string_tab;
      char mcast[ MAX_TCP_HOST_LEN + 64 ], port_str[ 8 ];
      ConfigTree::StringPair *p;

      tptr = stab.make<ConfigTree::Transport>();
      stab.ref_string( T_NAME, T_NAME_SZ, tptr->type );
      stab.ref_string( dev, len, tptr->tport );

      p = stab.make<ConfigTree::StringPair>();
      stab.ref_string( R_CONNECT, R_CONNECT_SZ, p->name );
      CatPtr mc( mcast );
      mc.x( dev, len )
        .s( NameSvc::default_name_mcast() )
        .end();
      stab.ref_string( mcast, mc.len(), p->value );
      tptr->route.push_tl( p );

      p = stab.make<ConfigTree::StringPair>();
      stab.ref_string( R_PORT, R_PORT_SZ, p->name );
      if ( port == 0 )
        port = NameSvc::default_name_port();
      size_t n = int32_to_string( port, port_str, int32_digits( port ) );
      stab.ref_string( port_str, n, p->value );
      tptr->route.push_tl( p );

      tptr->tport_id = this->tree.transport_cnt++;
      tptr->is_temp = true;
      this->tree.transports.push_tl( tptr );
    }
    Unrouteable *un = this->unrouteable.find( tptr );
    if ( un == NULL ) {
      this->create_name( *tptr );
      un = this->unrouteable.find( tptr );
    }
    if ( un != NULL && un->name != NULL )
      name_svc.push( un->name );
  }
  return name_svc.count > 0;
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
