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
  for ( p = this->tree.parameters.hd; p != NULL; p = p->next ) {
    for ( sp = p->parms.hd; sp != NULL; sp = sp->next ) {
      if ( sp->name.equals( name, name_sz ) ) {
        for ( len = sp->value.len; len > 0 && sp->value.val[ len - 1 ] == ' ';
          len-- ) ;
        tport = this->tree.find_transport( sp->value.val, len );
        rte   = this->user_db.transport_tab.find_transport( tport );
        if ( rte != NULL ) {
          if ( ! rte->is_set( TPORT_IS_SHUTDOWN ) ) {
            fprintf( stderr,
                     "startup %.*s transport \"%.*s\" already running\n",
                     (int) name_sz, name,
                     (int) len, sp->value.val );
            return true;
          }
        }
        if ( tport == NULL ) {
          fprintf( stderr, "startup %.*s transport \"%.*s\" not found\n",
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
    this->tree.transports.push_tl( rvd );
  }
  if ( ! this->add_transport( *rvd, true ) )
    return false;
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
          int port = web->get_host_port( addr, tmp, len );
          if ( port != 0 ) {
            port += 80;
            if ( web->is_wildcard( addr ) )
              ::snprintf( buf, sizeof( buf ), "*:%d", port );
            else if ( ::strchr( tmp, ':' ) != NULL )
              ::snprintf( buf, sizeof( buf ), "[%s]:%d", addr, port );
            else
              ::snprintf( buf, sizeof( buf ), "%s:%d", addr, port );
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
  uint32_t f = TPORT_IS_IPC;
  StringTab & stab = this->user_db.string_tab;

  tptr = this->tree.find_transport( T_IPC, T_IPC_SZ );
  if ( tptr == NULL ) {
    tptr = stab.make<ConfigTree::Transport>();
    stab.ref_string( T_IPC, T_IPC_SZ, tptr->type );
    tptr->tport = tptr->type;
    tptr->tport_id = this->tree.transport_cnt++;
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

  this->tree.find_parameter( P_MAP_FILE, map_name, NULL );
  this->tree.find_parameter( P_IPC_NAME, ipc_name, NULL );
  this->tree.find_parameter( P_DB_NUM, db_num, NULL );

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
                         const char *svc,  size_t svc_len ) noexcept
{
  ConfigTree::Transport * t;
  ConfigTree & tree = this->tree;
  StringTab  & stab = this->user_db.string_tab;
  RvMcast2     mc;
  char         svc_buf[ 1024 ];
  int          svc_buf_len;
  bool is_listener = true;

  if ( mc.parse_network2( net, net_len ) != sassrv::HOST_OK )
    return false;
  if ( mc.type == NET_NONE )
    return false;

  /*t = tree.find_transport( svc, svc_len );
  if ( t != NULL ) {*/
  for ( int i = 0; ; i++ ) {
    if ( i == 0 )
      svc_buf_len = ::snprintf( svc_buf, sizeof( svc_buf ), "net_%.*s",
                                (int) svc_len, svc );
    else
      svc_buf_len = ::snprintf( svc_buf, sizeof( svc_buf ), "net%d_%.*s", i,
                                (int) svc_len, svc );
    t = tree.find_transport( svc_buf, svc_buf_len );
    if ( t == NULL )
      break;
  }
  t = stab.make<ConfigTree::Transport>();
  stab.ref_string( svc_buf, svc_buf_len, t->tport );
  t->tport_id = tree.transport_cnt++;
  tree.transports.push_tl( t );

  char host_ip[ 64 ];
  int  host_ip_len;
  host_ip_len = mc.device_ip( host_ip, sizeof( host_ip ) );
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
  return this->add_transport( *t, is_listener );
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
  NameSvc * name_svc[ MAX_TCP_HOSTS ];
  uint32_t  name_svc_count = 0;

  if ( ! this->in_list( IN_ACTIVE_LIST ) ) {
    if ( this->init_sock() != 0 )
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
      name_svc_count = this->start_name_services( t, name_svc );
      if ( name_svc_count > 0 )
        f |= TPORT_IS_DEVICE;
    }
  }

  ConfigTree::Transport * tptr = &t;
  char svc_name[ 256 ];
  if ( t.type.equals( T_RV, T_RV_SZ ) || t.type.equals( T_NATS, T_NATS_SZ ) ||
       t.type.equals( T_REDIS, T_REDIS_SZ ) ) {
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
  bool is_new = false;

  rte = NULL;
  if ( ( f & TPORT_IS_IPC ) != 0 )
    rte = this->user_db.ipc_transport;

  if ( rte == NULL ) {
    void * p = aligned_malloc( sizeof( TransportRoute ) );
    rte = new ( p )
      TransportRoute( this->poll, *this, this->svc, *tptr, svc_name, f );
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
  if ( t.type.equals( T_TELNET, T_TELNET_SZ ) )
    return this->shutdown_telnet( t );
  if ( t.type.equals( T_WEB, T_WEB_SZ ) )
    return this->shutdown_web( t );

  uint32_t count = (uint32_t) this->user_db.transport_tab.count,
           match = 0;
  for ( uint32_t id = 0; id < count; id++ ) {
    TransportRoute *rte = this->user_db.transport_tab.ptr[ id ];
    if ( &rte->transport == &t ) {
      match += rte->shutdown();
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
      if ( rte.connect_ctx != NULL )
        rte.connect_ctx->reconnect();
    }
    if ( rte.is_set( TPORT_IS_DEVICE ) )
      this->name_hb( 0 );
    return true;
  }
  else if ( rte.transport.type.equals( T_MESH, T_MESH_SZ ) ) {
    if ( rte.listener != NULL ) {
      if ( rte.is_set( TPORT_IS_SHUTDOWN ) ) {
        if ( ! rte.start_listener( rte.listener, rte.transport ) )
          return false;
        rte.create_listener_mesh_url();
      }
      if ( ! is_listener )
        rte.add_mesh_connect( NULL, 0 );
      if ( rte.is_set( TPORT_IS_DEVICE ) )
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
      if ( rte->connect_ctx == NULL ) {
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

  rte->printf( "add_mesh_accept from %s\n", conn.peer_address.buf );
  if ( is_new ) {
    this->user_db.add_transport( *rte );
  }
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

  uint32_t count = (uint32_t) this->user_db.transport_tab.count;
  if ( conn_hash != 0 ) {
    for ( id = 0; id < count; id++ ) {
      rte = this->user_db.transport_tab.ptr[ id ];
      if ( rte->conn_hash == conn_hash && &t == &rte->transport )
        return rte;
    }
  }
  for ( uint32_t id = 0; id < count; id++ ) {
    rte = this->user_db.transport_tab.ptr[ id ];
    if ( &t == &rte->transport &&
         rte->all_set( TPORT_IS_SHUTDOWN | TPORT_IS_TCP ) &&
         rte->dev_id == src_rte.dev_id ) {
      if ( rte->connect_ctx == NULL ) {
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

  rte->printf( "add_tcp_accept\n" );
  this->events.on_connect( rte->tport_id, TPORT_IS_TCP, conn.encrypt );
  if ( ! rte->connected.test_set( conn.fd ) )
    rte->connect_count++;

  d_tran( "%s connect_count %u\n", rte->name, rte->connect_count );
  return true;
}

bool
SessionMgr::add_mesh_connect( TransportRoute &mesh_rte ) noexcept
{
  EvTcpTransportParameters parm;
  char     url_buf[ MAX_TCP_HOSTS ][ MAX_TCP_HOST_LEN ];
  size_t   url_buf_sz[ MAX_TCP_HOSTS ], i, j;
  uint32_t url_hash[ MAX_TCP_HOSTS ];

  parm.parse_tport( mesh_rte.transport, PARAM_NB_CONNECT, *this );

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
              mesh_rte.printf( "already connected (%s)\n", mesh_url[ i ] );
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

  char         host_buf[ MAX_TCP_HOST_LEN ];
  const char * host = url;
  size_t       len  = sizeof( host_buf );
  int          port;
  uint32_t     count;
  bool         is_new = true;

  port = ConfigTree::Transport::get_host_port( host, host_buf, len );
  opts.parse( mesh_rte.transport, PARAM_NB_CONNECT, *this );

  mesh_rte.printf( "add_mesh_connect timeout=%u encrypt=%s %s (%x)\n",
             opts.timeout, opts.noencrypt ? "false" : "true", url, url_hash );
  count = (uint32_t) this->user_db.transport_tab.count;
  for ( uint32_t tport_id = 0; tport_id < count; tport_id++ ) {
    rte = this->user_db.transport_tab.ptr[ tport_id ];
    if ( rte->all_set( TPORT_IS_SHUTDOWN | TPORT_IS_MESH ) &&
         rte->mesh_id == mesh_rte.mesh_id ) {
      if ( rte->connect_ctx == NULL || rte->mesh_equal( url, url_hash ) ) {
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
  if ( this->listen_start_noencrypt( tport, un.telnet, "telnet_listen" ) ) {
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

  tport.get_route_pairs( R_DEVICE, el, MAX_TCP_HOSTS );
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
      stab.ref_string( T_NAME, T_NAME_SZ, tptr->type );
      stab.ref_string( dev, dev_len, tptr->tport );

      p = stab.make<ConfigTree::StringPair>();
      stab.ref_string( R_CONNECT, R_CONNECT_SZ, p->name );
      ::snprintf( mcast, sizeof( mcast ), "%.*s%s", dev_len, dev,
                  NameSvc::default_name_mcast() );
      stab.ref_string( mcast, ::strlen( mcast ), p->value );
      tptr->route.push_tl( p );

      p = stab.make<ConfigTree::StringPair>();
      stab.ref_string( R_PORT, R_PORT_SZ, p->name );
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
