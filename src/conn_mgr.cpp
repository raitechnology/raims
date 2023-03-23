#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <netdb.h>
#include <raims/transport.h>
#include <raims/session.h>
#include <raims/ev_tcp_transport.h>
#include <raims/ev_nats_transport.h>
#include <raims/ev_redis_transport.h>
#include <raims/ev_rv_transport.h>

using namespace rai;
using namespace ms;
using namespace kv;
using namespace ds;
using namespace natsmd;
using namespace sassrv;

bool
TransportRoute::is_self_connect( kv::EvSocket &conn ) noexcept
{
  uint32_t count = (uint32_t) this->user_db.transport_tab.count;
  for ( uint32_t id = 0; id < count; id++ ) {
    TransportRoute * rte = this->user_db.transport_tab.ptr[ id ];
    if ( rte->connect_ctx != NULL && rte->connect_ctx->client != NULL ) {
      PeerAddrStr paddr;
      paddr.set_sock_addr( rte->connect_ctx->client->fd );
      if ( paddr.len() == conn.peer_address.len() &&
           ::memcmp( paddr.buf, conn.peer_address.buf, paddr.len() ) == 0 ) {
        rte->printf( "connected to self, closing\n" );
        conn.idle_push( EV_CLOSE );
        rte->connect_ctx->client->idle_push( EV_CLOSE );
        rte->connect_ctx->client->set_sock_err( EV_ERR_CONN_SELF, 0 );
        rte->connect_ctx->state = ConnectCtx::CONN_SHUTDOWN;
        rte->clear( TPORT_IS_INPROGRESS );
        rte->set( TPORT_IS_SHUTDOWN );
        return true;
      }
    }
  }
  return false;
}

static const char /*nats_kind[]  = "nats",
                  redis_kind[] = "redis",*/
                  rv_kind[]    = "rv";

TransportRvHost::TransportRvHost( TransportRoute &r,  kv::EvSocket &c ) noexcept
                : rte( r ), conn( c ), rv_host( 0 ), rv_service( 0 )
{
  if ( r.rv_svc != NULL ) {
    if ( ! c.get_service( &this->rv_host, this->rv_service ) )
      this->rv_service = 0;
  }
}

int
TransportRvHost::start_session( void ) noexcept
{
  if ( this->rv_service == 0 || this->rv_host == NULL ||
       ::strcmp( this->conn.kind, rv_kind ) == 0 )
    return 0;

  RvHost  * host;
  RvHostNet hn( this->rv_service, 0, true );
  char      session[ EvSocket::MAX_SESSION_LEN ];
  uint32_t  delay_secs;
  int       status;

  *this->rv_host = NULL;
  status = this->rte.rv_svc->db.start_service( host, this->rte.poll,
                                               this->rte.sub_route, hn );
  if ( status != 0 )
    return status;
  status = this->rte.rv_svc->start_host( *host, hn, delay_secs );
  if ( status != 0 )
    return status;

  host->active_clients++;
  host->start_host2( 0 );
  host->make_session( this->conn.start_ns, session );

  this->conn.set_session( session );
  if ( host->active_clients == 1 )
    host->send_host_start( NULL );
  host->send_session_start( this->conn );
  *this->rv_host = host;
  return 0;
}

void
TransportRvHost::stop_session( void ) noexcept
{
  if ( this->rv_service == 0 || this->rv_host == NULL ||
       ::strcmp( this->conn.kind, rv_kind ) == 0 )
    return;
  RvHost * host = *this->rv_host;
  host->send_session_stop( this->conn );
  if ( host->stop_network() )
    this->rte.rv_svc->stop_host( *host );
}

uint16_t
SessionMgr::parse_rv_service( const char *svc,  size_t svclen ) noexcept
{
  uint32_t match_svc = 0;
  if ( svclen < 6 ) {
    for ( size_t i = 0; i < svclen; i++ ) {
      if ( svc[ i ] < '0' || svc[ i ] > '9' )
        return 0;
      match_svc = match_svc * 10 + (uint32_t) (uint8_t) ( svc[ i ] - '0' );
    }
    if ( match_svc > 0xffffU ) /* must be short */
      match_svc = 0;
  }
  return (uint16_t) match_svc;
}

uint16_t
SessionMgr::sub_has_rv_service( const char *sub,  size_t sublen ) noexcept
{
  uint32_t match_svc = 0;
  if ( sublen < 3 || sub[ 0 ] != '_' )
    return 0;
  for ( size_t i = 1; i < sublen; i++ ) {
    if ( sub[ i ] < '0' || sub[ i ] > '9' ) {
      if ( i == 1 || i > 6 || sub[ i ] != '.' ) /* look for _<svc>. */
        return 0;
      break;
    }
    match_svc = match_svc * 10 + (uint32_t) (uint8_t) ( sub[ i ] - '0' );
  }
  if ( match_svc > 0xffffU ) /* must be short */
    return 0;
  return (uint16_t) match_svc;
}

RvSvc *
SessionMgr::get_rv_session( uint16_t svc,  bool start_host ) noexcept
{
  size_t i;
  for ( i = 0; i < this->rv_svc_db.count; i++ ) {
    if ( this->rv_svc_db.ptr[ i ].svc == svc )
      break;
  }
  RvSvc & x = this->rv_svc_db[ i ];
  x.svc = svc;
  if ( x.ref_count == 0 ) {
    if ( ! start_host || this->user_db.ipc_transport == NULL )
      return NULL;
    TransportRoute & ipc_rte = *this->user_db.ipc_transport;
    if ( ipc_rte.rv_svc == NULL ) {
      ipc_rte.rv_svc = new ( ::malloc( sizeof( RvTransportService ) ) )
        RvTransportService( ipc_rte );
    }
    RvHostNet hn( svc, 0, true );
    uint32_t  delay_secs;
    int       status;

    status = ipc_rte.rv_svc->db.start_service( x.host, this->poll,
                                               ipc_rte.sub_route, hn );
    if ( status != 0 )
      return NULL;
    status = ipc_rte.rv_svc->start_host( *x.host, hn, delay_secs );
    if ( status != 0 )
      return NULL;

    x.host->active_clients++;
    x.host->start_host2( 0 );
    x.session_len = x.host->make_session( this->poll.now_ns, x.session );

    if ( x.host->active_clients == 1 )
      x.host->send_host_start( NULL );
    x.host->send_session_start( ipc_rte );
  }
  return &x;
}

void
SessionMgr::stop_rv_session( RvSvc *rv_svc ) noexcept
{
  TransportRoute & ipc_rte = *this->user_db.ipc_transport;
  rv_svc->host->send_session_stop( ipc_rte );
  if ( rv_svc->host->stop_network() )
    ipc_rte.rv_svc->stop_host( *rv_svc->host );
}
/* get session name */
size_t
TransportRoute::get_userid( char userid[ MAX_USERID_LEN ] ) noexcept
{
  if ( ! this->is_ipc() )
    return 0;
  size_t len = this->user_db.user.user.len;
  if ( len > MAX_USERID_LEN - 1 )
    len = MAX_USERID_LEN - 1;
  ::memcpy( userid, this->user_db.user.user.val, len );
  userid[ len ] = '\0';
  return len;
}
/* get session name */
size_t
TransportRoute::get_session( uint16_t svc,
                             char session[ MAX_SESSION_LEN ] ) noexcept
{
  if ( ! this->is_ipc() )
    return 0;
  size_t i;
  for ( i = 0;; i++ ) {
    if ( i == this->mgr.rv_svc_db.count )
      return 0;
    if ( this->mgr.rv_svc_db.ptr[ i ].svc == svc )
      break;
  }
  RvSvc & x = this->mgr.rv_svc_db.ptr[ i ];
  ::memcpy( session, x.session, x.session_len );
  session[ x.session_len ] = '\0';
  return x.session_len;
}
/* get session name */
size_t
TransportRoute::get_subscriptions( uint16_t svc,  SubRouteDB &subs ) noexcept
{
  if ( ! this->is_ipc() )
    return 0;
  return this->mgr.console.get_subscriptions( svc, subs );
}

size_t
TransportRoute::get_patterns( uint16_t svc,  int pat_fmt,
                              SubRouteDB &pats ) noexcept
{
  if ( ! this->is_ipc() )
    return 0;
  return this->mgr.console.get_patterns( svc, pat_fmt, pats );
}

void
TransportRoute::on_connect( kv::EvSocket &conn ) noexcept
{
  uint32_t connect_type  = 0;
  bool     is_encrypt    = false,
           first_connect = true;

  if ( this->is_ipc() ) {
    if ( ! this->connected.test_set( conn.fd ) ) {
      TransportRvHost svc( *this, conn );
      this->connect_count++;
      if ( svc.rv_service != 0 ) {
        int status;
        if ( (status = svc.start_session()) != 0 ) {
          this->printf( "status %d, %s connect to service %u\n",
                        status, svc.conn.kind, svc.rv_service );
        }
      }
    }
  }
  else {
    this->clear( TPORT_IS_SHUTDOWN );
    if ( ! this->is_mcast() ) {
      EvTcpTransport &tcp = (EvTcpTransport &) conn;
      is_encrypt = tcp.encrypt;

      if ( this->connect_ctx != NULL ) { /* connected sock */
        if ( (EvConnection *) &tcp == this->connect_ctx->client &&
             this->connect_ctx->connect_tries > 1 )
          first_connect = false;
      }
      else if ( this->is_self_connect( conn ) ) /* accepted sock */
        return;

      if ( first_connect ) {
        this->printf( "%s %s %s %s using %s fd %u\n",
                      tcp.is_connect ? "connect" : "accept",
                      tcp.encrypt ? "encrypted" : "plaintext",
                      conn.peer_address.buf, conn.type_string(),
                      this->sub_route.service_name, conn.fd );
      }
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
      this->printf( "connect %s %s using %s fd %u\n",
                    conn.peer_address.buf, conn.type_string(),
                    this->sub_route.service_name, conn.fd );
    }
    if ( first_connect )
      this->mgr.events.on_connect( this->tport_id, connect_type, is_encrypt );
    if ( ! this->connected.test_set( conn.fd ) )
      this->connect_count++;
  }
}

void
TransportRoute::on_shutdown( EvSocket &conn,  const char *err,
                             size_t errlen ) noexcept
{
  const char *s = "disconnected";
  char errbuf[ 256 ];

  if ( this->is_ipc() ) {
    if ( this->connected.test_clear( conn.fd ) ) {
      this->connect_count--;
      TransportRvHost svc( *this, conn );
      if ( svc.rv_service != 0 )
        svc.stop_session();

      if ( conn.sock_err != 0 || errlen != 0 ) {
        if ( errlen == 0 ) {
          errlen = conn.print_sock_error( errbuf, sizeof( errbuf ) );
          if ( errlen > 0 )
            err = errbuf;
        }
        if ( errlen > 0 ) {
          this->printf( "%s %s (%.*s)\n",
                        conn.kind, conn.peer_address.buf, (int) errlen, err );
        }
      }
    }
  }
  else {
    if ( &conn == (EvSocket *) this->listener )
      s = "listener stopped";
    else if ( errlen >= 15 && ::memcmp( err, "already connect", 15 ) == 0 )
      s = "stopped trying";
    if ( errlen == 0 ) {
      errlen = conn.print_sock_error( errbuf, sizeof( errbuf ) );
      if ( errlen > 0 )
        err = errbuf;
    }
    if ( conn.bytes_recv > 0  ) {
      this->printf( "%s %s (count=%u) %.*s\n", s,
                    conn.peer_address.buf, this->connect_count,
                    (int) errlen, err );
      this->mgr.events.on_shutdown( this->tport_id, conn.fd >= 0 );
    }
    if ( conn.fd >= 0 ) {
      this->user_db.retire_source( *this, conn.fd );
      if ( this->connected.test_clear( conn.fd ) ) {
        if ( --this->connect_count == 0 ) {
          this->last_connect_count = 0;
          if ( ! this->is_listen() ) {
            this->set( TPORT_IS_SHUTDOWN );
            if ( this->notify_ctx != NULL ) {
              if ( this->notify_ctx->state == ConnectCtx::CONN_SHUTDOWN )
                this->notify_ctx->reconnect();
              this->notify_ctx = NULL;
            }
          }
        }
      }
      else if ( &conn == (EvSocket *) this->listener )
        this->set( TPORT_IS_SHUTDOWN );
    }
    else if ( this->connect_count == 0 ) {
      this->set( TPORT_IS_SHUTDOWN );
      this->last_connect_count = 0;
    }
  }
  d_conn( "%s connect_count %u\n", this->name, this->connect_count );
}

void
TransportRoute::on_data_loss( EvSocket &conn,  EvPublish &pub ) noexcept
{
  if ( this->is_ipc() ) {
    d_conn( "on_data_loss fd %d pub_status %d\n", conn.fd, pub.pub_status );
    TransportRvHost svc( *this, conn );
    if ( svc.rv_host != NULL ) {
      RvHost  * host = *svc.rv_host;
      size_t    pos;
      uint32_t  uid;
      StringVal user;
      if ( this->user_db.host_ht->find( pub.pub_host, pos, uid ) ) {
        if ( uid == 0 )
          user = this->user_db.user.user;
        else {
          UserBridge * n = this->user_db.bridge_tab[ uid ];
          if ( n != NULL ) {
            uint32_t msg_loss = pub.pub_status;
            if ( msg_loss == EV_PUB_RESTART )
              msg_loss = 1;
            user = n->peer.user;
            if ( msg_loss <= EV_MAX_LOSS ) {
              uint64_t cur_pub = pub.cnt ^ ( (uint64_t) pub.subj_hash << 32 );
              if ( n->last_idl_pub != cur_pub ) {
                n->last_idl_pub = cur_pub;
                n->inbound_msg_loss += msg_loss;
                if ( n->inbound_svc_loss == NULL ) {
                  n->inbound_svc_loss = UIntHashTab::resize( NULL );
                }
                else {
                  size_t   pos;
                  uint32_t val;
                  if ( n->inbound_svc_loss->find( svc.rv_service, pos, val ) ) {
                    uint64_t tmp = (uint64_t) val + (uint64_t) msg_loss;
                    if ( tmp > 0xffffffffU )
                      tmp = 0xffffffffU;
                    msg_loss = (uint32_t) tmp;
                  }
                }
                n->inbound_svc_loss->upsert_rsz( n->inbound_svc_loss,
                                                 svc.rv_service, msg_loss );
                if ( n->is_set( AUTHENTICATED_STATE ) )
                  this->user_db.uid_rtt.add( n->uid );
              }
            }
          }
        }
      }
      host->inbound_data_loss( conn, pub, user.val );
    }
  }
}

void
TransportRoute::on_timeout( uint32_t connect_tries,  uint64_t nsecs ) noexcept
{
  this->printf( "connect timeout, connect tries: %u, time used: %.1f secs\n",
                connect_tries, (double) nsecs / 1000000000.0 );
  this->mgr.events.on_timeout( this->tport_id, connect_tries );
}

TransportRoute *
SessionMgr::find_mesh( const StringVal &mesh_url ) noexcept
{
  uint32_t count = (uint32_t) this->user_db.transport_tab.count;

  for ( uint32_t tport_id = 0; tport_id < count; tport_id++ ) {
    TransportRoute *rte = this->user_db.transport_tab.ptr[ tport_id ];
    if ( ! rte->is_shutdown() && rte->is_listen() && rte->is_mesh() ) {
      if ( rte->mesh_url.equals( mesh_url ) )
        return rte;
    }
  }
  return NULL;
}

TransportRoute *
SessionMgr::find_ucast( const StringVal &ucast_url ) noexcept
{
  uint32_t count = (uint32_t) this->user_db.transport_tab.count;

  for ( uint32_t tport_id = 0; tport_id < count; tport_id++ ) {
    TransportRoute *rte = this->user_db.transport_tab.ptr[ tport_id ];
    if ( ! rte->is_shutdown() && rte->is_mcast() ) {
      if ( rte->ucast_url.equals( ucast_url ) )
        return rte;
    }
  }
  return NULL;
}

TransportRoute *
SessionMgr::find_mesh( TransportRoute &mesh_rte,
                       struct addrinfo *addr_list ) noexcept
{
  uint32_t count = (uint32_t) this->user_db.transport_tab.count;
  uint32_t addr_count = 0;
  uint32_t dns_cache[ 128 ];
  char     url_buf[ 128 ];
  const struct addrinfo * p;

  for ( uint32_t tport_id = 0; tport_id < count; tport_id++ ) {
    TransportRoute *rte = this->user_db.transport_tab.ptr[ tport_id ];
    if ( rte != &mesh_rte && rte->mesh_id == mesh_rte.mesh_id &&
         ! rte->is_shutdown() && ! rte->is_listen() ) {
      if ( rte->mesh_url_hash == mesh_rte.mesh_url_hash ) {
        d_conn( "mesh matched %u(%x)(%.*s) %u(%x)(%.*s)\n",
         rte->tport_id, rte->mesh_url_hash, rte->mesh_url.len, rte->mesh_url.val,
         mesh_rte.tport_id, mesh_rte.mesh_url_hash, mesh_rte.mesh_url.len, mesh_rte.mesh_url.val );
        return rte;
      }
    }
  }
  for ( p = addr_list; p != NULL; ) {
    addr_count = 0;
    while ( p != NULL ) {
      uint32_t n = 0;
      PeerAddrStr paddr;
      if ( p->ai_family == AF_INET || p->ai_family == AF_INET6 ) {
        paddr.set_addr( (struct sockaddr *) p->ai_addr );
        ::memcpy( url_buf, "tcp://", 6 );
        ::memcpy( &url_buf[ 6 ], paddr.buf, paddr.len() );
        n = 6 + paddr.len();
        url_buf[ n ] = '\0';
      }
      p = p->ai_next;
      if ( n > 0 ) {
        dns_cache[ addr_count++ ] = kv_crc_c( url_buf, n, 0 );
        if ( addr_count == sizeof( dns_cache ) / sizeof( dns_cache[ 0 ] ) )
          break;
      }
    }
    for ( uint32_t tport_id = 0; tport_id < count; tport_id++ ) {
      TransportRoute *rte = this->user_db.transport_tab.ptr[ tport_id ];
      if ( rte != &mesh_rte && rte->mesh_id == mesh_rte.mesh_id &&
           ! rte->is_shutdown() && ! rte->is_listen() ) {
        for ( uint32_t i = 0; i < addr_count; i++ ) {
          if ( rte->mesh_url_hash == dns_cache[ i ] )
            return rte;
        }
      }
    }
  }
  return NULL;
}

bool
ConnectMgr::connect( ConnectCtx &ctx ) noexcept
{
  TransportRoute  * rte = this->user_db.transport_tab.ptr[ ctx.event_id ],
                  * active_rte;
  struct addrinfo * ai  = ctx.addr_info.addr_list;

  if ( rte->is_mesh() &&
       (active_rte = this->mgr.find_mesh( *rte, ai )) != NULL ) {
    const char * host = "";
    if ( ctx.addr_info.host != NULL )
      host = ctx.addr_info.host;
    rte->clear( TPORT_IS_INPROGRESS );
    rte->set( TPORT_IS_SHUTDOWN );
    if ( debug_conn )
      rte->printf( "connect %s:%d stopped, accepted connection active\n",
                   host, ctx.addr_info.port );
    ctx.state = ConnectCtx::CONN_SHUTDOWN;
    active_rte->notify_ctx = &ctx;
    return true;
  }

  EvTcpTransportClient *cl =
    this->poll.get_free_list<EvTcpTransportClient>( this->sock_type );
  cl->rte      = rte;
  cl->route_id = rte->sub_route.route_id;
  cl->encrypt  = ( ( ctx.opts & TCP_OPT_ENCRYPT ) != 0 );
  ctx.client   = cl;
  if ( cl->connect( ctx.opts, &ctx, ai, ++this->next_timer ) )
    return true;
  ctx.client = NULL;
  rte->on_shutdown( *cl, NULL, 0 );
  this->poll.push_free_list( cl );
  return false;
}

void
ConnectMgr::on_dns( ConnectCtx &ctx,  const char *host,  int port,
                    int opts ) noexcept
{
  TransportRoute * rte = this->user_db.transport_tab.ptr[ ctx.event_id ];
  if ( debug_conn )
    rte->printf( "resolving %s:%d opts(%x)\n", host, port, opts );
  rte->set( TPORT_IS_INPROGRESS );
}

void
ConnectMgr::on_connect( ConnectCtx &ctx ) noexcept
{
  TransportRoute * rte = this->user_db.transport_tab.ptr[ ctx.event_id ];
  rte->clear( TPORT_IS_INPROGRESS );
  rte->on_connect( *ctx.client );
}

bool
ConnectMgr::on_shutdown( ConnectCtx &ctx,  const char *msg,
                         size_t len ) noexcept
{
  TransportRoute * rte = this->user_db.transport_tab.ptr[ ctx.event_id ];
  rte->on_shutdown( *ctx.client, msg, len );
  if ( ctx.client->sock_err == EV_ERR_CONN_SELF )
    return false;
  if ( ctx.state != ConnectCtx::CONN_SHUTDOWN ) {
    rte->set( TPORT_IS_INPROGRESS );
    rte->clear( TPORT_IS_SHUTDOWN );
  }
  return true;
}

void
ConnectMgr::on_timeout( ConnectCtx &ctx ) noexcept
{
  TransportRoute * rte = this->user_db.transport_tab.ptr[ ctx.event_id ];
  rte->clear( TPORT_IS_INPROGRESS );
  rte->on_timeout( ctx.connect_tries,
                   current_monotonic_time_ns() - ctx.start_mono_time );
}

ConnectCtx *
ConnectDB::create( uint64_t id ) noexcept
{
  ConnectCtx * ctx = new ( ::malloc( sizeof( ConnectCtx ) ) )
    ConnectCtx( this->poll, *this, id );
  this->ctx_array[ id ] = ctx;
  return ctx;
}

void
ConnectCtx::connect( const char *host,  int port,  int opts,
                     int timeout ) noexcept
{
  if ( this->db.poll.quit )
    return;
  this->timeout         = timeout;
  this->opts            = opts;
  this->connect_tries   = 0;
  this->state           = CONN_GET_ADDRESS;
  this->start_mono_time = current_monotonic_time_ns();
  this->addr_info.timeout_ms = this->next_timeout() / 4;
  this->db.on_dns( *this, host, port, opts );
  this->addr_info.get_address( host, port, opts );
}

void
ConnectCtx::reconnect( void ) noexcept
{
  this->connect( this->addr_info.host, this->addr_info.port, this->opts,
                 this->timeout );
}

void
ConnectCtx::on_connect( kv::EvSocket & ) noexcept
{
  this->state = CONN_ACTIVE;
  this->db.on_connect( *this );
}

bool
ConnectCtx::expired( uint64_t cur_time ) noexcept
{
  if ( this->timeout == 0 )
    return false;
  if ( cur_time == 0 )
    cur_time = current_monotonic_time_ns();
  return this->start_mono_time +
    ( (uint64_t) this->timeout * 1000000000 ) < cur_time;
}

void
ConnectCtx::on_shutdown( EvSocket &,  const char *msg,  size_t len ) noexcept
{
  bool was_connected = ( this->client->bytes_recv > 0 );

  if ( ! this->db.on_shutdown( *this, msg, len ) )
    this->state = CONN_SHUTDOWN;

  this->client = NULL;
  uint64_t cur_time = current_monotonic_time_ns();
  if ( was_connected || this->state == CONN_SHUTDOWN ) {
    this->start_mono_time = cur_time;
    this->connect_tries   = 0;
  }

  if ( this->state != CONN_SHUTDOWN ) {
    if ( ! this->expired( cur_time ) && ! this->db.poll.quit ) {
      this->state = CONN_TIMER;
      this->db.poll.timer.add_timer_millis( *this, this->next_timeout(), 0,
                                            this->event_id );
    }
    else {
      this->state = CONN_IDLE;
      this->db.on_timeout( *this );
    }
  }
}

bool
ConnectCtx::timer_cb( uint64_t, uint64_t eid ) noexcept
{
  if ( eid == this->event_id && this->state != CONN_SHUTDOWN &&
       ! this->db.poll.quit ) {
    this->state = CONN_GET_ADDRESS;
    this->addr_info.timeout_ms = this->next_timeout() / 4;
    this->addr_info.free_addr_list();
    this->addr_info.ipv6_prefer = ! this->addr_info.ipv6_prefer;
    this->db.on_dns( *this, this->addr_info.host, this->addr_info.port,
                     this->opts );
    this->addr_info.get_address( this->addr_info.host, this->addr_info.port,
                                 this->opts );
  }
  return false;
}

void
ConnectCtx::addr_resolve_cb( CaresAddrInfo & ) noexcept
{
  if ( this->state == CONN_SHUTDOWN || this->db.poll.quit )
    return;
  this->connect_tries++;
  if ( this->addr_info.addr_list != NULL ) {
    if ( this->db.connect( *this ) )
      return;
  }
  if ( this->state != CONN_SHUTDOWN ) {
    if ( ! this->expired() && ! this->db.poll.quit ) {
      this->state = CONN_TIMER;
      this->db.poll.timer.add_timer_millis( *this, this->next_timeout(), 0,
                                            this->event_id );
    }
    else {
      this->state = CONN_IDLE;
      this->db.on_timeout( *this );
    }
  }
}

