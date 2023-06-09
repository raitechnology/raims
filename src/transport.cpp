#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdarg.h>
#if ! defined( _MSC_VER ) && ! defined( __MINGW32__ )
#include <unistd.h>
#else
#include <raikv/win.h>
#endif
#include <raims/transport.h>
#include <raims/session.h>
#include <raims/ev_tcp_transport.h>
#include <raims/ev_nats_transport.h>
#include <raims/ev_redis_transport.h>
#include <raims/ev_pgm_transport.h>
#include <raims/ev_inbox_transport.h>
#include <raims/ev_rv_transport.h>

using namespace rai;
using namespace ms;
using namespace kv;
using namespace md;
using namespace ds;
using namespace sassrv;
using namespace natsmd;

TransportRoute::TransportRoute( kv::EvPoll &p,  SessionMgr &m,
                                ConfigTree::Service &s,
                                ConfigTree::Transport &t,
                                const char *svc_name, uint32_t f ) noexcept
    : EvSocket( p, p.register_type( "transport_route" ) ),
      poll( p ), mgr( m ), user_db( m.user_db ),
      sub_route( p.sub_route.get_service( svc_name, m.user_db.next_svc_id( f ),
                                          m.user_db.next_tport_id() ) ),
      uid_in_mesh( &this->mesh_connected ),
      uid_in_device( &this->mesh_connected ),
      mesh_csum( &this->mesh_csum2 ),
      hb_time( 0 ), hb_mono_time( 0 ), hb_seqno( 0 ),
      stats_seqno( 0 ), timer_id( ++m.next_timer ), delta_recv( 0 ),
      tport_id( m.user_db.next_tport_id() ), hb_count( 0 ),
      last_hb_count( 0 ), connect_count( 0 ), last_connect_count( 0 ),
      state( f ), mesh_id( 0 ), dev_id( 0 ), listener( 0 ),
      connect_ctx( 0 ), notify_ctx( 0 ), pgm_tport( 0 ), ibx_tport( 0 ),
      rv_svc( 0 ), mesh_url_hash( 0 ),
      conn_hash( 0 ), ucast_url_hash( 0 ), oldest_uid( 0 ),
      ext( 0 ), mesh_cache( 0 ), svc( s ), transport( t )
{
  uint8_t i;
  ::memset( &this->inbox, 0, sizeof( this->inbox ) );
  ::memset( &this->mcast, 0, sizeof( this->mcast ) );
  this->inbox.fd = -1;
  this->mcast.fd = -1;
  this->uid_connected.tport      = t.tport;
  this->uid_connected.tport_type = t.type;
  this->uid_connected.tport_id   = this->tport_id;
  for ( i = 0; i < COST_PATH_COUNT; i++ )
    this->router_rt[ i ] = NULL;
  /* parse config that has cost, cost2 ... */
  ConfigTree::StringPairArray el;
  t.get_route_pairs( R_COST, el );
  /* parse config that uses array of cost */
  if ( el.count > 0 )
    this->uid_connected.is_advertised = true;

  int cost, j = 0;
  for ( i = 0; i < COST_PATH_COUNT; i++ ) {
    if ( i >= el.count || ! el[ i ]->value.get_int( cost ) || cost <= 0 )
      cost = ( i == 0 ? COST_DEFAULT : this->uid_connected.cost[ j++ ] );
    this->uid_connected.cost[ i ] = cost;
    this->initial_cost[ i ] = cost;
  }
  if ( debug_tran )
    printf( "transport.%u(%s) [%u,%u,%u,%u] created\n", this->tport_id, t.tport.val,
             this->uid_connected.cost[ 0 ], this->uid_connected.cost[ 1 ],
             this->uid_connected.cost[ 2 ], this->uid_connected.cost[ 3 ] );
  this->sock_opts = OPT_NO_POLL;
  /* external tports do not have protocol for link state routing:
   *   _I.inbox, _X.HB, _Z.ADD, _Z.BLM, _Z.ADJ, _S.JOIN, _P.PSUB, etc */
  /* console_rt causes msgs to flow from tport -> session management */
  if ( ! this->is_ipc() ) {
    BloomRoute *rt;
    rt = this->sub_route.create_bloom_route( m.fd, &m.sub_db.console, 0 );
    rt->add_bloom_ref( &m.sys_bloom );
    this->sub_route.create_bloom_route( m.ipc_rt.fd, &m.sub_db.ipc, 0 );
  }
  else {
    this->sub_route.create_bloom_route( m.console_rt.fd, &m.sub_db.console, 0 );
    /* extrenal routes do not have system subjects */
  }
  /*this->user_db.check_bloom_route( *this, 0 );*/
  this->mesh_csum2.zero();
  this->hb_cnonce.zero();
  for ( int i = 0; i < 3; i++ )
    this->auth[ i ].zero();
  this->user_db.transport_tab.push( this );
  this->bp_flags = BP_FORWARD | BP_NOTIFY;
}
/* return ref_count++ */
uint32_t
BitRefCount::ref( uint32_t i ) noexcept
{
  if ( ! this->bits.test_set( i ) )
    return 0;
  size_t   pos;
  uint32_t val = 1;
  if ( this->ht == NULL )
    this->ht = UIntHashTab::resize( NULL );
  if ( this->ht->find( i, pos, val ) )
    this->ht->set( i, pos, val + 1 );
  else
    this->ht->set_rsz( this->ht, i, pos, 1 );
  return val;
}
/* return --ref_count */
uint32_t
BitRefCount::deref( uint32_t i ) noexcept
{
  if ( this->ht != NULL ) {
    size_t   pos;
    uint32_t val;
    if ( this->ht->find( i, pos, val ) ) {
      if ( val == 1 )
        this->ht->remove_rsz( this->ht, pos );
      else
        this->ht->set( i, pos, val - 1 );
      return val;
    }
  }
  if ( this->bits.test_clear( i ) )
    return 0;
  return -1;
}

int
TransportRoute::init( void ) noexcept
{
  int pfd = this->poll.get_null_fd();
  d_tran( "tport %s fd %d\n", this->sub_route.service_name, pfd );
  this->PeerData::init_peer( this->poll.get_next_id(), pfd,
                             this->sub_route.route_id, NULL, "tport" );
  this->set_peer_name( *this, "tport" );
  int status = this->poll.add_sock( this );
  if ( status != 0 )
    return status;
  this->mgr.router_set.add( pfd );
  /* router_rt tport causes msgs to flow from tport -> routable user subs */
  for ( uint8_t i = 0; i < COST_PATH_COUNT; i++ )
    this->router_rt[ i ] = this->sub_route.create_bloom_route( pfd, NULL, i );
  /*this->user_db.check_bloom_route( *this, 0 );*/
  return 0;
}

void
TransportRoute::init_state( void ) noexcept
{
  this->clear_all();
  this->mesh_url.zero();
  this->conn_url.zero();
  this->ucast_url.zero();
  this->uid_connected.rem_uid = 0;
  this->uid_connected.rem_tport_id = 0;
  this->mesh_id        = NULL;
  this->dev_id         = NULL;
  this->uid_in_mesh    = &this->mesh_connected;
  this->uid_in_device  = &this->mesh_connected;
  this->mesh_csum      = &this->mesh_csum2;
  this->mesh_url_hash  = 0;
  this->conn_hash      = 0;
  this->ucast_url_hash = 0;
  /*this->user_db.check_bloom_route( *this, 0 );*/
}

void
TransportRoute::set_peer_name( PeerData &pd,  const char *suff ) noexcept
{
  ConfigTree::Transport & tport = this->transport;
  ConfigTree::Service   & svc   = this->svc;
  CatMalloc p( svc.svc.len + tport.tport.len + 32 );
  p.s( svc.svc.val ).s( "." )
   .s( tport.tport.val ).s( "." )
   .s( suff ).s( "." )
   .u( this->tport_id );
  pd.set_name( p.start, p.end() );
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

bool
TransportRoute::update_cost( UserBridge &n,  StringVal &tport,  uint32_t *cost,
                             uint32_t rem_tport_id,  const char *s ) noexcept
{
  uint8_t i, eq_count = 0;
  uint32_t *cost2 = this->uid_connected.cost;
  StringVal & my_tport = this->transport.tport;
  bool updated = false, cost_updated = false, ok = true;
  uint32_t update_cost[ 4 ] = {0,0,0,0};
  if ( cost != NULL )
    ::memcpy( update_cost, cost, sizeof( update_cost ) );

  if ( this->uid_connected.cost[ 0 ] == COST_BAD ) {
#if 0
    if ( cost != NULL && this->uid_connected.is_advertised ) {
      if ( ::memcmp( cost, this->initial_cost,
                     sizeof( this->initial_cost ) ) == 0 ) {
        if ( my_tport.equals( tport ) )
          n.printf( "cost [%u,%u,%u,%u] is good again %s rem %u fd=%u (%s)\n",
                     cost[ 0 ], cost[ 1 ], cost[ 2 ], cost[ 3 ], this->name,
                     rem_tport_id, n.user_route->mcast.fd, s );
      }
    }
#endif
    return false;
  }
  if ( this->uid_connected.rem_uid != 0 && ! this->is_mcast() ) {
    if ( n.uid != this->uid_connected.rem_uid ||
         rem_tport_id != this->uid_connected.rem_tport_id ) {
      n.printe( "uid %u.%u is not uid connected %u.%u %s (%s)\n",
                n.uid, rem_tport_id, this->uid_connected.rem_uid,
                this->uid_connected.rem_tport_id, this->name, s );
      return false;
    }
  }
  if ( ! my_tport.equals( tport ) ) {
    if ( this->is_mesh() ) {
      ok = false;
      goto invalid_cost;
    }
  }
  if ( this->uid_connected.rem_uid == 0 ) {
    this->uid_connected.rem_uid = n.uid;
    this->uid_connected.rem_tport_id = rem_tport_id;
    updated = true;
  }
  else if ( this->uid_connected.rem_uid == n.uid ) {
    if ( this->uid_connected.rem_tport_id == 0 ||
         rem_tport_id < this->uid_connected.rem_tport_id ) {
      this->uid_connected.rem_tport_id = rem_tport_id;
      updated = true;
    }
  }
  else {
    UserBridge * m =
      this->user_db.bridge_tab.ptr[ this->uid_connected.rem_uid ];
    if ( ! m->is_set( AUTHENTICATED_STATE ) || n.start_time < m->start_time ) {
      this->uid_connected.rem_uid = n.uid;
      this->uid_connected.rem_tport_id = rem_tport_id;
      updated = true;
    }
  }
  if ( updated ) {
    if ( debug_tran )
      this->printf( "update uid %u tport %u (%s)\n", 
          this->uid_connected.rem_uid,
          this->uid_connected.rem_tport_id, s );
  }
  if ( cost != NULL ) {
    for ( i = 0; i < COST_PATH_COUNT; i++ ) {
      if ( cost[ i ] == cost2[ i ] )
        eq_count++;
      else {
        if ( this->uid_connected.is_advertised ) {
          ok = false;
          goto invalid_cost;
        }
      }
    }
    if ( eq_count != COST_PATH_COUNT ) {
      for ( i = 0; i < COST_PATH_COUNT; i++ )
        this->uid_connected.cost[ i ] = cost[ i ];
      updated = true;
      cost_updated = true;
    }
  }
  /* will update adjacency later if not authenticated */
  if ( ! updated )
    return true;
  if ( debug_tran )
    n.printf( "update cost [%u,%u,%u,%u] on %s (rem=%u) %s fd=%u (%s)\n",
              update_cost[ 0 ], update_cost[ 1 ], update_cost[ 2 ],
              update_cost[ 3 ], this->name, rem_tport_id,
              n.is_set( AUTHENTICATED_STATE ) ? "auth" : "not",
              n.user_route->mcast.fd, s );

  if ( 0 ) {
invalid_cost:;
    n.printe( "conflicting tport[%.*s] cost[%u,%u,%u,%u] (advert)"
              " != tport[%.*s] [%u,%u,%u,%u] rte=%s remote=%u fd=%u (%s)\n",
                tport.len, tport.val,
                update_cost[ 0 ], update_cost[ 1 ], update_cost[ 2 ],
                update_cost[ 3 ], my_tport.len, my_tport.val,
                cost2[ 0 ], cost2[ 1 ], cost2[ 2 ], cost2[ 3 ],
                this->name, rem_tport_id, n.user_route->mcast.fd, s );
    for ( i = 0; i < COST_PATH_COUNT; i++ )
      this->uid_connected.cost[ i ] = COST_BAD;
  }
  this->user_db.peer_dist.invalidate( ADVERTISED_COST_INV, n.uid );
  this->user_db.adjacency_change.append( n.uid, this->tport_id,
                                  this->user_db.link_state_seqno + 1, true );
  /*p->rem_uid     = this->uid_connected.rem_uid;
  p->rem_tportid = this->uid_connected.rem_tport_id;*/
  if ( cost_updated ) {
    if ( this->is_mesh() ) {
      uint32_t count = (uint32_t) this->user_db.transport_tab.count;
      for ( uint32_t id = 0; id < count; id++ ) {
        if ( id == this->tport_id )
          continue;
        TransportRoute *rte = this->user_db.transport_tab.ptr[ id ];
        if ( ! rte->is_shutdown() ) {
          if ( rte->is_mesh() &&
               rte->mesh_id == this->mesh_id ) {
            for ( i = 0; i < COST_PATH_COUNT; i++ )
              rte->uid_connected.cost[ i ] = cost[ i ];
          }
        }
      }
    }
  }
  return ok;
}

void
TransportRoute::make_url_from_sock( StringTab &string_tab,  StringVal &url,
                                    EvSocket &sock, const char *proto ) noexcept
{
  char   buf[ MAX_TCP_HOST_LEN + 1 ];
  size_t off = ::strlen( proto );
  if ( off > MAX_TCP_HOST_LEN )
    off = MAX_TCP_HOST_LEN;
  ::memcpy( buf, proto, off );
  if ( off < MAX_TCP_HOST_LEN ) buf[ off++ ] = ':';
  if ( off < MAX_TCP_HOST_LEN ) buf[ off++ ] = '/';
  if ( off < MAX_TCP_HOST_LEN ) buf[ off++ ] = '/';

  size_t len = get_strlen64( sock.peer_address.buf );
  bool is_ip4_wildcard, is_ip6_wildcard;
  is_ip4_wildcard = ( ::strncmp( sock.peer_address.buf, "0.0.0.0:", 8 ) == 0 );
  is_ip6_wildcard = ( ! is_ip4_wildcard &&
                      ::strncmp( sock.peer_address.buf, "[::]:", 5 ) == 0 );
  if ( is_ip4_wildcard || is_ip6_wildcard ) {
    size_t i = 0;
    if ( ::gethostname( &buf[ off ], MAX_TCP_HOST_LEN - off ) == 0 ) {
      off += ::strlen( &buf[ off ] );
      if ( is_ip4_wildcard )
        i = 7;
      else
        i = 4;
    }
    while ( off < MAX_TCP_HOST_LEN && i < len )
      buf[ off++ ] = sock.peer_address.buf[ i++ ];
    len = off;
  }
  else {
    if ( len > MAX_TCP_HOST_LEN - off )
      len = MAX_TCP_HOST_LEN - off;
    ::memcpy( &buf[ off ], sock.peer_address.buf, len );
    len += off;
  }
  buf[ len ] = '\0';
  string_tab.ref_string( buf, len, url );
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
TransportRoute::on_msg( EvPublish &pub ) noexcept
{
  this->msgs_recv++;
  this->bytes_recv += pub.msg_len;
  if ( pub.src_route.fd == this->mgr.fd ) {
    d_tran( "xxx discard %s transport_route: on_msg (%.*s)\n",
            ( pub.src_route.fd == this->fd ? "from tport" : "from mgr" ),
            (int) pub.subject_len, pub.subject );
    return true;
  }
  if ( ! pub.is_pub_type( PUB_TYPE_ROUTING ) ) {
    uint32_t id = pub.sub_route.route_id;
    TransportRoute * rte = this->user_db.transport_tab.ptr[ id ];
    if ( rte->is_set( TPORT_IS_IPC ) ) {
      d_tran( "rte(%s) forward external: on_msg (%.*s)\n",
              rte->name, (int) pub.subject_len, pub.subject );
      bool b = this->mgr.forward_ipc( *rte, pub );
      return this->check_flow_control( b );
    }
    d_tran( "rte(%s) pub_type == (%x) transport_route: on_msg (%.*s)\n",
            rte->name, pub.publish_type, (int) pub.subject_len, pub.subject );
    return true;
  }
  MsgFramePublish & fpub = (MsgFramePublish &) pub;
  MsgHdrDecoder   & dec  = fpub.dec;
  if ( ( fpub.flags & MSG_FRAME_TPORT_CONTROL ) != 0 ||
       fpub.status == FRAME_STATUS_DUP_SEQNO ) {
    d_tran( "rte(%s) dup transport_route: on_msg (%.*s)\n",
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
  UserBridge * dst;
  uint8_t path_select = dec.msg->caba.get_path();
  if ( dec.msg->caba.get_type() == CABA_INBOX &&
       (dst = this->user_db.is_inbox_sub( pub.subject,
                                          pub.subject_len )) != NULL ) {
    UidSrcPath & path = dst->src_path[ path_select ];
    if ( path.tport != this->tport_id ) {
      UserRoute * u_path = dst->user_route_ptr( this->user_db, path.tport );
      if ( u_path->is_valid() ) {
        d_tran( "transport_route: inbox (%.*s) -> %u\n",
                (int) pub.subject_len, pub.subject, path.tport );
        /*this->msgs_sent++;
        this->bytes_sent += pub.msg_len;*/
        bool b = this->user_db.forward_to_inbox(
                   *dst, pub.subject, pub.subject_len, pub.subj_hash,
                   pub.msg, pub.msg_len, this, NULL, 0, pub.src_route, u_path );
        return this->check_flow_control( b );
      }
    }
  }
  else {
    /* cache of the multicast tree for messages originating at n */
    if ( path_select > 0 && n.bloom_rt[ path_select ] == NULL )
      path_select = 0;

    if ( debug_tran ) {
      n.printf( "transport_route sub %.*s (0x%x) path %u\n", 
               (int) pub.subject_len, pub.subject, pub.subj_hash, path_select );
    }
    ForwardCache   & forward = n.forward_path[ path_select ];
    TransportRoute * rte;
    uint32_t         tport_id,
                     rcnt,
                     total_rcnt = 0;
    bool             b = true;
    pub.shard = path_select;
    this->user_db.peer_dist.update_forward_cache( forward, n.uid, path_select );
    if ( forward.first( tport_id ) ) {
      do {
        rte = this->user_db.transport_tab.ptr[ tport_id ];
        if ( debug_tran ) {
          n.printf( "transport_route fwd %.*s to %s\n", 
                    (int) pub.subject_len, pub.subject, rte->name );
        }
        b &= rte->sub_route.forward_except_with_cnt( pub, this->mgr.router_set,
                                                     rcnt, this );
        total_rcnt += rcnt;
      } while ( forward.next( tport_id ) );
    }
    if ( total_rcnt == 0 )
      n.null_route_count++;
    return this->check_flow_control( b );
  }
  return true;
}

void
TransportRoute::on_write_ready( void ) noexcept
{
  this->pop( EV_WRITE_POLL );
  if ( ! this->wait_empty() )
    this->notify_ready();
}

const char *
TransportRoute::connected_names( char *buf,  size_t buflen ) noexcept
{
  return this->user_db.uid_names( this->uid_connected, buf, buflen );
}

size_t
TransportRoute::port_status( char *buf,  size_t buflen ) noexcept
{
  buf[ 0 ] = '\0';
  if ( this->listener != NULL )
    return this->listener->print_sock_error( buf, buflen );
  if ( this->connect_ctx != NULL && this->connect_ctx->client != NULL )
    return this->connect_ctx->client->print_sock_error( buf, buflen );
  if ( this->pgm_tport != NULL )
    return this->pgm_tport->print_sock_error( buf, buflen );
  return 0;
}

void
TransportRoute::create_listener_mesh_url( void ) noexcept
{
  make_url_from_sock( this->user_db.string_tab, this->mesh_url,
                      *this->listener, "mesh" );
  this->mesh_url_hash = kv_crc_c( this->mesh_url.val, this->mesh_url.len, 0 );
  d_tran( "%s: %s (%x)\n", this->name, this->mesh_url.val,
          this->mesh_url_hash );
}

void
TransportRoute::create_listener_conn_url( void ) noexcept
{
  make_url_from_sock( this->user_db.string_tab, this->conn_url,
                      *this->listener, "tcp" );
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
  bool is_listener = this->is_listen(), b = false;
  if ( tport.type.equals( T_ANY, T_ANY_SZ ) ) {
    return true;
  }
  if ( tport.type.equals( T_RV, T_RV_SZ ) ) {
    return this->create_rv_listener( tport );
  }
  if ( tport.type.equals( T_NATS, T_NATS_SZ ) ) {
    return this->create_nats_listener( tport );
  }
  if ( tport.type.equals( T_REDIS, T_REDIS_SZ ) ) {
    return this->create_redis_listener( tport );
  }
  if ( tport.type.equals( T_TCP, T_TCP_SZ ) ) {
    if ( this->is_device() )
      this->dev_id = this;
    else
      this->dev_id = NULL;
    if ( this->is_listen() ) {
      this->listener = this->create_tcp_listener( tport );
      this->create_listener_conn_url();
      goto out_listen;
    }
    b = this->create_tcp_connect( tport );
    goto out_connect;
  }
  if ( tport.type.equals( T_PGM, T_PGM_SZ ) ) {
    this->set( TPORT_IS_MCAST );
    if ( is_listener ) {
      if ( this->create_pgm( TPORT_IS_LISTEN, tport ) )
        return true;
      this->set( TPORT_IS_SHUTDOWN );
      return false;
    }
    b = this->create_pgm( TPORT_IS_CONNECT, tport );
    goto out_connect;
  }
  if ( tport.type.equals( T_MESH, T_MESH_SZ ) ) {
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

    if ( ! is_listener || this->is_connect() ) {
      this->set( TPORT_IS_CONNECT );
      this->add_mesh_connect( NULL, 0 );
    }
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
  if ( &this->transport == &tport ) {
    if ( this->transport.type.equals( T_TCP, T_TCP_SZ ) ||
         this->transport.type.equals( T_MESH, T_MESH_SZ ) ) {
      this->notify_ctx = NULL;
      if ( this->listener != NULL &&
           this->listener->in_list( IN_ACTIVE_LIST ) ) {
        this->listener->idle_push( EV_SHUTDOWN );
        count++;
      }
      if ( this->connect_ctx != NULL ) {
        this->connect_ctx->state = ConnectCtx::CONN_SHUTDOWN;
        this->clear( TPORT_IS_INPROGRESS );
        if ( this->connect_ctx->client != NULL )
          this->connect_ctx->client->idle_push( EV_SHUTDOWN );
        count++;
      }
      uint32_t fd;
      for ( bool ok = this->connected.first( fd ); ok;
            ok = this->connected.next( fd ) ) {
        if ( fd <= this->poll.maxfd ) {
          EvSocket *s = this->poll.sock[ fd ];
          if ( s != NULL ) {
            if ( ! s->test( EV_SHUTDOWN ) ) {
              s->idle_push( EV_SHUTDOWN );
              count++;
            }
          }
        }
      }
      this->set( TPORT_IS_SHUTDOWN );
    }
    else if ( this->transport.type.equals( T_PGM, T_PGM_SZ ) ) {
      if ( ! this->test_set( TPORT_IS_SHUTDOWN ) ) {
        if ( this->pgm_tport != NULL )
          this->pgm_tport->idle_push( EV_SHUTDOWN );
        if ( this->ibx_tport != NULL )
          this->ibx_tport->idle_push( EV_SHUTDOWN );
        count++;
      }
      this->set( TPORT_IS_SHUTDOWN );
    }
  }
  else if ( this->ext != NULL ) {
    for ( IpcRte *el = this->ext->list.hd; el != NULL; el = el->next ) {
      if ( &el->transport == &tport ) {
        if ( el->listener->in_list( IN_ACTIVE_LIST ) ) {
          el->listener->idle_push( EV_SHUTDOWN );
          count++;
        }
      }
    }
  }
  return count;
}

bool
TransportRoute::start_listener( EvTcpListen *l,
                                ConfigTree::Transport &tport ) noexcept
{
  EvTcpTransportParameters parm;
  bool encrypt = false;
  parm.parse_tport( tport, PARAM_LISTEN, this->mgr );

  if ( tport.type.equals( T_TCP, T_TCP_SZ ) ||
       tport.type.equals( T_MESH, T_MESH_SZ ) ) {
    ((EvTcpTransportListen *) l)->encrypt = ! parm.noencrypt;
    encrypt = ! parm.noencrypt;
  }
  int status = l->listen( parm.host( 0 ), parm.port( 0 ), parm.opts );
  if ( status != 0 ) {
    fprintf( stderr, "%s.%u listen %s:%u failed\n", tport.tport.val,
             this->tport_id,
             ConfigTree::Transport::is_wildcard( parm.host( 0 ) ) ? "*" :
             parm.host( 0 ), parm.port( 0 ) );
    this->mgr.events.on_shutdown( this->tport_id, false );
    this->set( TPORT_IS_LISTEN | TPORT_IS_SHUTDOWN );
    return false;
  }
  this->mgr.events.on_connect( this->tport_id, TPORT_IS_LISTEN, encrypt );
  this->set( TPORT_IS_LISTEN );
  if ( parm.edge )
    this->set( TPORT_IS_EDGE );
  else
    this->clear( TPORT_IS_EDGE );
  this->clear( TPORT_IS_SHUTDOWN );
  this->printf( "%s listening on %s%s\n", tport.tport.val,
                l->peer_address.buf,
                this->is_edge() ? " edge is true" : "" );
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
  IpcRte *el = this->ext->find( tport );
  if ( el != NULL && el->listener->in_list( IN_ACTIVE_LIST ) )
    return true;
  EvRvTransportListen * l;
  if ( el == NULL ) {
    if ( this->rv_svc == NULL )
      this->rv_svc = new ( malloc( sizeof( RvTransportService ) ) )
        RvTransportService( *this );
    l = new ( aligned_malloc( sizeof( EvRvTransportListen ) ) )
      EvRvTransportListen( this->poll, *this, *this->rv_svc );
    el = new ( ::malloc( sizeof( IpcRte ) ) ) IpcRte( tport, l );
    this->ext->list.push_tl( el );
  }
  else {
    l = (EvRvTransportListen *) el->listener;
  }
  bool b;
  if ( tport.get_route_bool( R_USE_SERVICE_PREFIX, b ) )
    l->has_service_prefix = b;
  if ( tport.get_route_bool( R_NO_PERMANENT, b ) )
    this->rv_svc->no_permanent |= b;
  if ( tport.get_route_bool( R_NO_MCAST, b ) )
    this->rv_svc->no_mcast |= b;
  if ( tport.get_route_bool( R_NO_FAKEIP, b ) )
    this->rv_svc->no_fakeip |= b;
  return this->start_listener( l, tport );
}

void
TransportRoute::get_tport_service( ConfigTree::Transport &tport,
                                   const char *&service,  size_t &service_len,
                                   uint16_t &rv_service ) noexcept
{
  const char * tmp = NULL,
             * net = NULL;
  rv_service = 0;

  if ( ! tport.get_route_str( R_SERVICE, tmp ) || ::strlen( tmp ) == 0 )
    tmp = tport.type.val;

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

    StringTab & stab = this->user_db.string_tab;
    StringVal   svc_tmp;
    stab.ref_string( buf, 1 + tmplen, svc_tmp );
    ::free( buf );
    tmp = svc_tmp.val;
  }
  service     = tmp;
  service_len = ::strlen( tmp );

  if ( service_len > 0 ) {
    rv_service = SessionMgr::sub_has_rv_service( service, service_len );

    this->printf( "%s.%s service: %.*s\n", tport.type.val, tport.tport.val,
                  (int) service_len - 2, &service[ 1 ] );
    if ( rv_service != 0 ) {
      if ( this->rv_svc == NULL )
        this->rv_svc = new ( malloc( sizeof( RvTransportService ) ) )
          RvTransportService( *this );
    }
  }

  if ( tport.get_route_str( R_NETWORK, net ) ) {
    this->mgr.add_network( net, ::strlen( net ), &service[ 1 ],
                           service_len - 2, false );
  }
}

bool
TransportRoute::create_nats_listener( ConfigTree::Transport &tport ) noexcept
{
  IpcRte *el = this->ext->find( tport );
  if ( el != NULL && el->listener->in_list( IN_ACTIVE_LIST ) )
    return true;

  const char * service     = NULL;
  size_t       service_len = 0;
  uint16_t     rv_service  = 0;

  this->get_tport_service( tport, service, service_len, rv_service );

  EvNatsTransportListen * l;
  if ( el == NULL ) {
    l = new ( aligned_malloc( sizeof( EvNatsTransportListen ) ) )
      EvNatsTransportListen( this->poll, *this );
    el = new ( ::malloc( sizeof( IpcRte ) ) ) IpcRte( tport, l );
    this->ext->list.push_tl( el );
  }
  else {
    l = (EvNatsTransportListen *) el->listener;
  }
  l->service     = service;
  l->service_len = service_len;
  l->rv_service  = rv_service;
  return this->start_listener( l, tport );
}

bool
TransportRoute::create_redis_listener( ConfigTree::Transport &tport ) noexcept
{
  IpcRte *el = this->ext->find( tport );
  if ( el != NULL && el->listener->in_list( IN_ACTIVE_LIST ) )
    return true;

  const char * service     = NULL;
  size_t       service_len = 0;
  uint16_t     rv_service  = 0;

  this->get_tport_service( tport, service, service_len, rv_service );

  EvRedisTransportListen * l;
  if ( el == NULL ) {
    l = new ( aligned_malloc( sizeof( EvRedisTransportListen ) ) )
      EvRedisTransportListen( this->poll, *this );
    el = new ( ::malloc( sizeof( IpcRte ) ) ) IpcRte( tport, l );
    this->ext->list.push_tl( el );
  }
  else {
    l = (EvRedisTransportListen *) el->listener;
  }
  l->service     = service;
  l->service_len = service_len;
  l->rv_service  = rv_service;
  return this->start_listener( l, tport );
}

bool
TransportRoute::create_tcp_connect( ConfigTree::Transport &tport ) noexcept
{
  EvTcpTransportParameters parm;
  parm.parse_tport( tport, PARAM_NB_CONNECT, this->mgr );

  if ( ! this->is_device() ) {
    if ( this->connect_ctx == NULL )
      this->connect_ctx = this->mgr.connect_mgr.create( this->tport_id );

    this->printf( "create_tcp_connect timeout=%u encrypt=%s host=%s port=%d\n",
                  parm.timeout, parm.noencrypt ? "false" : "true",
                  parm.host( 0 ) ? parm.host( 0 ) : "*", parm.port( 0 ) );

    this->connect_ctx->connect( parm.host( 0 ), parm.port( 0 ), parm.opts,
                                parm.timeout );
  }
  return true;
}

bool
TransportRoute::add_tcp_connect( const char *conn_url,
                                 uint32_t conn_hash ) noexcept
{
  TransportRoute   * rte = this;
  EvTcpTransportOpts opts;
  char         host_buf[ MAX_TCP_HOST_LEN ];
  size_t       len  = sizeof( host_buf );
  const char * host = conn_url;
  int          port;

  opts.parse( rte->transport, PARAM_NB_CONNECT, this->mgr );

  rte->printf( "add_tcp_connect timeout=%u encrypt=%s %s (%x)\n",
                opts.timeout, opts.noencrypt ? "false" : "true", conn_url,
                conn_hash );
  if ( rte->connect_ctx != NULL ) {
    if ( rte->connect_ctx->state != ConnectCtx::CONN_SHUTDOWN ) {
      if ( rte->conn_hash == conn_hash ) {
        if ( rte->connect_ctx->state == ConnectCtx::CONN_IDLE ) {
          rte->connect_ctx->opts    = opts.opts;
          rte->connect_ctx->timeout = opts.timeout;
          rte->connect_ctx->reconnect();
        }
        return true;
      }
    }
    rte = NULL;
  }
  if ( rte == NULL || rte->connect_ctx == NULL ) {
    rte = this->mgr.add_tcp_rte( *this, conn_hash );
    if ( rte == NULL )
      return false;
    if ( rte->connect_ctx == NULL )
      rte->connect_ctx = rte->mgr.connect_mgr.create( rte->tport_id );
  }
  port = ConfigTree::Transport::get_host_port( host, host_buf, len,
                                               this->mgr.tree.hosts );
  rte->conn_hash = conn_hash;
  rte->connect_ctx->connect( host, port, opts.opts, opts.timeout );
  return true;
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

bool
TransportRoute::create_pgm( int kind,  ConfigTree::Transport &tport ) noexcept
{
  EvPgmTransportParameters parm;
  char         net_buf[ 1024 ];
  const char * name = ( kind & TPORT_IS_LISTEN ) ? R_LISTEN : R_CONNECT;
  parm.parse_tport( name, tport, net_buf,
                    this->user_db.reliability, this->mgr );
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
  len = min_int( len, (int) sizeof( tmp ) - 1 );
  this->user_db.string_tab.ref_string( tmp, len, this->ucast_url );
  this->ucast_url_hash = kv_crc_c( tmp, len, 0 );
  this->inbox          = *s;
  this->mcast          = *l;
  d_tran( "set mcast_fd=%u inbox_route=%u\n", l->fd, s->fd );
  return true;
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
namespace {
enum {
  IS_SUB     = 1,
  IS_UNSUB   = 2,
  IS_PAT     = 4,
  IS_PSUB    = IS_PAT | IS_SUB,
  IS_PUNSUB  = IS_PAT | IS_UNSUB,
  IS_REPEAT  = 8,
  IS_RESUB   = IS_SUB | IS_REPEAT,
  IS_REPSUB  = IS_PSUB | IS_REPEAT,
  IS_CONSOLE = 16,
  IS_SESSION = 32,
  IS_RV      = 64,
  IS_NATS    = 128,
  IS_REDIS   = 256,
  IS_KV      = 512,
  IS_INBOX   = 1024,
  IS_QUEUE   = 2048
};
}
/* src_type :
 * 'C' = console, 'M' : session, 'V' = RV, ''N' = NATS, 'R' = redis, 'K' = kv */
static inline int src_type_flag( char src_type ) {
  switch ( src_type ) {
    case 'C': return IS_CONSOLE;
    case 'M': return IS_SESSION;
    case 'V': return IS_RV;
    case 'N': return IS_NATS;
    case 'R': return IS_REDIS;
    case 'K': return IS_KV;
    default : return 0;
  }
}
static inline int src_type_flag( NotifySub &sub ) {
  int fl = src_type_flag( sub.src_type );
  if ( sub.is_notify_queue() )
    fl |= IS_QUEUE;
  switch ( SubDB::match_ipc_any( sub.subject, sub.subject_len ) ) {
    default: break;
    case SubDB::IPC_IS_INBOX_PREFIX:
    case SubDB::IPC_IS_INBOX: fl |= IS_INBOX; break;
    case SubDB::IPC_IS_QUEUE: fl |= IS_QUEUE; break;
  }
  return fl;
}
static inline int src_type_flag( NotifyPattern &pat ) {
  int fl = src_type_flag( pat.src_type );
  if ( pat.is_notify_queue() )
    fl |= IS_QUEUE;
  switch ( SubDB::match_ipc_any( pat.pattern, pat.pattern_len ) ) {
    default: break;
    case SubDB::IPC_IS_INBOX_PREFIX:
    case SubDB::IPC_IS_INBOX: fl |= IS_INBOX; break;
    case SubDB::IPC_IS_QUEUE: fl |= IS_QUEUE; break;
  }
  return fl;
}

void
IpcRteList::on_sub( NotifySub &sub ) noexcept
{
  int flags = IS_SUB | src_type_flag( sub );
  if ( ( flags & ( IS_CONSOLE | IS_SESSION ) ) == 0 ) {
    if ( ( flags & IS_QUEUE ) == 0 )
      this->rte.mgr.sub_db.ipc_sub_start( sub, this->rte.tport_id );
    else
      this->rte.mgr.sub_db.queue_sub_update( (NotifyQueue &) sub,
                                             this->rte.tport_id, 1 );
  }
  if ( ( flags & ( IS_SESSION | IS_RV ) ) == 0 )
    this->send_listen( sub.src, sub.subject, sub.subject_len,
                       (const char *) sub.reply, sub.reply_len, 1, flags );
  d_tran( "on_sub(%.*s) rcnt=%u src_type=%c\n", (int) sub.subject_len,
          sub.subject, sub.sub_count, sub.src_type );
}

void
IpcRteList::on_unsub( NotifySub &sub ) noexcept
{
  int flags = IS_UNSUB | src_type_flag( sub );
  if ( ( flags & ( IS_SESSION | IS_RV ) ) == 0 )
    this->send_listen( sub.src, sub.subject, sub.subject_len, NULL, 0, 0,
                       flags );
  if ( ( flags & ( IS_CONSOLE | IS_SESSION ) ) == 0 ) {
    if ( ( flags & IS_QUEUE ) == 0 ) {
      if ( sub.sub_count == 0 )
        this->rte.mgr.sub_db.ipc_sub_stop( sub, this->rte.tport_id );
    }
    else
      this->rte.mgr.sub_db.queue_sub_update( (NotifyQueue &) sub,
                                             this->rte.tport_id, 0 );
  }
  d_tran( "on_unsub(%.*s) rcnt=%u src_type=%c\n", (int) sub.subject_len,
          sub.subject, sub.sub_count, sub.src_type );
}

void
IpcRteList::on_resub( NotifySub &sub ) noexcept
{
  int flags = IS_RESUB | src_type_flag( sub );
  if ( ( flags & ( IS_SESSION | IS_RV ) ) == 0 ) {
    if ( sub.get_notify_type() == NOTIFY_ADD_REF )
      this->send_listen( sub.src, sub.subject, sub.subject_len,
                         (const char *) sub.reply, sub.reply_len, sub.sub_count,
                         flags );
  }
#if 0
  if ( ( flags & ( IS_CONSOLE | IS_SESSION ) ) == 0 ) {
    if ( ( flags & IS_QUEUE ) != 0 )
      this->rte.mgr.sub_db.queue_sub_update( (NotifyQueue &) sub,
                                            this->rte.tport_id, sub.sub_count );
  }
#endif
}

void
IpcRteList::on_psub( NotifyPattern &pat ) noexcept
{
  int flags = IS_PSUB | src_type_flag( pat );
  if ( ( flags & ( IS_CONSOLE | IS_SESSION ) ) == 0 ) {
    if ( ( flags & IS_QUEUE ) == 0 )
      this->rte.mgr.sub_db.ipc_psub_start( pat, this->rte.tport_id );
    else
      this->rte.mgr.sub_db.queue_psub_update( (NotifyPatternQueue &) pat,
                                              this->rte.tport_id, 1 );
  }
  if ( ( flags & ( IS_SESSION | IS_RV ) ) == 0 )
    this->send_listen( pat.src, pat.pattern, pat.pattern_len, NULL, 0, 1,
                       flags );
  d_tran( "on_psub(%.*s) rcnt=%u src_type=%c\n", (int) pat.pattern_len,
        pat.pattern, pat.sub_count, pat.src_type );
}

bool
IpcRteList::punsub_test( NotifyPattern &pat ) noexcept
{
  if ( pat.refp != NULL ) {
    RouteRef & ref  = *pat.refp;
    EvPoll   & poll = this->rte.poll;
    for ( uint32_t i = 0; i < ref.rcnt; i++ ) {
      uint32_t r = ref.routes[ i ];
      if ( r != (uint32_t) pat.src.fd && r <= poll.maxfd ) {
        EvSocket *s;
        if ( (s = poll.sock[ r ]) != NULL ) {
          uint8_t v = s->is_psubscribed( pat );
          if ( ( v & EV_NOT_SUBSCRIBED ) == 0 )
            return true;
        }
      }
    }
  }
  return false;
}

void
IpcRteList::on_punsub( NotifyPattern &pat ) noexcept
{
  int flags = IS_PUNSUB | src_type_flag( pat );
  uint32_t count = pat.sub_count;
  if ( ( flags & ( IS_SESSION | IS_RV ) ) == 0 )
    this->send_listen( pat.src, pat.pattern, pat.pattern_len, NULL, 0, 0,
                       flags );
  if ( ( flags & ( IS_CONSOLE | IS_SESSION ) ) == 0 ) {
    if ( ( flags & IS_QUEUE ) == 0 ) {
      if ( count != 0 && ! this->punsub_test( pat ) )
        count = 0;
      if ( count == 0 )
        this->rte.mgr.sub_db.ipc_psub_stop( pat, this->rte.tport_id );
    }
    else
      this->rte.mgr.sub_db.queue_psub_update( (NotifyPatternQueue &) pat,
                                              this->rte.tport_id, 0 );
  }
  d_tran( "on_punsub(%.*s) rcnt=%u src_type=%c\n", (int) pat.pattern_len,
        pat.pattern, pat.sub_count, pat.src_type );
}

void
IpcRteList::on_repsub( NotifyPattern &pat ) noexcept
{
  int flags = IS_REPSUB | src_type_flag( pat );
  if ( ( flags & ( IS_SESSION | IS_RV ) ) == 0 ) {
    if ( pat.get_notify_type() == NOTIFY_ADD_REF )
      this->send_listen( pat.src, pat.pattern, pat.pattern_len, NULL, 0,
                         pat.sub_count, flags );
  }
#if 0
  if ( ( flags & ( IS_CONSOLE | IS_SESSION ) ) == 0 ) {
    if ( ( flags & IS_QUEUE ) != 0 )
      this->rte.mgr.sub_db.queue_psub_update( (NotifyPatternQueue &) pat,
                                            this->rte.tport_id, pat.sub_count );
  }
#endif
}

void
IpcRteList::send_listen( const PeerId &src,  const char *subj,  size_t sublen,
                         const char *reply,  size_t replen,
                         uint32_t refcnt,  int sub_flags ) noexcept
{
  RvSvc   * rv_svc  = NULL;
  RvHost ** host    = NULL;
  char      session[ EvSocket::MAX_SESSION_LEN ];
  size_t    session_len;
  uint16_t  match_svc, svc;
  bool      is_sub = ( sub_flags & IS_SUB ) != 0;

  match_svc = SessionMgr::sub_has_rv_service( subj, sublen );
  if ( match_svc == 0 )
    return;
  if ( ( sub_flags & IS_CONSOLE ) != 0 ) {
    if ( (rv_svc = this->rte.mgr.get_rv_session( match_svc, is_sub )) == NULL )
      return;
    host = &rv_svc->host;
    session_len = rv_svc->session_len;
    ::memcpy( session, rv_svc->session, session_len );
    session[ session_len ] = '\0';
  }
  else {
    const EvSocket &sock = (const EvSocket &) src;
    /* redis patterns are different beats, need a conversion */
    if ( ( sub_flags & IS_PAT ) != 0 ) {
      if ( ::strcmp( sock.kind, "redis" ) == 0 )
        return; /* convert to rv wildcard ? */
    }
    /* needs a host and a service */
    if ( ! sock.get_service( &host, svc ) || svc == 0 )
      return;
    if ( (uint32_t) svc != match_svc || host == NULL || *host == NULL )
      return;
    /* needs a session */
    session_len = sock.get_session( svc, session );
    if ( session_len == 0 )
      return;
  }
  size_t service_len = (*host)->service_len; /* strip _7500. */
  if ( sublen > service_len + 2 ) {
    subj   = &subj[ service_len + 2 ];
    sublen = sublen - ( service_len + 2 );

    if ( ( sub_flags & IS_SUB ) != 0 ) {
      if ( replen > service_len + 2 ) {
        reply   = &reply[ service_len + 2 ];
        replen -= service_len + 2;
      }
      (*host)->send_listen_start( session, session_len, subj, sublen,
                                  reply, replen, refcnt );
    }
    else {
      (*host)->send_listen_stop( session, session_len, subj, sublen, refcnt );
    }
  }
}

void
IpcRteList::on_reassert( uint32_t , kv::RouteVec<kv::RouteSub> &,
                         kv::RouteVec<kv::RouteSub> & ) noexcept
{
  d_tran( "on_reassert()\n" );
}

void
IpcRteList::on_bloom_ref( BloomRef &ref ) noexcept
{
  d_tran( "ipc on_bloom_ref %s\n", ref.name );
}

void
IpcRteList::on_bloom_deref( BloomRef &ref ) noexcept
{
  d_tran( "ipc on_bloom_deref %s\n", ref.name );
}

void
IpcRteList::on_sub_q( NotifyQueue &sub ) noexcept
{
  this->on_sub( sub );
}

void
IpcRteList::on_resub_q( NotifyQueue &sub ) noexcept
{
  this->on_resub( sub );
}

void
IpcRteList::on_unsub_q( NotifyQueue &sub ) noexcept
{
  this->on_unsub( sub );
}

void
IpcRteList::on_psub_q( NotifyPatternQueue &pat ) noexcept
{
  this->on_psub( pat );
}

void
IpcRteList::on_repsub_q( NotifyPatternQueue &pat ) noexcept
{
  this->on_repsub( pat );
}

void
IpcRteList::on_punsub_q( NotifyPatternQueue &pat ) noexcept
{
  this->on_punsub( pat );
}
