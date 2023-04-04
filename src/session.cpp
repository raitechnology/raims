#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#define __STDC_FORMAT_MACROS
#include <inttypes.h>
#include <raikv/os_file.h>
#define DECLARE_SUB_CONST
#define INCLUDE_FRAME_CONST
#define DECLARE_CONFIG_CONST
#include <raims/session.h>
#include <raims/transport.h>
#include <raims/ev_name_svc.h>
#include <raims/ev_web.h>
#include <raims/ev_telnet.h>

using namespace rai;
using namespace ms;
using namespace kv;
using namespace md;

extern "C" {
const char *
ms_get_version( void )
{
  return kv_stringify( MS_VER );
}
}
int rai::ms::dbg_flags; /* TCP_DBG | PGM_DBG | IBX_DBG */

IpcRoute::IpcRoute( EvPoll &p,  SessionMgr &m ) noexcept
        : EvSocket( p, p.register_type( "ipc_route" ) ),
          mgr( m ), user_db( m.user_db ), sub_db( m.sub_db ) {
  this->sock_opts = OPT_NO_POLL;
  this->bp_flags  = BP_FORWARD | BP_NOTIFY;
}

void
IpcRoute::on_write_ready( void ) noexcept
{
  this->pop( EV_WRITE_POLL );
  if ( ! this->wait_empty() )
    this->notify_ready();
}

ConsoleRoute::ConsoleRoute( EvPoll &p,  SessionMgr &m ) noexcept
            : EvSocket( p, p.register_type( "console_route" ) ),
              mgr( m ), user_db( m.user_db ), sub_db( m.sub_db ) {
  this->sock_opts = OPT_NO_POLL;
}

QueueRoute::QueueRoute( EvPoll &p,  SessionMgr &m ) noexcept
          : EvSocket( p, p.register_type( "queue_route" ) ),
            mgr( m ), user_db( m.user_db ), sub_db( m.sub_db ) {
  this->sock_opts = OPT_NO_POLL;
}

SessionMgr::SessionMgr( EvPoll &p,  Logger &l,  ConfigTree &c,
                        ConfigTree::User &u,  ConfigTree::Service &s,
                        StringTab &st,  ConfigStartup &start ) noexcept
           : EvSocket( p, p.register_type( "session_mgr" ) ),
             ipc_rt( p, *this ), console_rt( p, *this ), queue_rt( p, *this ),
             tree( c ), user( u ), svc( s ), startup( start ), timer_id( 0 ),
             timer_mono_time( 0 ), timer_time( 0 ),
             timer_converge_time( 0 ), converge_seqno( 0 ),
             timer_start_mono( 0 ), timer_start( 0 ), timer_ival( 0 ),
             user_db( p, u, s, *this, this->sub_db, st, this->events,
                      this->router_set ),
             sub_db( p, this->user_db, *this ),
             sys_bloom( 0, "(sys)", p.g_bloom_db ), events( &p.now_ns ),
             console( *this ), log( l ),
             connect_mgr( *this, this->user_db, p, p.register_type( "ev_tcp_tport_client" ) ),
             pub_window_mono_time( 0 ), sub_window_mono_time( 0 ),
             name_svc_mono_time( 0 ),
             pub_window_size( 4 * 1024 * 1024 ),
             sub_window_size( 8 * 1024 * 1024 ),
             pub_window_ival( sec_to_ns( 10 ) ),
             sub_window_ival( sec_to_ns( 10 ) ),
             tcp_timeout( 10 ), tcp_noencrypt( false ), tcp_ipv4( true ),
             tcp_ipv6( true ), session_started( false ), idle_busy( 16 )
{
  this->sock_opts = OPT_NO_POLL;
  this->bp_flags  = BP_FORWARD | BP_NOTIFY;
  this->next_timer = (uint64_t) this->sock_type << 56;
  this->tcp_accept_sock_type = p.register_type( "ev_tcp_tport" );
  this->tcp_connect_sock_type = p.register_type( "ev_tcp_tport_client" );
  hello_h = kv_crc_c( X_HELLO, X_HELLO_SZ, 0 );
  hb_h    = kv_crc_c( X_HB,    X_HB_SZ,    0 );
  bye_h   = kv_crc_c( X_BYE,   X_BYE_SZ,   0 );
  name_h  = kv_crc_c( X_NAME,  X_NAME_SZ,  0 );
  add_h   = kv_crc_c( Z_ADD,   Z_ADD_SZ,   0 );
  del_h   = kv_crc_c( Z_DEL,   Z_DEL_SZ,   0 );
  blm_h   = kv_crc_c( Z_BLM,   Z_BLM_SZ,   0 );
  adj_h   = kv_crc_c( Z_ADJ,   Z_ADJ_SZ,   0 );
  uint32_t seed;
  seed    = p.sub_route.prefix_seed( S_JOIN_SZ ),
  join_h  = kv_crc_c( S_JOIN, S_JOIN_SZ, seed );
  seed    = p.sub_route.prefix_seed( S_LEAVE_SZ ),
  leave_h = kv_crc_c( S_LEAVE, S_LEAVE_SZ, seed );
  seed    = p.sub_route.prefix_seed( P_PSUB_SZ ),
  psub_h  = kv_crc_c( P_PSUB, P_PSUB_SZ, seed );
  seed    = p.sub_route.prefix_seed( P_PSTOP_SZ ),
  pstop_h = kv_crc_c( P_PSTOP, P_PSTOP_SZ, seed );
  ::memset( this->msg_recv_counter, 0, sizeof( this->msg_recv_counter ) );

  md_init_auto_unpack();
  CabaMsg::init_auto_unpack();
}

void
SessionMgr::on_write_ready( void ) noexcept
{
  this->pop( EV_WRITE_POLL );
  if ( ! this->wait_empty() )
    this->notify_ready();
}

bool
SessionMgr::init_param( void ) noexcept
{
  const char *s = "", *val = NULL;
  uint64_t hb_ival, rel_ival, time_val, bytes_val;
  bool ipv4_only = false, ipv6_only = false;

  if ( this->tree.parameters.find( s = P_IDLE_BUSY, val, NULL ) ) {
    uint64_t idle = 0;
    if ( ! ConfigTree::string_to_uint( val, idle ) )
      goto fail;
    if ( idle >= ((uint64_t) 1 << 32) )
      this->idle_busy = 0xffffffffU;
    else
      this->idle_busy = (uint32_t) idle;
  }
  if ( this->tree.parameters.find( s = P_PUB_WINDOW_SIZE, val, NULL ) &&
       ! ConfigTree::string_to_bytes( val, this->pub_window_size ) ) goto fail;
  if ( this->tree.parameters.find( s = P_SUB_WINDOW_SIZE, val, NULL ) &&
       ! ConfigTree::string_to_bytes( val, this->sub_window_size ) ) goto fail;
  if ( this->tree.parameters.find( s = P_PUB_WINDOW_TIME, val, NULL ) &&
       ! ConfigTree::string_to_nanos( val, this->pub_window_ival ) ) goto fail;
  if ( this->tree.parameters.find( s = P_SUB_WINDOW_TIME, val, NULL ) &&
       ! ConfigTree::string_to_nanos( val, this->sub_window_ival ) ) goto fail;
  if ( this->tree.parameters.find( s = P_HEARTBEAT, val, NULL ) ) {
    if ( ! ConfigTree::string_to_secs( val, hb_ival ) ) goto fail;
    this->user_db.hb_interval = (uint32_t) hb_ival;
  }
  if ( this->tree.parameters.find( s = P_RELIABILITY, val, NULL ) ) {
    if ( ! ConfigTree::string_to_secs( val, rel_ival ) ) goto fail;
    this->user_db.reliability = (uint32_t) rel_ival;
  }
  if ( this->tree.parameters.find( s = P_TIMESTAMP, val, NULL ) ) {
    if ( val != NULL &&
         ( ::strcmp( val, "gmt" ) == 0 || ::strcmp( val, "GMT" ) == 0 ) )
      tz_stamp_gmt = true;
  }
  if ( this->tree.parameters.find( s = P_TCP_NOENCRYPT, val, NULL ) ) {
    if ( ! ConfigTree::string_to_bool( val, this->tcp_noencrypt ) ) goto fail;
  }
  if ( this->tree.parameters.find( s = P_TCP_TIMEOUT, val, NULL ) ) {
    if ( ! ConfigTree::string_to_secs( val, time_val ) ) goto fail;
    this->tcp_timeout = (int) time_val;
  }
  if ( this->tree.parameters.find( s = P_TCP_WRITE_TIMEOUT, val, NULL ) ) {
    if ( ! ConfigTree::string_to_nanos( val, time_val ) ) goto fail;
    this->poll.wr_timeout_ns = time_val;
    this->poll.so_keepalive_ns = time_val;
  }
  if ( this->tree.parameters.find( s = P_TCP_WRITE_HIGHWATER, val, NULL ) ) {
    if ( ! ConfigTree::string_to_bytes( val, bytes_val ) ) goto fail;
    this->poll.send_highwater = (uint32_t) bytes_val;
  }
  if ( this->tree.parameters.find( s = P_TCP_IPV4ONLY, val, NULL ) ) {
    if ( ! ConfigTree::string_to_bool( val, ipv4_only ) ) goto fail;
  }
  if ( this->tree.parameters.find( s = P_TCP_IPV6ONLY, val, NULL ) ) {
    if ( ! ConfigTree::string_to_bool( val, ipv6_only ) ) goto fail;
  }
  if ( ipv4_only && ! ipv6_only ) {
    this->tcp_ipv4 = true;
    this->tcp_ipv6 = false;
  }
  if ( ipv6_only && ! ipv4_only ) {
    this->tcp_ipv6 = true;
    this->tcp_ipv4 = false;
  }
  update_tz_stamp();
  return true;

fail:
  fprintf( stderr, "bad %s value: %s\n", s, val );
  return false;
}

int
SessionMgr::init_sock( void ) noexcept
{
  this->events.startup( this->user_db.start_time );

  int xfd[ 4 ] = { this->poll.get_null_fd(),
                   this->poll.get_null_fd(),
                   this->poll.get_null_fd(),
                   this->poll.get_null_fd() };
  #define swap( x, y ) { int z = x; x = y; y = z; }
  for ( int i = 0; i < 3; i++ ) {
    for ( int j = i+1; j < 4; j++ ) {
      if ( xfd[ i ] > xfd[ j ] )
        swap( xfd[ i ], xfd[ j ] );
    }
  }
  #undef swap
  /* make ipc, queue, console the lower fd number, dispatched first */
  int ifd = xfd[ 0 ],
      qfd = xfd[ 1 ],
      cfd = xfd[ 2 ],
      sfd = xfd[ 3 ];
  this->router_set.add( ifd );
  this->router_set.add( qfd );
  this->router_set.add( cfd );
  this->router_set.add( sfd );

  char buf[ 256 ];
  size_t sz = min_int<size_t>( this->svc.svc.len, sizeof( buf ) - 16 );
  CatPtr p( buf );

  p.begin().x( this->svc.svc.val, sz ).s( ".ipc" ).end();
  this->ipc_rt.PeerData::init_peer( this->poll.get_next_id(), ifd, -1, NULL, "ipc" );
  this->ipc_rt.PeerData::set_name( buf, p.len() );

  p.begin().x( this->svc.svc.val, sz ).s( ".queue" ).end();
  this->queue_rt.PeerData::init_peer( this->poll.get_next_id(), qfd, -1, NULL,
                                      "queue" );
  this->queue_rt.PeerData::set_name( buf, p.len() );

  p.begin().x( this->svc.svc.val, sz ).s( ".console" ).end();
  this->console_rt.PeerData::init_peer( this->poll.get_next_id(), cfd, -1, NULL,
                                        "console" );
  this->console_rt.PeerData::set_name( buf, p.len() );

  p.begin().x( this->svc.svc.val, sz ).s( ".session" ).end();
  this->PeerData::init_peer( this->poll.get_next_id(), sfd, -1, NULL, "session" );
  this->PeerData::set_name( buf, p.len() );

  int status = this->poll.add_sock( &this->ipc_rt );
  if ( status == 0 )
    status = this->poll.add_sock( &this->console_rt );
  if ( status == 0 )
    status = this->poll.add_sock( &this->queue_rt );
  if ( status == 0 )
    status = this->poll.add_sock( this );
  return status;
}

int
SessionMgr::init_session( const CryptPass &pwd ) noexcept
{
  if ( ! this->in_list( IN_ACTIVE_LIST ) ) {
    int status = this->init_sock();
    if ( status != 0 )
      return status;
  }
  if ( ! this->user_db.init( pwd, this->tree ) ) {
    fprintf( stderr, "User DB failed to init\n" );
    return -1;
  }
  this->sub_db.init();
  this->console.update_prompt();
  char nonce_buf[ NONCE_B64_LEN + 1 ];
  printf( "session %s.%s[%s] started, start time %" PRIu64 ".%" PRIu64 "\n",
          this->user.user.val,
          this->svc.svc.val,
          this->user_db.bridge_id.nonce.to_base64_str( nonce_buf ),
          this->user_db.start_time / SEC_TO_NS,
          this->user_db.start_time % SEC_TO_NS );
  /*this->sub_seqno = 0;*/

  InboxBuf ibx( this->user_db.bridge_id );
  this->ibx.len = (uint16_t) ibx.len();
  this->ibx.init( ibx, _AUTH     , U_INBOX_AUTH );
  this->ibx.init( ibx, _SUBS     , U_INBOX_SUBS );
  this->ibx.init( ibx, _PING     , U_INBOX_PING );
  this->ibx.init( ibx, _PONG     , U_INBOX_PONG );
  this->ibx.init( ibx, _REM      , U_INBOX_REM );
  this->ibx.init( ibx, _RESUB    , U_INBOX_RESUB );
  this->ibx.init( ibx, _REPSUB   , U_INBOX_REPSUB );
  this->ibx.init( ibx, _ADD_RTE  , U_INBOX_ADD_RTE );
  this->ibx.init( ibx, _SYNC_REQ , U_INBOX_SYNC_REQ );
  this->ibx.init( ibx, _SYNC_RPY , U_INBOX_SYNC_RPY );
  this->ibx.init( ibx, _BLOOM_REQ, U_INBOX_BLOOM_REQ );
  this->ibx.init( ibx, _BLOOM_RPY, U_INBOX_BLOOM_RPY );
  this->ibx.init( ibx, _ADJ_REQ  , U_INBOX_ADJ_REQ );
  this->ibx.init( ibx, _ADJ_RPY  , U_INBOX_ADJ_RPY );
  this->ibx.init( ibx, _MESH_REQ , U_INBOX_MESH_REQ );
  this->ibx.init( ibx, _MESH_RPY , U_INBOX_MESH_RPY );
  this->ibx.init( ibx, _UCAST_REQ, U_INBOX_UCAST_REQ );
  this->ibx.init( ibx, _UCAST_RPY, U_INBOX_UCAST_RPY );
  this->ibx.init( ibx, _TRACE    , U_INBOX_TRACE );
  this->ibx.init( ibx, _ACK      , U_INBOX_ACK );
  this->ibx.init( ibx, _ANY      , U_INBOX_ANY );
  this->ibx.init( ibx, _SYNC     , U_INBOX_SYNC );

  McastBuf mcb;
  this->mch.len = (uint16_t) mcb.len();
  this->mch.init( mcb, _PING     , U_MCAST_PING );
  this->mch.init( mcb, _SYNC     , U_MCAST_SYNC );

  if ( ! this->ibx.is_full() || ! this->mch.is_full() ) {
    fprintf( stderr, "not fully initialized\n" );
    exit( 1 );
  }
  /*         subscribe to    _I.USER.NONCE.> */
  /* can't add to u_tab[] maybe collision, since it is rand */
  this->ibx.hash = this->add_wildcard_rte( ibx.buf, this->ibx.len, U_INBOX );
  this->mch.hash = this->add_wildcard_rte( mcb.buf, this->mch.len, U_MCAST );

  this->add_rte( X_HELLO, X_HELLO_SZ, hello_h, U_SESSION_HELLO );/*_X.HELLO */
  this->add_rte( X_HB   , X_HB_SZ   , hb_h   , U_SESSION_HB );   /*_X.HB    */
  this->add_rte( X_BYE  , X_BYE_SZ  , bye_h  , U_SESSION_BYE );  /*_X.BYE   */
  this->add_rte( Z_ADD  , Z_ADD_SZ  , add_h  , U_PEER_ADD );     /*_Z.ADD   */
  this->add_rte( Z_DEL  , Z_DEL_SZ  , del_h  , U_PEER_DEL );     /*_Z.DEL   */
  this->add_rte( Z_BLM  , Z_BLM_SZ  , blm_h  , U_BLOOM_FILTER ); /*_Z.BLM   */
  this->add_rte( Z_ADJ  , Z_ADJ_SZ  , adj_h  , U_ADJACENCY );    /*_Z.ADJ   */
  this->add_wildcard_rte( S_JOIN , S_JOIN_SZ , U_SUB_JOIN );     /*_S.JOIN. */
  this->add_wildcard_rte( S_LEAVE, S_LEAVE_SZ, U_SUB_LEAVE );    /*_S.LEAV. */
  this->add_wildcard_rte( P_PSUB , P_PSUB_SZ , U_PSUB_START );   /*_P.PSUB. */
  this->add_wildcard_rte( P_PSTOP, P_PSTOP_SZ, U_PSUB_STOP );    /*_P.PSTP. */

  this->sub_db.bloom.add_route( this->ibx.len, this->ibx.hash );
  this->sub_db.bloom.add_route( this->mch.len, this->mch.hash );
  this->sys_bloom.add_route( this->ibx.len, this->ibx.hash );
  this->sys_bloom.add_route( this->mch.len, this->mch.hash );

  return 0;
}

void
SessionMgr::add_rte( const char *sub,  size_t sub_len,  uint32_t hash,
                     PublishType type ) noexcept
{
  this->sys_bloom.add( hash );
  if ( ! this->u_tab.set( hash, sub_len, type ) ) {
    fprintf( stderr, "hash %x pref %.*s repeats\n",
             hash, (int) sub_len, sub );
    exit( 1 );
  }
}

uint32_t
SessionMgr::add_wildcard_rte( const char *prefix,  size_t pref_len,
                              PublishType type ) noexcept
{
  uint32_t seed = this->poll.sub_route.prefix_seed( pref_len ),
           hash = kv_crc_c( prefix, pref_len, seed );
  this->sys_bloom.add_route( (uint16_t) pref_len, hash );
  if ( type != U_INBOX && type != U_MCAST ) {
    if ( ! this->u_tab.set( hash, pref_len, type ) ) {
      fprintf( stderr, "hash %x pref %.*s repeats\n",
               hash, (int) pref_len, prefix );
      exit( 1 );
    }
  }
  return hash;
}

void
SessionMgr::fork_daemon( int err_fd,  const char *wkdir ) noexcept
{
  if ( err_fd > 0 ) {
    char buf[ 256 ];
    size_t i;
    int n;
    if ( this->user_db.transport_tab.count > 0 &&
         this->user_db.transport_tab.ptr[ 0 ]->ext != NULL ) {
      IpcRte * ipc = this->user_db.transport_tab.ptr[ 0 ]->ext->list.hd;
      for ( ; ipc != NULL; ipc = ipc->next ) {
        n = ::snprintf( buf, sizeof( buf ), "%s running at %s\n",
                        ipc->transport.tport.val,
                        ipc->listener->peer_address.buf );
        if ( n > 0 )
          os_write( err_fd, buf, min_int( n, (int) sizeof( buf ) - 1 ) );
      }
    }
    for ( i = 0; i < this->unrouteable.count; i++ ) {
      Unrouteable & u = this->unrouteable.ptr[ i ];
      const char  * addr;
      if ( u.telnet != NULL )
        addr = u.telnet->peer_address.buf;
      else if ( u.web != NULL )
        addr = u.web->peer_address.buf;
      else
        addr = u.name->mcast_recv.peer_address.buf;
      n = ::snprintf( buf, sizeof( buf ), "%s running at %s\n",
                      u.tport->tport.val, addr );
      if ( n > 0 )
        os_write( err_fd, buf, min_int( n, (int) sizeof( buf ) - 1 ) );
    }
    for ( i = 1; i < this->user_db.transport_tab.count; i++ ) {
      TransportRoute * rte = this->user_db.transport_tab.ptr[ i ];
      if ( rte->listener != NULL ) {
        n = ::snprintf( buf, sizeof( buf ), "%s running at %s\n",
                        rte->name, rte->listener->peer_address.buf );
      }
      else {
        n = ::snprintf( buf, sizeof( buf ), "%s running\n",
                        rte->name );
      }
      if ( n > 0 )
        os_write( err_fd, buf, min_int( n, (int) sizeof( buf ) - 1 ) );
    }
    static char status_line[] = "moving to background daemon\n";
    os_write( err_fd, status_line, sizeof( status_line ) - 1 );
  }
  if ( ::fork() > 0 )
    ::exit( 0 );
  if ( wkdir != NULL )
    ::chdir( wkdir );
  ::setsid();
  ::umask( 0 );
  if ( ::fork() > 0 )
    ::exit( 0 );
  pid_t pid = ::getpid();
  const char * pidfile = NULL;
  printf( "running background deamon PID: %d\n", pid );
  if ( this->tree.parameters.find( P_PID_FILE, pidfile, NULL ) &&
       pidfile != NULL ) {
    FILE * fp;
    if ( (fp = ::fopen( pidfile, "w" )) != NULL ) {
      fprintf( fp, "%d\n", pid );
      ::fclose( fp );
    }
  }
}

void
SessionMgr::start( void ) noexcept
{
  printf( "%s: %lu bytes\n", P_PUB_WINDOW_SIZE, this->pub_window_size );
  printf( "%s: %lu bytes\n", P_SUB_WINDOW_SIZE, this->sub_window_size );
  printf( "%s: %lu secs\n", P_PUB_WINDOW_TIME, ns_to_sec( this->pub_window_ival ) );
  printf( "%s: %lu secs\n", P_SUB_WINDOW_TIME, ns_to_sec( this->sub_window_ival ) );
  printf( "%s: %u secs\n", P_HEARTBEAT, this->user_db.hb_interval );
  printf( "%s: %u secs\n", P_RELIABILITY, this->user_db.reliability );
  printf( "%s: %lu secs\n", P_TCP_WRITE_TIMEOUT, ns_to_sec( this->poll.wr_timeout_ns ) );
  printf( "%s: %u bytes\n", P_TCP_WRITE_HIGHWATER, this->poll.send_highwater );
  printf( "%s: %s\n", P_TCP_IPV4ONLY, this->tcp_ipv6 &&
                                      ! this->tcp_ipv4 ? "true" : "false" );
  printf( "%s: %s\n", P_TCP_IPV6ONLY, this->tcp_ipv4 &&
                                      ! this->tcp_ipv6 ? "true" : "false" );
  printf( "%s: %s\n", P_TCP_NOENCRYPT, this->tcp_noencrypt ? "true" : "false" );

  uint64_t cur_time = this->poll.current_coarse_ns(),
           cur_mono = this->poll.mono_ns,
           ival_ns  = sec_to_ns( this->user_db.hb_interval );
  size_t   i, count;

  this->timer_id             = ++this->next_timer;
  this->timer_mono_time      = cur_mono;
  this->timer_time           = cur_time;
  this->timer_converge_time  = cur_time;
  this->converge_seqno       = seqno_init( cur_time );
  this->timer_start_mono     = cur_mono;
  this->timer_start          = cur_time;
  this->stats.mono_time      = cur_mono;
  this->stats.mono_time     -= cur_time % sec_to_ns( STATS_INTERVAL );
  this->stats.mono_time     += sec_to_ns( STATS_INTERVAL );
  this->pub_window_mono_time = cur_mono + this->pub_window_ival;
  this->sub_window_mono_time = cur_mono + this->sub_window_ival;

  this->sub_db.seqno_tab.flip_time     = cur_time;
  this->sub_db.seqno_tab.trailing_time = cur_time - this->sub_window_ival;
  this->sub_db.pub_tab.flip_time       = cur_time;
  this->sub_db.pub_tab.trailing_time   = cur_time - this->pub_window_ival;
  this->sub_db.any_tab.gc_time         = cur_time;

  this->timer_ival         = (uint32_t) ( ival_ns / 250 );
  this->user_db.hb_ival_ns = ival_ns;
  for ( i = 1; i <= 32; i *= 2 )
    ival_ns |= ( ival_ns >> i );
  this->user_db.hb_ival_mask = ival_ns;
  this->poll.timer.add_timer_nanos( this->fd, (uint32_t) this->timer_ival,
                                    this->timer_id, 0 );
  this->session_started = true;
  this->user_db.hello_hb();
  this->name_hb( cur_mono );
  count = this->rv_svc_db.count;
  for ( i = 0; i < count; i++ ) {
    RvSvc *rv_svc = this->get_rv_session( this->rv_svc_db.ptr[ i ].svc, true );
    rv_svc->ref_count++;
  }
}

void
SessionMgr::name_hb( uint64_t cur_mono ) noexcept
{
  if ( cur_mono == 0 ) {
    this->poll.current_coarse_ns();
    cur_mono = this->poll.mono_ns;
  }
  this->name_svc_mono_time = cur_mono + this->user_db.hb_ival_ns;
  for ( size_t i = 0; i < this->unrouteable.count; i++ ) {
    NameSvc *name = this->unrouteable.ptr[ i ].name;
    if ( name != NULL ) {
      this->user_db.mcast_name( *name );
    }
  }
}

void
SessionMgr::stop( void ) noexcept
{
  this->user_db.bye_hb();
  this->timer_id = 0;
}

bool
SessionMgr::timer_expire( uint64_t tid,  uint64_t ) noexcept
{
  uint64_t cur_time = this->poll.current_coarse_ns(),
           cur_mono = this->poll.mono_ns;
  if ( tid != this->timer_id )
    return false;
  this->timer_mono_time = cur_mono;
  this->timer_time      = cur_time;
  if ( this->user_db.net_converge_time > this->timer_converge_time &&
       cur_time >= this->user_db.net_converge_time ) {
    uint64_t seqno = seqno_init( cur_time );
    if ( seqno != this->converge_seqno ) {
      d_sess( "set converge seqno %lu\n", seqno );
      this->converge_seqno      = seqno;
      this->timer_converge_time = cur_time;
    }
  }
  this->user_db.interval_hb( cur_mono, cur_time );
  this->user_db.check_user_timeout( cur_mono, cur_time );
  if ( cur_mono > this->name_svc_mono_time )
    this->name_hb( cur_mono );

  if ( this->console.log_rotate_time <= cur_time )
    this->console.rotate_log();
  this->console.on_log( this->log );

  if ( cur_mono > this->pub_window_mono_time ) {
    if ( this->sub_db.pub_tab.flip( this->pub_window_size, cur_time ) ) {
      this->pub_window_mono_time = cur_mono + this->pub_window_ival;
      printf( "pub_tab rotated, count %lu size %lu\n",
              this->sub_db.pub_tab.pub_old->pop_count(),
              this->sub_db.pub_tab.pub_old->mem_size() );
    }
  }

  if ( cur_mono > this->sub_window_mono_time ) {
    if ( this->sub_db.seqno_tab.flip( this->sub_window_size, cur_time ) ) {
      this->sub_window_mono_time = cur_mono + this->sub_window_ival;
      printf( "sub_tab rotated, count %lu size %lu\n",
              this->sub_db.seqno_tab.tab_old->pop_count(),
              this->sub_db.seqno_tab.tab_old->mem_size() );
    }
  }
  this->sub_db.any_tab.gc( cur_time );
  this->sub_db.gc_memo( cur_mono );

  if ( cur_mono < this->stats.mono_time )
    return true;
  do {
    this->stats.mono_time += sec_to_ns( STATS_INTERVAL );
  } while ( this->stats.mono_time < cur_mono );
  this->publish_stats( cur_time );
  return true;
}

void
MsgFramePublish::print( const char *what ) const noexcept
{
  char buf[ MAX_NONCE_STATE_STRING ];
  if ( this->n != NULL ) {
    this->n->printf( "%s %.*s, %s\n", what,
                     (int) this->subject_len, this->subject,
                     this->n->state_to_string( buf ) );
  }
  else {
    const MsgHdrDecoder & dec = this->dec;
    ::strcpy( buf, "unkown" );
    if ( dec.test( FID_BRIDGE ) ) {
      Nonce src_bridge_id;
      src_bridge_id.copy_from( dec.mref[ FID_BRIDGE ].fptr );
      src_bridge_id.to_base64_str( buf );
    }
    printf( "%s %.*s, unknown source [%s]\n", what,
             (int) this->subject_len, this->subject, buf );
  }
  MDOutput mout( MD_OUTPUT_OPAQUE_TO_B64 );
  if ( this->dec.msg != NULL ) {
    this->dec.msg->print( &mout, 1, "%19s : ", NULL );
  }
  else {
    mout.print_hex( this->msg, this->msg_len );
  }
}

const char *
MsgFramePublish::status_string( void ) const noexcept
{
  if ( this->status < FRAME_STATUS_MAX )
    return frame_status_str[ this->status ];
  return frame_status_str[ 0 ];
}

void
SessionMgr::ignore_msg( const MsgFramePublish &fpub ) noexcept
{
  d_sess( "From src_route %d/%s status %d/%s\n", fpub.src_route.fd,
           fpub.rte.name, fpub.status, fpub.status_string() );
  if ( debug_sess )
    fpub.print( "Ignoring" );
}

void
SessionMgr::show_debug_msg( const MsgFramePublish &fpub,
                            const char *where ) noexcept
{ /* message recv debug */
  /* skip _X.HB if not debugging hb */
  const bool show_msg = ( debug_hb || fpub.subject[ 0 ] != '_' ||
                          fpub.subject[ 1 ] != 'X' );
  if ( show_msg && debug_msgr && fpub.n != NULL ) {
    UserBridge & n = *fpub.n;
    n.printf(
 "### %.*s (len=%u, v=%u, f=%s, o=%u, type=%s from %s, in %s, fd %d)\n",
              (int) fpub.subject_len, fpub.subject,
              fpub.msg_len,
              fpub.dec.msg->caba.get_ver(),
              fpub.dec.msg->caba.type_str(),
              fpub.dec.msg->caba.get_opt(),
              publish_type_to_string( fpub.dec.type ),
              fpub.rte.name, where, fpub.src_route.fd );
    MDOutput mout( MD_OUTPUT_OPAQUE_TO_B64 );
    fpub.dec.msg->print( &mout, 1, "%19s : ", NULL );
  }
  if ( show_msg && debug_msgh ) {
    MDOutput mout;
    mout.print_hex( fpub.msg, fpub.msg_len );
  }
}
/* decode the message header and find the sending peer */
MsgFrameStatus
SessionMgr::parse_msg_hdr( MsgFramePublish &fpub,  bool is_ipc ) noexcept
{
  MsgHdrDecoder & dec = fpub.dec;

  if ( dec.decode_msg() != 0 ||
       ! dec.get_ival<uint64_t>( FID_SEQNO, dec.seqno ) )
    return fpub.status = FRAME_STATUS_BAD_MSG;

  PublishType  type  = MCAST_SUBJECT;
  CabaTypeFlag tflag = dec.msg->caba.get_type();
  if ( tflag != CABA_MCAST ) {
    if ( is_ipc )
      return FRAME_STATUS_MY_MSG;
    uint8_t i;
    /* an inbox subject */
    if ( tflag == CABA_INBOX ) {
      if ( ( dec.msg->caba.get_opt() & CABA_OPT_ANY ) == 0 ) {
        /* match _I.Nonce. + hash( _I.Nonce. ) */
        for ( i = 0; i < fpub.prefix_cnt; i++ ) {
          if ( fpub.hash[ i ] == this->ibx.hash &&
               fpub.prefix[ i ] == this->ibx.len ) {
            const char * num = &fpub.subject[ this->ibx.len ];
            size_t       len = fpub.subject_len - this->ibx.len;
            if ( len > 0 && num[ 0 ] >= '0' && num[ 0 ] <= '9' ) {
              type = U_INBOX;
              /* if _I.Nonce.<int> */
              uint64_t ret = num[ 0 ] - '0';
              for ( size_t i = 1; i < len; i++ ) {
                if ( num[ i ] >= '0' || num[ i ] <= '9' )
                  ret = ( ret * 10 ) + ( num[ i ] - '0' );
              }
              dec.inbox_ret = (uint32_t) ret;
            }
            else {
              /* inbox routing, match subject
               * _I.Nonce.auth, _I.Nonce.subs, _I.Nonce.ping, ... */
              type = this->ibx.lookup( fpub.subj_hash, fpub.subject_len );
            }
            break;
          }
        }
      }
      else {
        type = U_INBOX_ANY_RTE;
      }
    }
    /* heartbeat: _X.HELLO, _X.HB, _X.BYE */
    else if ( tflag == CABA_HEARTBEAT ) {
      type = this->u_tab.lookup( fpub.subj_hash, fpub.subject_len );
    }
    else if ( tflag == CABA_RTR_ALERT ) {
      /* _Z.ADD, _Z.ADJ */
      type = this->u_tab.lookup( fpub.subj_hash, fpub.subject_len );
      if ( type == U_NORMAL ) {
        /* control message: _S.JOIN. _S.LEAV. _P.PSUB. _P.PSTP. _M. */
        for ( i = 0; i < fpub.prefix_cnt; i++ ) {
          /* match _M. + hash( _M. ) */
          if ( fpub.hash[ i ] == this->mch.hash &&
               fpub.prefix[ i ] == this->mch.len )
            type = this->mch.lookup( fpub.subj_hash, fpub.subject_len );
          else
            type = this->u_tab.lookup( fpub.hash[ i ], fpub.prefix[ i ] );
          if ( type != U_NORMAL )
            break;
        }
      }
    }
    if ( type == U_NORMAL ) {
      printf( "?? %.*s %s %s (%x)\n", (int) fpub.subject_len, fpub.subject,
              caba_type_flag_str( tflag ), publish_type_to_string( type ),
              fpub.subj_hash );
      for ( i = 0; i < fpub.prefix_cnt; i++ ) {
        printf( "[%u] = %u.%x, type %s\n", i, fpub.prefix[ i ], fpub.hash[ i ],
                publish_type_to_string( 
                  this->u_tab.lookup( fpub.hash[ i ], fpub.prefix[ i ] ) ) );
      }
    }
  }
  dec.type = type;
  this->msg_recv_counter[ type & ( MAX_PUB_TYPE - 1 ) ]++;

  fpub.n = this->user_db.lookup_user( fpub, dec );
  /*if ( fpub.status == FRAME_STATUS_MY_MSG )
    return FRAME_STATUS_MY_MSG;*/
  return fpub.status;
}

void
SessionMgr::show_seqno_status( MsgFramePublish &fpub,  UserBridge &n,
                               MsgHdrDecoder &dec,  SeqnoArgs &seq,
                               int status,  bool is_session ) noexcept
{
  n.printf( "%s %s %.*s seqno %lu.%lu last %lu.%lu miss 0x%x (%s)\n",
            is_session ? "session" : "ipc",
            seqno_status_string( (SeqnoStatus) status ),
            (int) fpub.subject_len, fpub.subject,
            seqno_frame( dec.seqno ), seqno_base( dec.seqno ),
            seqno_frame( seq.last_seqno ), seqno_base( seq.last_seqno ),
            seq.msg_loss, fpub.rte.name );
}
/* forward a message published by my ipc to the network, add a subject seqno */
bool
IpcRoute::on_msg( EvPublish &pub ) noexcept
{
  this->msgs_recv++;
  this->bytes_recv += pub.msg_len;
  if ( this->equals( pub.src_route ) )
    return true;
  if ( pub.pub_type != 'X' ) {
    fprintf( stderr, "IPC publish has no frame %.*s\n",
             (int) pub.subject_len, pub.subject );
    return true;
  }
  MsgFramePublish & fpub = (MsgFramePublish &) pub;
  /* find user and determine message type */
  if ( fpub.dec.type == UNKNOWN_SUBJECT ) {
    if ( fpub.status != FRAME_STATUS_UNKNOWN ) /* bad msg or no user */
      return true;
    if ( this->mgr.parse_msg_hdr( fpub, true ) == FRAME_STATUS_MY_MSG )
      return true;
  }
  //const PublishType type = fpub.dec.type;
  /* adj messages may occur before user is known */
  if ( fpub.status == FRAME_STATUS_NO_USER )
    return true;
  /* if other status, can't process it */
  if ( fpub.status != FRAME_STATUS_NO_AUTH && fpub.status != FRAME_STATUS_OK ) {
    this->mgr.ignore_msg( fpub );
    return true;
  }
  if ( debug_msg )
    this->mgr.show_debug_msg( fpub, "ipc_rte" );

  UserBridge & n = *fpub.n;
  MsgHdrDecoder & dec = fpub.dec;

  if ( fpub.status == FRAME_STATUS_NO_AUTH ) {
    /* move from FRAME_STATUS_NO_AUTH -> FRAME_STATUS_OK */
    if ( dec.msg->verify( n.peer_key ) )
      fpub.status = FRAME_STATUS_OK;
    else if ( n.is_set( AUTHENTICATED_STATE ) || debug_sess ) {
      n.printf( "verify failed %.*s\n", (int) fpub.subject_len, fpub.subject );
      /*printf( "ha1: " ); n.ha1.print(); printf( "\n" );*/
    }
  }
  /* authentication happens above, must be authenticated */
  if ( ! n.is_set( AUTHENTICATED_STATE ) || fpub.status != FRAME_STATUS_OK ) {
    /* ignore other msgs until authenticated */
    this->mgr.ignore_msg( fpub );
    return true;
  }
  void       * data     = NULL;
  const char * reply    = NULL;
  size_t       datalen  = 0,
               replylen = 0;
  if ( dec.test( FID_DATA ) ) {
    data    = dec.mref[ FID_DATA ].fptr;
    datalen = dec.mref[ FID_DATA ].fsize;
  }
  if ( dec.test( FID_REPLY ) ) {
    const char * host;
    size_t       host_len;
    reply    = (const char *) dec.mref[ FID_REPLY ].fptr;
    replylen = dec.mref[ FID_REPLY ].fsize;

    if ( SubDB::match_inbox( reply, replylen, host, host_len ) )
      this->sub_db.reply_memo( reply, replylen, host, host_len, n,
                               this->poll.mono_ns );
  }
  SeqnoArgs seq( this->mgr.timer_time );
  uint32_t  fmt = 0;

  dec.get_ival<uint64_t>( FID_CHAIN_SEQNO, seq.chain_seqno );
  dec.get_ival<uint64_t>( FID_TIME, seq.time );
  dec.get_ival<uint32_t>( FID_FMT, fmt );
  SeqnoStatus status = this->sub_db.match_seqno( fpub, seq );

  uint16_t opt = dec.msg->caba.get_opt();
  if ( ( fpub.flags & MSG_FRAME_ACK_CONTROL ) == 0 ) {
    fpub.flags |= MSG_FRAME_ACK_CONTROL;
    if ( opt != CABA_OPT_NONE ) {
      if ( ( opt & CABA_OPT_ACK ) != 0 )
        this->mgr.send_ack( fpub, n, dec, _ACK );
      if ( ( opt & CABA_OPT_TRACE ) != 0 )
        this->mgr.send_ack( fpub, n, dec, _TRACE );
    }
  }
  if ( ( opt & CABA_OPT_TRACE ) != 0 ) {
    if ( datalen == 0 && replylen == 0 && fmt == 0 ) {
      if ( status <= SEQNO_UID_NEXT )
        return true;
    }
  }
  d_sess( "-> ipc_rte: %.*s seqno %lu.%lu (%s) reply %.*s "
          "(len=%u, from %s, fd %d, msg_enc %x)\n",
          (int) fpub.subject_len, fpub.subject,
          seqno_frame( dec.seqno ), seqno_base( dec.seqno ),
          seqno_status_string( status ), (int) replylen, reply,
          fpub.msg_len, fpub.rte.name, fpub.src_route.fd, fmt );

  if ( status > SEQNO_UID_NEXT ) {
    if ( status != SEQNO_NOT_SUBSCR ) {
      if ( status > SEQNO_UID_SKIP )
        fpub.status = FRAME_STATUS_DUP_SEQNO;
    }
    if ( status == SEQNO_UID_REPEAT ) {
      if ( debug_sess_repeat )
        this->mgr.show_seqno_status( fpub, n, dec, seq, status, false );
      n.msg_repeat_count++;
      n.msg_repeat_time = this->mgr.timer_time;
    }
    else if ( status == SEQNO_NOT_SUBSCR ) {
      if ( debug_sess_not_sub )
        this->mgr.show_seqno_status( fpub, n, dec, seq, status, false );
      n.msg_not_subscr_count++;
      n.msg_not_subscr_time = this->mgr.timer_time;
    }
    else if ( status == SEQNO_UID_SKIP ) {
      if ( debug_sess_loss )
        this->mgr.show_seqno_status( fpub, n, dec, seq, status, false );
      n.msg_loss_time = this->mgr.timer_time;
      if ( seq.msg_loss <= MAX_MSG_LOSS )
        n.msg_loss_count += seq.msg_loss;
      else
        n.msg_loss_count++;
    }
    else if ( debug_sess )
      this->mgr.show_seqno_status( fpub, n, dec, seq, status, false );
    if ( status > SEQNO_UID_SKIP ) /* forward when skipped ahead */
      return true;
  }
  else if ( status < SEQNO_UID_NEXT ) {
    if ( status == SEQNO_UID_FIRST )
      seq.msg_loss = EV_PUB_START;
    else if ( status == SEQNO_UID_CYCLE )
      seq.msg_loss = EV_PUB_CYCLE;
  }
  /*MDMsgMem mem;
  if ( fmt == CABA_TYPE_ID ) {
    fmt = fpub.dec.msg->caba_to_rvmsg( mem, data, datalen );
  }*/
  bool b = true;
  size_t i, count = this->user_db.transport_tab.count;
  if ( seq.tport_mask != SubRefs::ALL_MASK ) {
    uint32_t mask = seq.tport_mask; /* ipc tports (currently only one) */
    for ( i = 0; mask != 0; i++ ) {
      bool is_set = ( mask & 1 ) != 0;
      mask >>= 1;
      if ( is_set ) {
        TransportRoute *rte = this->user_db.transport_tab.ptr[ i ];
        if ( &fpub.rte != rte && rte->is_set( TPORT_IS_IPC ) ) {
          EvPublish pub( fpub.subject, fpub.subject_len, reply, replylen,
                         data, datalen, rte->sub_route, fpub.src_route,
                         fpub.subj_hash, fmt, 'p', seq.msg_loss,
                         n.bridge_nonce_int, dec.seqno );
          b &= rte->sub_route.forward_except( pub, this->mgr.router_set, this );
        }
      }
    }
  }
  else {
    for ( i = 0; i < count; i++ ) {
      TransportRoute *rte = this->user_db.transport_tab.ptr[ i ];
      if ( &fpub.rte != rte && rte->is_set( TPORT_IS_IPC ) ) {
        EvPublish pub( fpub.subject, fpub.subject_len, reply, replylen,
                       data, datalen, rte->sub_route, fpub.src_route,
                       fpub.subj_hash, fmt, 'p', seq.msg_loss,
                       n.bridge_nonce_int, dec.seqno );
        b &= rte->sub_route.forward_except( pub, this->mgr.router_set, this );
      }
    }
  }
  this->check_flow_control( b );
  if ( seq.cb != NULL ) {
    fpub.flags |= MSG_FRAME_IPC_CONTROL;
    SubMsgData val( fpub, &n, data, datalen );

    val.seqno = dec.seqno;
    val.fmt   = fmt;
    dec.get_ival<uint64_t>( FID_STAMP,     val.stamp );
    dec.get_ival<uint64_t>( FID_TOKEN,     val.token );
    dec.get_ival<uint64_t>( FID_REF_SEQNO, val.ref_seqno );
    dec.get_ival<uint32_t>( FID_RET,       val.reply );
    dec.get_ival<uint32_t>( FID_TPORTID,   val.tport_id );
    seq.cb->on_data( val );
  }
  return b;
}
/* forward console subscribed subject from local ipc */
bool
ConsoleRoute::on_msg( EvPublish &pub ) noexcept
{
  this->fwd_console( pub, false );
  return true;
}

bool
QueueRoute::on_msg( EvPublish & ) noexcept
{
  /*this->fwd_console( pub, false );*/
  return true;
}

uint32_t
ConsoleRoute::fwd_console( EvPublish &pub,  bool is_caba ) noexcept
{
  TransportRoute & rte = *this->user_db.ipc_transport;
  SeqnoArgs seq( this->mgr.timer_time );

  if ( is_caba ) {
    MDMsgMem  mem;
    CabaMsg * msg         = NULL;
    uint64_t  time        = 0,
              stamp       = 0,
              chain_seqno = 0,
              ref_seqno   = 0;
    size_t    end         = pub.msg_len;

    if ( CabaMsg::unpack2( (uint8_t *) pub.msg, 0, end, &mem, msg ) != 0 )
      return 0;

    MsgFramePublish fpub( pub, msg, rte );
    fpub.dec.decode_msg();
    fpub.dec.get_ival<uint64_t>( FID_SEQNO, fpub.dec.seqno );
    fpub.dec.get_ival<uint64_t>( FID_REF_SEQNO, ref_seqno );
    fpub.dec.get_ival<uint64_t>( FID_CHAIN_SEQNO, chain_seqno );
    fpub.dec.get_ival<uint64_t>( FID_TIME, time );
    fpub.dec.get_ival<uint64_t>( FID_STAMP, stamp );

    seq.time        = time;
    seq.chain_seqno = chain_seqno;
    SeqnoStatus status = this->sub_db.match_seqno( fpub, seq );

    if ( status > SEQNO_UID_NEXT ) {
      if ( status != SEQNO_NOT_SUBSCR )
        printf( "fwd_console %s %.*s seqno %" PRIu64 " (%s)\n",
                 seqno_status_string( status ),
                 (int) fpub.subject_len, fpub.subject, fpub.dec.seqno,
                 fpub.rte.name );
    }
    if ( status <= SEQNO_UID_SKIP ) {
      if ( seq.cb != NULL ) {
        SubMsgData val( fpub, NULL, NULL, 0 );

        val.seqno     = fpub.dec.seqno;
        val.ref_seqno = ref_seqno;
        val.stamp     = stamp;
        val.fmt       = pub.msg_enc;
        seq.cb->on_data( val );
        return 1;
      }
    }
  }
  /* no seqno yet, came from ipc */
  else if ( this->sub_db.match_subscription( pub, seq ) && seq.cb != NULL ) {
    MsgFramePublish fpub( pub, NULL, rte );
    SubMsgData val( fpub, NULL, pub.msg, pub.msg_len );

    val.fmt = pub.msg_enc;
    seq.cb->on_data( val );
    return 1;
  }
  return 0;
}
/* decapsulate a message published to my inbox subscribed by an ipc route,
 * usually an _INBOX subject */
bool
IpcRoute::on_inbox( MsgFramePublish &fpub,  UserBridge &n,
                    MsgHdrDecoder &dec ) noexcept
{
  if ( ! dec.test( FID_SUBJECT ) ) {
    fprintf( stderr, "No inbox subject\n" );
    return true;
  }
  const char * subject  = (const char *) dec.mref[ FID_SUBJECT ].fptr;
  void       * reply    = NULL,
             * data     = NULL;
  size_t       subjlen  = dec.mref[ FID_SUBJECT ].fsize,
               replylen = 0,
               datalen  = 0;
  uint32_t     h        = kv_crc_c( subject, subjlen, 0 ),
               fmt;
  if ( dec.test( FID_DATA ) ) {
    data    = dec.mref[ FID_DATA ].fptr;
    datalen = dec.mref[ FID_DATA ].fsize;
  }
  if ( dec.test( FID_REPLY ) ) {
    reply    = dec.mref[ FID_REPLY ].fptr;
    replylen = dec.mref[ FID_REPLY ].fsize;
  }
  dec.get_ival<uint32_t>( FID_FMT, fmt );

  d_sess( "on_inbox(%.*s)\n", (int) subjlen, subject );
  bool b = true;
  size_t i, count = this->user_db.transport_tab.count;
  uint32_t rcnt = 0;
  for ( i = 0; i < count; i++ ) {
    TransportRoute *rte = this->user_db.transport_tab.ptr[ i ];
    if ( &fpub.rte != rte && rte->is_set( TPORT_IS_IPC ) ) {
      EvPublish pub( subject, subjlen, reply, replylen,
                     data, datalen, rte->sub_route, fpub.src_route, h, fmt, 'p',
                     0, n.bridge_nonce_int, dec.seqno );
      b &= rte->sub_route.forward_except_with_cnt( pub, this->mgr.router_set,
                                                   rcnt, &this->mgr );
      if ( rcnt != 0 ) {
        d_sess( "rte %s\n", rte->name );
        break;
      }
    }
  }
  if ( rcnt == 0 ) {
    SubOnMsg * cb = this->sub_db.match_any_sub( subject, subjlen );
    if ( cb != NULL ) {
      SubMsgData val( fpub, &n, data, datalen );
      val.seqno = dec.seqno;
      val.fmt   = fmt;
      cb->on_data( val );
    }
    else {
      d_sess( "no inbox sub (%.*s)\n", (int) subjlen, subject );
    }
  }
  return this->mgr.check_flow_control( b );
}
/* system subjects from peers to maintain the network */
bool
SessionMgr::on_msg( EvPublish &pub ) noexcept
{
  this->msgs_recv++;
  this->bytes_recv += pub.msg_len;
  if ( this->equals( pub.src_route ) )
    return true;
  if ( pub.pub_type != 'X' ) {
    fprintf( stderr, "Session publish has no frame %.*s\n",
             (int) pub.subject_len, pub.subject );
    return true;
  }
  MsgFramePublish & fpub = (MsgFramePublish &) pub;
  if ( ( fpub.flags &
         ( MSG_FRAME_CONSOLE_CONTROL | MSG_FRAME_IPC_CONTROL ) ) != 0 )
    return true;
  /* find user and determine message type */
  if ( fpub.dec.type == UNKNOWN_SUBJECT ) {
    if ( fpub.status != FRAME_STATUS_UNKNOWN ) /* bad msg or no user */
      return true;
    if ( this->parse_msg_hdr( fpub, false ) == FRAME_STATUS_MY_MSG )
      return true;
  }
  /* adj messages may occur before user is known */
  const PublishType type = fpub.dec.type;
  if ( fpub.status == FRAME_STATUS_NO_USER && type == U_ADJACENCY ) {
    this->user_db.save_unauthorized_adjacency( fpub );
    return true;
  }
  /* if other status, can't process it */
  if ( fpub.status != FRAME_STATUS_NO_AUTH && fpub.status != FRAME_STATUS_OK ) {
    this->ignore_msg( fpub );
    return true;
  }
  if ( debug_msg )
    this->show_debug_msg( fpub, "sess_rte" );

  UserBridge    & n   = *fpub.n;
  MsgHdrDecoder & dec = fpub.dec;

  static const uint64_t session_type =
    ( (uint64_t) 1 << U_SESSION_HELLO ) | ( (uint64_t) 1 << U_SESSION_HB ) |
    ( (uint64_t) 1 << U_SESSION_BYE ) | ( (uint64_t) 1 << U_INBOX_AUTH );

  if ( (( (uint64_t) 1 << type ) & session_type) != 0 ) {
    if ( fpub.status == FRAME_STATUS_NO_AUTH ) {
      if ( type != U_INBOX_AUTH ) {
        if ( n.is_set( AUTHENTICATED_STATE ) ) {
          /* verify with peer key */
          if ( dec.msg->verify( n.peer_key ) )
            fpub.status = FRAME_STATUS_OK;
        }
        else {
          /* before authenticated, allow hb to be signed by hello key */
          if ( dec.msg->verify_hb( n.peer_hello ) )
            fpub.status = FRAME_STATUS_HB_NO_AUTH;
        }
      }
      else {
        /* inbox auth has key exchange encrypted, that is used to verify msg */
        fpub.status = FRAME_STATUS_INBOX_AUTH;
      }
    }
    if ( type != U_SESSION_BYE && fpub.status != FRAME_STATUS_NO_AUTH ) {
      if ( ! n.is_set( INBOX_ROUTE_STATE ) ) 
        this->user_db.add_inbox_route( n, NULL ); /* need an inbox */
    }
    /* authorize user by verifying the DSA key exchange */
    if ( type == U_INBOX_AUTH && fpub.status == FRAME_STATUS_INBOX_AUTH ) {
      uint64_t seqno = n.inbox.recv_seqno;
      n.inbox.set_recv( dec.seqno, U_INBOX_AUTH );
      if ( seqno > dec.seqno ) /* auth trust reuses seqno from auth */
        n.inbox.recv_seqno = seqno;
      return this->user_db.on_inbox_auth( fpub, n, dec );
    }
    /* maybe authorize if needed by starting DSA exchange */
    if ( ( type == U_SESSION_HELLO || type == U_SESSION_HB ) &&
         ( fpub.status == FRAME_STATUS_OK ||
           fpub.status == FRAME_STATUS_HB_NO_AUTH ) )
      return this->user_db.on_heartbeat( fpub, n, dec );

    /* ciao frog */
    if ( type == U_SESSION_BYE && fpub.status == FRAME_STATUS_OK )
      return this->user_db.on_bye( fpub, n, dec );
  }
  else if ( fpub.status == FRAME_STATUS_NO_AUTH ) {
    /* move from FRAME_STATUS_NO_AUTH -> FRAME_STATUS_OK */
    if ( dec.msg->verify( n.peer_key ) )
      fpub.status = FRAME_STATUS_OK;
    else if ( n.is_set( AUTHENTICATED_STATE ) || debug_sess ) {
      n.printf( "verify failed %.*s\n", (int) fpub.subject_len, fpub.subject );
      /*printf( "ha1: " ); n.ha1.print(); printf( "\n" );*/
    }
  }
  /* the _X.HELLO, _X.HB, _X.BYE messages and _I.Nonce.auth message */
  /* authentication happens above, must be authenticated */
  if ( ! n.is_set( AUTHENTICATED_STATE ) || fpub.status != FRAME_STATUS_OK ) {
    /* adj messages may occur before user is authorized */
    if ( fpub.status == FRAME_STATUS_NO_AUTH && type == U_ADJACENCY ) {
      this->user_db.save_unauthorized_adjacency( fpub );
      return true;
    }
    /* ignore other msgs until authenticated */
    this->ignore_msg( fpub );
    return true;
  }
  if ( ( fpub.flags & MSG_FRAME_ACK_CONTROL ) == 0 ) {
    uint16_t opt = dec.msg->caba.get_opt();
    fpub.flags |= MSG_FRAME_ACK_CONTROL;
    if ( opt != CABA_OPT_NONE ) {
      if ( ( opt & CABA_OPT_ACK ) != 0 )
        this->send_ack( fpub, n, dec, _ACK );
      if ( ( opt & CABA_OPT_TRACE ) != 0 )
        this->send_ack( fpub, n, dec, _TRACE );
    }
  }
  /* dispatch other subject types */
  switch ( type ) {
    case U_SUB_JOIN:      /* _S.JOIN.subject */
    case U_SUB_LEAVE:     /* _S.LEAV.subject */
    case U_PSUB_START:    /* _P.PSUB.wildcard */
    case U_PSUB_STOP:     /* _P.PSTP.wildcard */
      if ( dec.seqno == n.sub_seqno + 1 ) {
        /* the leave, stop must be updated in order, dropping subs which have no
         * start will cause corruption of the bloom */
        this->sub_db.update_sub_seqno( n.sub_seqno, dec.seqno );
        n.sub_recv_mono_time = current_monotonic_time_ns();
        this->sub_db.sub_update_mono_time = n.sub_recv_mono_time;
        switch ( type ) {
          case U_SUB_JOIN:   return this->sub_db.recv_sub_start( fpub, n, dec );
          case U_SUB_LEAVE:  return this->sub_db.recv_sub_stop( fpub, n, dec );
          case U_PSUB_START: return this->sub_db.recv_psub_start( fpub, n, dec );
          case U_PSUB_STOP:  return this->sub_db.recv_psub_stop( fpub, n, dec );
          default: break;
        }
      }
      if ( dec.seqno <= n.sub_seqno ) {
        if ( debug_sess )
          n.printf( "%.*s ignoring sub seqno replay %" PRIu64 " -> %" PRIu64 " (%s)\n",
                    (int) fpub.subject_len, fpub.subject,
                    n.sub_seqno, dec.seqno, fpub.rte.name );
      }
      else if ( n.sub_seqno != 0 ) {
        n.printf( "%.*s missing sub seqno %" PRIu64 " -> %" PRIu64 " (%s)\n",
                  (int) fpub.subject_len, fpub.subject,
                  n.sub_seqno, dec.seqno, fpub.rte.name );
        this->user_db.send_adjacency_request( n, MISSING_SYNC_REQ );
      }
      fpub.status = FRAME_STATUS_DUP_SEQNO;
      break;

    case U_PEER_ADD:       /* _Z.ADD */
    case U_PEER_DEL:       /* _Z.DEL */
    case U_BLOOM_FILTER:   /* _Z.BLM */
    case U_ADJACENCY: {    /* _Z.ADJ */
      if ( dec.seqno > n.peer_recv_seqno ) {
        n.peer_recv_seqno = dec.seqno;
        /* bloom and adj are sequenced independently (sub_seqno, link_state) */
        switch ( type ) {
          case U_BLOOM_FILTER: return this->sub_db.recv_bloom_result( fpub, n, dec );
          case U_PEER_ADD:     return this->user_db.recv_peer_add( fpub, n, dec, AUTH_FROM_PEER_ADD );
          case U_PEER_DEL:     return this->user_db.recv_peer_del( fpub, n, dec );
          case U_ADJACENCY:    return this->user_db.recv_adjacency_change( fpub, n, dec );
          default: break;
        }
      }
      else {
        if ( debug_sess ) {
          n.printf( "%.*s ignoring peer seqno replay %" PRIu64 " -> %" PRIu64 " (%s)\n",
                    (int) fpub.subject_len, fpub.subject,
                    n.peer_recv_seqno, dec.seqno, fpub.rte.name );
        }
        fpub.status = FRAME_STATUS_DUP_SEQNO;
      }
      break;
    }
    case U_INBOX_PING: return this->user_db.recv_ping_request( fpub, n, dec );/* _I.Nonce.ping */
    case U_INBOX_PONG: return this->user_db.recv_pong_result( fpub, n, dec ); /* _I.Nonce.pong */
    case U_INBOX_SYNC: return this->user_db.recv_mcast_sync_result( fpub, n, dec ); /* _I.Nonce.sync */

    case U_INBOX_SUBS:      /* _I.Nonce.subs      */
    case U_INBOX_REM:       /* _I.Nonce.rem       */
    case U_INBOX_RESUB:     /* _I.Nonce.resub     */
    case U_INBOX_REPSUB:    /* _I.Nonce.repsub    */
    case U_INBOX_ADD_RTE:   /* _I.Nonce.add_rte   */
    case U_INBOX_SYNC_REQ:  /* _I.Nonce.sync_req  */
    case U_INBOX_SYNC_RPY:  /* _I.Nonce.sync_rpy  */
    case U_INBOX_BLOOM_REQ: /* _I.Nonce.bloom_req */
    case U_INBOX_BLOOM_RPY: /* _I.Nonce.bloom_rpy */
    case U_INBOX_ADJ_REQ:   /* _I.Nonce.adj_req   */
    case U_INBOX_ADJ_RPY:   /* _I.Nonce.adj_rpy   */
    case U_INBOX_MESH_REQ:  /* _I.Nonce.mesh_req  */
    case U_INBOX_MESH_RPY:  /* _I.Nonce.mesh_rpy  */
    case U_INBOX_UCAST_REQ: /* _I.Nonce.ucast_req */
    case U_INBOX_UCAST_RPY: /* _I.Nonce.ucast_rpy */
    case U_INBOX_ANY_RTE:   /* _I.Nonce.any, ipc_rt inbox */
      if ( dec.seqno > n.inbox.recv_seqno ) {
        if ( n.inbox.recv_seqno != 0 && dec.seqno != n.inbox.recv_seqno + 1 ) {
          /*uint64_t recv_seqno = n.inbox.recv_seqno;
          if ( recv_seqno > 32 ) recv_seqno -= 32; else recv_seqno = 1;
          while ( recv_seqno < n.inbox.recv_seqno ) {
            printf( "recv: %lu, type %s\n",
              recv_seqno, publish_type_to_string(
                (PublishType) n.inbox.recv_type[ recv_seqno % 32 ] ) );
            recv_seqno++;
          }*/
          n.inbox_msg_loss_time   = this->timer_time;
          n.inbox_msg_loss_count += dec.seqno - ( n.inbox.recv_seqno + 1 );
          n.printf( "%.*s missing inbox seqno %" PRIu64 " -> %" PRIu64 " (%s)\n",
                    (int) fpub.subject_len, fpub.subject,
                    n.inbox.recv_seqno, dec.seqno, fpub.rte.name );
        }
        /* these should be in order, otherwise message loss occurred */
        n.inbox.set_recv( dec.seqno, type );
        switch ( type ) {
          case U_INBOX_SUBS:      return this->sub_db.recv_subs_request( fpub, n, dec );
          case U_INBOX_REM:       return this->console.recv_remote_request( fpub, n, dec );
          case U_INBOX_RESUB:     return this->sub_db.recv_resub_result( fpub, n, dec );
          case U_INBOX_REPSUB:    return this->sub_db.recv_repsub_result( fpub, n, dec );
          case U_INBOX_ADD_RTE:   return this->user_db.recv_add_route( fpub, n, dec );
          case U_INBOX_SYNC_REQ:  return this->user_db.recv_sync_request( fpub, n, dec );
          case U_INBOX_SYNC_RPY:  return this->user_db.recv_sync_result( fpub, n, dec );
          case U_INBOX_BLOOM_REQ: return this->sub_db.recv_bloom_request( fpub, n, dec );
          case U_INBOX_BLOOM_RPY: return this->sub_db.recv_bloom_result( fpub, n, dec );
          case U_INBOX_ADJ_REQ:   return this->user_db.recv_adjacency_request( fpub, n, dec );
          case U_INBOX_ADJ_RPY:   return this->user_db.recv_adjacency_result( fpub, n, dec );
          case U_INBOX_MESH_REQ:  return this->user_db.recv_mesh_request( fpub, n, dec );
          case U_INBOX_MESH_RPY:  return this->user_db.recv_mesh_result( fpub, n, dec );
          case U_INBOX_UCAST_REQ: return true; /* probably don't need these */
          case U_INBOX_UCAST_RPY: return true;
          case U_INBOX_ANY_RTE:   return this->ipc_rt.on_inbox( fpub, n, dec );
          default: break;
        }
      }
      else {
        n.printf( "%.*s ignoring inbox seqno replay %" PRIu64 " -> %" PRIu64 " (%s)\n",
                  (int) fpub.subject_len, fpub.subject,
                  n.inbox.recv_seqno, dec.seqno, fpub.rte.name );
        fpub.status = FRAME_STATUS_DUP_SEQNO;
      }
      break;

    case U_MCAST_SYNC:
      return this->user_db.recv_mcast_sync_request( fpub, n, dec ); /* _M.sync */

    case U_MCAST_PING:
    case U_MCAST:
      return this->user_db.recv_ping_request( fpub, n, dec, true ); /* _M.ping */

    case U_NORMAL:        /* _SUBJECT */
    case U_INBOX:         /* _I.Nonce.<inbox_ret> */
    case U_INBOX_TRACE:   /* _I.Nonce.trace */
    case U_INBOX_ACK:     /* _I.Nonce.ack */
    case U_INBOX_ANY:     /* _I.Nonce.any */
    case MCAST_SUBJECT:   /* SUBJECT */
      this->dispatch_console( fpub, n, dec );
      break;
    default:
      n.printf( "no sub type\n" );
      break;
  }
  return true;
}
/* send message to console callback */
void
SessionMgr::dispatch_console( MsgFramePublish &fpub,  UserBridge &n,
                              MsgHdrDecoder &dec ) noexcept
{
  void * data    = NULL;
  size_t datalen = 0;
  if ( dec.test( FID_DATA ) ) {
    data    = dec.mref[ FID_DATA ].fptr;
    datalen = dec.mref[ FID_DATA ].fsize;
  }
  SubMsgData val( fpub, &n, data, datalen );
  SeqnoArgs  seq( this->timer_time );

  val.seqno = dec.seqno;
  dec.get_ival<uint64_t>( FID_CHAIN_SEQNO, seq.chain_seqno );
  dec.get_ival<uint64_t>( FID_STAMP,       val.stamp );
  dec.get_ival<uint64_t>( FID_TOKEN,       val.token );
  dec.get_ival<uint64_t>( FID_REF_SEQNO,   val.ref_seqno );
  dec.get_ival<uint32_t>( FID_RET,         val.reply );
  dec.get_ival<uint32_t>( FID_FMT,         val.fmt );
  dec.get_ival<uint32_t>( FID_TPORTID,     val.tport_id );
  dec.get_ival<uint64_t>( FID_TIME,        seq.time );

  /* if _I.Nonce.<inbox_ret>, find the inbox_ret */
  if ( dec.inbox_ret != 0 || dec.type == U_INBOX_ANY ) {
    if ( n.inbox.recv_seqno != 0 && dec.seqno != n.inbox.recv_seqno + 1 ) {
      n.printf( "%.*s missing inbox return seqno %" PRIu64 " -> %" PRIu64 " (%s)\n",
                (int) fpub.subject_len, fpub.subject,
                n.inbox.recv_seqno, dec.seqno, fpub.rte.name );
    }
    /* these should be in order, otherwise message loss occurred */
    n.inbox.set_recv( dec.seqno, dec.type );
    if ( dec.type != U_INBOX_ANY ) {
      const char * num = &fpub.subject[ this->ibx.len ];
      size_t       len = fpub.subject_len - this->ibx.len;
      InboxSub   * ibx = this->sub_db.inbox_tab.find(
                                 kv_hash_uint( dec.inbox_ret ), num, len );
      if ( ibx == NULL ) {
        n.printf( "%.*s inbox not found (%s)\n", (int) fpub.subject_len,
                  fpub.subject, fpub.rte.name );
        return;
      }
      seq.cb = ibx->on_data;
    }
    else if ( dec.test( FID_SUBJECT ) ) {
      const char * sub    = (const char *) dec.mref[ FID_SUBJECT ].fptr;
      uint16_t     sublen = (uint16_t) dec.mref[ FID_SUBJECT ].fsize;
      seq.cb = this->sub_db.match_any_sub( sub, sublen );
      if ( seq.cb == NULL ) {
        n.printf( "%.*s any match not found (%s)\n", (int) sublen, sub,
                  fpub.rte.name );
        return;
      }
    }
  }
  /* find the subject and matching subscription */
  else {
    SeqnoStatus status = this->sub_db.match_seqno( fpub, seq );

    if ( status > SEQNO_UID_NEXT ) {
      if ( status != SEQNO_NOT_SUBSCR ) {
        if ( status > SEQNO_UID_SKIP )
          fpub.status = FRAME_STATUS_DUP_SEQNO;
      }
      if ( status == SEQNO_UID_REPEAT ) {
        if ( debug_sess_repeat )
          this->show_seqno_status( fpub, n, dec, seq, status, true );
        n.msg_repeat_count++;
        n.msg_repeat_time = this->timer_time;
      }
      else if ( status == SEQNO_NOT_SUBSCR ) {
        if ( debug_sess_not_sub )
          this->show_seqno_status( fpub, n, dec, seq, status, true );
        n.msg_not_subscr_count++;
        n.msg_not_subscr_time = this->timer_time;
      }
      else if ( status == SEQNO_UID_SKIP ) {
        if ( debug_sess_loss )
          this->show_seqno_status( fpub, n, dec, seq, status, true );
        n.msg_loss_time = this->timer_time;
        if ( seq.msg_loss <= MAX_MSG_LOSS )
          n.msg_loss_count += seq.msg_loss;
        else
          n.msg_loss_count++;
      }
      else if ( debug_sess )
        this->show_seqno_status( fpub, n, dec, seq, status, true );
      if ( status > SEQNO_UID_SKIP )
        return;
    }
  }
  if ( seq.cb != NULL )
    seq.cb->on_data( val );
  else {
    n.printf( "Not subscribed: %.*s seqno %" PRIu64 " (%s)\n",
              (int) fpub.subject_len, fpub.subject, dec.seqno,
              fpub.rte.name );
  }
}

/* publish a mcast message, usually from console */
bool
SessionMgr::publish( PubMcastData &mc ) noexcept
{
  mc.path_select = 0;
  mc.subj_hash   = kv_crc_c( mc.sub, mc.sublen, 0 );
  if ( ( mc.option & CABA_OPT_ANY ) != 0 )
    return this->publish_any( mc );

  UserBridge * dest_bridge_id  = NULL;
  uint64_t     chain_seqno     = 0,
               time            = 0;
  uint32_t     h               = mc.subj_hash;
  CabaFlags    fl( CABA_MCAST );
  bool         need_seqno      = true,
               is_mcast_prefix = false;
  
  if ( mc.sublen > 2 && mc.sub[ 0 ] == '_' ) {
    static const char   inbox_prefix[] = _INBOX ".",
                        mcast_prefix[] = _MCAST ".";
    static const size_t inbox_prefix_len = sizeof( inbox_prefix ) - 1,
                        mcast_prefix_len = sizeof( mcast_prefix ) - 1;
    if ( ::memcmp( inbox_prefix, mc.sub, inbox_prefix_len ) == 0 ) {
      dest_bridge_id = this->user_db.is_inbox_sub( mc.sub, mc.sublen );
      if ( dest_bridge_id != NULL ) {
        mc.seqno   = dest_bridge_id->inbox.next_send( U_INBOX );
        need_seqno = false;
        fl.set_type( CABA_INBOX );
      }
    }
    else if ( ::memcmp( mcast_prefix, mc.sub, mcast_prefix_len ) == 0 ) {
      mc.seqno = ++this->user_db.mcast_send_seqno;
      need_seqno = false;
      is_mcast_prefix = true;
      this->user_db.msg_send_counter[ U_MCAST_PING ]++;
    }
    if ( caba_rtr_alert( mc.sub ) )
      fl.set_type( CABA_RTR_ALERT );
  }
  if ( need_seqno ) {
    RouteLoc loc;
    Pub * p = this->sub_db.pub_tab.upsert( h, mc.sub, mc.sublen, loc );
    if ( p == NULL )
      return false;

    mc.seqno = p->next_seqno( loc.is_new, time, this->timer_time,
                              this->converge_seqno, chain_seqno );
    this->user_db.msg_send_counter[ MCAST_SUBJECT ]++;
    if ( debug_sess && chain_seqno != 0 ) {
      printf( "seqno frame jump\n" );
    }
  }

  uint16_t option = mc.option;
  option &= ~( ( COST_PATH_COUNT - 1 ) << CABA_OPT_MC_SHIFT );
  if ( fl.get_type() == CABA_MCAST ||
       ( is_mcast_prefix && mc.path < COST_PATH_COUNT ) ) {
    if ( mc.path >= COST_PATH_COUNT )
      mc.path_select = caba_hash_to_path( h );
    else
      mc.path_select = mc.path;
    option |= mc.path_select << CABA_OPT_MC_SHIFT;
  }
  fl.set_opt( option );

  MsgEst e( mc.sublen );
  e.seqno       ()
   .chain_seqno ()
   .ret         ()
   .reply       ( mc.inbox_len )
   .time        ()
   .stamp       ()
   .token       ()
   .fmt         ()
   .data        ( mc.datalen );

  MsgCat m;
  m.reserve( e.sz );

  m.open( this->user_db.bridge_id.nonce, mc.sublen )
   .seqno ( mc.seqno );

  if ( chain_seqno != 0 )
    m.chain_seqno( chain_seqno );
  if ( mc.reply != 0 )
    m.ret( mc.reply );
  if ( mc.inbox_len != 0 )
    m.reply( mc.inbox, mc.inbox_len );
  if ( time != 0 )
    m.time( time );
  if ( mc.stamp != 0 )
    m.stamp( mc.stamp );
  if ( mc.token != 0 )
    m.token( mc.token );
  if ( mc.fmt != 0 )
    m.fmt( mc.fmt );
  if ( mc.datalen != 0 )
    m.data( mc.data, mc.datalen );
  m.close( e.sz, h, fl );

  m.sign( mc.sub, mc.sublen, *this->user_db.session_key );

  if ( dest_bridge_id != NULL )
    return this->user_db.forward_to_primary_inbox( *dest_bridge_id, mc.sub,
                                                 mc.sublen, h, m.msg, m.len() );

  ForwardCache   & forward = this->user_db.forward_path[ mc.path_select ];
  TransportRoute * rte;
  uint32_t         tport_id;
  bool             b = true;

  this->user_db.peer_dist.update_forward_cache( forward, 0, mc.path_select );
  if ( forward.first( tport_id ) ) {
    do {
      rte = this->user_db.transport_tab.ptr[ tport_id ];
      if ( debug_sess ) {
        printf( "pub %.*s (0x%x) path %u to %s\n",
                 (int) mc.sublen, mc.sub, h, mc.path_select, rte->name );
      }
      EvPublish pub( mc.sub, mc.sublen, NULL, 0, m.msg, m.len(),
                     rte->sub_route, *this, h, CABA_TYPE_ID, 'p' );
      pub.shard = mc.path_select;
      b &= rte->sub_route.forward_except( pub, this->router_set );
    } while ( forward.next( tport_id ) );
  }
  if ( (rte = this->user_db.ipc_transport) != NULL ) {
    uint32_t fmt = mc.fmt;
    if ( fmt == 0 && mc.datalen > 0 )
      fmt = MD_STRING;
    EvPublish pub( mc.sub, mc.sublen, mc.inbox, mc.inbox_len,
                   mc.data, mc.datalen, rte->sub_route, *this, h, fmt, 'p' );
    b &= rte->sub_route.forward_except( pub, this->router_set );
  }
  return b;
}

bool
SessionMgr::forward_uid_inbox( TransportRoute &src_rte,  EvPublish &fwd,
                               uint32_t uid ) noexcept
{
  const void * frag = NULL;
  size_t frag_sz = 0;

  if ( uid >= this->user_db.next_uid ||
       this->user_db.bridge_tab[ uid ] == NULL ) {
    fprintf( stderr, "bad uid %u\n", uid );
    return true;
  }
  UserBridge * n = this->user_db.bridge_tab[ uid ];
  InboxBuf  ibx( n->bridge_id );
  CabaFlags fl( CABA_INBOX );

  ibx.s( _ANY );

  MsgEst e( ibx.len() );
  e.seqno  ()
   .subject( fwd.subject_len )
   .reply  ( fwd.reply_len )
   .fmt    ();

  if ( fwd.msg_len != 0 ) {
    if ( fwd.msg_len <= this->poll.recv_highwater )
      e.data( fwd.msg_len );
    else {
      frag = fwd.msg;
      frag_sz = fwd.msg_len;
      e.data_frag();
    }
  }
  MsgCat m;
  m.reserve( e.sz );

  m.open( this->user_db.bridge_id.nonce, ibx.len() )
   .seqno ( n->inbox.next_send( U_INBOX_ANY ) );

  m.subject( fwd.subject, fwd.subject_len );
  if ( fwd.reply_len != 0 )
    m.reply( (const char *) fwd.reply, fwd.reply_len );
  if ( fwd.msg_enc != 0 )
    m.fmt( fwd.msg_enc );
  fl.set_opt( CABA_OPT_ANY );

  uint32_t h = ibx.hash();

  if ( fwd.msg_len != 0 ) {
    if ( frag_sz == 0 )
      m.data( fwd.msg, fwd.msg_len );
    else
      m.data_frag( frag_sz );
  }
  d_sess( "forward inbox %.*s\n", (int) fwd.subject_len, fwd.subject );

  if ( frag_sz == 0 ) {
    m.close( e.sz, h, fl );
    m.sign( ibx.buf, ibx.len(), *this->user_db.session_key );
  }
  else {
    frag = fwd.msg; frag_sz = fwd.msg_len;
    m.close_frag( e.sz, fwd.msg_len, h, fl );
    m.sign_frag( ibx.buf, ibx.len(), frag, frag_sz,
                 *this->user_db.session_key );
  }
  return this->user_db.forward_to_primary_inbox( *n, ibx, h, m.msg, m.len(),
                                                 &src_rte, frag, frag_sz,
                                                 fwd.src_route );
}
/* find a peer target for an _INBOX endpoint, and send it direct to the peer */
bool
SessionMgr::forward_inbox( TransportRoute &src_rte,  EvPublish &fwd,
                           const char *host,  size_t host_len ) noexcept
{
  uint32_t uid = this->sub_db.host_match( host, host_len );
  bool     b   = true;

  if ( uid == 0 ) {
    uid = this->sub_db.lookup_memo( fwd.subj_hash, fwd.subject,
                                    fwd.subject_len );
    d_sess( "reply.lookup( %.*s ) = %u\n",
            (int) fwd.subject_len, fwd.subject, uid );
  }
  if ( uid != 0 )
    b &= this->forward_uid_inbox( src_rte, fwd, uid );
  else {
    AnyMatch * any = this->sub_db.any_match( fwd.subject, fwd.subject_len,
                                             fwd.subj_hash );
    if ( any->set_count == 0 ) {
      printf( "no match for %.*s\n", (int) fwd.subject_len, fwd.subject );
      return true;
    }
    BitSetT<uint64_t> set( any->bits() );
    uint32_t uid, cnt = 0;

    set.first( uid, any->max_uid );
    for (;;) {
      b &= this->forward_uid_inbox( src_rte, fwd, uid );
      if ( ++cnt == any->set_count )
        break;
      set.next( uid, any->max_uid );
    }
  }
  return src_rte.check_flow_control( b );
}
/* forward a message from local ipc to peers, add subject sequence number */
bool
SessionMgr::forward_ipc( TransportRoute &src_rte,  EvPublish &pub ) noexcept
{
  CabaFlags fl( CABA_MCAST );
  RouteLoc  loc;
  Pub * p = this->sub_db.pub_tab.pub->find( pub.subj_hash, pub.subject,
                                            pub.subject_len, loc );
  if ( p == NULL ) {
    const char * host;
    size_t       host_len;
    if ( SubDB::match_inbox( pub.subject, pub.subject_len, host, host_len ) )
      return this->forward_inbox( src_rte, pub, host, host_len );
    p = this->sub_db.pub_tab.upsert( pub.subj_hash, pub.subject,
                                     pub.subject_len, loc );
    if ( p == NULL ) {
      fprintf( stderr, "error forward_ipc\n" );
      return true;
    }
  }
  uint64_t time, seqno, chain_seqno;
  seqno = p->next_seqno( loc.is_new, time, this->timer_time,
                         this->converge_seqno, chain_seqno );

  d_sess( "-> fwd_ipc: %.*s seqno %lu reply %.*s "
          "(len=%u, from %s, fd %d, enc %x)\n",
          (int) pub.subject_len, pub.subject, seqno,
          (int) pub.reply_len, (char *) pub.reply,
          pub.msg_len, src_rte.name, pub.src_route.fd, pub.msg_enc );

  const void * frag = NULL;
  size_t frag_sz = 0;
  uint8_t path_select = 0;
  if ( pub.pub_type == 'p' ) {
    path_select = caba_hash_to_path( pub.subj_hash );
    fl.set_opt( path_select << CABA_OPT_MC_SHIFT );
  }
  MsgEst e( pub.subject_len );
  e.seqno       ()
   .chain_seqno ()
   .time        ()
   .reply       ( pub.reply_len )
   .fmt         ();
  if ( pub.msg_len <= this->poll.recv_highwater )
    e.data( pub.msg_len );
  else {
    frag = pub.msg;
    frag_sz = pub.msg_len;
    e.data_frag();
  }
  MsgCat m;
  m.reserve( e.sz );

  m.open( this->user_db.bridge_id.nonce, pub.subject_len )
   .seqno ( seqno );

  if ( chain_seqno != 0 )
    m.chain_seqno( chain_seqno );
  if ( time != 0 )
    m.time( time );
  if ( pub.reply_len != 0 )
    m.reply( (const char *) pub.reply, pub.reply_len );
  if ( pub.msg_enc != 0 )
    m.fmt( pub.msg_enc );
  if ( pub.msg_len != 0 ) {
    if ( frag_sz == 0 )
      m.data( pub.msg, pub.msg_len );
    else
      m.data_frag( frag_sz );
  }
  if ( frag_sz == 0 ) {
    m.close( e.sz, pub.subj_hash, fl );
    m.sign( pub.subject, pub.subject_len, *this->user_db.session_key );
  }
  else {
    m.close_frag( e.sz, pub.msg_len, pub.subj_hash, fl );
    m.sign_frag( pub.subject, pub.subject_len, frag, frag_sz,
                 *this->user_db.session_key );
  }

  ForwardCache   & forward = this->user_db.forward_path[ path_select ];
  TransportRoute * rte;
  uint32_t         tport_id;
  bool             b = true;

  this->user_db.msg_send_counter[ MCAST_SUBJECT ]++;
  this->user_db.peer_dist.update_forward_cache( forward, 0, path_select );
  if ( forward.first( tport_id ) ) {
    do {
      rte = this->user_db.transport_tab.ptr[ tport_id ];
      if ( &src_rte != rte ) {
        if ( frag_sz == 0 ) {
          EvPublish evp( pub.subject, pub.subject_len, NULL, 0, m.msg, m.len(),
                         rte->sub_route, pub.src_route, pub.subj_hash,
                         CABA_TYPE_ID, 'p' );
          evp.shard = path_select;

          b &= rte->sub_route.forward_except( evp, this->router_set, &src_rte );
        }
        else {
          MsgFragPublish fvp( pub.subject, pub.subject_len, m.msg, m.len(),
                              rte->sub_route, pub.src_route, pub.subj_hash,
                              CABA_TYPE_ID, frag, frag_sz );
          fvp.shard = path_select;

          b &= rte->sub_route.forward_except( fvp, this->router_set, &src_rte );
        }
      }
    } while ( forward.next( tport_id ) );
  }
  if ( (rte = this->user_db.ipc_transport) != NULL ) {
    if ( &src_rte != rte ) {
      EvPublish evp( pub.subject, pub.subject_len, NULL, 0,
                     pub.msg, pub.msg_len,
                     rte->sub_route, pub.src_route, pub.subj_hash, 
                     pub.msg_enc, 'p' );
      b &= rte->sub_route.forward_except( evp, this->router_set, &src_rte );
    }
  }
  return src_rte.check_flow_control( b );
}
/* forward a message to any peer, chosen randomly */
bool
SessionMgr::publish_any( PubMcastData &mc ) noexcept
{
  uint32_t     h = mc.subj_hash;
  AnyMatch * any = this->sub_db.any_match( mc.sub, mc.sublen, h );
  UserBridge * n = any->get_destination( this->user_db );

  if ( n == NULL ) {
    printf( "no match for %.*s\n", (int) mc.sublen, mc.sub );
    return true;
  }
  if ( h == 0 ) {
    h = kv_crc_c( mc.sub, mc.sublen, 0 );
    mc.subj_hash = h;
  }
  PubPtpData ptp( *n, mc );
  ptp.option |= CABA_OPT_ANY;
  return this->publish_to( ptp );
}
/* forward to a peer using its inbox address, envelopes subject */
bool
SessionMgr::publish_to( PubPtpData &ptp ) noexcept
{
  InboxBuf  ibx( ptp.peer.bridge_id );
  CabaFlags fl( CABA_INBOX );

  if ( ptp.reply )
    ibx.i( ptp.reply );
  else
    ibx.s( _ANY );
  ptp.seqno = ptp.peer.inbox.next_send( U_INBOX );

  MsgEst e( ibx.len() );
  e.seqno  ()
   .subject( ptp.sublen )
   .ret    ()
   .stamp  ()
   .token  ()
   .fmt    ()
   .data   ( ptp.datalen );

  MsgCat m;
  m.reserve( e.sz );

  m.open( this->user_db.bridge_id.nonce, ibx.len() )
   .seqno ( ptp.seqno );

  if ( ptp.sublen != 0 )
    m.subject( ptp.sub, ptp.sublen );
  if ( ptp.reply2 != 0 )
    m.ret( ptp.reply2 );
  if ( ptp.stamp != 0 )
    m.stamp( ptp.stamp );
  if ( ptp.token != 0 )
    m.token( ptp.token );
  if ( ptp.fmt != 0 )
    m.fmt( ptp.fmt );
  if ( ptp.option != 0 )
    fl.set_opt( ptp.option );

  uint32_t h = ibx.hash();
  m.data( ptp.data, ptp.datalen )
   .close( e.sz, h, fl );

  m.sign( ibx.buf, ibx.len(), *this->user_db.session_key );

  d_sess( "-> publish_to : sub %.*s seqno %lu inbox %.*s\n",
          (int) ptp.sublen, ptp.sub, ptp.seqno,
          (int) ibx.len(), (char *) ibx.buf );

  return this->user_db.forward_to_primary_inbox( ptp.peer, ibx, h,
                                                 m.msg, m.len() );
}
/* if a message has the ACK flag set, ack back to sender */
void
SessionMgr::send_ack( const MsgFramePublish &pub,  UserBridge &n,
                      const MsgHdrDecoder &dec,  const char *suf ) noexcept
{
  char     ret_buf[ 16 ];
  InboxBuf ibx( n.bridge_id, dec.get_return( ret_buf, suf ) );
  uint64_t stamp, token = 0, ref_seqno = 0;
  uint32_t d;

  MsgEst e( ibx.len() );
  e.seqno    ()
   .stamp    ()
   .token    ()
   .cost     ()
   .tportid  ()
   .subject  ( pub.subject_len )
   .ref_seqno();

  dec.get_ival<uint64_t>( FID_TOKEN, token );
  dec.get_ival<uint64_t>( FID_SEQNO, ref_seqno );
  if ( ! dec.get_ival<uint64_t>( FID_STAMP, stamp ) || stamp == 0 )
    stamp = current_realtime_ns();
  uint16_t opt         = dec.msg->caba.get_opt();
  uint8_t  path_select = ( opt >> CABA_OPT_MC_SHIFT ) % COST_PATH_COUNT;
  d = this->user_db.peer_dist.calc_transport_cache( n.uid, pub.rte.tport_id,
                                                    path_select );
  MsgCat m;
  m.reserve( e.sz );
  m.open( this->user_db.bridge_id.nonce, ibx.len() )
   .seqno    ( n.inbox.next_send( U_INBOX_ACK /* or TRACE */ ) )
   .stamp    ( stamp );
  if ( token != 0 )
    m.token( token );
  m.cost     ( d )
   .tportid  ( pub.rte.tport_id )
   .subject  ( pub.subject, pub.subject_len )
   .ref_seqno( ref_seqno );
  uint32_t h = ibx.hash();
  m.close( e.sz, h, CABA_INBOX );
  m.sign( ibx.buf, ibx.len(), *this->user_db.session_key );

  this->user_db.forward_to_primary_inbox( n, ibx, h, m.msg, m.len() );
}
/* event loop */
bool
SessionMgr::loop( uint32_t &idle ) noexcept
{
  int status;
  uint32_t idle_count = idle;
  if ( this->poll.quit >= 5 )
    return false;
  if ( (status = this->poll.dispatch()) == EvPoll::DISPATCH_IDLE ) {
    int timeout = 0;
    idle_count++;
    if ( idle_count > this->idle_busy ) {
      timeout = 100;
      if ( ! this->user_db.peer_dist.clear_cache_if_dirty() ) {
        if ( this->user_db.converge_network( this->poll.mono_ns,
                                             this->poll.now_ns, false ) )
          timeout = 0;
      }
      else {
        if ( ! this->user_db.adjacency_change.is_empty() ) {
          this->user_db.send_adjacency_change();
          timeout = 0;
        }
      }
    }
    this->poll.wait( timeout );
  }
  if ( ( status & EvPoll::POLL_NEEDED ) != 0 ) {
    this->poll.wait( 0 );
    status = this->poll.dispatch();
  }
  if ( ( status & EvPoll::WRITE_PRESSURE ) != 0 ) {
    for ( int i = 0; i < 10; i++ ) {
      status = this->poll.dispatch();
      if ( ( status & EvPoll::WRITE_PRESSURE ) == 0 )
        break;
    }
  }
  idle = idle_count;
  return true;
}

void SessionMgr::write( void ) noexcept {}
void SessionMgr::read( void ) noexcept {}
void SessionMgr::process( void ) noexcept {}
void SessionMgr::release( void ) noexcept {}
void IpcRoute::write( void ) noexcept {}
void IpcRoute::read( void ) noexcept {}
void IpcRoute::process( void ) noexcept {}
void IpcRoute::release( void ) noexcept {}
void ConsoleRoute::write( void ) noexcept {}
void ConsoleRoute::read( void ) noexcept {}
void ConsoleRoute::process( void ) noexcept {}
void ConsoleRoute::release( void ) noexcept {}
void QueueRoute::write( void ) noexcept {}
void QueueRoute::read( void ) noexcept {}
void QueueRoute::process( void ) noexcept {}
void QueueRoute::release( void ) noexcept {}

#if 0
void
SessionMgr::on_connect( EvSocket &conn ) noexcept
{
  printf( "connected %s %s\n", conn.peer_address, conn.type_string() );
  this->user_db.connected.add( conn.fd );
}

void
SessionMgr::on_shutdown( EvSocket &conn,  const char *,  size_t ) noexcept
{
  printf( "disconnected %s\n", conn.peer_address );
  this->user_db.retire_source( conn.fd );
  this->user_db.connected.remove( conn.fd );
}
#endif
