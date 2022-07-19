#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdarg.h>
#include <raims/session.h>
#include <raims/transport.h>

using namespace rai;
using namespace ms;
using namespace kv;
using namespace md;

void
UserDB::make_hb( TransportRoute &rte,  const char *sub,  size_t sublen,
                 uint32_t h,  MsgCat &m ) noexcept
{
  static const char * ver_str;
  static size_t       ver_len;

  if ( ver_len == 0 ) {
    ver_str = ms_get_version();
    ver_len = ::strlen( ver_str );
  }

  uint64_t uptime = rte.hb_mono_time - this->start_mono_time;
  if ( uptime == 0 )
    uptime = 1;

  MsgEst e( sublen );
  e.user_hmac ()
   .seqno     ()
   .time      ()
   .uptime    ()
   .start     ()
   .interval  ()
   .cnonce    ()
   .sub_seqno ()
   .link_state()
   .uid_cnt   ()
   .uid_csum  ()
   .mesh_csum ()
   .ucast_url ( rte.ucast_url_len )
   .mesh_url  ( rte.mesh_url_len )
   .cost      ()
   .cost2     ()
   .cost3     ()
   .cost4     ()
   .version   ( ver_len )
   .pk_digest ();

  m.reserve( e.sz );
  m.open( this->bridge_id.nonce, sublen )
   .user_hmac( this->bridge_id.hmac )
   .seqno    ( rte.hb_seqno     )
   .time     ( rte.hb_time      )
   .uptime   ( uptime           )
   .start    ( this->start_time );
  
  if ( h != bye_h ) {
    m.interval  ( this->hb_interval      )
     .cnonce    ( rte.hb_cnonce          )
     .sub_seqno ( this->sub_db.sub_seqno );
    if ( h != hello_h ) {
      m.link_state( this->link_state_seqno )
       .uid_cnt   ( this->uid_auth_count   )
       .uid_csum  ( this->uid_csum         );
      if ( rte.is_set( TPORT_IS_MESH ) ) {
        Nonce csum = *rte.mesh_csum;
        csum ^= this->bridge_id.nonce;
        m.mesh_csum( csum );
      }
    }
    if ( rte.ucast_url_len != 0 )
      m.ucast_url( rte.ucast_url_addr, rte.ucast_url_len );
    if ( rte.mesh_url_len != 0 )
      m.mesh_url( rte.mesh_url_addr, rte.mesh_url_len );
    if ( rte.uid_connected.is_advertised ) {
      m.cost( rte.uid_connected.cost[ 0 ] );
      m.cost2( rte.uid_connected.cost[ 1 ] );
      m.cost3( rte.uid_connected.cost[ 2 ] );
      m.cost4( rte.uid_connected.cost[ 3 ] );
    }
    m.version( ver_str, ver_len );
  }
  m.pk_digest();
  m.close( e.sz, h, CABA_HEARTBEAT );
  m.sign_hb( sub, sublen, *this->session_key, *this->hello_key );
}

void
UserDB::push_hb_time( TransportRoute &rte,  uint64_t time,  uint64_t mono ) noexcept
{
  rte.auth[ 2 ] = rte.auth[ 1 ];
  rte.auth[ 1 ] = rte.auth[ 0 ];
  rte.auth[ 0 ].cnonce = rte.hb_cnonce;
  rte.auth[ 0 ].time   = rte.hb_time;
  rte.auth[ 0 ].seqno  = rte.hb_seqno;

  rte.hb_cnonce          = this->cnonce->calc();
  rte.hb_time            = time;
  rte.hb_seqno++;
  rte.hb_mono_time       = mono;
  rte.last_connect_count = rte.connect_count;
  rte.last_hb_count      = rte.hb_count;
}

void
UserDB::hello_hb( void ) noexcept
{
  size_t count = this->transport_tab.count;
  this->events.send_hello();
  for ( size_t i = 0; i < count; i++ ) {
    TransportRoute *rte = this->transport_tab.ptr[ i ];
    if ( rte->connect_count > 0 ) {
      MsgCat m;
      this->push_hb_time( *rte, this->start_time, this->start_mono_time );
      this->make_hb( *rte, X_HELLO, X_HELLO_SZ, hello_h, m );

      char buf[ HMAC_B64_LEN + 1 ], buf2[ NONCE_B64_LEN + 1 ];
      d_hb( "hello %s(%u): %s:%s -> %s\n", this->user.user.val, this->my_src_fd,
             this->bridge_id.hmac.to_base64_str( buf ),
             this->bridge_id.nonce.to_base64_str( buf2 ), rte->name );
      EvPublish pub( X_HELLO, X_HELLO_SZ, NULL, 0, m.msg, m.len(),
                     rte->sub_route, this->my_src_fd, hello_h,
                     CABA_TYPE_ID, 'p' );
      rte->forward_to_connected( pub );
    }
  }
}

void
UserDB::bye_hb( void ) noexcept
{
  MsgCat m;
  uint64_t cur_time = current_realtime_ns(),
           cur_mono = current_monotonic_time_ns();
  size_t   count    = this->transport_tab.count;
  for ( size_t i = 0; i < count; i++ ) {
    TransportRoute *rte = this->transport_tab.ptr[ i ];
    if ( rte->connect_count > 0 ) {
      this->push_hb_time( *rte, cur_time, cur_mono );
      this->make_hb( *rte, X_BYE, X_BYE_SZ, bye_h, m );
      d_hb( "bye\n" );
      EvPublish pub( X_BYE, X_BYE_SZ, NULL, 0, m.msg, m.len(),
                     rte->sub_route, this->my_src_fd,
                     bye_h, CABA_TYPE_ID, 'p' );
      rte->forward_to_connected( pub );
    }
  }
}

void
UserDB::interval_hb( uint64_t cur_mono,  uint64_t cur_time ) noexcept
{
  uint64_t ival  = this->hb_ival_ns;
  size_t   count = this->transport_tab.count;
  for ( size_t i = 0; i < count; i++ ) {
    TransportRoute *rte = this->transport_tab.ptr[ i ];
    if ( rte->connect_count > 0 ) {
      bool do_hb = false;
      if ( rte->hb_mono_time + ival < cur_mono + ival / 64 )
        do_hb = true;
       else if ( ! rte->is_mcast() ) {
         if ( rte->hb_count != rte->last_hb_count ||
              rte->connect_count != rte->last_connect_count )
           do_hb = true;
      }
      if ( do_hb ) {
        if ( debug_hb )
          printf( "send hb %s\n", rte->name );
        MsgCat m;
        this->push_hb_time( *rte, cur_time, cur_mono );
        this->make_hb( *rte, X_HB, X_HB_SZ, hb_h, m );
        EvPublish pub( X_HB, X_HB_SZ, NULL, 0, m.msg, m.len(),
                       rte->sub_route, this->my_src_fd,
                       hb_h, CABA_TYPE_ID, 'p' );
        rte->forward_to_connected( pub );
      }
    }
  }
}
/* _X.HELLO, _X.HB */
bool
UserDB::on_heartbeat( const MsgFramePublish &pub,  UserBridge &n,
                      MsgHdrDecoder &dec ) noexcept
{
  Nonce    cnonce;
  uint64_t time, seqno, uptime, start, old_hb_seqno, current_mono_time;
  uint32_t cost[ COST_PATH_COUNT ] = { COST_DEFAULT, COST_DEFAULT,
                                       COST_DEFAULT, COST_DEFAULT },
           ival;
  if ( ! dec.get_ival<uint64_t>( FID_UPTIME, uptime ) ||
       ! dec.get_ival<uint64_t>( FID_SEQNO, seqno ) ||
       ! dec.get_ival<uint64_t>( FID_TIME, time ) ||
       ! dec.get_ival<uint64_t>( FID_START, start ) ||
       ! dec.get_ival<uint32_t>( FID_INTERVAL, ival ) ||
       ! dec.get_nonce( FID_CNONCE, cnonce ) )
    return true;

  if ( seqno <= n.user_route->hb_seqno ) {
    if ( seqno == n.user_route->hb_seqno ) {
      n.printe( "peer warp from %s, seqno %lu, uptime %lu\n",
                pub.rte.name, seqno, uptime );
    }
    return true;
  }
  if ( pub.status == FRAME_STATUS_OK && n.is_set( AUTHENTICATED_STATE ) ) {
    if ( ! pub.rte.uid_connected.is_member( n.uid ) ) {
      if ( debug_hb )
        n.printf( "authenticated but not a uid member!\n" );
      this->pop_user_route( n, *n.user_route );
      n.user_route->hops = 0;
      this->push_user_route( n, *n.user_route );
    }
    if ( ! n.test_set( HAS_HB_STATE ) ) {
      UserRoute * primary = n.primary( *this );
      if ( primary->hops > n.user_route->hops ) {
        if ( debug_hb )
          n.printf( "primary hops greater than hb user_route!\n" );
        this->add_inbox_route( n, n.user_route );
      }
      this->uid_hb_count++;
    }
    if ( dec.get_ival<uint32_t>( FID_COST, cost[ 0 ] ) ) {
      dec.get_ival<uint32_t>( FID_COST2, cost[ 1 ] );
      dec.get_ival<uint32_t>( FID_COST3, cost[ 2 ] );
      dec.get_ival<uint32_t>( FID_COST4, cost[ 3 ] );
      n.user_route->rte.update_cost( n, cost );
    }
  }
  if ( ! n.user_route->test_set( HAS_HB_STATE ) ) {
    n.user_route->rte.hb_count++;
    if ( debug_hb )
      n.printf( "set hb state %s\n", n.user_route->rte.name );
  }

  if ( dec.test( FID_MESH_URL ) )
    this->set_mesh_url( *n.user_route, dec );

  if ( dec.test( FID_UCAST_URL ) )
    this->set_ucast_url( *n.user_route, dec );

  /*if ( seqno <= n.hb_seqno )
    return true;*/
  /* the following for unauthenticated, watches for hb replay */
  if ( n.primary_route != pub.rte.tport_id ) {
    if ( pub.status != FRAME_STATUS_OK ) {
      if ( debug_hb )
        n.printf( "primary route not hb %s\n", n.user_route->rte.name );
      return true;
    }
  }
  if ( seqno > n.hb_seqno ) {
    old_hb_seqno      = n.hb_seqno;
    n.hb_seqno        = seqno;
    n.hb_time         = time;
    n.hb_interval     = ival;
    n.start_time      = start;
    current_mono_time = current_monotonic_time_ns();
    n.hb_mono_time    = current_mono_time;
    n.hb_cnonce       = cnonce;

    /*n.printf( "HB %.*s\n", (int) pub.subject_len, pub.subject );*/
    /* challenge the peer for auth, both client and server use this */
    if ( ! n.is_set( AUTHENTICATED_STATE | CHALLENGE_STATE ) ) {
      bool i_am_older = false, do_challenge = false, oldest_peer;
      if ( start > this->start_time )
        i_am_older = true;
      /*else if ( start == this->start_time )
        i_am_older = ( uptime <= n.hb_mono_time - this->start_mono_time );*/
      /* if I am the oldest node in route_list (or only node), do the challenge */
      oldest_peer = ( pub.rte.oldest_uid == 0 );
      uint64_t cur_time = current_realtime_ns();

      if ( i_am_older && oldest_peer ) {
        do_challenge = true;
        n.printf( "I am oldest peer\n" );
      }
      /* if a heartbeat passed and peer is old, try to challenge */
      else {
        n.printf( "i_am %s oldest %s\n", i_am_older ? "true" : "false",
                                         oldest_peer ? "true" : "false" );
        if ( ( oldest_peer && pub.rte.is_mcast() ) ||
             ( old_hb_seqno > 0 && old_hb_seqno + 1 == seqno &&
               start + SEC_TO_NS < cur_time ) ) {
          n.printf( "old_hb_seqno %lu seqno %lu, age %lu\n",
                    old_hb_seqno, seqno, cur_time - start );
          do_challenge = true;
        }
      }
      if ( do_challenge ) {
        this->compare_version( n, dec );
        n.auth[ 0 ].construct( n.hb_time, n.hb_seqno, n.hb_cnonce );
        n.auth[ 1 ].construct( cur_time, ++n.send_inbox_seqno,
                               this->cnonce->calc() );
        this->send_challenge( n, AUTH_FROM_HELLO );
        if ( ! n.test_set( CHALLENGE_STATE ) ) {
          n.set( CHALLENGE_STATE );
          n.challenge_count++;
          this->challenge_queue.push( &n );
        }
      }
    }
  }
  /* ignore hb which are not authenticated */
  if ( pub.status != FRAME_STATUS_OK || ! n.is_set( AUTHENTICATED_STATE ) )
    return true;
  if ( n.is_set( IN_HB_QUEUE_STATE ) ) {
    this->hb_queue.remove( &n );
    this->hb_queue.push( &n );
  }
  else {
    this->events.hb_queue( n.uid, 1 );
    if ( debug_hb )
      n.printf( "not in hb queue!\n" );
    n.set( IN_HB_QUEUE_STATE );
    this->hb_queue.push( &n );
  }
  if ( dec.test_2( FID_LINK_STATE, FID_SUB_SEQNO ) ) {
    uint64_t link_seqno = 0,
             sub_seqno  = 0;
    cvt_number<uint64_t>( dec.mref[ FID_LINK_STATE ], link_seqno );
    cvt_number<uint64_t>( dec.mref[ FID_SUB_SEQNO ], sub_seqno );
    if ( n.link_state_seqno < link_seqno || n.sub_seqno < sub_seqno ) {
      if ( debug_hb )
        n.printf( "hb link_state %lu != link_state %lu || "
                  "hb sub_seqno %lu != sub_seqno %lu\n", n.link_state_seqno,
                  link_seqno, n.sub_seqno, sub_seqno );
      this->send_adjacency_request( n, HB_SYNC_REQ );
    }
    else {
      char buf[ NONCE_B64_LEN + 1 ], buf2[ NONCE_B64_LEN + 1 ];
      if ( dec.test( FID_UID_CSUM ) ) {
        Nonce csum;
        csum.copy_from( dec.mref[ FID_UID_CSUM ].fptr );
        n.uid_csum = csum;
        if ( this->uid_csum != csum ) {
          n.printf( "uid_csum not equal %s=[%s] hb[%s]\n",
                   n.peer.user.val, this->uid_csum.to_base64_str( buf ),
                   csum.to_base64_str( buf2 ) );
          /*if ( debug_hb )
            this->debug_uids( this->uid_authenticated, csum );*/
        }
      }
      if ( dec.test( FID_MESH_CSUM ) && pub.rte.is_mesh() ) {
        Nonce csum, my_csum = *pub.rte.mesh_csum;
        csum.copy_from( dec.mref[ FID_MESH_CSUM ].fptr );
        my_csum ^= this->bridge_id.nonce;
        if ( my_csum != csum ) {
          current_mono_time = current_monotonic_time_ns();
          if ( this->last_auth_mono + SEC_TO_NS < current_mono_time )
            n.printf( "mesh_csum not equal %s=[%s] hb[%s] "
                      "mesh pending queue is_empty=%u\n",
                   n.peer.user.val, my_csum.to_base64_str( buf ),
                   csum.to_base64_str( buf2 ), this->mesh_pending.is_empty() );
          /*if ( debug_hb )
            this->debug_uids( *pub.rte.uid_in_mesh, csum );*/
          if ( this->mesh_pending.is_empty() )
            this->send_mesh_request( n, dec );
        }
      }
    }
  }
  return true;
}

void
UserDB::debug_uids( BitSpace &uids,  Nonce &csum ) noexcept
{
  Nonce csum2 = csum;
  uint32_t count = ( 2 << uids.count() ) - 1;
  char nm[ 128 ];
  char buf[ NONCE_B64_LEN + 1 ];
  printf( "uids: %s\n",
        this->uid_names( uids, nm, sizeof( nm ) ) );
  for ( uint32_t i = 1; i <= count; i++ ) {
    printf( "i = %u -> %u\n", i, count );
    if ( i & 1 ) {
      csum = this->bridge_id.nonce;
      printf( "+ %s = %s (%u)\n", this->user.user.val,
              csum.to_base64_str( buf ), csum == csum2 );
    }
    uint32_t uid, j = 2;
    for ( bool ok = uids.first( uid ); ok; ok = uids.next( uid ) ) {
      if ( i & j ) {
        csum ^= this->bridge_tab.ptr[ uid ]->bridge_id.nonce;
        printf( "+ %s = %s (%u)\n", this->bridge_tab.ptr[ uid ]->peer.user.val,
                csum.to_base64_str( buf ), csum == csum2 );
      }
      j <<= 1;
    }
  }
}

uint32_t
UserDB::random_uid_walk( void ) noexcept
{
  uint32_t serial_count = this->uid_auth_count;
  if ( serial_count == 0 )
    return 0;
  if ( serial_count > 8 )
    serial_count /= 4;
  if ( ( this->uid_ping_count++ % serial_count ) == 0 )
    this->next_ping_uid = (uint32_t) this->rand.next() % this->next_uid;

  if ( this->uid_authenticated.next( this->next_ping_uid ) ||
       this->uid_authenticated.first( this->next_ping_uid ) )
    return this->next_ping_uid;
  return 0;
}

void
UserDB::interval_ping( uint64_t curr_mono,  uint64_t ) noexcept
{
  if ( this->next_ping_mono > curr_mono )
    return;

  uint64_t hb_ns   = this->hb_ival_ns,
           hb_mask = this->hb_ival_mask;
  this->next_ping_mono  = curr_mono;
  this->next_ping_mono += ( this->rand.next() & hb_mask ) + hb_ns / 2;

  uint32_t uid = this->random_uid_walk();
  if ( uid == 0 /*|| this->bridge_tab.ptr[ uid ]->test( HAS_HB_STATE )*/ )
    return;

  UserBridge & n = *this->bridge_tab.ptr[ uid ];
  if ( n.auth_mono_time + hb_ns < curr_mono ) {
    if ( debug_hb )
      n.printf( "send ping\n" );
    this->send_ping_request( n );
  }
}

void
UserDB::send_ping_request( UserBridge &n ) noexcept
{
  InboxBuf ibx( n.bridge_id, _PING );
  uint64_t time = current_realtime_ns();
  n.ping_send_count++;
  n.ping_send_time = time;

  MsgEst e( ibx.len() );
  e.seqno     ()
   .time      ()
   .sub_seqno ()
   .link_state();

  MsgCat m;
  m.reserve( e.sz );

  m.open( this->bridge_id.nonce, ibx.len() )
   .seqno     ( ++n.send_inbox_seqno   )
   .time      ( time                   )
   .sub_seqno ( this->sub_db.sub_seqno )
   .link_state( this->link_state_seqno );
  uint32_t h = ibx.hash();
  m.close( e.sz, h, CABA_INBOX );
  m.sign( ibx.buf, ibx.len(), *this->session_key );

  this->forward_to_inbox( n, ibx, h, m.msg, m.len(), true );
}

bool
UserDB::recv_ping_request( const MsgFramePublish &,  UserBridge &n,
                           const MsgHdrDecoder &dec ) noexcept
{
  char     ret_buf[ 16 ];
  const char * suf = dec.get_return( ret_buf, _PONG );
  InboxBuf ibx( n.bridge_id, suf );
  uint64_t time = 0, token = 0;

  if ( dec.test( FID_TIME ) )
    cvt_number<uint64_t>( dec.mref[ FID_TIME ], time );
  if ( dec.test( FID_TOKEN ) )
    cvt_number<uint64_t>( dec.mref[ FID_TOKEN ], token );
  if ( time == 0 )
    time = current_realtime_ns();
  if ( suf != ret_buf ) { /* exclude manual pings */
    n.ping_recv_count++;
    n.ping_recv_time = time;
  }
  MsgEst e( ibx.len() );
  e.seqno  ()
   .time   ()
   .token  ();

  MsgCat m;
  m.reserve( e.sz );

  m.open( this->bridge_id.nonce, ibx.len() )
   .seqno  ( ++n.send_inbox_seqno )
   .time   ( time );
  if ( token != 0 )
    m.token( token );
  uint32_t h = ibx.hash();
  m.close( e.sz, h, CABA_INBOX );
  m.sign( ibx.buf, ibx.len(), *this->session_key );
  bool b = this->forward_to_inbox( n, ibx, h, m.msg, m.len(),
                                   dec.is_mcast_type() );
  if ( dec.test_2( FID_SUB_SEQNO, FID_LINK_STATE ) ) {
    uint64_t link_seqno = 0,
             sub_seqno  = 0;
    cvt_number<uint64_t>( dec.mref[ FID_LINK_STATE ], link_seqno );
    cvt_number<uint64_t>( dec.mref[ FID_SUB_SEQNO ], sub_seqno );
    if ( n.link_state_seqno < link_seqno || n.sub_seqno < sub_seqno ) {
      if ( debug_hb )
        n.printf( "ping link_state %lu != link_state %lu || "
                  "ping sub_seqno %lu != sub_seqno %lu\n", n.link_state_seqno,
                  link_seqno, n.sub_seqno, sub_seqno );
      this->send_adjacency_request( n, PING_SYNC_REQ );
    }
  }
  return b;
}

bool
UserDB::recv_pong_result( const MsgFramePublish &,  UserBridge &n,
                          const MsgHdrDecoder &dec ) noexcept
{
  uint64_t time = 0;
  if ( dec.test( FID_TIME ) )
    cvt_number<uint64_t>( dec.mref[ FID_TIME ], time );
  n.pong_recv_time = time;
  n.pong_recv_count++;
  time = current_realtime_ns() - time;
  n.round_trip_time = time;
  if ( n.test_clear( PING_STATE ) ) {
    this->ping_queue.remove( &n );
    n.ping_fail_count = 0;
  }
  if ( debug_hb )
    n.printf( "recv pong\n" );
  return true;
}

