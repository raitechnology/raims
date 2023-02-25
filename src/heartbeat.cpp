#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#define __STDC_FORMAT_MACROS
#include <inttypes.h>
#include <stdarg.h>
#include <math.h>
#include <raims/session.h>
#include <raims/transport.h>
#include <raims/ev_name_svc.h>
#include <raims/ev_rv_transport.h>

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
  StringVal mesh_url;
  if ( rte.mesh_id != NULL )
    mesh_url = rte.mesh_id->mesh_url;

  if ( ver_len == 0 ) {
    ver_str = ms_get_version();
    ver_len = ::strlen( ver_str );
  }

  uint64_t uptime = rte.hb_mono_time - this->start_mono_time;
  if ( uptime == 0 )
    uptime = 1;

  MsgEst e( sublen );
  e.user_hmac     ()
   .seqno         ()
   .time          ()
   .uptime        ()
   .start         ()
   .interval      ()
   .cnonce        ()
   .pubkey        ()
   .sub_seqno     ()
   .link_state    ()
   .sub_seqno_sum ()
   .link_state_sum()
   .converge      ()
   .uid_cnt       ()
   .uid_csum      ()
   .mesh_csum     ()
   .user          ( this->user.user.len )
   .create        ( this->user.create.len )
   .expires       ( this->user.expires.len )
   .ucast_url     ( rte.ucast_url.len )
   .mesh_url      ( mesh_url.len )
   .cost          ()
   .cost2         ()
   .cost3         ()
   .cost4         ()
   .tportid       ()
   .tport         ( rte.transport.tport.len )
   .version       ( ver_len )
   .pk_digest     ();

  m.reserve( e.sz );
  m.open( this->bridge_id.nonce, sublen )
   .user_hmac( this->bridge_id.hmac )
   .seqno    ( rte.hb_seqno     )
   .time     ( rte.hb_time      )
   .uptime   ( uptime           )
   .start    ( this->start_time );
  
  if ( h != bye_h ) {
    m.interval     ( this->hb_interval          )
     .cnonce       ( rte.hb_cnonce              )
     .pubkey       ( this->hb_keypair->pub      )
     .sub_seqno    ( this->sub_db.sub_seqno     )
     .sub_seqno_sum( this->sub_db.sub_seqno_sum )
     .user         ( this->user.user.val,
                     this->user.user.len        )
     .create       ( this->user.create.val,
                     this->user.create.len      );
    if ( this->user.expires.len > 0 )
      m.expires ( this->user.expires.val,
                  this->user.expires.len );
    if ( h != hello_h ) {
      m.link_state    ( this->link_state_seqno  )
       .link_state_sum( this->link_state_sum    )
       .converge      ( this->net_converge_time )
       .uid_cnt       ( this->uid_auth_count    )
       .uid_csum      ( this->uid_csum          );
      if ( rte.is_set( TPORT_IS_MESH ) ) {
        Nonce csum = *rte.mesh_csum;
        csum ^= this->bridge_id.nonce;
        m.mesh_csum( csum );
      }
    }
    if ( rte.ucast_url.len != 0 )
      m.ucast_url( rte.ucast_url.val, rte.ucast_url.len );
    if ( mesh_url.len != 0 )
      m.mesh_url( mesh_url.val, mesh_url.len );
    if ( rte.uid_connected.is_advertised ) {
      m.cost( rte.uid_connected.cost[ 0 ] );
      m.cost2( rte.uid_connected.cost[ 1 ] );
      m.cost3( rte.uid_connected.cost[ 2 ] );
      m.cost4( rte.uid_connected.cost[ 3 ] );
    }
    m.tportid( rte.tport_id );
    m.tport  ( rte.transport.tport.val, rte.transport.tport.len );
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
  this->msg_send_counter[ U_SESSION_HELLO ]++;
  for ( size_t i = 0; i < count; i++ ) {
    TransportRoute *rte = this->transport_tab.ptr[ i ];
    if ( rte->connect_count > 0 && ! rte->is_set( TPORT_IS_IPC ) ) {
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
    if ( rte->connect_count > 0 && ! rte->is_set( TPORT_IS_IPC ) ) {
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
  uint64_t ival   = this->hb_ival_ns;
  size_t   count  = this->transport_tab.count;
  uint32_t hb_cnt = 0;
  for ( size_t i = 0; i < count; i++ ) {
    TransportRoute *rte = this->transport_tab.ptr[ i ];
    if ( rte->connect_count > 0 && ! rte->is_set( TPORT_IS_IPC ) ) {
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
        hb_cnt++;
      }
    }
  }
  if ( hb_cnt > 0 )
    this->msg_send_counter[ U_SESSION_HB ]++;
}
/* _X.HELLO, _X.HB */
bool
UserDB::on_heartbeat( const MsgFramePublish &pub,  UserBridge &n,
                      MsgHdrDecoder &dec ) noexcept
{
  Nonce       cnonce;
  ec25519_key pubkey;
  uint64_t    time, seqno, uptime, start, old_hb_seqno,
              current_mono_time = 0;
  uint32_t    ival;

  if ( ! dec.get_ival<uint64_t>( FID_UPTIME, uptime ) ||
       ! dec.get_ival<uint64_t>( FID_SEQNO, seqno ) ||
       ! dec.get_ival<uint64_t>( FID_TIME, time ) ||
       ! dec.get_ival<uint64_t>( FID_START, start ) ||
       ! dec.get_ival<uint32_t>( FID_INTERVAL, ival ) ||
       ! dec.get_nonce( FID_CNONCE, cnonce ) ||
       ! dec.get_pubkey( FID_PUBKEY, pubkey ) )
    return true;

  uint64_t cur_time = current_realtime_ns();
  int64_t  skew     = (int64_t) ( cur_time - time );
  if ( n.hb_skew == 0 || n.hb_skew_ref != 0 ||
       n.hb_skew != min_abs( skew, n.hb_skew ) ) {
    n.hb_skew = skew;
    n.skew_upd++;
    n.hb_skew_ref = 0;
  }

  if ( seqno <= n.user_route->hb_seqno ) {
    if ( seqno == n.user_route->hb_seqno ) {
      n.printe( "peer warp from %s, seqno %lu, uptime %lu\n",
                pub.rte.name, seqno, uptime );
    }
    return true;
  }

  TransportRoute & rte = pub.rte;
  if ( pub.status == FRAME_STATUS_OK && n.is_set( AUTHENTICATED_STATE ) ) {
    if ( ! rte.uid_connected.is_member( n.uid ) ) {
      if ( debug_hb )
        n.printf( "authenticated but not a uid member (%s)\n", rte.name );
      this->set_connected_user_route( n, *n.user_route );
      /*this->pop_user_route( n, *n.user_route );
      n.user_route->connected( 0 );
      this->push_user_route( n, *n.user_route );*/
    }
    if ( ! n.test_set( HAS_HB_STATE ) ) {
      UserRoute * primary = n.primary( *this );
      if ( primary->hops() > n.user_route->hops() ) {
        if ( debug_hb )
          n.printf( "hb reconnect inbox (%s)\n", rte.name );
        this->add_inbox_route( n, n.user_route );
      }
      this->uid_hb_count++;
    }
    uint32_t cost[ COST_PATH_COUNT ] = { COST_DEFAULT, COST_DEFAULT,
                                         COST_DEFAULT, COST_DEFAULT },
             rem_tport_id = 0;
    StringVal tport;
    dec.get_ival<uint32_t>( FID_TPORTID, rem_tport_id );
    if ( dec.test( FID_TPORT ) ) {
      tport.val = (const char *) dec.mref[ FID_TPORT ].fptr;
      tport.len = dec.mref[ FID_TPORT ].fsize;
    }
    bool b;
    if ( dec.get_ival<uint32_t>( FID_COST, cost[ 0 ] ) ) {
      dec.get_ival<uint32_t>( FID_COST2, cost[ 1 ] );
      dec.get_ival<uint32_t>( FID_COST3, cost[ 2 ] );
      dec.get_ival<uint32_t>( FID_COST4, cost[ 3 ] );
      b = rte.update_cost( n, tport, cost, rem_tport_id, "hb1" );
    }
    else {
      b = rte.update_cost( n, tport, NULL, rem_tport_id, "hb2" );
    }
    if ( ! b ) {
      if ( debug_hb )
        n.printf( "bad transport cost (%s)\n", rte.name );
      return true;
    }
  }
  if ( ! n.user_route->test_set( HAS_HB_STATE ) ) {
    n.user_route->rte.hb_count++;
    if ( debug_hb )
      n.printf( "set hb state %s\n", n.user_route->rte.name );
  }

  if ( dec.test( FID_MESH_URL ) )
    this->set_mesh_url( *n.user_route, dec, "hb" );

  if ( dec.test( FID_UCAST_URL ) )
    this->set_ucast_url( *n.user_route, dec, "hb" );

  /*if ( seqno <= n.hb_seqno )
    return true;*/
  /* the following for unauthenticated, watches for hb replay */
  if ( n.primary_route != rte.tport_id ) {
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
    n.hb_pubkey       = pubkey;
    /*n.printf( "HB %.*s\n", (int) pub.subject_len, pub.subject );*/
    /* challenge the peer for auth, both client and server use this */
    if ( ! n.is_set( AUTHENTICATED_STATE | CHALLENGE_STATE ) ) {
      bool i_am_older = false, do_challenge = false, oldest_peer;
      if ( start > this->start_time )
        i_am_older = true;
      /*else if ( start == this->start_time )
        i_am_older = ( uptime <= n.hb_mono_time - this->start_mono_time );*/
      /* if I am the oldest node in route_list (or only node), do the challenge */
      oldest_peer = ( rte.oldest_uid == 0 );
      if ( n.hb_skew < -(int64_t) sec_to_ns( ival ) ||
           n.hb_skew >  (int64_t) sec_to_ns( ival ) ) {
        n.printe( "heartbeat time skew %ld is greater than the "
                  "interval(%u), time=%lu cur_time=%lu\n",
                  n.hb_skew, ival, time, cur_time );
      }

      if ( i_am_older && oldest_peer ) {
        do_challenge = true;
        n.printf( "I am oldest peer\n" );
      }
      /* if a heartbeat passed and peer is old, try to challenge */
      else {
        n.printf( "i_am %s oldest %s\n", i_am_older ? "true" : "false",
                                         oldest_peer ? "true" : "false" );
        if ( ( oldest_peer && rte.is_mcast() ) ||
             ( old_hb_seqno > 0 && old_hb_seqno + 1 == seqno &&
               start + sec_to_ns( 1 ) < cur_time ) ) {
          n.printf( "old_hb_seqno %lu seqno %lu, age %lu\n",
                    old_hb_seqno, seqno, cur_time - start );
          do_challenge = true;
        }
      }
      if ( do_challenge ) {
        this->compare_version( n, dec );
        n.auth[ 0 ].construct( time, seqno, cnonce );
        n.auth[ 1 ].construct( cur_time, n.inbox.next_send( U_INBOX_AUTH ),
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
  if ( dec.test( FID_CONVERGE ) ) {
    uint64_t converge = 0;
    cvt_number<uint64_t>( dec.mref[ FID_CONVERGE ], converge );
    if ( converge > this->net_converge_time )
      this->net_converge_time = converge;
  }
  if ( dec.test_2( FID_LINK_STATE, FID_SUB_SEQNO ) ) {
    uint64_t link_seqno     = 0,
             sub_seqno      = 0;
    bool     sync_adj       = false,
             sync_uid_csum  = false,
             sync_mesh_csum = false;
    cvt_number<uint64_t>( dec.mref[ FID_LINK_STATE ], link_seqno );
    cvt_number<uint64_t>( dec.mref[ FID_SUB_SEQNO ], sub_seqno );
    if ( n.link_state_seqno < link_seqno || n.sub_seqno < sub_seqno ) {
      if ( debug_hb )
        n.printf( "hb link_state %lu != link_state %lu || "
                  "hb sub_seqno %lu != sub_seqno %lu\n", n.link_state_seqno,
                  link_seqno, n.sub_seqno, sub_seqno );
      sync_adj = true;
      this->send_adjacency_request( n, HB_SYNC_REQ );
    }
    else {
      if ( dec.test( FID_UID_CSUM ) ) {
        Nonce csum;
        csum.copy_from( dec.mref[ FID_UID_CSUM ].fptr );
        n.uid_csum = csum;
        if ( this->uid_csum != csum ) {
          sync_uid_csum = true;
          if ( current_mono_time == 0 )
            current_mono_time = current_monotonic_time_ns();
          if ( this->last_auth_mono + sec_to_ns( 1 ) < current_mono_time ) {
            if ( ! this->check_uid_csum( n, csum ) )
              this->send_adjacency_request( n, UID_CSUM_SYNC_REQ );
          }
        }
      }
      if ( dec.test( FID_MESH_CSUM ) && rte.is_mesh() ) {
        Nonce csum, my_csum = *rte.mesh_csum;
        csum.copy_from( dec.mref[ FID_MESH_CSUM ].fptr );
        my_csum ^= this->bridge_id.nonce; /* includes all nonces */
        if ( my_csum != csum ) {
          if ( rte.mesh_cache == NULL ||
               rte.mesh_cache->uid != n.uid ||
               rte.mesh_cache->csum != csum ) {
            sync_mesh_csum = true;
            if ( current_mono_time == 0 )
              current_mono_time = current_monotonic_time_ns();
            if ( this->last_auth_mono + sec_to_ns( 5 ) < current_mono_time ) {
              char buf[ NONCE_B64_LEN + 1 ],
                   buf2[ NONCE_B64_LEN + 1 ],
                   buf3[ NONCE_B64_LEN + 1 ];
              uint32_t cache_uid = 0;
              buf3[ 0 ] = '\0';
              if ( rte.mesh_cache != NULL ) {
                rte.mesh_cache->csum.to_base64_str( buf3 );
                cache_uid = rte.mesh_cache->uid;
              }
              if ( this->mesh_pending.is_empty() ) {
                n.printf( "hb mesh_csum %s=[%s] hb[%s] cache[%s/%u]\n",
                     n.peer.user.val, my_csum.to_base64_str( buf ),
                     csum.to_base64_str( buf2 ), buf3, cache_uid );
                this->send_mesh_request( n, dec, csum );
              }
            }
          }
        }
        else if ( rte.mesh_cache != NULL ) {
          delete rte.mesh_cache;
          rte.mesh_cache = NULL;
        }
      }

      if ( ! sync_adj && ! sync_uid_csum && ! sync_mesh_csum ) {
        if ( dec.test_2( FID_LINK_STATE_SUM, FID_SUB_SEQNO_SUM ) ) {
          cvt_number<uint64_t>( dec.mref[ FID_LINK_STATE_SUM ],
                                n.link_state_sum );
          cvt_number<uint64_t>( dec.mref[ FID_SUB_SEQNO_SUM ],
                                n.sub_seqno_sum );
          if ( n.link_state_sum != this->link_state_sum ||
               n.sub_seqno_sum != this->sub_db.sub_seqno_sum ) {
            if ( current_mono_time == 0 )
              current_mono_time = current_monotonic_time_ns();
            if ( this->converge_mono + sec_to_ns( 3 ) < current_mono_time ) {
              n.sync_sum_diff++;
              /*n.printf( "hb link sum %lu != %lu || sub sum %lu != %lu\n",
                        n.link_state_sum, this->link_state_sum,
                        n.sub_seqno_sum, this->sub_db.sub_seqno_sum );*/
              this->mcast_sync( rte );
            }
          }
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
  if ( this->uid_auth_count == 0 )
    return 0;
  if ( this->next_ping_uid == 0 ) {
    this->next_ping_uid = (uint32_t) this->rand.next() % this->next_uid;
    this->uid_ping_count = 1;
  }
/*
  if ( serial_count == 0 )
    return 0;
  if ( serial_count > 8 )
    serial_count /= 4;
  if ( ( this->uid_ping_count++ % serial_count ) == 0 )
    this->next_ping_uid = (uint32_t) this->rand.next() % this->next_uid;
*/
  if ( this->uid_rtt.count() != 0 ) {
    if ( this->uid_rtt.next( this->next_ping_uid ) ||
         this->uid_rtt.first( this->next_ping_uid ) ) {
      return this->next_ping_uid;
    }
  }
  else if ( this->uid_ping_count++ >= this->next_uid ) {
    if ( this->uid_auth_count > 8 )
      this->next_ping_uid = (uint32_t) this->rand.next() % this->next_uid;
    this->uid_ping_count = 1;
  }
  /*printf( "uid auth %u [", this->next_ping_uid );
  uint32_t i;
  for ( bool b = this->uid_authenticated.first( i ); b;
        b = this->uid_authenticated.next( i ) ) {
    printf( "%u ", i );
  }
  printf( "] " );*/
  if ( this->uid_authenticated.next( this->next_ping_uid ) ) {
    /*printf( "next %u\n", this->next_ping_uid );*/
    return this->next_ping_uid;
  }
  else if ( this->uid_authenticated.first( this->next_ping_uid ) ) {
    /*printf( "first %u\n", this->next_ping_uid );*/
    return this->next_ping_uid;
  }
  return 0;
}

void
UserDB::interval_ping( uint64_t curr_mono,  uint64_t /*cur_time*/ ) noexcept
{
  if ( this->next_ping_mono > curr_mono )
    return;

  uint64_t hb_ns   = this->hb_ival_ns,
           hb_mask = this->hb_ival_mask;

  uint32_t uid = this->random_uid_walk();
  if ( uid != 0 ) {
    UserBridge & n = *this->bridge_tab.ptr[ uid ];
    if ( n.auth_mono_time + hb_ns / 4 > curr_mono )
      return;
    if ( debug_hb )
      n.printf( "send ping\n" );
    this->send_ping_request( n );
  }
  this->next_ping_mono  = curr_mono;
  this->next_ping_mono += ( this->rand.next() & hb_mask ) + hb_ns / 2;
}

void
UserDB::send_ping_request( UserBridge &n ) noexcept
{
  InboxBuf ibx( n.bridge_id, _PING );
  uint64_t stamp = current_realtime_ns();
  this->msg_send_counter[ U_INBOX_PING ]++;
  n.ping_send_count++;
  n.ping_send_time = stamp;

  MsgEst e( ibx.len() );
  e.seqno       ()
   .stamp       ()
   .sub_seqno   ()
   .link_state  ()
   .idl_service ()
   .idl_msg_loss();

  MsgCat m;
  m.reserve( e.sz );

  m.open( this->bridge_id.nonce, ibx.len() )
   .seqno     ( ++n.ping_send_seqno )
   .stamp     ( stamp                  )
   .sub_seqno ( this->sub_db.sub_seqno )
   .link_state( this->link_state_seqno );

  if ( n.inbound_msg_loss != 0 ) {
    size_t pos;
    if ( n.inbound_svc_loss->first( pos ) ) {
      uint32_t svc, loss;
      n.inbound_svc_loss->get( pos, svc, loss );
      m.idl_service( svc )
       .idl_msg_loss( loss );

      if ( debug_hb )
        n.printf( "ping svc %u loss %u\n", svc, loss );
    }
  }
  uint32_t h = ibx.hash();
  m.close( e.sz, h, CABA_INBOX );
  m.sign( ibx.buf, ibx.len(), *this->session_key );

  this->forward_to_primary_inbox( n, ibx, h, m.msg, m.len() );
}

void
UserDB::mcast_sync( TransportRoute &rte ) noexcept
{
  static const char m_sync[] = _MCAST "." _SYNC;
  static const uint32_t m_sync_len = sizeof( m_sync ) - 1;

  ForwardCache & forward = this->forward_path[ 0 ];
  this->peer_dist.update_forward_cache( forward, 0, 0 );
  if ( ! forward.is_member( rte.tport_id ) )
    return;

  uint64_t seqno = ++this->mcast_send_seqno;
  uint64_t stamp = current_realtime_ns();
  this->msg_send_counter[ U_MCAST_SYNC ]++;

  MsgEst e( m_sync_len );
  e.seqno         ()
   .stamp         ()
   .sub_seqno     ()
   .link_state    ()
   .sub_seqno_sum ()
   .link_state_sum();

  MsgCat m;
  m.reserve( e.sz );

  m.open( this->bridge_id.nonce, m_sync_len    )
   .seqno         ( seqno                      )
   .stamp         ( stamp                      )
   .sub_seqno     ( this->sub_db.sub_seqno     )
   .link_state    ( this->link_state_seqno     )
   .sub_seqno_sum ( this->sub_db.sub_seqno_sum )
   .link_state_sum( this->link_state_sum       );

  uint32_t h = kv_crc_c( m_sync, m_sync_len, 0 );
  m.close( e.sz, h, CABA_RTR_ALERT );
  m.sign( m_sync, m_sync_len, *this->session_key );

  EvPublish pub( m_sync, m_sync_len, NULL, 0, m.msg, m.len(),
                 rte.sub_route, this->my_src_fd, h,
                 CABA_TYPE_ID, 'p' );
  rte.sub_route.forward_except( pub, this->router_set );
}

bool
UserDB::hb_adjacency_request( UserBridge &n,  const MsgHdrDecoder &dec,
                              AdjacencyRequest type,  uint32_t &cnt ) noexcept
{
  if ( dec.test_2( FID_SUB_SEQNO, FID_LINK_STATE ) ) {
    uint64_t link_seqno = 0,
             sub_seqno  = 0;
    cvt_number<uint64_t>( dec.mref[ FID_LINK_STATE ], link_seqno );
    cvt_number<uint64_t>( dec.mref[ FID_SUB_SEQNO ], sub_seqno );
    if ( n.link_state_seqno < link_seqno || n.sub_seqno < sub_seqno ) {
      if ( debug_hb )
        n.printf( "sync link_state %lu != link_state %lu || "
                  "sync sub_seqno %lu != sub_seqno %lu\n", n.link_state_seqno,
                  link_seqno, n.sub_seqno, sub_seqno );
      cnt++;
      return this->send_adjacency_request( n, type );
    }
  }
  return true;
}

bool
UserDB::recv_mcast_sync_request( MsgFramePublish &pub,  UserBridge &n,
                                 const MsgHdrDecoder &dec ) noexcept
{
  char         ret_buf[ 16 ];
  const char * suf = dec.get_return( ret_buf, _SYNC );
  uint64_t     seqno;

  if ( dec.seqno != 0 ) {
    seqno = n.mcast_recv_seqno;
    if ( dec.seqno > seqno )
      n.mcast_recv_seqno = dec.seqno;
    if ( dec.seqno <= seqno ) {
      n.printf(
        "%.*s ignoring sync seqno replay %" PRIu64 " -> %" PRIu64 " (%s)\n",
        (int) pub.subject_len, pub.subject, seqno, dec.seqno, pub.rte.name );
      pub.status = FRAME_STATUS_DUP_SEQNO;
      return true;
    }
  }

  uint64_t sub_seqno_sum  = 0,
           link_state_sum = 0;
  bool     b = true;

  if ( dec.test( FID_SUB_SEQNO_SUM ) )
    cvt_number<uint64_t>( dec.mref[ FID_SUB_SEQNO_SUM ], sub_seqno_sum );
  if ( dec.test( FID_LINK_STATE_SUM ) )
    cvt_number<uint64_t>( dec.mref[ FID_LINK_STATE_SUM ], link_state_sum );

  if ( sub_seqno_sum != this->sub_db.sub_seqno_sum ||
       link_state_sum != this->link_state_sum ) {
    InboxBuf ibx( n.bridge_id, suf );
    uint64_t stamp = 0, token = 0;
    uint64_t cur_time = current_realtime_ns();

    if ( dec.test( FID_STAMP ) )
      cvt_number<uint64_t>( dec.mref[ FID_STAMP ], stamp );
    if ( dec.test( FID_TOKEN ) )
      cvt_number<uint64_t>( dec.mref[ FID_TOKEN ], token );
    if ( stamp == 0 )
      stamp = cur_time;

    MsgEst e( ibx.len() );
    e.seqno         ()
     .stamp         ()
     .reply_stamp   ()
     .token         ()
     .sub_seqno     ()
     .link_state    ()
     .sub_seqno_sum ()
     .link_state_sum();

    MsgCat m;
    m.reserve( e.sz );

    if ( suf == ret_buf )
      seqno = n.inbox.next_send( U_INBOX_SYNC );
    else {
      this->msg_send_counter[ U_INBOX_SYNC ]++;
      seqno = ++n.sync_send_seqno;
    }
    m.open( this->bridge_id.nonce, ibx.len() )
     .seqno       ( seqno    )
     .stamp       ( stamp    )
     .reply_stamp ( cur_time );
    if ( token != 0 )
      m.token( token );
    m.sub_seqno     ( this->sub_db.sub_seqno     )
     .link_state    ( this->link_state_seqno     )
     .sub_seqno_sum ( this->sub_db.sub_seqno_sum )
     .link_state_sum( this->link_state_sum       );

    uint32_t h = ibx.hash();
    m.close( e.sz, h, CABA_INBOX );
    m.sign( ibx.buf, ibx.len(), *this->session_key );
    b = this->forward_to_primary_inbox( n, ibx, h, m.msg, m.len() );
    n.sync_sum_req++;
  }

  b &= this->hb_adjacency_request( n, dec, MCAST_SYNC_REQ,
                                   n.sync_sum_req_adj );
  return b;
}

bool
UserDB::recv_mcast_sync_result( MsgFramePublish &pub,  UserBridge &n,
                                const MsgHdrDecoder &dec ) noexcept
{
  if ( dec.seqno != 0 ) {
    uint64_t seqno = n.sync_recv_seqno;
    if ( dec.seqno > seqno )
      n.sync_recv_seqno = dec.seqno;
    if ( dec.seqno <= seqno ) {
      n.printf(
        "%.*s ignoring sync seqno replay %" PRIu64 " -> %" PRIu64 " (%s)\n",
        (int) pub.subject_len, pub.subject, seqno, dec.seqno, pub.rte.name );
      pub.status = FRAME_STATUS_DUP_SEQNO;
      return true;
    }
  }
  n.sync_sum_res++;
  return this->hb_adjacency_request( n, dec, MCAST_SYNC_RES,
                                     n.sync_sum_res_adj );
}

bool
UserDB::recv_ping_request( MsgFramePublish &pub,  UserBridge &n,
                           const MsgHdrDecoder &dec,
                           bool is_mcast_ping ) noexcept
{
  char         ret_buf[ 16 ];
  const char * suf = dec.get_return( ret_buf, _PONG );
  uint64_t     seqno;

  if ( dec.seqno != 0 ) {
    if ( is_mcast_ping ) {
      seqno = n.mcast_recv_seqno;
      if ( dec.seqno > seqno )
        n.mcast_recv_seqno = dec.seqno;
    }
    else if ( suf == ret_buf ) { /* when using _I.<bridge>.N, uses inbox seqno */
      seqno = n.inbox.recv_seqno;
      if ( dec.seqno > seqno )
        n.inbox.set_recv( dec.seqno, U_INBOX_PING );
    }
    else { /* using _I.<bridge>.PING, uses ping seqno */
      seqno = n.ping_recv_seqno;
      if ( dec.seqno > seqno )
        n.ping_recv_seqno = dec.seqno;
    }
    if ( dec.seqno <= seqno ) {
      n.printf(
        "%.*s ignoring ping seqno replay %" PRIu64 " -> %" PRIu64 " (%s)\n",
        (int) pub.subject_len, pub.subject, seqno, dec.seqno, pub.rte.name );
      pub.status = FRAME_STATUS_DUP_SEQNO;
      return true;
    }
  }
  InboxBuf ibx( n.bridge_id, suf );
  uint64_t stamp = 0, token = 0;
  uint64_t cur_time = current_realtime_ns();

  if ( dec.test( FID_STAMP ) )
    cvt_number<uint64_t>( dec.mref[ FID_STAMP ], stamp );
  if ( dec.test( FID_TOKEN ) )
    cvt_number<uint64_t>( dec.mref[ FID_TOKEN ], token );
  if ( stamp == 0 )
    stamp = cur_time;
  else {
    int64_t skew = (int64_t) ( cur_time - stamp );
    if ( n.ping_skew == 0 || n.ping_skew != min_abs( skew, n.ping_skew ) ) {
      n.ping_skew = skew;
      n.skew_upd++;
    }
  }
  if ( suf != ret_buf ) { /* exclude manual pings */
    n.ping_recv_count++;
    n.ping_recv_time = stamp;
  }

  uint16_t idl_svc  = 0;
  uint32_t idl_loss = 0;
  if ( dec.test_2( FID_IDL_SERVICE, FID_IDL_MSG_LOSS ) ) {
    cvt_number<uint16_t>( dec.mref[ FID_IDL_SERVICE ], idl_svc );
    cvt_number<uint32_t>( dec.mref[ FID_IDL_MSG_LOSS ], idl_loss );

    if ( debug_hb )
      n.printf( "ping idl_svc %u idl_loss %u\n", idl_svc, idl_loss );
  }

  MsgEst e( ibx.len() );
  e.seqno       ()
   .stamp       ()
   .reply_stamp ()
   .tportid     ()
   .token       ()
   .idl_service ()
   .idl_msg_loss();

  MsgCat m;
  m.reserve( e.sz );

  if ( suf == ret_buf )
    seqno = n.inbox.next_send( U_INBOX_PONG );
  else {
    this->msg_send_counter[ U_INBOX_PONG ]++;
    seqno = ++n.pong_send_seqno;
  }
  m.open( this->bridge_id.nonce, ibx.len() )
   .seqno       ( seqno    )
   .stamp       ( stamp    )
   .reply_stamp ( cur_time )
   .tportid     ( pub.rte.tport_id );
  if ( token != 0 )
    m.token( token );
  if ( idl_svc != 0 ) {
   m.idl_service ( idl_svc )
    .idl_msg_loss( idl_loss );
  }
  uint32_t h = ibx.hash();
  m.close( e.sz, h, CABA_INBOX );
  m.sign( ibx.buf, ibx.len(), *this->session_key );
  bool b;
  if ( dec.is_mcast_type() )
    b = this->forward_to_primary_inbox( n, ibx, h, m.msg, m.len() );
  else
    b = this->forward_to_inbox( n, ibx, h, m.msg, m.len() );
  b &= this->hb_adjacency_request( n, dec, PING_SYNC_REQ,
                                   n.ping_sync_adj );

  if ( idl_svc != 0 ) {
    size_t count = this->transport_tab.count;
    for ( size_t i = 0; i < count; i++ ) {
      TransportRoute *rte = this->transport_tab.ptr[ i ];
      if ( rte->is_set( TPORT_IS_IPC ) && rte->rv_svc != NULL ) {
        rte->rv_svc->outbound_data_loss( idl_svc, idl_loss, n.bridge_nonce_int,
                                         n.peer.user.val );
        break;
      }
    }
  }
  return b;
}

bool
UserDB::recv_pong_result( MsgFramePublish &pub,  UserBridge &n,
                          const MsgHdrDecoder &dec ) noexcept
{
  if ( dec.seqno <= n.pong_recv_seqno ) {
    n.printf( "%.*s ignoring pong seqno replay %u -> %" PRIu64 " (%s)\n",
              (int) pub.subject_len, pub.subject,
              n.pong_recv_seqno, dec.seqno, pub.rte.name );
    pub.status = FRAME_STATUS_DUP_SEQNO;
    return true;
  }
  n.pong_recv_seqno = dec.seqno;

  uint64_t stamp = 0, reply_stamp = 0,
           cur_time = current_realtime_ns(),
           cur_mono = current_monotonic_time_ns();

  n.pong_recv_time = cur_time;
  n.pong_recv_count++;

  if ( dec.test( FID_STAMP ) )
    cvt_number<uint64_t>( dec.mref[ FID_STAMP ], stamp );
  if ( dec.test( FID_REPLY_STAMP ) )
    cvt_number<uint64_t>( dec.mref[ FID_REPLY_STAMP ], reply_stamp );

  if ( stamp != 0 ) {
    uint64_t rtt = cur_time - stamp;
    if ( reply_stamp != 0 ) {
      if ( n.min_rtt == 0 || rtt < n.min_rtt ) {
        uint64_t peer_now = reply_stamp + rtt / 2;
        n.pong_skew = (int64_t) cur_time - (int64_t) peer_now;
        if ( debug_hb )
          n.printf( "pong_skew %ld rtt %lu min %lu\n", n.pong_skew,
                    rtt, n.min_rtt );
        n.min_rtt = rtt;
        n.skew_upd++;
      }
      else {
        n.min_rtt += n.min_rtt / 8;
      }
    }
    n.round_trip_time = rtt;
    Rtt x;
    x.latency   = rtt;
    x.mono_time = cur_mono;
    n.rtt.append( x );
    this->uid_rtt.remove( n.uid );
  }

  if ( n.test_clear( PING_STATE ) ) {
    this->ping_queue.remove( &n );
    n.ping_fail_count = 0;
  }

  if ( dec.test_2( FID_IDL_SERVICE, FID_IDL_MSG_LOSS ) ) {
    uint16_t idl_svc  = 0;
    uint32_t idl_loss = 0, loss = 0;
    size_t   pos;
    cvt_number<uint16_t>( dec.mref[ FID_IDL_SERVICE ], idl_svc );
    cvt_number<uint32_t>( dec.mref[ FID_IDL_MSG_LOSS ], idl_loss );

    if ( debug_hb )
      n.printf( "pong idl_svc %u idl_loss %u\n", idl_svc, idl_loss );

    if ( n.inbound_svc_loss->find( idl_svc, pos, loss ) ) {
      if ( idl_loss >= loss ) {
        if ( n.inbound_svc_loss->elem_count == 1 ) {
          delete n.inbound_svc_loss;
          n.inbound_svc_loss = NULL;
          n.inbound_msg_loss = 0;
        }
        else {
          n.inbound_svc_loss->remove( pos );
        }
      }
      else {
        loss -= idl_loss;
        n.inbound_svc_loss->set( idl_svc, pos, loss );
      }
    }
    if ( n.inbound_msg_loss != 0 )
      this->uid_rtt.add( n.uid );
  }

  if ( debug_hb )
    n.printf( "recv pong\n" );
  return true;
}

int64_t
UserDB::get_min_skew( UserBridge &n,  uint32_t i ) noexcept
{
  int64_t skew;
  if ( i == this->next_uid )
    return 0;
  if ( n.pong_skew != 0 )
    skew = n.pong_skew;
  else if ( n.ping_skew != 0 )
    skew = n.ping_skew;
  else {
    skew = n.hb_skew;
    if ( n.hb_skew_ref != 0 ) {
      UserBridge &m = *this->bridge_tab.ptr[ n.hb_skew_ref ];
      uint64_t cur_time = current_realtime_ns(),
               m_time   = (uint64_t) ( (int64_t) cur_time -
                                       this->get_min_skew( m, i + 1 ) ),
               n_time   = (uint64_t) ( (int64_t) m_time - skew );
      skew = (int64_t) cur_time - n_time;
    }
  }
  n.skew_upd = 0;
  return n.clock_skew = skew;
}
