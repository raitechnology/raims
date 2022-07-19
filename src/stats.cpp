#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#define __STDC_FORMAT_MACROS
#include <inttypes.h>
#include <raims/session.h>
#include <raims/transport.h>

using namespace rai;
using namespace ms;
using namespace kv;
using namespace md;

void
SessionMgr::publish_stats( uint64_t cur_time ) noexcept
{
  uint32_t     h,
               peer_len;
  const char * peer_val;
  UserBridge * peer;

  bool sub_updated =
    ( this->stats.update_mono_time != this->sub_db.sub_update_mono_time ||
      this->stats.ipc_update_seqno != this->sub_db.update_seqno );
  if ( sub_updated ) {
    this->stats.ipc_update_seqno = this->sub_db.update_seqno;
    this->stats.update_mono_time = this->sub_db.sub_update_mono_time;
  }
  bool n_port_subscribed =
    ( this->stats.n_port_rcount != 0 || this->stats.n_port_ipc_rcount != 0 );
  bool n_peer_subscribed =
    ( this->stats.n_peer_rcount != 0 || this->stats.n_peer_ipc_rcount != 0 );
  bool n_all_subscribed =
    ( this->stats.n_all_rcount != 0 || this->stats.n_all_ipc_rcount != 0 );

  uint64_t cache_seqno = this->user_db.peer_dist.cache_seqno;
  bool cache_synced = ( cache_seqno == this->user_db.peer_dist.update_seqno );
  bool adj_changed  = false;

  if ( cache_synced && this->stats.adjacency_cache_seqno != cache_seqno ) {
    this->stats.adjacency_cache_seqno = cache_seqno;
    adj_changed = true;
    uint32_t n_adj_rcount    = 0,
             n_adj_ipc_count = 0;

    SubjectVar s( N_ADJ, N_ADJ_SZ, this->user.user.val,
                  this->user.user.len );
    h = s.hash();
    MsgEst e( s.len() );
    e.seqno      ()
     .time       ()
     .fmt        ()
     .user       ( this->user.user.len );

    MsgCat m;
    m.reserve( e.sz );

    m.open      ( this->user_db.bridge_id.nonce, s.len() )
     .seqno     ( cache_seqno )
     .time      ( cur_time )
     .fmt       ( CABA_TYPE_ID )
     .user      ( this->user.user.val, this->user.user.len );

    m.close( e.sz, h, CABA_MCAST );
    m.sign( s.msg, s.len(), *this->user_db.session_key );

    this->fwd_stat_msg( s, m, h, n_adj_rcount, n_adj_ipc_count );
    this->stats.n_adj_rcount     = n_adj_rcount;
    this->stats.n_adj_ipc_rcount = n_adj_ipc_count;
  }

  if ( sub_updated || n_peer_subscribed ) {
    uint32_t n_peer_rcount    = 0,
             n_peer_ipc_count = 0,
             n_peer_pub_count = 0,
             uid_count        = this->user_db.next_uid;
    for ( uint32_t uid = 0; uid < uid_count; uid++ ) {
      char         lat_buf[ 64 ];
      const char * latency_val;
      UserRoute  * u_ptr;
      uint64_t     seqno, sub_count;
      uint32_t     cost;
      int          latency_len;

      n_peer_pub_count++;
      peer = NULL;
      if ( uid != 0 ) {
        peer = this->user_db.bridge_tab[ uid ];
        if ( peer == NULL || ! peer->is_set( AUTHENTICATED_STATE ) )
          continue;
        peer_len    = peer->peer.user.len;
        peer_val    = peer->peer.user.val;
        u_ptr       = peer->primary( this->user_db );
        cost        = this->user_db.peer_dist.calc_transport_cache( uid,
                                                   u_ptr->rte.tport_id, 0 );
        seqno       = ++peer->stats_seqno;
        sub_count   = peer->bloom.bits->count;

        latency_len = 0;
        latency_val = NULL;

        uint64_t lat = peer->round_trip_time;
        if ( lat > 0 ) {
          const char * units = "us";
          while ( lat > 1000000 ) {
            lat /= 1000;
            if ( units[ 0 ] == 'u' )
              units = "ms";
            else {
              units = "se";
              break;
            }
          }
          latency_len = ::snprintf( lat_buf, sizeof( lat_buf ),
                                    "%.3g%s", (double) lat / 1000.0, units );
          latency_val = lat_buf;
        }
      }
      else {
        peer_len    = this->user.user.len;
        peer_val    = this->user.user.val;
        cost        = 0;
        seqno       = ++this->stats.n_peer_seqno;
        sub_count   = this->sub_db.bloom.bits->count;
        latency_len = 1;
        latency_val = "0";
      }
      SubjectVar s( N_PEER, N_PEER_SZ, this->user.user.val,
                    this->user.user.len );
      s.s( "." ).i( uid );
      h = s.hash();

      MsgEst e( s.len() );
      e.seqno     ()
       .time      ()
       .fmt       ()
       .peer      ( peer_len )
       .uid       ()
       .sub_cnt   ()
       .latency   ( latency_len )
       /*.tport     ( tport_len )*/
       .cost      ();
       /*.address   ( addr_len );*/

      MsgCat m;
      m.reserve( e.sz );

      m.open      ( this->user_db.bridge_id.nonce, s.len() )
       .seqno     ( seqno )
       .time      ( cur_time )
       .fmt       ( CABA_TYPE_ID )
       .peer      ( peer_val, peer_len )
       .uid       ( uid )
       .sub_cnt   ( sub_count )
       .latency   ( latency_val, latency_len )
       .cost      ( cost );

      m.close( e.sz, h, CABA_MCAST );
      m.sign( s.msg, s.len(), *this->user_db.session_key );

      this->fwd_stat_msg( s, m, h, n_peer_rcount, n_peer_ipc_count );
    }
    if ( n_peer_pub_count > 0 ) {
      this->stats.n_peer_ipc_rcount = n_peer_ipc_count;
      this->stats.n_peer_rcount     = n_peer_rcount;
    }
  }

  uint32_t  n_port_rcount    = 0,
            n_port_ipc_count = 0,
            n_port_pub_count = 0;
  PortStats all_total,
            all_rate;
  uint32_t  tport_count = this->user_db.transport_tab.count,
            all_ref     = 0;
  all_total = 0;
  all_rate  = 0;
  for ( uint32_t tport_id = 0; tport_id < tport_count; tport_id++ ) {
    TransportRoute * rte = this->user_db.transport_tab.ptr[ tport_id ];

    PortStats total, rate;
    uint32_t  ref = 0;
    total = 0;
    rate  = 0;
    total.sum( rte->sub_route.peer_stats.bytes_sent,
               rte->sub_route.peer_stats.bytes_recv,
               rte->sub_route.peer_stats.msgs_sent,
               rte->sub_route.peer_stats.msgs_recv );
    for ( uint32_t n = 0; n <= this->poll.maxfd; n++ ) {
      EvSocket *s = this->poll.sock[ n ];
      if ( s != NULL && s->sock_base > EV_LISTEN_BASE ) {
        if ( s->route_id == rte->sub_route.route_id ) {
          total.sum( s->bytes_sent, s->bytes_recv,
                     s->msgs_sent, s->msgs_recv );
          ref++;
        }
      }
    }
    PortStats & last = this->stats.last[ tport_id ];
    rate.diff( total, last );
    all_total.sum( total );
    if ( ! rate.is_zero() ) {
      last = total;

      if ( sub_updated || n_port_subscribed || adj_changed ) {
        n_port_pub_count++;
        SubjectVar s( N_PORT, N_PORT_SZ, this->user.user.val,
                      this->user.user.len );
        s.s( "." ).s( rte->transport.tport.val ).s( "." ).i( tport_id );
        this->fwd_port_stat_msg( s, rte, rate, total, cur_time, ref,
                                 rte->uid_connected.count(),
                                 n_port_rcount, n_port_ipc_count );
      }
    }
  }
  if ( n_port_pub_count > 0 ) {
    this->stats.n_port_ipc_rcount = n_port_ipc_count;
    this->stats.n_port_rcount     = n_port_rcount;
  }
  PortStats &last = this->stats.last_total;
  all_rate.diff( all_total, last );
  if ( ! all_rate.is_zero() ) {
    uint32_t rcount = 0, ipc_count = 0;
    last = all_total;

    if ( sub_updated || n_all_subscribed || adj_changed ) {
      SubjectVar s( N_ALL, N_ALL_SZ, this->user.user.val,
                    this->user.user.len );
      this->fwd_port_stat_msg( s, NULL, all_rate, all_total, cur_time, all_ref,
                               this->user_db.uid_auth_count, rcount, ipc_count);
      this->stats.n_all_rcount     = rcount;
      this->stats.n_all_ipc_rcount = ipc_count;
    }
  }
}

void
SessionMgr::fwd_port_stat_msg( SubjectVar &s,  TransportRoute *rte,
                               PortStats &rate,  PortStats &total,
                               uint64_t cur_time,  uint32_t fd_cnt,
                               uint32_t uid_cnt,  uint32_t &rcount,
                               uint32_t &ipc_count ) noexcept
{
  UserBridge * peer      = NULL;
  const char * peer_val  = NULL,
             * tport_val = NULL;
  uint32_t     uid, h = s.hash(),
               peer_len    = 0,
               tport_len   = 0,
               tport_id    = 0;
  uint64_t     stats_seqno = 0;

  if ( rte != NULL ) {
    if ( rte->uid_connected.first( uid ) ) {
      if ( uid != 0 ) {
        peer = this->user_db.bridge_tab[ uid ];
        if ( peer != NULL && ! peer->is_set( AUTHENTICATED_STATE ) )
          peer = NULL;
      }
    }
    tport_val   = rte->transport.tport.val;
    tport_len   = rte->transport.tport.len;
    tport_id    = rte->tport_id;
    stats_seqno = ++rte->stats_seqno;
  }
  else {
    stats_seqno = ++this->stats.stats_seqno;
  }
  if ( peer != NULL ) {
    peer_len = peer->peer.user.len;
    peer_val = peer->peer.user.val;
  }

  MsgEst e( s.len() );
  e.seqno   ()
   .time    ()
   .fmt     ()
   .user    ( this->user.user.len )
   .peer    ( peer_len )
   .tport   ( tport_len )
   .tportid ()
   .fd_cnt  ()
   .uid_cnt ()
   .bs      ()
   .br      ()
   .ms      ()
   .mr      ()
   .bs_tot  ()
   .br_tot  ()
   .ms_tot  ()
   .mr_tot  ();

  MsgCat m;
  m.reserve( e.sz );

  m.open    ( this->user_db.bridge_id.nonce, s.len() )
   .seqno   ( stats_seqno )
   .time    ( cur_time )
   .fmt     ( CABA_TYPE_ID )
   .user    ( this->user.user.val, this->user.user.len )
   .peer    ( peer_val, peer_len )
   .tport   ( tport_val, tport_len )
   .tportid ( tport_id )
   .fd_cnt  ( fd_cnt )
   .uid_cnt ( uid_cnt )
   .bs      ( rate.bs )
   .br      ( rate.br )
   .ms      ( rate.ms )
   .mr      ( rate.mr )
   .bs_tot  ( total.bs )
   .br_tot  ( total.br )
   .ms_tot  ( total.ms )
   .mr_tot  ( total.mr );
  m.close( e.sz, h, CABA_MCAST );
  m.sign( s.msg, s.len(), *this->user_db.session_key );

  this->fwd_stat_msg( s, m, h, rcount, ipc_count );
}

void
SessionMgr::fwd_stat_msg( SubjectVar &s,  MsgCat &m,  uint32_t h,
                          uint32_t &rcount,  uint32_t &ipc_count ) noexcept
{
  uint32_t phash[ MAX_RTE ];
  uint8_t  prefix[ MAX_RTE ];
  uint32_t tport_count = this->user_db.transport_tab.count;

  for ( uint32_t j = 0; j < tport_count; j++ ) {
    TransportRoute * fwd = this->user_db.transport_tab.ptr[ j ];
    EvPublish pub( s.msg, s.len(), NULL, 0, m.msg, m.len(),
                   fwd->sub_route, this->fd, h, CABA_TYPE_ID, 'p' );
    if ( ! fwd->is_set( TPORT_IS_IPC ) ) {
      uint32_t k;
      fwd->sub_route.forward_set_with_cnt( pub, fwd->connected_auth, k );
      rcount += k;
    }
    else {
      uint8_t n = 1;
      phash[ 0 ]  = h;
      prefix[ 0 ] = SUB_RTE;
      n += this->sub_db.pat_tab.prefix_hash( s.msg, s.len(),
                                             &phash[ 1 ], &prefix[ 1 ] );
      pub.hash       = phash;
      pub.prefix     = prefix;
      pub.prefix_cnt = n;
      ipc_count += this->console_rt.fwd_console( pub, true );
    }
  }
}

