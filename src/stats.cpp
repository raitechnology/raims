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
      uint32_t     dist;
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
        dist        = this->user_db.peer_dist.calc_transport_cache( uid,
                                              u_ptr->rte.tport_id, u_ptr->rte );
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
        dist        = 0;
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
       .distance  ();
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
       .distance  ( dist );

      m.close( e.sz, h, CABA_MCAST );
      m.sign( s.msg, s.len(), *this->user_db.session_key );

      this->fwd_stat_msg( s, m, h, n_peer_rcount, n_peer_ipc_count );
    }
    if ( n_peer_pub_count > 0 ) {
      this->stats.n_peer_ipc_rcount = n_peer_ipc_count;
      this->stats.n_peer_rcount     = n_peer_rcount;
    }
  }

  uint32_t n_port_rcount    = 0,
           n_port_ipc_count = 0,
           n_port_pub_count = 0;
  uint32_t tport_count = this->user_db.transport_tab.count;
  for ( uint32_t tport_id = 0; tport_id < tport_count; tport_id++ ) {
    TransportRoute * rte = this->user_db.transport_tab.ptr[ tport_id ];
    uint64_t bs_tot  = 0, br_tot  = 0, ms_tot  = 0, mr_tot  = 0,
             bs_rate = 0, br_rate = 0, ms_rate = 0, mr_rate = 0;
    uint32_t ref = 0;
    rte->stats_seqno++;
    for ( uint32_t n = 0; n <= this->poll.maxfd; n++ ) {
      EvSocket *s = this->poll.sock[ n ];
      if ( s != NULL && s->sock_base > EV_LISTEN_BASE ) {
        if ( s->route_id == rte->sub_route.route_id ) {
          bs_tot += s->bytes_sent;
          br_tot += s->bytes_recv;
          ms_tot += s->msgs_sent;
          mr_tot += s->msgs_recv;
          ref++;
        }
      }
    }
    if ( ref > 0 ) {
      StatsLast &last = this->stats.last[ tport_id ];
      bs_rate = bs_tot - last.bytes_sent;
      br_rate = br_tot - last.bytes_recv;
      ms_rate = ms_tot - last.msgs_sent;
      mr_rate = mr_tot - last.msgs_recv;
      last.bytes_sent = bs_tot;
      last.bytes_recv = br_tot;
      last.msgs_sent  = ms_tot;
      last.msgs_recv  = mr_tot;
    }

    if ( ( sub_updated || n_port_subscribed || adj_changed ) && ref > 0 ) {
      uint32_t uid;
      n_port_pub_count++;
      SubjectVar s( N_PORT, N_PORT_SZ, this->user.user.val,
                    this->user.user.len );
      s.s( "." ).s( rte->transport.tport.val ).s( "." ).i( tport_id );
      h = s.hash();
      peer = NULL;
      if ( rte->uid_connected.first( uid ) ) {
        if ( uid != 0 ) {
          peer = this->user_db.bridge_tab[ uid ];
          if ( peer != NULL && ! peer->is_set( AUTHENTICATED_STATE ) )
            peer = NULL;
        }
      }
      if ( peer != NULL ) {
        peer_len = peer->peer.user.len;
        peer_val = peer->peer.user.val;
      }
      else {
        peer_len = 0;
        peer_val = NULL;
      }
      MsgEst e( s.len() );
      e.seqno   ()
       .time    ()
       .fmt     ()
       .user    ( this->user.user.len )
       .peer    ( peer_len )
       .tport   ( rte->transport.tport.len )
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
       .seqno   ( rte->stats_seqno )
       .time    ( cur_time )
       .fmt     ( CABA_TYPE_ID )
       .user    ( this->user.user.val, this->user.user.len )
       .peer    ( peer_val, peer_len )
       .tport   ( rte->transport.tport.val, rte->transport.tport.len )
       .tportid ( tport_id )
       .fd_cnt  ( ref )
       .uid_cnt ( rte->uid_connected.count() )
       .bs      ( bs_rate )
       .br      ( br_rate )
       .ms      ( ms_rate )
       .mr      ( mr_rate )
       .bs_tot  ( bs_tot )
       .br_tot  ( br_tot )
       .ms_tot  ( ms_tot )
       .mr_tot  ( mr_tot );
      m.close( e.sz, h, CABA_MCAST );
      m.sign( s.msg, s.len(), *this->user_db.session_key );

      this->fwd_stat_msg( s, m, h, n_port_rcount, n_port_ipc_count );
    }
  }
  if ( n_port_pub_count > 0 ) {
    this->stats.n_port_ipc_rcount = n_port_ipc_count;
    this->stats.n_port_rcount     = n_port_rcount;
  }
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

