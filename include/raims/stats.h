#ifndef __rai_raims__stats_h__
#define __rai_raims__stats_h__

#include <raikv/array_space.h>

namespace rai {
namespace ms {

static const uint64_t STATS_INTERVAL = 1;

struct PortStats {
  uint64_t bs, br, ms, mr;
  void set( int v ) {
    this->bs = this->br = this->ms = this->mr = (uint64_t) v;
  }
  void set( const PortStats &v ) {
    this->bs = v.bs; this->br = v.br; this->ms = v.ms; this->mr = v.mr;
  }
  void sum( uint64_t bytes_sent, uint64_t bytes_recv, uint64_t msgs_sent,
            uint64_t msgs_recv ) {
    this->bs += bytes_sent;
    this->br += bytes_recv;
    this->ms += msgs_sent;
    this->mr += msgs_recv;
  }
  void sum( const PortStats &v ) {
    this->sum( v.bs, v.br, v.ms, v.mr );
  }
  void diff( const PortStats &x,  const PortStats &y ) {
    this->bs = ( x.bs > y.bs ) ? x.bs - y.bs : 0;
    this->br = ( x.br > y.br ) ? x.br - y.br : 0;
    this->ms = ( x.ms > y.ms ) ? x.ms - y.ms : 0;
    this->mr = ( x.mr > y.mr ) ? x.mr - y.mr : 0;
  }
  bool is_zero( void ) const {
    return ( this->bs | this->br | this->ms | this->mr ) == 0;
  }
  PortStats & operator=( int z ) { this->set( z ); return *this; }
  PortStats & operator=( const PortStats &z ) { this->set( z ); return *this; }
};
typedef kv::ArrayCount< PortStats, 16 > LastArray;

struct SessionStats {
  uint64_t  update_mono_time,
            ipc_update_seqno,
            mono_time,
            n_peer_seqno,
            adjacency_cache_seqno,
            stats_seqno;
  uint32_t  n_port_ipc_rcount,
            n_port_rcount,
            n_peer_ipc_rcount,
            n_peer_rcount,
            n_adj_ipc_rcount,
            n_adj_rcount,
            n_all_rcount,
            n_all_ipc_rcount;
  LastArray last;
  PortStats last_total;

  SessionStats() {
    ::memset( &this->update_mono_time, 0, 
              (char *) (void *) &this->last -
              (char *) (void *) &this->update_mono_time );
    this->last_total = 0;
  }
};

}
}
#endif
