#ifndef __rai_raims__stats_h__
#define __rai_raims__stats_h__

#include <raikv/array_space.h>

namespace rai {
namespace ms {

static const uint64_t STATS_INTERVAL = 1;

struct StatsLast {
  uint64_t bytes_sent,
           bytes_recv,
           msgs_sent,
           msgs_recv;
};
typedef kv::ArrayCount< StatsLast, 16 > LastArray;

struct SessionStats {
  uint64_t  update_mono_time,
            ipc_update_seqno,
            mono_time,
            n_peer_seqno,
            adjacency_cache_seqno;
  uint32_t  n_port_ipc_rcount,
            n_port_rcount,
            n_peer_ipc_rcount,
            n_peer_rcount,
            n_adj_ipc_rcount,
            n_adj_rcount;
  LastArray last;
  SessionStats() {
    ::memset( &this->update_mono_time, 0, 
              (char *) (void *) &this->last -
              (char *) (void *) &this->update_mono_time );
  }
};

}
}
#endif
