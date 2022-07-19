#ifndef __rai__raims__adjacency_h__
#define __rai__raims__adjacency_h__

#include <raims/string_tab.h>
#include <raikv/bit_set.h>

#ifndef TEST_ADJ
namespace rai {
namespace ms {
#endif

struct UserNonceTab;
struct UserDB;
struct UserBridge;
struct TransportRoute;

enum PeerSyncReason {
  NO_REASON_SYNC  = 0,
  PEER_DB_SYNC    = 1,
  PEER_ADD_SYNC   = 2,
  ADJ_CHANGE_SYNC = 3,
  ADJ_RESULT_SYNC = 4,
  UNAUTH_ADJ_SYNC = 5,
  MAX_REASON_SYNC = 6
};
enum AdjacencyChange {
  UNKNOWN_CHANGE    = 0,
  HAVE_ADJ_CHANGE   = 1, /* adj update but not needed */
  NEED_ADJ_SYNC     = 2, /* can't use adj update, need sync */
  UPDATE_ADJ_CHANGE = 3, /* updated sync change */
  MAX_ADJ_CHANGE    = 4
};
enum AdjacencyRequest {
  UNKNOWN_ADJ_REQ   = 0,
  PING_SYNC_REQ     = 1, /* ping message with link state */
  HB_SYNC_REQ       = 2, /* hb message with link state */
  DIJKSTRA_SYNC_REQ = 3, /* missing link found using dijkstra */
  AUTH_SYNC_REQ     = 4, /* auth message with link state */
  PEER_SYNC_REQ     = 5, /* sync message containing adjacency */
  PEERDB_SYNC_REQ   = 6, /* peer db with link state */
  ADJ_CHG_SYNC_REQ  = 7, /* adjacency change message with link state */
  MISSING_SYNC_REQ  = 8, /* missing sub seqno */
  MAX_ADJ_REQ       = 9
};
enum InvalidReason {
  INVALID_NONE          = 0,
  UNKNOWN_ADJACENCY_INV = 1, /* unknown peer added */
  PUSH_ROUTE_INV        = 2, /* added a new peer link */
  POP_ROUTE_INV         = 3, /* removed a peer link */
  ADJACENCY_CHANGE_INV  = 4, /* recvd an adjacency change update */
  ADJACENCY_UPDATE_INV  = 5, /* recvd an adjacency sync from peer */
  ADD_TRANSPORT_INV     = 6, /* added a new transport */
  ADD_MESH_URL_INV      = 7, /* discovered a new mesh endpoint */
  ADD_UCAST_URL_INV     = 8, /* discovered a new ucast endpoint */
  ADVERTISED_COST_INV   = 9, /* transport advertised a different cost */
  MAX_INVALIDATE        = 10
};
#ifdef INCLUDE_PEER_CONST
static const char *peer_sync_reason_str[] = {
  "no_reason",
  "peer_db",
  "peer_add",
  "adj_change",
  "adj_result",
  "unauth_adj"
};
static const char *adjacency_change_str[] = {
  "unknown",
  "have_adj",
  "need_sync",
  "update_adj"
};
static const char *adjacency_request_str[] = {
  "unknown",
  "hb_sync",
  "ping_sync",
  "dijk_sync",
  "auth_sync",
  "peer_sync",
  "pdb_sync",
  "adjc_sync",
  "missing_sync"
};
static const char *invalid_reason_str[] = {
  "no_reason",
  "unknown_adj",
  "push_route",
  "pop_route",
  "adj_change",
  "adj_update",
  "add_tport",
  "add_mesh",
  "add_ucast",
  "adv_cost"
};
#if __cplusplus >= 201103L
static_assert( MAX_REASON_SYNC == ( sizeof( peer_sync_reason_str ) / sizeof( peer_sync_reason_str[ 0 ] ) ), "peer_sync_reason" );
static_assert( MAX_ADJ_CHANGE == ( sizeof( adjacency_change_str ) / sizeof( adjacency_change_str[ 0 ] ) ), "invalid_adj_change" );
static_assert( MAX_ADJ_REQ == ( sizeof( adjacency_request_str ) / sizeof( adjacency_request_str[ 0 ] ) ), "invalid_adj_request" );
static_assert( MAX_INVALIDATE == ( sizeof( invalid_reason_str ) / sizeof( invalid_reason_str[ 0 ] ) ), "invalid_reason" );
#endif
#endif
const char *peer_sync_reason_string( PeerSyncReason r ) noexcept;
const char *adjacency_change_string( AdjacencyChange c ) noexcept;
const char *adjacency_request_string( AdjacencyRequest r ) noexcept;
const char *invalidate_reason_string( InvalidReason r ) noexcept;

struct ForwardCache : public kv::UIntBitSet {
  uint32_t tport_count, fwd_count;
  uint64_t adjacency_cache_seqno;
  uint64_t bits;
  ForwardCache() : tport_count( 0 ), fwd_count( 0 ), adjacency_cache_seqno( 0 ),
                   bits( 0 ) {
    this->ptr = &this->bits;
  }
  ~ForwardCache() {
    this->reset();
  }
  void reset( void ) {
    if ( this->ptr != &this->bits )
      ::free( this->ptr );
    this->ptr = &this->bits;
    this->tport_count = this->fwd_count = 0;
    this->adjacency_cache_seqno = this->bits = 0;
  }
  bool first( uint32_t &tport_id ) const {
    return this->kv::UIntBitSet::first( tport_id, this->tport_count );
  }
  bool next( uint32_t &tport_id ) const {
    return this->kv::UIntBitSet::next( tport_id, this->tport_count );
  }
};

struct UidDist {
  uint32_t uid, dist;
};
struct UidMissing {
  uint32_t uid, uid2;
};

static const uint32_t COST_MAXIMUM    = 0xffffffffU,
                      COST_DEFAULT    = 1000;
static const uint8_t  COST_PATH_COUNT = 4;

struct AdjacencySpace : public kv::BitSpace {
  AdjacencySpace * next_link; /* tenp list for equal paths calc */
  ms::StringVal    tport;     /* name of link that peer advertised */
  uint32_t         uid,       /* uid owner of link */
                   tport_id,  /* tport owner of link */
                   cost[ COST_PATH_COUNT ]; /* cost of each path shard */
  uint16_t         clock;     /* adjacency calc upates when route is chosen */
  bool             is_advertised; /* whether to publish cost in hb */

  void * operator new( size_t, void *ptr ) { return ptr; }
  void operator delete( void *ptr ) { ::free( ptr ); }

  AdjacencySpace()
      : next_link( 0 ), uid( 0 ), tport_id( 0 ), clock( 0 ),
        is_advertised( false ) {
    for ( uint8_t i = 0; i < COST_PATH_COUNT; i++ )
      this->cost[ i ] = COST_DEFAULT;
  }
};

struct AdjacencyTab : public kv::ArrayCount< AdjacencySpace *, 4 > {
  AdjacencySpace *get( size_t n,  uint32_t uid,
                       uint32_t cost[ COST_PATH_COUNT ] ) {
    if ( n >= this->count ) {
      this->make( n + 1, true );
      this->count = n + 1;
    }
    if ( this->ptr[ n ] == NULL )
      this->ptr[ n ] =
        new ( ::malloc( sizeof( AdjacencySpace ) ) ) AdjacencySpace();
    this->ptr[ n ]->uid      = uid;
    this->ptr[ n ]->tport_id = n;

    for ( uint8_t i = 0; i < COST_PATH_COUNT; i++ )
      this->ptr[ n ]->cost[ i ] = cost[ i ];

    return this->ptr[ n ];
  }
  void reset( void ) {
    for ( size_t i = 0; i < this->count; i++ ) {
      if ( this->ptr[ i ] != NULL )
        delete this->ptr[ i ];
    }
    this->kv::ArrayCount<AdjacencySpace *, 4>::clear();
  }
};

struct UidSrcPath {
  uint32_t tport,   /* tport index by uid */
           src_uid, /* which uid tport routes to */
           cost;    /* tport cost index by uid */
  UidSrcPath() : tport( 0 ), src_uid( 0 ), cost( 0 ) {}
  void zero( void ) {
    this->tport = this->src_uid = this->cost = 0;
  }
};

struct PathSeqno {
  UidSrcPath * path;
  uint64_t     seqno;   /* cache update seqno */
};

struct AdjDistance : public md::MDMsgMem {
  UserDB       & user_db;
  UidDist      * stack;         /* stack of uids to check for distance */
  uint32_t     * cache,         /* cache of uid distence via a tport */
               * visit,         /* minimum distance to uid */
               * inc_list;      /* list of uids to be checked for links */
  PathSeqno      x[ COST_PATH_COUNT ]; /* x[ path_select ].port[ uid ]*/
  UidMissing   * missing;       /* list of missing links */
  kv::UIntBitSet inc_visit,     /* inconsistent check visit uid map */
                 adj,           /* uid map masked with path for coverage */
                 path,          /* path through the network */
                 fwd,           /* next uid map transitioning at cost */
                 reachable;     /* reachable uid map through tport */
  kv::ArrayCount< AdjacencySpace *, 4 > links; /* links for fwd */
  uint64_t       cache_seqno,   /* seqno of adjacency in cache */
                 update_seqno;  /* seqno of current adjacency */
  uint32_t       max_uid,       /* all uid < max_uid */
                 max_tport,     /* all tport < max_tport */
                 miss_tos,      /* number of missing uids in missing[] */
                 inc_hd,        /* list hd of uids in inc_list[] */
                 inc_tl,        /* list to of uids in inc_list[] */
                 inc_run_count; /* count of inc_runs after adjacency change */
  uint64_t       last_run_mono, /* timestamp of last adjacency update */
                 invalid_mono; /* when cache was invalidated */
  uint16_t       adjacency_clock; /* label transitions that were taken */
  InvalidReason  invalid_reason; /* why cache was invalidated */
  uint8_t        coverage_select; /* which path select */
  bool           inc_running,   /* whether incomplete check is running */
                 found_inconsistency; /* if current or last run inconsistent */

  static void zero_mem( void *x,  void *y ) {
    ::memset( x, 0, (char *) y - (char *) x );
  }
  AdjDistance( UserDB &u ) : user_db( u ) {
    zero_mem( &this->stack, &this->inc_visit );
    zero_mem( &this->cache_seqno, &this[ 1 ] );
  }

  void invalidate( InvalidReason why ) {
    if ( this->update_seqno++ == this->cache_seqno ) {
      if ( ! this->found_inconsistency ) {
        this->invalid_mono = kv::current_monotonic_time_ns();
        this->invalid_reason = why;
      }
    }
  }
  bool is_valid( uint64_t seqno ) {
    this->clear_cache_if_dirty();
    return seqno == this->cache_seqno;
  }
  void clear_cache_if_dirty( void ) {
    if ( this->cache_seqno != this->update_seqno )
      this->clear_cache();
  }
  void clear_cache( void ) noexcept;
  void update_forward_cache( ForwardCache &fwd,  uint32_t src_uid,
                             uint8_t path_select ) {
    if ( this->is_valid( fwd.adjacency_cache_seqno ) )
      return;
    this->calc_forward_cache( fwd, src_uid, path_select );
  }
  void calc_forward_cache( ForwardCache &fwd,  uint32_t src_uid,
                           uint8_t path_select ) noexcept;
  uint32_t adjacency_count( uint32_t uid ) const noexcept;
  AdjacencySpace * adjacency_set( uint32_t uid,  uint32_t i ) const noexcept;
  uint64_t adjacency_start( uint32_t uid ) const noexcept;
  void push_inc_list( uint32_t uid ) noexcept;
  bool find_inconsistent( UserBridge *&from, UserBridge *&to ) noexcept;
  uint32_t uid_refs( uint32_t from,  uint32_t to ) noexcept;
  uint32_t inbound_refs( uint32_t to ) noexcept;
  uint32_t outbound_refs( uint32_t from ) noexcept;

  uint32_t calc_transport_cache( uint32_t dest_uid,  uint32_t tport_id,
                                 uint8_t path_select ) {
    this->clear_cache_if_dirty();
    return this->calc_transport_cache2( dest_uid, tport_id, path_select );
  }
  uint32_t calc_transport_cache2( uint32_t dest_uid,  uint32_t tport_id,
                                  uint8_t path_select ) {
    size_t     off = tport_id * this->max_uid + dest_uid;
    uint32_t & d   = this->cache[ off * (size_t) ( path_select + 1 ) ];
    if ( d == 0 )
      d = this->calc_transport_cost( dest_uid, tport_id, path_select ) + 1;
    return d - 1;
  }
  uint32_t calc_transport_cost( uint32_t dest_uid, uint32_t tport_id,
                                uint8_t path_select ) noexcept;
  uint32_t calc_cost( uint32_t src_id, uint32_t dest_uid,
                      uint8_t path_select ) noexcept;
  uint32_t search_cost( uint32_t dest_uid,  uint32_t tos,
                        uint8_t path_select ) noexcept;

  void zero_clocks( void ) noexcept;
  void coverage_init( uint32_t src_uid,  uint8_t path_select ) noexcept;
  void push_link( AdjacencySpace *set ) noexcept;
  uint32_t coverage_step( void ) noexcept;
  AdjacencySpace *coverage_link( uint32_t target_uid ) noexcept;
  uint32_t calc_coverage( uint32_t src_uid,  uint8_t path_select ) noexcept;

  void update_path( uint8_t path_select ) {
    this->clear_cache_if_dirty();
    if ( this->x[ path_select ].seqno != this->update_seqno )
      this->calc_path( path_select );
  }
  void calc_path( uint8_t path_select ) noexcept;

  bool get_path( uint32_t uid,  uint8_t path_select,  UidSrcPath &path ) {
    this->update_path( path_select );
    if ( uid >= this->max_uid )
      return false;
    path = this->x[ path_select ].path[ uid ];
    if ( path.cost == 0 )
      return false;
    return true;
  }
  void calc_reachable( TransportRoute &rte ) noexcept;

  const char * uid_name( uint32_t uid,  char *buf,  size_t buflen ) noexcept;
  const char * uid_name( uint32_t uid,  char *buf,  size_t &off,
                         size_t buflen ) noexcept;
  const char * uid_set_names( kv::UIntBitSet &set,  char *buf,
                              size_t buflen ) noexcept;
};

#ifndef TEST_ADJ
}
}
#endif
#endif
