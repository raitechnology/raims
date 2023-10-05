#ifndef __rai__raims__adjacency_h__
#define __rai__raims__adjacency_h__

#include <raims/adj_graph.h>

namespace rai {
namespace ms {

struct UserNonceTab;
struct UserDB;
struct UserBridge;
struct TransportRoute;

enum PeerSyncReason {
  NO_REASON_SYNC  = 0,
  PEER_DB_SYNC    = 1,  /* peer db sync found new user */
  PEER_ADD_SYNC   = 2,  /* peer add msg found new user */
  ADJ_CHANGE_SYNC = 3,  /* adjacency change msg found new user */
  ADJ_RESULT_SYNC = 4,  /* adjacency result msg found new user */
  UNAUTH_ADJ_SYNC = 5,  /* placeholder waiting for auth user to verify */
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
  DIJKSTRA_NULL_REQ = 4, /* missing link null result */
  AUTH_SYNC_REQ     = 5, /* auth message with link state */
  PEER_SYNC_REQ     = 6, /* sync message containing adjacency */
  PEERDB_SYNC_REQ   = 7, /* peer db with link state */
  ADJ_CHG_SYNC_REQ  = 8, /* adjacency change message with link state */
  MISSING_SYNC_REQ  = 9, /* missing sub seqno */
  REQUEST_SYNC_REQ  = 10, /* adjacency request bounce */
  UID_CSUM_SYNC_REQ = 11, /* uid csum not correct */
  MCAST_SYNC_REQ    = 12, /* mcast link_state_sum and sub_seqno_sum */
  MCAST_SYNC_RES    = 13, /* mcast link_state_sum and sub_seqno_sum */
  MAX_ADJ_REQ       = 14
};
enum InvalidReason {
  INVALID_NONE          = 0,
  UNKNOWN_ADJACENCY_INV = 1, /* unknown peer added */
  PUSH_ROUTE_INV        = 2, /* added a new peer link */
  POP_ROUTE_INV         = 3, /* removed a peer link */
  ADJACENCY_CHANGE_INV  = 4, /* recvd an adjacency change update */
  ADJACENCY_UPDATE_INV  = 5, /* recvd an adjacency sync from peer */
  ADD_TRANSPORT_INV     = 6, /* added a new transport */
  ADVERTISED_COST_INV   = 7, /* transport advertised a different cost */
  MAX_INVALIDATE        = 8
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
  "ping_sync",
  "hb_sync",
  "dijk_sync",
  "dijk_null",
  "auth_sync",
  "peer_sync",
  "pdb_sync",
  "adjc_sync",
  "missing_sync",
  "request_sync",
  "uid_csum_sync",
  "mcast_sync_req",
  "mcast_sync_res"
};
static const char *invalid_reason_str[] = {
  "no_reason",
  "unknown_adj",
  "push_route",
  "pop_route",
  "adj_change",
  "adj_update",
  "add_tport",
  "adv_cost"
};
#if __cplusplus >= 201103L
static_assert( MAX_REASON_SYNC == ( sizeof( peer_sync_reason_str ) / sizeof( peer_sync_reason_str[ 0 ] ) ), "peer_sync_reason" );
static_assert( MAX_ADJ_CHANGE == ( sizeof( adjacency_change_str ) / sizeof( adjacency_change_str[ 0 ] ) ), "invalid_adj_change" );
static_assert( MAX_ADJ_REQ == ( sizeof( adjacency_request_str ) / sizeof( adjacency_request_str[ 0 ] ) ), "invalid_adj_request" );
static_assert( MAX_INVALIDATE == ( sizeof( invalid_reason_str ) / sizeof( invalid_reason_str[ 0 ] ) ), "invalid_reason" );
#endif
#endif

struct UidSrcPath {
  uint32_t tport,   /* tport index by uid */
           src_uid, /* which uid tport routes to */
           cost;    /* tport cost index by uid */
};

struct ForwardCache : public kv::UIntBitSet {
  uint32_t     tport_count;
  uint64_t     adjacency_cache_seqno;
  UidSrcPath * path; /* one for each uid */

  ForwardCache() : tport_count( 0 ), adjacency_cache_seqno( 0 ), path( 0 ) {}
  void init( uint32_t count,  uint64_t seqno,  uint64_t *p ) {
    this->ptr = p;
    this->tport_count = count;
    this->adjacency_cache_seqno = seqno;
  }
  bool first( uint32_t &tport_id ) const {
    return this->kv::UIntBitSet::first( tport_id, this->tport_count );
  }
  bool next( uint32_t &tport_id ) const {
    return this->kv::UIntBitSet::next( tport_id, this->tport_count );
  }
};
typedef kv::ArrayCount< ForwardCache, 4 > ForwardCacheArray;

static const uint32_t COST_MAXIMUM  = 0xffffffffU,
                      COST_DEFAULT  = 1000,
                      COST_BAD      = 1000 * 1000 * 1000, /* label bad path */
                      NO_PATH       = 0xffff,
                      MAX_PATH_MASK = 0xff; /* 1 byte in protocol packet */

struct AdjacencySpace : public kv::BitSpace {
  AdjacencySpace * next_link; /* tenp list for equal paths calc */
  ms::StringVal    tport,     /* name of link that peer advertised */
                   tport_type;/* type of link (mesh, tcp, pgm, ipc) */
  uint32_t         uid,       /* uid owner of link */
                   tport_id,  /* tport owner of link */
                   rem_uid,      /* uid rem_tport blongs to */
                   rem_tport_id; /* remote tport_id */
  AdjCost          cost;
  bool             is_advertised; /* whether to publish cost in hb */

  void * operator new( size_t, void *ptr ) { return ptr; }
  void operator delete( void *ptr ) { ::free( ptr ); }

  AdjacencySpace() : next_link( 0 ), uid( 0 ), tport_id( 0 ),
        rem_uid( 0 ), rem_tport_id( 0 ), cost( COST_DEFAULT ),
        is_advertised( false ) {
  }
};

struct AdjacencyTab : public kv::ArrayCount< AdjacencySpace *, 4 > {
  AdjacencySpace *get( size_t n,  uint32_t uid,  const AdjCost &cost ) {
    if ( n >= this->count ) {
      this->make( n + 1, true );
      this->count = n + 1;
    }
    if ( this->ptr[ n ] == NULL )
      this->ptr[ n ] =
        new ( ::malloc( sizeof( AdjacencySpace ) ) ) AdjacencySpace();
    this->ptr[ n ]->uid      = uid;
    this->ptr[ n ]->tport_id = n;
    this->ptr[ n ]->cost     = cost;

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

struct UserBridgeElem {
  UserBridgeElem * next;
  UserDB & user_db;
  uint32_t uid;
  void * operator new( size_t, void *ptr ) { return ptr; }
  UserBridgeElem( UserDB &udb,  uint32_t id )
    : next( 0 ), user_db( udb ), uid( id ) {}
};

struct UserBridgeList : public kv::SLinkList<UserBridgeElem> {
  static int cmp_user( const UserBridgeElem &e1,
                       const UserBridgeElem &e2 ) noexcept;
  static int cmp_nonce( const UserBridgeElem &e1,
                        const UserBridgeElem &e2 ) noexcept;
  static int cmp_start( const UserBridgeElem &e1,
                        const UserBridgeElem &e2 ) noexcept;
  static int cmp_stop( const UserBridgeElem &e1,
                       const UserBridgeElem &e2 ) noexcept;

  void add_users( UserDB &user_db,  md::MDMsgMem &mem ) noexcept;
  void add_zombie( UserDB &user_db,  md::MDMsgMem &mem ) noexcept;
};

struct UidDist {
  uint32_t uid, dist;
};
struct UidMissing {
  uint32_t uid, uid2;
};
struct AdjGraph;

struct AdjDistance : public md::MDMsgMem {
  UserDB          & user_db;
  UidDist         * stack;      /* stack of uids to check for distance */
  uint32_t        * visit,      /* minimum distance to uid */
                  * inc_list,   /* list of uids to be checked for links */
                  * graph_idx_order; /* order of uid in start time ordered list */
  AdjGraph        * graph;
  kv::UIntHashTab * cache_ht;

  kv::UIntBitSet inc_visit;     /* inconsistent check visit uid map */
  kv::ArrayCount< UidMissing, 8 > missing;

  uint64_t       cache_seqno,   /* seqno of adjacency in cache */
                 update_seqno;  /* seqno of current adjacency */
  uint32_t       max_uid,       /* all uid < max_uid */
                 max_tport,     /* all tport < max_tport */
                 path_count,
                 miss_tos,      /* number of missing uids in missing[] */
                 inc_hd,        /* list hd of uids in inc_list[] */
                 inc_tl,        /* list to of uids in inc_list[] */
                 inc_run_count; /* count of inc_runs after adjacency change */
  uint64_t       clear_stamp,
                 last_run_mono, /* timestamp of last adjacency update */
                 invalid_mono; /* when cache was invalidated */
  uint32_t       invalid_src_uid;
  InvalidReason  invalid_reason; /* why cache was invalidated */
  bool           inc_running,   /* whether incomplete check is running */
                 found_inconsistency; /* if current or last run inconsistent */

  static void zero_mem( void *x,  void *y ) {
    ::memset( x, 0, (char *) y - (char *) x );
  }
  AdjDistance( UserDB &u ) : user_db( u ) {
    zero_mem( (void *) &this->stack, (void *) &this->inc_visit );
    zero_mem( (void *) &this->max_uid, (void *) &this[ 1 ] );
    this->cache_seqno  = 0;
    this->update_seqno = 1;
    this->clear_stamp  = 1;
    this->path_count   = 1;
  }
  template<class AR>
  AR *mkar( size_t elcnt ) {
    size_t sz = sizeof( AR ) * elcnt;
    void *p = this->make( sz );
    ::memset( p, 0, sz );
    return (AR *) p;
  }
  uint32_t get_path_count( void ) {
    if ( this->cache_seqno != this->update_seqno )
      this->clear_cache();
    return this->path_count;
  }
  uint32_t hash_to_path( uint32_t h ) {
    return ( h & MAX_PATH_MASK ) % this->get_path_count();
  }
  void invalidate( InvalidReason why,  uint32_t src_uid ) {
    if ( this->update_seqno++ == this->cache_seqno ) {
      if ( ! this->found_inconsistency ) {
        this->invalid_mono = kv::current_monotonic_time_ns();
        this->invalid_reason = why;
      }
      this->invalid_src_uid = src_uid;
    }
    this->inc_run_count = 0;
  }
  bool is_valid( uint64_t seqno ) {
    this->clear_cache_if_dirty();
    return seqno == this->cache_seqno;
  }
  bool clear_cache_if_dirty( void ) {
    if ( this->cache_seqno != this->update_seqno ) {
      this->clear_cache();
      return false;
    }
    return true;
  }
  void clear_cache( void ) noexcept;

  /* update for my forwarding ports */
  void update_path( ForwardCache &fwd,  uint16_t path_select ) {
    if ( ! this->is_valid( fwd.adjacency_cache_seqno ) )
      this->calc_path( fwd, path_select );
  }
  void calc_path( ForwardCache &fwd,  uint16_t path_select ) noexcept;

  /* update for src forwarding ports */
  void update_source_path( ForwardCache &fwd,  uint32_t src_uid,
                           uint16_t path_select ) {
    if ( ! this->is_valid( fwd.adjacency_cache_seqno ) )
      this->calc_source_path( fwd, src_uid, path_select );
  }
  void calc_source_path( ForwardCache &fwd,  uint32_t src_uid,
                         uint16_t path_select ) noexcept;

  uint32_t adjacency_count( uint32_t uid ) const noexcept;
  AdjacencySpace * adjacency_set( uint32_t uid,  uint32_t i ) const noexcept;
  void push_inc_list( uint32_t uid ) noexcept;

  enum { CONSISTENT = 0, LINK_MISSING = 1, UID_ORPHANED = 2 };
  int find_inconsistent2( UserBridge *&from,  UserBridge *&to ) noexcept;
  bool match_target_set( uint32_t source_uid,  uint32_t target_uid,
                         AdjacencySpace &set ) noexcept;
  uint32_t uid_refs( uint32_t from,  uint32_t to ) noexcept;
  uint32_t inbound_refs( uint32_t to ) noexcept;
  uint32_t outbound_refs( uint32_t from ) noexcept;

  uint32_t calc_transport_cache( uint32_t dest_uid,  uint32_t tport_id,
                                 uint16_t path_select ) noexcept;
  uint32_t calc_transport_cost( uint32_t dest_uid, uint32_t tport_id,
                                uint16_t path_select ) noexcept;
  uint32_t calc_cost( uint32_t src_id, uint32_t dest_uid,
                      uint16_t path_select ) noexcept;
  uint32_t search_cost( uint32_t dest_uid,  uint32_t tos,
                        uint16_t path_select ) noexcept;

  const char * uid_name( uint32_t uid,  char *buf,  size_t buflen ) noexcept;
  const char * uid_name( uint32_t uid,  char *buf,  size_t &off,
                         size_t buflen ) noexcept;
  const char * uid_user( uint32_t uid ) noexcept;
  const char * uid_set_names( kv::UIntBitSet &set,  char *buf,
                              size_t buflen ) noexcept;
  void message_graph_description( kv::ArrayOutput &out ) noexcept;
  void update_graph( void ) noexcept;
};
}
}
#endif
