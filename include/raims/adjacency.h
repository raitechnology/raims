#ifndef __rai__raims__adjacency_h__
#define __rai__raims__adjacency_h__

#include <raims/string_tab.h>
#include <raikv/bit_set.h>

#ifndef MS_NAMESPACE
#define MS_NAMESPACE ms
#endif

namespace rai {
namespace MS_NAMESPACE {

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
  ms::StringVal    tport,     /* name of link that peer advertised */
                   tport_type;/* type of link (mesh, tcp, pgm, ipc) */
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
  kv::UIntBitSet inc_visit,     /* inconsistent check visit uid map */
                 adj,           /* uid map masked with path for coverage */
                 path,          /* path through the network */
                 fwd,           /* next uid map transitioning at cost */
                 reachable;     /* reachable uid map through tport */
  kv::ArrayCount< UidMissing, 8 > missing;
  kv::ArrayCount< AdjacencySpace *, 4 > links; /* links for fwd */
  kv::BitSpace   graph_used,    /* graph description visit map */
                 graph_mesh;    /* mesh common peers */
  uint64_t       cache_seqno,   /* seqno of adjacency in cache */
                 update_seqno;  /* seqno of current adjacency */
  uint32_t       max_uid,       /* all uid < max_uid */
                 max_tport,     /* all tport < max_tport */
                 miss_tos,      /* number of missing uids in missing[] */
                 inc_hd,        /* list hd of uids in inc_list[] */
                 inc_tl,        /* list to of uids in inc_list[] */
                 inc_run_count, /* count of inc_runs after adjacency change */
                 max_tport_count; /* maximum tports any peer has, for graph */
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
    zero_mem( &this->max_uid, &this[ 1 ] );
    this->cache_seqno = 0;
    this->update_seqno = 1;
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

  void update_path( ForwardCache &fwd,  uint8_t path_select ) {
    this->clear_cache_if_dirty();
    if ( this->x[ path_select ].seqno != this->update_seqno )
      this->calc_path( fwd, path_select );
  }
  void calc_path( ForwardCache &fwd,  uint8_t path_select ) noexcept;

  bool get_path( ForwardCache &fwd,  uint32_t uid,  uint8_t path_select,
                 UidSrcPath &path ) {
    this->update_path( fwd, path_select );
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
  const char * uid_user( uint32_t uid ) noexcept;
  const char * uid_set_names( kv::UIntBitSet &set,  char *buf,
                              size_t buflen ) noexcept;
  bool find_peer_conn( const char *type,  uint32_t uid,
                       uint32_t peer_uid,  uint32_t &peer_conn_id ) noexcept;
  bool find_peer_set( const char *type,  uint32_t uid,
                      const AdjacencySpace &set,  uint32_t peer_uid,
                      uint32_t &peer_conn_id ) noexcept;
  void message_graph_description( kv::ArrayOutput &out ) noexcept;
};

#ifdef INCLUDE_DUMMY_DEFS
/* onlu sed for calculations in test_adj.cpp */
struct PeerEntry {
  ms::StringVal user, svc;
  PeerEntry() {
    ::memset( (void *) this, 0, sizeof( *this ) );
  }
  void set( const char *u,  const char *s,  ms::StringTab &st ) {
    st.ref_string( u, ::strlen( u ), this->user );
    st.ref_string( s, ::strlen( s ), this->svc );
  }
};

struct TransportRoute {
  UserDB       & user_db;
  uint32_t       tport_id;
  AdjacencySpace uid_connected;

  void * operator new( size_t, void *ptr ) { return ptr; }
  void operator delete( void *ptr ) { ::free( ptr ); }
  TransportRoute( UserDB &u,  uint32_t id ) : user_db( u ), tport_id( id ) {}
};

enum { AUTHENTICATED_STATE };
struct UserBridge {
  AdjacencyTab adjacency;
  uint64_t     start_time;
  uint32_t     uid, step, cost;
  PeerEntry    peer;
  kv::BitSpace fwd;
  bool is_set( int ) { return true; }

  void * operator new( size_t, void *ptr ) { return ptr; }
  void operator delete( void *ptr ) { ::free( ptr ); }
  UserBridge( uint32_t id ) : start_time( 0 ), uid( id ), step( 0 ), cost( 0 ){}
  ~UserBridge();

  AdjacencySpace *add_link( uint32_t cost[ COST_PATH_COUNT ],
                            const char *type,  const char *name,
                            ms::StringTab &st ) {
    AdjacencySpace *adj = this->adjacency.get( this->adjacency.count,
                                               this->uid, cost );
    if ( type != NULL )
      st.ref_string( type, ::strlen( type ), adj->tport_type );
    if ( name != NULL )
      st.ref_string( name, ::strlen( name ), adj->tport );
    return adj;
  }
  AdjacencySpace *add_link( uint32_t target_uid,
                            uint32_t cost[ COST_PATH_COUNT ],
                            const char *type,  const char *name,
                            ms::StringTab &st ) {
    AdjacencySpace *adj = this->add_link( cost, type, name, st );
    adj->add( target_uid );
    return adj;
  }
  AdjacencySpace *add_link( UserBridge *n,  uint32_t cost[ COST_PATH_COUNT ],
                            const char *type,  const char *name,
                            ms::StringTab &st ) {
    return this->add_link( n->uid, cost, type, name, st );
  }
};

struct TransportTab : public kv::ArrayCount< TransportRoute *, 4 > {};
struct UserBridgeTab : public kv::ArrayCount< UserBridge *, 128 > {};

struct UserDB {
  PeerEntry     user;
  uint32_t      next_uid, step, cost;
  uint64_t      start_time;
  UserBridgeTab bridge_tab;
  TransportTab  transport_tab;
  kv::BitSpace  uid_authenticated,
                fwd;
  AdjDistance   peer_dist;

  UserDB() : next_uid( 1 ), step( 0 ), cost( 0 ), peer_dist( *this ) {}
  ~UserDB();

  UserBridge *add( const char *u,  const char *s,  ms::StringTab &st ) {
    uint32_t uid = this->next_uid++;
    UserBridge *n = new ( ::malloc( sizeof( UserBridge ) ) ) UserBridge( uid );
    this->bridge_tab[ uid ] = n;
    n->peer.set( u, s, st );
    n->start_time = kv::current_realtime_ns() + (uint64_t) uid;
    this->uid_authenticated.add( uid );
    this->peer_dist.update_seqno++;
    return n;
  }
  UserBridge *find( const char *u,  const char *s,  ms::StringTab &st ) {
    for ( uint32_t uid = 1; uid < this->next_uid; uid++ ) {
      if ( this->bridge_tab[ uid ]->peer.user.equals( u ) )
        return this->bridge_tab[ uid ];
    }
    if ( this->user.user.len == 0 || this->user.user.equals( u ) ) {
      if ( this->user.user.len == 0 )
        this->user.set( u, s, st );
      return NULL;
    }
    return this->add( u, s, st );
  }
  TransportRoute *add_tport( uint32_t cost[ COST_PATH_COUNT ],
                             const char *type,  const char *name,
                             ms::StringTab &st ) {
    uint32_t tport_id = this->transport_tab.count;
    void * p = ::malloc( sizeof( TransportRoute ) );
    TransportRoute *t = new ( p ) TransportRoute( *this, tport_id );
    this->transport_tab[ tport_id ] = t;
    for ( uint8_t i = 0; i < COST_PATH_COUNT; i++ )
      t->uid_connected.cost[ i ] = cost[ i ];
    t->uid_connected.tport_id = tport_id;
    if ( type != NULL )
      st.ref_string( type, ::strlen( type ), t->uid_connected.tport_type );
    if ( name != NULL )
      st.ref_string( name, ::strlen( name ), t->uid_connected.tport );
    this->peer_dist.update_seqno++;
    return t;
  }
  TransportRoute *add_link( UserBridge *n,  uint32_t cost[ COST_PATH_COUNT ],
                            const char *type,  const char *name,
                            ms::StringTab &st ) {
    TransportRoute * t = this->add_tport( cost, type, name, st );
    t->uid_connected.add( n->uid );
    n->add_link( (uint32_t) 0, cost, type, name, st );
    this->peer_dist.update_seqno++;
    return t;
  }
  void make_link( UserBridge *x,  UserBridge *y,
                  uint32_t cost[ COST_PATH_COUNT ],
                  const char *type,  const char *name,  ms::StringTab &st ) {
    if ( x == NULL )
      this->add_link( y, cost, type, name, st );
    else if ( y == NULL )
      this->add_link( x, cost, type, name, st );
    else {
      x->add_link( y, cost, type, name, st );
      y->add_link( x, cost, type, name, st );
    }
  }
  bool load_users( const char *fn,  ms::StringTab &st,
                   uint32_t &start_uid ) noexcept;
  bool load_users( const char *p,  size_t size,  ms::StringTab &st,
                   uint32_t &start_uid ) noexcept;
  void print_elements( kv::ArrayOutput &out ) noexcept;
  void print_paths( kv::ArrayOutput &out,  uint32_t start_uid ) noexcept;
};
#endif
}

namespace ms {
bool compute_message_graph( const char *start,  const char *network,
                            size_t network_len,
                            kv::ArrayOutput &out ) noexcept;
}

}
#endif
