#ifndef __rai__raims__peer_h__
#define __rai__raims__peer_h__

#include <raims/crypt.h>
#include <raims/string_tab.h>
#include <raikv/bit_set.h>

namespace rai {
namespace ms {

static const uint64_t SEC_TO_NS = 1000 * 1000 * 1000;
/* hmac of user + instance nonce */
struct UserNonce {
  PolyHmacDigest hmac;  /* hmac ( hash_digest( pub key ), user + service ) */
  Nonce          nonce; /* random session nonce */
  void * operator new( size_t, void *ptr ) { return ptr; }
  UserNonce() {}

  void zero( void ) {
    this->hmac.zero();
    this->nonce.zero();
  }
  void copy_from( const void *ptr ) {
    this->hmac.copy_from( ptr );
    this->nonce.copy_from( &((uint8_t *) ptr)[ HMAC_SIZE ] );
  }
  void print( void ) {
    this->hmac.print(); printf( "::" ); this->nonce.print();
  }
  bool operator==( const UserNonce &x ) const {
    return this->hmac == x.hmac && this->nonce == x.nonce;
  }
  bool operator<( const UserNonce &x ) const {
    return this->hmac < x.hmac ||
           ( this->hmac == x.hmac && this->nonce < x.nonce );
  }
  bool operator>( const UserNonce &x ) const {
    return this->hmac > x.hmac ||
           ( this->hmac == x.hmac && this->nonce > x.nonce );
  }
  char *to_string( char *buf ) noexcept;
};
/* derived from config or from peer */
struct PeerEntry {
  PolyHmacDigest hmac,
                 secret_hmac;
  HashDigest     hello_key;
  StringVal      user,
                 svc,
                 create,
                 expires;
  void * operator new( size_t, void *ptr ) { return ptr; }
  PeerEntry() {
    ::memset( this, 0, sizeof( *this ) );
  }
  void print( void ) noexcept;
};

typedef kv::ArrayCount< PeerEntry *, 128 > PeerEntryTab;

/* where a pending route comes from */
struct PendingUid {
  uint32_t uid, tport_id;
  PendingUid * next;
  PendingUid( const PendingUid &puid )
    : uid( puid.uid ), tport_id( puid.tport_id ), next( 0 ) {}
  PendingUid( uint32_t i = 0,  uint32_t t = 0 )
    : uid( i ), tport_id( t ), next( 0 ) {}
  bool operator==( const PendingUid &x ) const {
    return this->uid == x.uid && this->tport_id == x.tport_id;
  }
};

enum PeerSyncReason {
  NO_REASON_SYNC  = 0,
  PEER_DB_SYNC    = 1,
  PEER_ADD_SYNC   = 2,
  ADJ_CHANGE_SYNC = 3,
  ADJ_RESULT_SYNC = 4,
  UNAUTH_ADJ_SYNC = 5,
  MAX_REASON_SYNC = 6
};

/* waiting for a route to resolve */
struct UserPendingRoute {
  static const uint16_t MAX_REQUESTS = 2;
  Nonce          bridge_nonce;       /* peer being reqeusted */
  PendingUid     hd, * tl, * ptr,   /* list if a number of peers possible */
                 uid_buf[ MAX_REQUESTS ];
  uint64_t       pending_add_mono,  /* when peer add started */
                 request_time_mono, /* the last reqeust time */
                 pending_seqno;     /* unique seqno identity */
  StringVal      user_sv;           /* bridge_nonce belongs to this user */
  uint16_t       request_count;     /* number of times requested */
  PeerSyncReason reason;

  void * operator new( size_t, void *ptr ) { return ptr; }
  void operator delete( void *ptr ) { ::free( ptr ); }

  UserPendingRoute( const Nonce &b_nonce,  const PendingUid &puid,
                    const StringVal &sv,  PeerSyncReason r )
    : bridge_nonce( b_nonce ), hd( puid ), tl( &this->hd ), ptr( &this->hd ),
      pending_add_mono( 0 ), request_time_mono( 0 ), pending_seqno( 0 ),
      user_sv( sv ), request_count( 0 ), reason( r ) {}

  bool push( const PendingUid &puid ) {
    PendingUid * el;
    if ( this->tl == &this->hd )
      el = &this->uid_buf[ 0 ];
    else if ( this->tl >= this->uid_buf &&
              this->tl < &this->uid_buf[ MAX_REQUESTS - 1 ] )
      el = &this->tl[ 1 ];
    else 
      return false;
    *el = puid;
    this->tl = this->tl->next = el;
    return true;
  }
  bool is_member( const PendingUid &puid ) const {
    for ( const PendingUid *p = &this->hd; p != NULL; p = p->next )
      if ( *p == puid )
        return true;
    return false;
  }
  static const uint64_t rq_timeout = SEC_TO_NS / 4; /* 250ms */
  static const uint64_t pending_timeout_total =
    rq_timeout + rq_timeout * 2 + rq_timeout * 3; /* 250 + 500 + 750 = 1.5s */

  uint64_t pending_timeout( void ) {
    uint64_t ival_ns = (uint64_t) this->request_count * rq_timeout;
    return this->request_time_mono + ival_ns;
  }
  static bool is_pending_older( UserPendingRoute *r1,  UserPendingRoute *r2 ) {
    return r1->pending_timeout() < r2->pending_timeout();
  }
};
/* key to peer key, encrypted by a node's key */
struct PeerKeyHash {
  uint32_t src_uid, dest_uid;
  PeerKeyHash() {}
  PeerKeyHash( uint32_t src,  uint32_t dest )
    : src_uid( src ), dest_uid( dest ) {}

  uint64_t u64( void ) const {
    return ( (uint64_t) this->src_uid  << 32 ) | (uint64_t) this->dest_uid;
  }
  bool operator==( const PeerKeyHash &h ) const {
    return this->u64() == h.u64();
  }
  PeerKeyHash &operator=( const PeerKeyHash &h ) {
    this->src_uid  = h.src_uid;
    this->dest_uid = h.dest_uid;
    return *this;
  }
  size_t operator&( size_t mod ) const {
    size_t h = kv_hash_uint( this->src_uid ) ^ kv_hash_uint( this->dest_uid );
    return h & mod;
  }
};

struct PeerKeyCache {
  uint32_t off;
  uint8_t  cache[ HASH_DIGEST_SIZE * 1024 ]; /* cache 1024 of them */

  void * operator new( size_t, void *ptr ) { return ptr; }
  PeerKeyCache() : off( 0 ) {}

  uint32_t new_key( void ) {
    if ( this->off == sizeof( this->cache ) )
      this->off = 0;
    uint32_t ret = this->off;
    this->off += HASH_DIGEST_SIZE;
    return ret;
  }
};

typedef kv::IntHashTabT<PeerKeyHash,uint32_t> PeerKeyHashTab;

struct AdjacencySpace : public kv::BitSpace {
  StringVal tport;
  AdjacencySpace() {}
};

struct ReversePathForward : public kv::BitSetT<uint64_t> {
  uint64_t adjacency_cache_seqno;
  uint64_t bits;
  ReversePathForward() : adjacency_cache_seqno( 0 ), bits( 0 ) {
    this->ptr = &this->bits;
  }
  ~ReversePathForward() {
    if ( this->ptr != &this->bits )
      ::free( this->ptr );
  }
  void clear( uint32_t maxbit,  uint64_t seqno ) {
    this->adjacency_cache_seqno = seqno;
    size_t sz = ( maxbit + WORD_BITS - 1 ) / WORD_BITS;
    if ( sz > 1 ) {
      if ( this->ptr == &this->bits )
        this->ptr = NULL;
      this->ptr = (uint64_t *) ::realloc( this->ptr, sz * sizeof( uint64_t ) );
    }
    for ( size_t i = 0; i < sz; i++ )
      this->ptr[ i ] = 0;
  }
};

/* each bit in the bitset is a uid which indexes into the UserNonceTab[] */
/* each index into the AracencyTab[] is a tport which indexes to a Transport */
struct AdjacencyTab : public kv::ArrayCount< AdjacencySpace *, 4 > {
  AdjacencySpace *get( size_t n ) {
    if ( n >= count ) {
      this->count = n + 1;
      this->make( n + 1, true );
    }
    if ( this->ptr[ n ] == NULL )
      this->ptr[ n ] =
        new ( ::malloc( sizeof( AdjacencySpace ) ) ) AdjacencySpace();
    return this->ptr[ n ];
  }
};

struct TransportRoute;
/* adjacency for X ( uid ) (X is me for state change, X is uid for unknown)
 *   [ nonce ] [ tport ]
 * where nonce is not yet resolved
 */
struct AdjPending {
  AdjPending     * next,
                 * back;
  TransportRoute & rte;   /* where nonce came from */
  Nonce            nonce; /* nonce of adjacency update, unknown or changed */
  uint64_t         link_state_seqno, /* link_state_seqno of X */
                   request_time_mono, /* last time request started */
                   pending_time_mono; /* when pending was added to list */
  uint32_t         uid,   /* uid this adj belongs to */
                   tport; /* tport of adj, tab[ tport ]->set.add( nonce ) */
  StringVal        tport_sv, /* name assigned to tport at src */
                   user_sv;  /* user assigned to nonce */
  uint64_t         pending_seqno; /* unique pending list seqno */
  uint32_t         request_count;
  PeerSyncReason   reason;
  bool             add;   /* whether to add or remove it */
  void * operator new( size_t, void *ptr ) { return ptr; }
  void operator delete( void *ptr ) { ::free( ptr ); }
  AdjPending( TransportRoute &r,  const Nonce &n,
              uint32_t id,  uint32_t tp,  uint64_t tx,  bool a,
              const StringVal &tp_sv,  const StringVal &us_sv,
              uint64_t pseqno,  PeerSyncReason reas ) :
    next( 0 ), back( 0 ), rte( r ), nonce( n ),
    link_state_seqno( tx ), request_time_mono( 0 ), pending_time_mono( 0 ),
    uid( id ), tport( tp ), tport_sv( tp_sv ), user_sv( us_sv ),
    pending_seqno( pseqno ), request_count( 0 ), reason( reas ), add( a ) {}

  AdjPending( TransportRoute &r,  const Nonce &n,  const StringVal &us_sv,
              uint64_t pseqno ) :
    next( 0 ), back( 0 ), rte( r ), nonce( n ),
    link_state_seqno( 0 ), request_time_mono( 0 ), pending_time_mono( 0 ),
    uid( 0 ), tport( 0 ), user_sv( us_sv ),
    pending_seqno( pseqno ), request_count( 0 ), reason( UNAUTH_ADJ_SYNC ),
    add( true ) {}
};

struct AdjPendingList : public kv::DLinkList< AdjPending > {
  uint64_t pending_seqno;
  AdjPendingList() : pending_seqno( 0 ) {}
  AdjPending *append( TransportRoute &r,  const Nonce &n,
                      uint32_t id,  uint32_t tp,  uint64_t tx,  bool a,
                      const StringVal &tp_sv,  const StringVal &us_sv,
                      PeerSyncReason reas ) {
    AdjPending *p = new ( ::malloc( sizeof( AdjPending ) ) )
        AdjPending( r, n, id, tp, tx, a, tp_sv, us_sv,
                    ++this->pending_seqno, reas );
    this->push_tl( p );
    return p;
  }
  void append( TransportRoute &r,  const Nonce &n, const StringVal &us_sv ) {
    AdjPending *p = new ( ::malloc( sizeof( AdjPending ) ) )
        AdjPending( r, n, us_sv, ++this->pending_seqno );
    this->push_tl( p );
  }
  AdjPending *update( TransportRoute &r,  const Nonce &n,  uint32_t id,
               uint32_t tp,  uint64_t tx,  bool a,  const StringVal &tp_sv,
               const StringVal &us_sv,  PeerSyncReason reas ) noexcept;
  void unauth( TransportRoute &r,  const Nonce &n,  StringVal &us_sv ) noexcept;
};

struct AdjChange {
  AdjChange * next,
            * back;
  Nonce       nonce; /* nonce of adjacency, unknown or changed */
  uint32_t    uid,   /* uid this adj belongs to */
              tport; /* tport of adj, tab[ tport ]->set.add( nonce ) */
  uint64_t    seqno; /* link_state_seqno of X */
  bool        add;   /* whether to add or remove it */
  void * operator new( size_t, void *ptr ) { return ptr; }
  void operator delete( void *ptr ) { ::free( ptr ); }
  AdjChange( const Nonce &n, uint32_t id, uint32_t tp, uint64_t tx, bool a ) :
    next( 0 ), back( 0 ), nonce( n ), uid( id ), tport( tp ), seqno( tx ),
    add( a ) {}
};

struct AdjChangeList : public kv::DLinkList< AdjChange > {
  void append( Nonce &n,  uint32_t id,  uint32_t tp,  uint64_t tx,  bool a ) {
    this->push_tl(
      new ( ::malloc( sizeof( AdjChange ) ) ) AdjChange( n, id, tp, tx, a ) );
  }
};

struct UserNonceTab;
struct UserDB;

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
  MAX_ADJ_REQ       = 8
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
  "hb_sync",
  "ping_sync",
  "dijk_sync",
  "auth_sync",
  "peer_sync",
  "pdb_sync",
  "adjc_sync"
};
static const char *invalid_reason_str[] = {
  "no_reason",
  "unknown_adj",
  "push_route",
  "pop_route",
  "adj_change",
  "adj_update",
  "add_tport",
  "add_mesh"
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

struct PeerUidSet : public kv::UIntBitSet {
  uint32_t size, nbits, src_uid, tport_id, dest_count,
           first_uid, last_uid, rec_idx;
  void * operator new( size_t, void *ptr ) { return ptr; }
  void operator delete( void *ptr ) { ::free( ptr ); }

  PeerUidSet( uint32_t idx ) : size( 0 ), nbits( 0 ), src_uid( 0 ),
    tport_id( 0 ), dest_count( 0 ), first_uid( 0 ), last_uid( 0 ),
    rec_idx( idx ) {}

  void reset( uint32_t maxbit ) {
    this->size = ( maxbit + WORD_BITS - 1 ) / WORD_BITS;
    if ( maxbit > this->nbits ) {
      this->ptr = (uint64_t *)
        ::realloc( this->ptr, this->size * sizeof( uint64_t ) );
    }
    for ( uint32_t i = 0; i < this->size; i++ )
      this->ptr[ i ] = 0;
    this->nbits = maxbit;
  }
  bool first( uint32_t &b ) const {
    return this->kv::UIntBitSet::first( b, this->nbits );
  }
  bool next( uint32_t &b ) const {
    return this->kv::UIntBitSet::next( b, this->nbits );
  }
  uint32_t count( void ) const {
    return this->kv::UIntBitSet::count( this->nbits );
  }
  void or_bits( const PeerUidSet &set ) {
    for ( uint32_t i = 0; i < this->size; i++ )
      this->ptr[ i ] |= set.ptr[ i ];
  }
  void not_bits( const PeerUidSet &set ) {
    for ( uint32_t i = 0; i < this->size; i++ )
      this->ptr[ i ] &= ~set.ptr[ i ];
  }
};

struct PeerUidRecord : public kv::ArraySpace<PeerUidSet *, 4> {
  uint32_t idx;
  PeerUidRecord() : idx( 0 ) {}
  void reset( void ) { this->idx = 0; }
  void append( PeerUidSet *set ) {
    PeerUidSet ** puid = this->make( this->idx + 1, true );
    puid[ this->idx++ ] = set;
  }
};

struct PeerUidFree : public kv::ArraySpace<PeerUidSet *, 4> {
  uint32_t idx;
  PeerUidFree() : idx( 0 ) {}
  void reset( void ) { this->idx = 0; }
  PeerUidSet *get( uint32_t maxbit ) {
    PeerUidSet ** puid = this->make( this->idx + 1, true );
    if ( puid[ this->idx ] == NULL ) {
      puid[ this->idx ] = new ( ::malloc( sizeof( PeerUidSet ) ) )
        PeerUidSet( this->idx );
    }
    puid[ this->idx ]->reset( maxbit );
    return puid[ this->idx++ ];
  }
  void requeue( PeerUidRecord &rec ) {
    if ( rec.idx > 0 ) {
      size_t end = this->size;
      PeerUidSet ** puid = this->make( end + rec.idx, true );
      for ( size_t i = 0; i < rec.idx; i++ ) {
        if ( (puid[ end + i ] = rec.ptr[ i ]) != NULL )
          puid[ end + i ]->rec_idx = end + i;
      }
      rec.reset();
    }
  }
};
typedef kv::ArraySpace<PeerUidSet *, 4> PeerUidIndex;

struct UidDist {
  uint32_t uid, dist;
};
struct UidMissing {
  uint32_t uid, uid2;
};
struct AdjDistance : public md::MDMsgMem {
  UserDB       & user_db;      /* database of uids and links */
  kv::UIntArray  cache;        /* cache of uid distence via a tport */
  UidDist      * stack;        /* stack of uids to check for distance */
  uint32_t     * visit,        /* minimum distance to uid */
               * inc_list;     /* list of uids to be checked for links */
               /* tport_dist;   * temporary dist for transports */
  UidMissing   * missing;      /* list of missing links */
  kv::UIntBitSet inc_visit;    /* inconsistent check visit uid map */
  uint64_t       cache_seqno,  /* seqno of adjacency in cache */
                 update_seqno, /* seqno of current adjacency */
                 invalid_mono, /* when cache was invalidated */
                 primary_seqno;
  InvalidReason  invalid_reason; /* why cache was invalidated */
  uint32_t       max_uid,      /* all uid < max_uid */
                 max_tport,    /* all tport < max_tport */
                 miss_tos,     /* number of missing uids in missing[] */
                 inc_hd,       /* list hd of uids in inc_list[] */
                 inc_tl,       /* list to of uids in inc_list[] */
                 inc_run_count;/* count of inc_runs after adjacency change */
  uint64_t       last_run_mono; /* when cache was cleared */
  PeerUidSet     uid_peers,
                 uid_visit;
  PeerUidFree    uid_free;
  PeerUidRecord  uid_next,
                 uid_primary;
  PeerUidIndex   primary_rec;
  bool           inc_running,  /* whether incomplete check is running */
                 found_inconsistency; /* if current or last run inconsistent */
  AdjDistance( UserDB &u ) : user_db( u ), cache( 0 ), stack( 0 ), visit( 0 ),
    inc_list( 0 ), /*tport_dist( 0 ),*/ missing( 0 ), inc_visit( 0 ),
    cache_seqno( 0 ), update_seqno( 1 ), invalid_mono( 0 ),
    primary_seqno( 0 ), invalid_reason( INVALID_NONE ),
    max_uid( 0 ), max_tport( 0 ), miss_tos( 0 ), inc_hd( 0 ), inc_tl( 0 ),
    inc_run_count( 0 ), last_run_mono( 0 ), uid_peers( 0 ), uid_visit( 0 ),
    inc_running( false ), found_inconsistency( false ) {}

  bool is_valid( uint64_t seqno ) {
    this->clear_cache_if_dirty();
    return seqno == this->cache_seqno;
  }
  void clear_cache_if_dirty( void ) {
    if ( this->cache_seqno != this->update_seqno )
      this->clear_cache();
  }
  void invalidate( InvalidReason why ) {
    if ( this->update_seqno++ == this->cache_seqno ) {
      if ( ! found_inconsistency ) {
        this->invalid_mono = kv::current_monotonic_time_ns();
        this->invalid_reason = why;
      }
    }
  }
  void clear_cache( void ) noexcept;
  uint32_t adjacency_count( uint32_t uid ) const noexcept;
  kv::BitSpace *adjacency_set( uint32_t uid,  uint32_t i ) const noexcept;
  uint64_t adjacency_start( uint32_t uid ) const noexcept;
  uint32_t uid_refs( uint32_t from,  uint32_t to ) noexcept;
  uint32_t inbound_refs( uint32_t to ) noexcept;
  uint32_t outbound_refs( uint32_t from ) noexcept;
  /*bool find_inconsistent( UserBridge *&from, UserBridge *&to ) noexcept;*/
  bool find_inconsistent2( UserBridge *&from, UserBridge *&to ) noexcept;
  bool is_consistent( void ) noexcept;
  uint32_t calc_distance( uint32_t dest_uid ) noexcept;
  uint32_t calc_transport_cache( uint32_t dest_uid,  uint32_t tport_id,
                                 TransportRoute &rte ) {
    this->clear_cache_if_dirty();
    return this->calc_transport_cache2( dest_uid, tport_id, rte );
  }
  uint32_t calc_transport_cache2( uint32_t dest_uid,  uint32_t tport_id,
                                  TransportRoute &rte ) {
    size_t   off = tport_id * this->max_uid + dest_uid;
    uint32_t d   = this->cache.get( off );
    if ( d != 0 )
      return d - 1;
    return this->calc_transport_cache3( dest_uid, tport_id, rte );
  }
  uint32_t calc_transport_cache3( uint32_t dest_uid,  uint32_t tport_id,
                                  TransportRoute &rte ) noexcept;
  void calc_reachable( TransportRoute &rte ) noexcept;
  uint32_t fill_to_dist( uint32_t tos,  uint32_t maxdist,
                         PeerUidSet &visit,  PeerUidSet &peers ) noexcept;
  /*uint32_t fill_to_edge( uint32_t tos,  PeerUidSet &visit ) noexcept;*/
  uint32_t push_peer( uint32_t peer_uid,  uint32_t dist,
                      PeerUidSet &visit ) noexcept;
  uint32_t find_best_route( void ) noexcept;
  bool get_primary_tport( uint32_t dest_uid,  uint32_t &dest_tport ) noexcept;
  void calc_primary( void ) noexcept;
  uint32_t calc_dist_peers( uint32_t src_uid,  uint32_t dist ) noexcept;
  uint32_t find_best_route2( void ) noexcept;
  uint32_t calc_dist_peers2( uint32_t src_uid,  uint32_t dist ) noexcept;
  uint32_t calc_transport( uint32_t dest_uid,
                           TransportRoute &rte ) noexcept;
  uint32_t calc_distance_from( UserBridge &src,
                               uint32_t dest_uid ) noexcept;
  uint32_t search( uint32_t dest_uid,  uint32_t tos ) noexcept;
  const char *uid_name( uint32_t uid,  char *buf,  size_t buflen ) noexcept;
  const char *uid_name( uint32_t uid,  char *buf,  size_t &off,
                        size_t buflen ) noexcept;
  const char *uid_set_names( const PeerUidSet &rec,  char *buf,
                            size_t buflen ) noexcept;
  void print( const char *what,  uint32_t uid,  uint32_t d ) noexcept;
  void print( const char *what,  TransportRoute &rte,  uint32_t uid,
              uint32_t d ) noexcept;
};

}
}

#endif
