#ifndef __rai__raims__peer_h__
#define __rai__raims__peer_h__

#include <raims/crypt.h>
#include <raims/string_tab.h>
#include <raikv/bit_set.h>
#include <raims/adjacency.h>
#include <raims/ed25519.h>
#include <raims/msg.h>

namespace rai {
namespace ms {

const char *peer_sync_reason_string( PeerSyncReason r ) noexcept;
const char *adjacency_change_string( AdjacencyChange c ) noexcept;
const char *adjacency_request_string( AdjacencyRequest r ) noexcept;
const char *invalidate_reason_string( InvalidReason r ) noexcept;

static const uint64_t SEC_TO_NS = 1000 * 1000 * 1000;
template <class Int> static inline uint64_t sec_to_ns( Int sec ) {
  return (uint64_t) sec * SEC_TO_NS;
}
template <class Int> static inline uint64_t ns_to_sec( Int ns ) {
  return (uint64_t) ns / SEC_TO_NS;
}
static inline int64_t min_abs( int64_t ns,  int64_t ns2 ) {
  int64_t x = ( ns < 0 ? -ns : ns ), y = ( ns2 < 0 ? -ns2 : ns2 );
  return ( x < y ? ns : ns2 );
}
static inline int64_t max_abs( int64_t ns,  int64_t ns2 ) {
  int64_t x = ( ns < 0 ? -ns : ns ), y = ( ns2 < 0 ? -ns2 : ns2 );
  return ( x > y ? ns : ns2 );
}

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
  PolyHmacDigest hmac;
  StringVal      user,
                 svc,
                 create,
                 expires;
  DSA            dsa;
  void * operator new( size_t, void *ptr ) { return ptr; }
  PeerEntry() {
    ::memset( (void *) this, 0, sizeof( *this ) );
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
  PendingUid & operator=( const PendingUid &puid ) {
    this->uid = puid.uid; this->tport_id = puid.tport_id; this->next = NULL;
    return *this;
  }
  PendingUid( uint32_t i = 0,  uint32_t t = 0 )
    : uid( i ), tport_id( t ), next( 0 ) {}
  bool operator==( const PendingUid &x ) const {
    return this->uid == x.uid && this->tport_id == x.tport_id;
  }
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
  PeerKeyHash( const PeerKeyHash &h ) {
    this->src_uid  = h.src_uid;
    this->dest_uid = h.dest_uid;
  }
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

struct PeerDBRec : public MsgFldSet {
  Nonce        nonce;
  const char * user;
  uint32_t     user_len,
               hops;
  uint64_t     sub_seqno,
               link_state;
  int64_t      hb_skew;
  PeerDBRec  * next;
  void * operator new( size_t, void *ptr ) { return ptr; }
  PeerDBRec() : user( 0 ), user_len( 0 ), hops( 0 ), sub_seqno( 0 ),
                link_state( 0 ), hb_skew( 0 ), next( 0 ) {
    this->nonce.zero();
  }
  void set_field( uint32_t fid,  md::MDReference &mref ) {
    switch ( fid ) {
      case FID_BRIDGE:     this->nonce.copy_from( mref.fptr ); break;
      case FID_HOPS:       md::cvt_number<uint32_t>( mref, this->hops ); break;
      case FID_SUB_SEQNO:  md::cvt_number<uint64_t>( mref, this->sub_seqno ); break;
      case FID_LINK_STATE: md::cvt_number<uint64_t>( mref, this->link_state ); break;
      case FID_HB_SKEW:    md::cvt_number<int64_t>( mref, this->hb_skew ); break;
      case FID_USER:
        this->user     = (const char *) mref.fptr;
        this->user_len = (uint32_t) mref.fsize;
        break;
      default:
        break;
    }
  }
  void print( void ) const noexcept;
  static void print_rec_list( const PeerDBRec *rec_list,
                              UserBridge &n ) noexcept;
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

struct TransportRoute;
struct AdjacencyRec;
/* adjacency for X ( uid ) (X is me for state change, X is uid for unknown)
 *   [ nonce ] [ tport ]
 * where nonce is not yet resolved
 */
struct AdjPending {
  AdjPending     * next,
                 * back;
  TransportRoute & rte;   /* where nonce came from */
  uint64_t         link_state_seqno,  /* link_state_seqno of X */
                   request_time_mono, /* last time request started */
                   pending_time_mono, /* when pending was added to list */
                   pending_seqno;     /* unique pending list seqno */
  uint32_t         uid,               /* uid this adj belongs to */
                   request_count,
                   rec_count;
  PeerSyncReason   reason;
  AdjacencyRec   * rec_list;

  void * operator new( size_t, void *ptr ) { return ptr; }
  void operator delete( void *ptr ) { ::free( ptr ); }

  AdjPending( TransportRoute &r ) :
    next( 0 ), back( 0 ), rte( r ), link_state_seqno( 0 ),
    request_time_mono( 0 ), pending_time_mono( 0 ), pending_seqno( 0 ),
    uid( 0 ), request_count( 0 ), rec_count( 0 ), reason( UNAUTH_ADJ_SYNC ),
    rec_list( 0 ) {}
};

struct AdjPendingList : public kv::DLinkList< AdjPending > {
  uint64_t pending_seqno;
  AdjPendingList() : pending_seqno( 0 ) {}
};

struct AdjChange {
  AdjChange * next,
            * back;
  uint32_t    uid,   /* uid this adj belongs to */
              tportid; /* tport of adj, tab[ tportid ]->set.add( nonce ) */
  uint64_t    seqno; /* link_state_seqno of X */
  bool        add;   /* whether to add or remove it */
  void * operator new( size_t, void *ptr ) { return ptr; }
  void operator delete( void *ptr ) { ::free( ptr ); }
  AdjChange( uint32_t u_id, uint32_t tp_id, uint64_t ls_seqno,  bool a )
    : next( 0 ), back( 0 ), uid( u_id ), tportid( tp_id ), seqno( ls_seqno ),
      add( a ) {}
};

struct AdjChangeList : public kv::DLinkList< AdjChange > {
  AdjChange *append( uint32_t uid,  uint32_t tp_id,  uint64_t ls_seqno,
                     bool a ) {
    AdjChange *p;
    for ( p = this->hd; p != NULL; p = p->next ) {
      if ( p->uid == uid && p->tportid == tp_id &&
           p->add == a )
        return p;
    }
    p = new ( ::malloc( sizeof( AdjChange ) ) )
        AdjChange( uid, tp_id, ls_seqno, a );
    this->push_tl( p );
    return p;
  }
};

struct AdjacencyRec : public MsgFldSet {
  Nonce          nonce,
                 rem_bridge;
  StringVal      tport_name,
                 tport_type,
                 user;
  uint32_t       tportid,
                 cost[ COST_PATH_COUNT ],
                 rem_tportid;
  bool           add;
  AdjacencyRec * next;
  void * operator new( size_t, void *ptr ) { return ptr; }
  AdjacencyRec() : tportid( 0 ), rem_tportid( 0 ), add( true ), next( 0 ) {
    for ( uint8_t i = 0; i < COST_PATH_COUNT; i++ )
      this->cost[ i ] = COST_DEFAULT;
    this->nonce.zero();
    this->rem_bridge.zero();
  }
  void copy( const AdjacencyRec &rec ) {
    uint32_t i;
    for ( i = 0; i < FID_MAX / 64; i++ )
      this->is_set[ i ] = rec.is_set[ i ];
    this->nonce       = rec.nonce;
    this->rem_bridge  = rec.rem_bridge;
    this->tport_name  = rec.tport_name;
    this->tport_type  = rec.tport_type;
    this->user        = rec.user;
    this->tportid     = rec.tportid;
    for ( i = 0; i < COST_PATH_COUNT; i++ )
      this->cost[ i ] = rec.cost[ i ];
    this->rem_tportid = rec.rem_tportid;
    this->add         = rec.add;
    this->next        = NULL;
  }
  void set_field( uint32_t fid,  md::MDReference &mref ) noexcept;
  char tchar( uint32_t fid ) const { return ( this->test( fid ) ) ? '+' : '-'; }
  void print( void ) const noexcept;
  static void print_rec_list( const AdjacencyRec *rec_list,
                              const char *where ) noexcept;
};

struct UrlDBFilter {
  uint32_t except_uid,
           match_count,
           url_count,
           return_count,
           request_count,
         * hash;
  bool   * matched;
  bool     invert_match,
           is_mesh_filter;

  UrlDBFilter( uint32_t except,  bool is_mesh,  MsgHdrDecoder *dec = NULL ) :
      except_uid( except ), match_count( 0 ), url_count( 0 ),
      return_count( 0 ), request_count( 0 ), hash( 0 ), matched( 0 ),
      invert_match( false ), is_mesh_filter( is_mesh ) {
    if ( dec != NULL )
      this->setup_filter( *dec );
  }

  void setup_filter( MsgHdrDecoder &dec ) noexcept;

  bool filter_hash( uint32_t h ) {
    bool is_matched = false;
    uint32_t i;
    for ( i = 0; i < this->url_count; i++ ) {
      if ( this->hash[ i ] == h ) {
        is_matched = true;
        break;
      }
    }
    if ( is_matched ) {
      if ( this->invert_match )
        return false;
      if ( ! this->matched[ i ] ) {
        this->matched[ i ] = true;
        this->match_count++;
      }
      return true;
    }
    return this->invert_match;
  }
};

enum MeshStatus {
  MESH_OK            = 0,
  MESH_NOT_FOUND     = 1,
  MESH_NO_ENTRIES    = 2,
  MESH_NOT_CONNECTED = 3
};

}
}

#endif
