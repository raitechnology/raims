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
  uint32_t         request_count,
                   cost[ COST_PATH_COUNT ];
  PeerSyncReason   reason;
  bool             add;   /* whether to add or remove it */
  void * operator new( size_t, void *ptr ) { return ptr; }
  void operator delete( void *ptr ) { ::free( ptr ); }

  AdjPending( TransportRoute &r,  const Nonce &n ) :
    next( 0 ), back( 0 ), rte( r ), nonce( n ),
    link_state_seqno( 0 ), request_time_mono( 0 ), pending_time_mono( 0 ),
    uid( 0 ), tport( 0 ), pending_seqno( 0 ), request_count( 0 ),
    reason( UNAUTH_ADJ_SYNC ), add( true ) {
    for ( uint8_t i = 0; i < COST_PATH_COUNT; i++ )
      this->cost[ i ] = COST_DEFAULT;
  }
};

struct AdjPendingList : public kv::DLinkList< AdjPending > {
  uint64_t pending_seqno;
  AdjPendingList() : pending_seqno( 0 ) {}

  AdjPending *find_unauth( const Nonce &n ) {
    for ( AdjPending *p = this->hd; p != NULL; p = p->next ) {
      if ( p->reason == UNAUTH_ADJ_SYNC ) {
        if ( p->nonce == n )
          return p;
      }
    }
    return NULL;
  }
  AdjPending *find_update( const Nonce &nonce,  uint32_t tport,  bool add ) {
    for ( AdjPending *p = this->hd; p != NULL; p = p->next ) {
      if ( p->reason != UNAUTH_ADJ_SYNC ) {
        if ( p->nonce == nonce && p->tport == tport && p->add == add )
          return p; 
      }
    }
    return NULL;
  }
  AdjPending *create( TransportRoute &rte,  const Nonce &nonce ) {
    AdjPending *p =
      new ( ::malloc( sizeof( AdjPending ) ) ) AdjPending( rte, nonce );
    p->pending_seqno = ++this->pending_seqno;
    this->push_tl( p );
    return p;
  }
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
  AdjChange( const Nonce &n, uint32_t u_id, uint32_t tp_id, uint64_t ls_seqno,
             bool a )
    : next( 0 ), back( 0 ), nonce( n ), uid( u_id ), tport( tp_id ),
      seqno( ls_seqno ), add( a ) {}
};

struct AdjChangeList : public kv::DLinkList< AdjChange > {
  void append( Nonce &n,  uint32_t u_id,  uint32_t tp_id,  uint64_t ls_seqno,
               bool a ) {
    this->push_tl(
      new ( ::malloc( sizeof( AdjChange ) ) )
        AdjChange( n, u_id, tp_id, ls_seqno, a ) );
  }
};

struct MeshDBFilter {
  uint32_t except_uid,
           match_count,
           url_count,
           return_count,
           request_count,
         * hash;
  bool   * matched;
  bool     invert_match;

  MeshDBFilter( uint32_t except,  MsgHdrDecoder &dec ) :
      except_uid( except ), match_count( 0 ), url_count( 0 ),
      return_count( 0 ), request_count( 0 ), hash( 0 ), matched( 0 ),
      invert_match( false ) {
    this->setup_filter( dec );
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

}
}

#endif
