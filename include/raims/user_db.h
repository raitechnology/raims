#ifndef __rai__raims__user_db_h__
#define __rai__raims__user_db_h__

#include <raims/transport.h>
#include <raims/user.h>
#include <raims/msg.h>
#include <raims/sub_list.h>
#include <raims/sub.h>
#include <raims/sub_const.h>
#include <raims/peer.h>
#include <raims/state_test.h>
#include <raims/event_rec.h>
#include <raims/debug.h>

namespace rai {
namespace ms {

static const uint32_t HB_DEFAULT_INTERVAL = 10; /* seconds */
/* random ms mod for pending peer add request (65ms) */
static const uint64_t PEER_RAND_DELAY_NS  = 64 * 1024 * 1024;

/* construct a subject for inbox */
struct ShortSubjectBuf : public MsgBuf {
  /* should be at least pre[40].nonce[22].suf[40] */
  char buf[ 128 ];
  ShortSubjectBuf() : MsgBuf( this->buf ) {}
  ShortSubjectBuf( const char *pre,  const UserNonce &un )
    : MsgBuf( this->buf ) {
    this->s( pre ).s( "." ).n( un.nonce );
  }
};
/* construct an inbox */
struct InboxBuf : public ShortSubjectBuf {
  /* make _I.Nonce. */
  InboxBuf( const UserNonce &un,  const char *x = NULL )
      : ShortSubjectBuf( _INBOX, un ) {
    this->s( "." ); if ( x != NULL ) this->s( x );
  }
  InboxBuf( const UserNonce &un,  uint32_t reply )
      : ShortSubjectBuf( _INBOX, un ) {
    this->s( "." ).i( reply );
  }
};
/* construct an mcast */
struct McastBuf : public ShortSubjectBuf {
  /* make _M. */
  McastBuf() { this->s( "_M." ); }
};

/* uid -> user nonce hash */
typedef kv::IntHashTabT<uint32_t,uint32_t> UidHT;

enum UserNonceState {
  CHALLENGE_STATE         =      1, /* challenge sent, this is timed for retry */
  AUTHENTICATED_STATE     =      2, /* challenge recvd and auth succeeded */
  INBOX_ROUTE_STATE       =      4, /* inbox routed to source */
  IN_ROUTE_LIST_STATE     =      8, /* is a member of the route list */
  SENT_ZADD_STATE         =   0x10, /* sent a zadd to peers after auth */
  IN_HB_QUEUE_STATE       =   0x20, /* is a member of the heartbeat queue */
  SUBS_REQUEST_STATE      =   0x40, /* is a member of the subs queue */
  ADJACENCY_REQUEST_STATE =   0x80, /* is a member of the adj queue */
  PING_STATE              =  0x100, /* is a member of the ping queue */
  ZOMBIE_STATE            =  0x200, /* timed out, no clear dead signal */
  DEAD_STATE              =  0x400, /* dead from bye or z.del */
  UCAST_URL_STATE         =  0x800, /* has ucast url */
  UCAST_URL_SRC_STATE     = 0x1000, /* routes through a ucast url */
  MESH_URL_STATE          = 0x2000, /* has a mesh url */
  HAS_HB_STATE            = 0x4000, /* recvd a hb */
  IS_INIT_STATE           = 0x8000  /* if initialized with reset() */
};
static const size_t MAX_NONCE_STATE_STRING = 16 * 16; /* 16 states * 16 chars*/
char *user_state_string( uint32_t state,  char *buf ) noexcept;
char *user_state_abrev( uint32_t state, char *buf ) noexcept;

template <class T>
struct UserStateTest : public StateTest<T> {
  char *state_to_string( char *buf ) {
    return user_state_string( ((T *) this)->state, buf );
  }
};

struct UserBridge;
struct UserDB;
struct UserRoute : public UserStateTest<UserRoute> {
  static const uint32_t NO_RTE  = -1;
  static const uint16_t NO_HOPS = -1;
  UserBridge      & n;
  TransportRoute  & rte;           /* transport */
  uint32_t          mcast_fd,      /* fd src, tcp fd or pgm fd */
                    inbox_fd;      /* inbox fd */
  uint16_t          hops,          /* number of links away */
                    state,         /* whether in route list */
                    ucast_url_len, /* if has ucast */
                    mesh_url_len;  /* if has mesh */
  uint32_t          url_hash,      /* hash of ucast_url, mesh_url */
                    hb_seqno;      /* hb sequence on this transport */
  uint64_t          bytes_sent,    /* bytes sent ptp */
                    msgs_sent;     /* msgs sent ptp */
  char            * ucast_url,     /* the address of a ptp link */
                  * mesh_url;      /* the address of a mesh link */
  const UserRoute * ucast_src;     /* route through url on another route */
  UserRoute       * next,          /* link in route list */
                  * back;
  void * operator new( size_t, void *ptr ) { return ptr; }
  UserRoute( UserBridge &u,  TransportRoute &r )
    : n( u ), rte( r ), ucast_url( 0 ), mesh_url( 0 ), next( 0 ), back( 0 ) {
    this->reset();
  }
  bool is_init( void ) const {
    return this->is_set( IS_INIT_STATE ) != 0;
  }
  bool is_valid( void ) const {
    return this->is_init() && this->hops != NO_HOPS;
  }
  void reset( void ) {
    this->mcast_fd      = NO_RTE;
    this->inbox_fd      = NO_RTE;
    this->hops          = NO_HOPS;
    this->state         = IS_INIT_STATE;
    this->ucast_url_len = 0;
    this->mesh_url_len  = 0;
    this->url_hash      = 0;
    this->hb_seqno      = 0;
    this->bytes_sent    = 0;
    this->msgs_sent     = 0;
    this->ucast_src     = NULL;
    if ( this->ucast_url != NULL ) {
      ::free( this->ucast_url );
      this->ucast_url = NULL;
    }
    if ( this->mesh_url != NULL ) {
      ::free( this->mesh_url );
      this->mesh_url = NULL;
    }
  }
  void set_ucast( UserDB &user_db,  const void *p,  size_t len,
                  const UserRoute *src ) noexcept;
  void set_mesh( UserDB &user_db,  const void *p,  size_t len ) noexcept;

  char * inbox_route_str( char *buf,  size_t buflen ) noexcept;
};
/* peer sessions */
struct UserBridge : public UserStateTest<UserBridge> {
  HashDigest         peer_key;            /* peer session key */
  const PeerEntry  & peer;                /* configuration entry */
  UserNonce          bridge_id;           /* the user hmac and nonce */
  ReversePathForward reverse_path_cache;  /* tports where to fwd mcast msgs */
  kv::BloomRef       bloom;               /* the subs by this user */
  AdjacencyTab       adjacency;           /* what nonce routes are adjacent */
  Nonce              uid_csum,            /* current xor of adjacency */
                     hb_cnonce;           /* last cnonce used for hb */
  UserRoute        * user_route;          /* the routes for this user */
  uint64_t           hb_seqno,            /* users hb seqno */
                     hb_time,             /* users hb time */
                     sub_seqno,           /* seqno used for start/stop sub */
                     link_state_seqno,    /* seqno used for link state db */
                     unknown_link_seqno,  /* edge of link_state_seqno */
                     recv_peer_seqno,     /* seqno used for add/del/blm peer */
                     send_inbox_seqno,    /* inbox seqnos for ptp links */
                     recv_inbox_seqno,    /* recv side inbox seqno */
                     recv_mcast_seqno,    /* recv side mcast seqno */
                     start_mono_time,     /* uptime from hb */
                     auth_mono_time,      /* when auth happens */
                     challenge_mono_time, /* time challenge sent */
                     hb_mono_time,        /* time hb recvd */
                     subs_mono_time,      /* time subs reqeust sent */
                     sub_recv_mono_time,  /* time subscription reqeust recv */
                     adj_mono_time,       /* time adjacency reqeust sent */
                     ping_mono_time,  
                     round_trip_time,     /* ping/pong */
                     start_time,          /* start timestamp */
                     ping_send_time,
                     ping_recv_time,
                     pong_recv_time,      /* ping times */
                     stats_seqno;         /* _N.PEER. stats */
  uint32_t           state,               /* UserNonceState bits */
                     uid,                 /* unique id for route */
                     hb_interval,         /* interval of heartbeat */
                     challenge_count,     /* count of challenges */
                     primary_route,       /* route with min hops */
                     unknown_refs,        /* link refs are yet to be resolved */
                     ping_send_count,
                     ping_recv_count,
                     pong_recv_count,
                     ping_fail_count,     /* ping counters */
                     seqno_repeat,
                     seqno_not_subscr,
                     auth_count;
  StageAuth          auth[ 2 ];           /* auth handshake state */
  UserRoute        * u_buf[ 24 ];         /* indexes user_route */
  void * operator new( size_t, void *ptr ) { return ptr; }

  UserBridge( const PeerEntry &pentry,  kv::BloomDB &db,  uint32_t seed )
      : peer( pentry ), bloom( seed, pentry.user.val, db ) {
    this->peer_key.zero();
    this->uid_csum.zero();
    this->hb_cnonce.zero();
    ::memset( &this->user_route , 0,
              (char *) (void *) &this->u_buf[ 24 ] -
              (char *) (void *) &this->user_route );
    this->hb_interval = HB_DEFAULT_INTERVAL;
  }
  static const uint32_t USER_ROUTE_SHIFT = 4,
                        USER_ROUTE_BASE  = ( 1U << USER_ROUTE_SHIFT );
  UserRoute * user_route_ptr( UserDB &me,  uint32_t id ) {
    uint32_t i = 31 - kv_clzw( ( id >> USER_ROUTE_SHIFT ) + 1 ),
             j = id - ( ( ( 1 << i ) - 1 ) << USER_ROUTE_SHIFT );
    if ( this->u_buf[ i ] != NULL ) {
      UserRoute * u_ptr = &this->u_buf[ i ][ j ];
      if ( u_ptr->is_init() )
        return u_ptr;
    }
    return this->init_user_route( me, i, j, id );
  }
  void user_route_reset( void ) {
    for ( uint32_t i = 0; i < 24; i++ ) {
      if ( this->u_buf[ i ] != NULL ) {
        uint32_t max_j = USER_ROUTE_BASE << i;
        for ( uint32_t j = 0; j < max_j; j++ ) {
          UserRoute * u_ptr = &this->u_buf[ i ][ j ];
          if ( u_ptr->is_init() )
            u_ptr->reset();
        }
      }
    }
  }
  UserRoute * init_user_route( UserDB &me,  uint32_t i,  uint32_t j,
                               uint32_t id ) noexcept;
  UserRoute * primary( UserDB &me ) {
    return this->user_route_ptr( me, this->primary_route );
  }
  double rtt_us( void ) const {
    return (double) this->round_trip_time / 1000.0;
  }
  uint64_t uptime( void ) const {
    return kv::current_monotonic_time_ns() - this->start_mono_time;
  }
  /* when to timeout peer for lack of heartbeats */
  uint64_t hb_timeout( void ) const {
    uint64_t ival_ns = (uint64_t) this->hb_interval * SEC_TO_NS;
    return this->hb_mono_time + ival_ns + ival_ns / 2;
  }
  static bool is_heartbeat_older( UserBridge *r1,  UserBridge *r2 ) {
    return r1->hb_timeout() > r2->hb_timeout();
  }
  /* when to allow repeat challenges */
  uint64_t challenge_timeout( void ) const {
    uint32_t count = this->challenge_count;
    if ( count > 7 )
      count = 7;
    uint64_t ival_ns = ( (uint64_t) 1 << count ) * SEC_TO_NS;
    return this->challenge_mono_time + ival_ns;
  }
  static bool is_challenge_older( UserBridge *r1,  UserBridge *r2 ) {
    return r1->challenge_timeout() > r2->challenge_timeout();
  }
  /* when to allow repeat subs request */
  uint64_t subs_timeout( void ) const {
    return this->subs_mono_time + SEC_TO_NS * 5;
  }
  static bool is_subs_older( UserBridge *r1,  UserBridge *r2 ) {
    return r1->subs_timeout() > r2->subs_timeout();
  }
  uint64_t adj_timeout( void ) const {
    return this->adj_mono_time + SEC_TO_NS * 5;
  }
  static bool is_adj_older( UserBridge *r1,  UserBridge *r2 ) {
    return r1->adj_timeout() > r2->adj_timeout();
  }
  uint64_t ping_timeout( void ) const {
    return this->ping_mono_time + SEC_TO_NS * 5;
  }
  static bool is_ping_older( UserBridge *r1,  UserBridge *r2 ) {
    return r1->ping_timeout() > r2->ping_timeout();
  }

  uint32_t make_inbox_subject( char *ibx,  const char *suffix ) {
    uint32_t len = sizeof( _INBOX ) - 1;
    ::memcpy( ibx, _INBOX, len );
    ibx[ len++ ] = '.';
    len += (uint32_t) this->bridge_id.nonce.to_base64( &ibx[ len ] );
    ibx[ len++ ] = '.';
    while ( *suffix != '\0' )
      ibx[ len++ ] = *suffix++;
    ibx[ len ] = '\0';
    return len;
  }
  int printn( const char *fmt, ... ) const noexcept __attribute__((format(printf,2,3)));
  int printf( const char *fmt, ... ) const noexcept __attribute__((format(printf,2,3)));
  int printe( const char *fmt, ... ) const noexcept __attribute__((format(printf,2,3)));
};

/* allocate memory from region that doeesn't allow core dump */
struct UserAllocBuf {
  static const size_t BUF_ALLOC_SIZE = 1024 * 1024;
  UserAllocBuf * next;
  uint8_t      * buf;
  size_t         buf_off;
  void * operator new( size_t, void *ptr ) { return ptr; }
  void operator delete( void *ptr ) { ::free( ptr ); }
  UserAllocBuf() : next( 0 ), buf( 0 ), buf_off( 0 ) {}
  void * alloc( size_t size ) {
    size_t a_size = kv::align<size_t>( size, 16 );
    if ( this->buf_off + a_size > BUF_ALLOC_SIZE )
      return NULL;
    void * p = &this->buf[ this->buf_off ];
    this->buf_off += a_size;
    return p;
  }
};

struct UserRouteList : public kv::DLinkList< UserRoute > {
  uint32_t sys_route_refs;
  UserRouteList() : sys_route_refs( 0 ) {}
};

struct SourceRouteList : public kv::ArrayCount<UserRouteList, 128> {
  bool is_empty( uint32_t fd ) const {
    return fd >= this->count || this->ptr[ fd ].is_empty();
  }
};

struct UserBridgeTab : public kv::ArrayCount< UserBridge *, 128 > {};

struct MeshRoute {
  MeshRoute       * next,
                  * back;
  TransportRoute  & rte;
  Nonce             b_nonce;
  const char      * mesh_url;
  uint32_t          mesh_url_len,
                    url_hash;
  void * operator new( size_t, void *ptr ) { return ptr; }
  void operator delete( void *ptr ) { ::free( ptr ); }
  MeshRoute( TransportRoute &r,  const char *url,  uint32_t len,
             uint32_t h,  const Nonce &n )
    : next( 0 ), back( 0 ), rte( r ), mesh_url( url ), mesh_url_len( len ),
      url_hash( h ) { this->b_nonce = n; }
};

struct DirectList : public kv::DLinkList< MeshRoute > {
  uint64_t last_process_mono;
  DirectList() : last_process_mono( 0 ) {}
  void update( UserRoute *u ) noexcept;
  void update( TransportRoute &rte,  const char *url,  uint32_t len,
               uint32_t h,  const Nonce &b_nonce ) noexcept;
};

typedef struct kv::PrioQueue< UserBridge *,
                        UserBridge::is_heartbeat_older > UserHeartbeatQueue;
typedef struct kv::PrioQueue< UserBridge *,
                        UserBridge::is_challenge_older > UserChallengeQueue;
typedef struct kv::PrioQueue< UserBridge *,
                        UserBridge::is_subs_older >      UserSubsQueue;
typedef struct kv::PrioQueue< UserBridge *,
                        UserBridge::is_adj_older >       UserAdjQueue;
typedef struct kv::PrioQueue< UserBridge *,
                        UserBridge::is_ping_older >      UserPingQueue;
typedef struct kv::PrioQueue< UserPendingRoute *,
                        UserPendingRoute::is_pending_older > UserPendingQueue;

/* nonce -> node_ht[ uid ] -> UserBridge */
typedef kv::IntHashTabT<Hash128Elem,uint32_t> NodeHashTab;

struct SubDB;
struct StringTab;
struct UserDB {
  static const uint32_t MY_UID = 0;      /* bridge_tab[ 0 ] reserved for me */
  TransportTab         transport_tab;
  TransportRoute     * ipc_transport;
  /* my identity */
  ConfigTree::User    & user;            /* my user */
  ConfigTree::Service & svc;             /* my service */
  SubDB               & sub_db;
  StringTab           & string_tab;      /* string constants */
  EventRecord         & events;
  uint64_t              start_mono_time,
                        start_time;
  /* my instance */
  UserNonce             bridge_id;       /* user hmac + session nonce */
  HashDigest          * session_key,     /* session key */
                      * hello_key;       /* svc + user key */
  CnonceRandom        * cnonce;          /* random nonce generator */
  Nonce                 uid_csum;        /* xor of link_state nonces */

  /* indexes of node instances */
  NodeHashTab         * node_ht,         /* nonce -> uid */
                      * zombie_ht;       /* timed out nodes */
  UidHT               * uid_tab;         /* uid -> src route */
  UserBridgeTab         bridge_tab;      /* route array bridge_tab[ uid ] */

  /* index of node identities */
  NodeHashTab         * peer_ht;         /* peer hmac -> pid (peer entry) */
  PeerEntryTab          peer_db;         /* peer_db[ pid ] peer entry secrets */

  /* [ bcast_src ] -> node instance1, node instance2 ... */
  SourceRouteList       route_list;      /* authenticated list through bcast */

  /* queues for timeouts */
  UserHeartbeatQueue    hb_queue;        /* when a HB is expected from peer */
  UserChallengeQueue    challenge_queue; /* throttle auth challenge */
  UserSubsQueue         subs_queue;      /* throttle subs request */
  UserAdjQueue          adj_queue;       /* throttle adjacency request */
  UserPingQueue         ping_queue;      /* test pingable */
  UserPendingQueue      pending_queue;   /* retry user/peer resolve */
  AdjPendingList        adjacency_unknown; /* adjacency recv not resolved */
  AdjChangeList         adjacency_change;  /* adjacency send pending */
  DirectList            direct_pending;
  /* cache of peer keys */
  PeerKeyHashTab      * peer_key_ht;      /* index cache by src uid, dest uid */
  PeerKeyCache        * peer_keys;        /* cache of peer keys encrypted */

  kv::BitSpace          uid_authenticated, /* uids authenticated */
                        random_walk;
  kv::BloomRef          auth_bloom;
  uint32_t              hb_interval,
                        next_uid,        /* next_uid available */
                        free_uid_count,  /* num uids freed */
                        my_src_fd,       /* my src fd */
                        uid_auth_count,  /* total trusted nodes */
                        uid_hb_count;    /* total hb / distance zero nones */
  uint64_t              send_peer_seqno, /* a unique seqno for peer multicast */
                        link_state_seqno, /* seqno of adjacency updates */
                        mcast_seqno,      /* seqno of mcast subjects */
                        hb_ival_ns,      /* heartbeat interval */
                        hb_ival_mask,    /* ping ival = pow2 hb_ival * 1.5 */
                        next_ping_mono;  /* when next ping is sent */
  kv::rand::xoroshiro128plus rand;       /* used to generate bloom seeds */

  kv::SLinkList<UserAllocBuf> buf_list;  /* secure buf alloc for nodes, keys */
  AdjDistance           peer_dist;       /* calc distance between nodes */
  ServiceBuf            my_svc;          /* pub key for service */

  UserDB( kv::EvPoll &p,  ConfigTree::User &u, ConfigTree::Service &s,
          SubDB &sdb,  StringTab &st,  EventRecord &ev ) noexcept;
  /* allocate from secure mem */
  void * alloc( size_t size ) {
    void * p;
    if ( this->buf_list.tl == NULL )
      return this->alloc_slow( size );
    if ( (p = this->buf_list.tl->alloc( size )) == NULL )
      return this->alloc_slow( size );
    return p;
  }
  void * alloc_slow( size_t size ) noexcept;

  template<class Obj> /* puts objs in secure area */
  Obj *make_secure_obj( void ) {
    return new ( this->alloc( sizeof( Obj ) ) ) Obj();
  }
  UserBridge *make_user_bridge( size_t len,  const PeerEntry &peer,
                                kv::BloomDB &db,  uint32_t seed ) {
    return new ( this->alloc( len ) ) UserBridge( peer, db, seed );
  }
  PeerEntry *make_peer_entry( size_t len ) {
    return new ( this->alloc( len ) ) PeerEntry();
  }
  /* release secure mem */
  void release_alloc( void ) noexcept;

  bool init( const CryptPass &pwd,  uint32_t my_fd, ConfigTree &tree ) noexcept;

  bool forward_to( UserBridge &n,  const char *sub,
                   size_t sublen,  uint32_t h,  const void *msg,
                   size_t msg_len,  UserRoute &u_rte ) noexcept;
  bool forward_to_inbox( UserBridge &n,  const char *sub,
                         size_t sublen,  uint32_t h,  const void *msg,
                         size_t msg_len ) {
    return this->forward_to( n, sub, sublen, h, msg, msg_len,
                             *n.primary( *this ) );
  }
  bool forward_to_inbox( UserBridge &n,  const InboxBuf &ibx,  uint32_t h,
                         const void *msg,  size_t msg_len,  bool primary ) {
    if ( primary )
      return this->forward_to( n, ibx.buf, ibx.len(), h, msg, msg_len,
                               *n.primary( *this ) );
    return this->forward_to( n, ibx.buf, ibx.len(), h, msg, msg_len,
                             *n.user_route );
  }

  PeerEntry *make_peer( const StringVal &user, const StringVal &svc,
                        const StringVal &create,
                        const StringVal &expires ) noexcept;
  void release( void ) noexcept;

  /* heartbeat.cpp */
  void hello_hb( void ) noexcept;
  void bye_hb( void ) noexcept;
  void interval_hb( uint64_t cur_mono,  uint64_t cur_time ) noexcept;
  void push_hb_time( TransportRoute &rte,  uint64_t time,
                     uint64_t mono ) noexcept;
  void make_hb( TransportRoute &rte,  const char *sub,  size_t sublen,
                uint32_t h,  MsgCat &m ) noexcept;
  bool on_heartbeat( const MsgFramePublish &pub,  UserBridge &n,
                     MsgHdrDecoder &dec ) noexcept;
  void interval_ping( uint64_t curr_mono,  uint64_t curr_time ) noexcept;
  void send_ping_request( UserBridge &n ) noexcept;
  bool recv_ping_request( const MsgFramePublish &pub,  UserBridge &n,
                          const MsgHdrDecoder &dec ) noexcept;
  bool recv_pong_result( const MsgFramePublish &pub,  UserBridge &n,
                         const MsgHdrDecoder &dec ) noexcept;
  /* auth.cpp */
  bool on_inbox_auth( const MsgFramePublish &pub,  UserBridge &n,
                      MsgHdrDecoder &dec ) noexcept;
  bool on_bye( const MsgFramePublish &pub,  UserBridge &n,
               const MsgHdrDecoder &dec ) noexcept;
  bool recv_challenge( const MsgFramePublish &pub,  UserBridge &n,
                    const MsgHdrDecoder &dec, AuthStage stage ) const noexcept;
  bool send_challenge( UserBridge &n,  AuthStage stage ) noexcept;
  bool send_trusted( const MsgFramePublish &pub,  UserBridge &n,
                     const MsgHdrDecoder &dec ) noexcept;
  bool recv_trusted( const MsgFramePublish &pub,  UserBridge &n,
                     MsgHdrDecoder &dec ) noexcept;
  /* user_db.cpp */
  void check_user_timeout( uint64_t current_mono_time,
                           uint64_t current_time ) noexcept;
  UserBridge * lookup_bridge( MsgFramePublish &pub,
                              const MsgHdrDecoder &dec ) noexcept;
  UserBridge * lookup_user( MsgFramePublish &pub,
                            const MsgHdrDecoder &dec ) noexcept;
  void add_user_route( UserBridge &n,  TransportRoute &rte,
                       uint32_t fd,  const MsgHdrDecoder &dec,
                       const UserRoute *src ) noexcept;
  UserBridge * add_user( TransportRoute &rte,  const UserRoute *src,
                         uint32_t fd,  const UserNonce &b_nonce,
                         const PeerEntry &peer,
                         const MsgHdrDecoder &dec ) noexcept;
  void set_ucast_url( UserRoute &u_rte, const MsgHdrDecoder &dec ) noexcept;
  void set_mesh_url( UserRoute &u_rte, const MsgHdrDecoder &dec ) noexcept;
  void find_user_primary_routes( void ) noexcept;
  void process_direct_pending( uint64_t curr_mono ) noexcept;
  UserBridge * closest_peer_route( TransportRoute &rte,  UserBridge &n,
                                   uint32_t &dist ) noexcept;
  uint32_t new_uid( void ) noexcept;
  uint32_t random_uid_walk( void ) noexcept;
  void retire_source( TransportRoute &rte,  uint32_t fd ) noexcept;
  void add_transport( TransportRoute &rte ) noexcept;
  void add_inbox_route( UserBridge &n,  UserRoute *primary ) noexcept;
  void remove_inbox_route( UserBridge &n ) noexcept;
  void add_authenticated( UserBridge &n,  const MsgHdrDecoder &dec,
                          AuthStage stage,  UserBridge *src ) noexcept;
  void remove_authenticated( UserBridge &n,  ByeReason bye ) noexcept;

  /* link_state.cpp */
  void process_unknown_adjacency( uint64_t current_mono_time ) noexcept;
  void save_unauthorized_adjacency( MsgFramePublish &fpub ) noexcept;
  void print_adjacency( const char *s,  UserBridge &n ) noexcept;
  void add_unknown_adjacency( UserBridge &n ) noexcept;
  void clear_unknown_adjacency( UserBridge &n ) noexcept;
  void remove_adjacency( const UserBridge &n ) noexcept;
  UserBridge *close_source_route( uint32_t fd ) noexcept;
  void push_source_route( UserBridge &n ) noexcept;
  void push_user_route( UserBridge &n,  UserRoute &u_rte ) noexcept;
  void pop_source_route( UserBridge &n ) noexcept;
  void pop_user_route( UserBridge &n,  UserRoute &u_rte ) noexcept;
  void send_adjacency_change( void ) noexcept;
  size_t adjacency_size( UserBridge *sync ) noexcept;
  void adjacency_submsg( UserBridge *sync,  MsgCat &m ) noexcept;
  bool recv_adjacency_change( const MsgFramePublish &pub,  UserBridge &n,
                              MsgHdrDecoder &dec ) noexcept;
  bool send_adjacency_request( UserBridge &n,  AdjacencyRequest reas ) noexcept;
  bool send_adjacency_request2( UserBridge &n,  UserBridge &sync,
                                AdjacencyRequest reas ) noexcept;
  bool recv_adjacency_request( const MsgFramePublish &pub,  UserBridge &n,
                               const MsgHdrDecoder &dec ) noexcept;
  bool recv_adjacency_result( const MsgFramePublish &pub,  UserBridge &n,
                              MsgHdrDecoder &dec ) noexcept;
  /* peer.cpp */
  UserPendingRoute * find_pending_peer( const Nonce &b_nonce,
                                        const PendingUid &puid ) noexcept;
  bool start_pending_peer( const Nonce &b_nonce,  UserBridge &n,
                           bool delay,  const StringVal &user_sv,
                           PeerSyncReason reas ) noexcept;
  UserPendingRoute * start_pending_adj( AdjPending &adj, 
                                        UserBridge &n ) noexcept;
  void process_pending_peer( uint64_t current_mono_time ) noexcept;
  bool request_pending_peer( UserPendingRoute &p,
                             uint64_t current_mono_time ) noexcept;
  /*bool request_nonce_peer( UserBridge &n,  Nonce &nonce ) noexcept;*/
  void remove_pending_peer( const Nonce *b_nonce,  uint64_t pseqno ) noexcept;

  void get_peer_key2( uint32_t src_uid,  const Nonce &dest_nonce,
                      HashDigest &hash ) noexcept;
  void get_peer_key( uint32_t src_uid,  uint32_t dest_id,
                     HashDigest &hash ) noexcept;
  /*void make_peer_msg( UserBridge &n,  const char *sub,  size_t sublen,  
                      MsgCat &m,  int peer_msg_type,  uint64_t &seqno,
                      uint32_t hops,  bool in_mesh ) noexcept;*/
  bool decode_peer_msg( UserBridge &from_n,  const MsgHdrDecoder &dec,
                        UserNonce &sync_bridge_id,  HashDigest &ha1,
                        UserBridge *&user_n,  UserBuf *user,
                        /*uint8_t *pub_der,  size_t &pub_sz,*/
                        uint64_t &start ) noexcept;
  UserBridge * make_peer_session( const MsgFramePublish &pub,
                                  UserBridge &from_n,
                                  const MsgHdrDecoder &dec,
                                  UserBridge *user_n ) noexcept;
  bool recv_peer_db( const MsgFramePublish &pub,  UserBridge &n,
                     MsgHdrDecoder &dec,  AuthStage stage ) noexcept;
  bool recv_peer_add( const MsgFramePublish &pub,  UserBridge &n,
                      MsgHdrDecoder &dec,  AuthStage stage ) noexcept;
  bool recv_peer_del( const MsgFramePublish &pub,  UserBridge &n,
                      const MsgHdrDecoder &dec ) noexcept;
  void make_peer_add_msg( UserBridge &n,  const char *sub,  size_t sublen,
                          uint32_t h,  MsgCat &m,  uint32_t hops,
                          bool in_mesh ) noexcept;
  void send_peer_add( UserBridge &n ) noexcept;
  void forward_peer_add( UserBridge &n,
                         const TransportRoute &except_rte ) noexcept;
  void get_peer_hops( TransportRoute &rte,  UserBridge &n,
                      UserBridge &n2,  uint32_t &hops,
                      bool &in_mesh ) noexcept;
  bool make_peer_db_msg( UserBridge &n,  const char *sub,  size_t sublen,
                         uint32_t h,  MsgCat &m ) noexcept;
  void send_peer_db( UserBridge &n ) noexcept;
  void make_peer_del_msg( UserBridge &n,  const char *sub,  size_t sublen,
                          uint32_t h,  MsgCat &m ) noexcept;
  void send_peer_del( UserBridge &n ) noexcept;
  bool recv_mesh_db( const MsgFramePublish &pub,  UserBridge &n,
                     MsgHdrDecoder &dec ) noexcept;
  size_t mesh_db_size( TransportRoute &rte,  uint32_t except_uid,
                       const MsgHdrDecoder &dec ) noexcept;
  void mesh_db_submsg( TransportRoute &rte,  uint32_t except_uid,
                       const MsgHdrDecoder &dec,  MsgCat &m ) noexcept;
  bool recv_mesh_request( const MsgFramePublish &pub,  UserBridge &n,
                          const MsgHdrDecoder &dec ) noexcept;
  bool recv_mesh_result( const MsgFramePublish &pub,  UserBridge &n,
                         MsgHdrDecoder &dec ) noexcept;
  bool send_mesh_request( UserBridge &n,  MsgHdrDecoder &dec ) noexcept;
  void make_peer_sync_msg( UserBridge &dest,  UserBridge &n,
                           const char *sub,  size_t sublen,  uint32_t h,
                           MsgCat &m,  uint32_t hops,  bool in_mesh ) noexcept;
  bool recv_sync_request( const MsgFramePublish &pub,  UserBridge &n,
                          const MsgHdrDecoder &dec ) noexcept;
  bool recv_add_route( const MsgFramePublish &pub,  UserBridge &n,
                       MsgHdrDecoder &dec ) noexcept;
  bool recv_sync_result( const MsgFramePublish &pub,  UserBridge &n,
                         MsgHdrDecoder &dec ) noexcept;
  /* _I.<nonce b64>. */
  static const size_t INBOX_PREFIX_SIZE = sizeof( _INBOX "." ) - 1;
  static const size_t INBOX_BASE_SIZE   = INBOX_PREFIX_SIZE + NONCE_B64_LEN + 1;

  UserBridge *is_inbox_sub( const char *sub,  size_t len ) {
    if ( len > INBOX_BASE_SIZE && /* must have _I.Nonce. */
         ::memcmp( sub, _INBOX ".", INBOX_PREFIX_SIZE ) == 0 ) {
      Nonce    n;
      size_t   pos;
      uint32_t uid;
      n.from_base64( &sub[ INBOX_PREFIX_SIZE ] );
      if ( this->node_ht->find( n, pos, uid ) )
        return this->bridge_tab[ uid ];
    }
    return NULL;
  }

  bool forward_pub( const MsgFramePublish &pub, const UserBridge &n,
                    const MsgHdrDecoder &dec ) noexcept;
  void debug_uids( kv::BitSpace &uids,  Nonce &csum ) noexcept;
  const char * uid_names( const kv::BitSpace &uids,  char *buf,
                          size_t buflen ) noexcept;
};

}
}
#endif
