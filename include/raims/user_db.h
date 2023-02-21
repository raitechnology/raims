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

static const uint32_t HB_DEFAULT_INTERVAL = 10, /* seconds */
                      DEFAULT_RELIABILITY = 15; /* seconds */
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

enum UserNonceState {
  CHALLENGE_STATE         =       1, /* challenge sent, this is timed for retry */
  AUTHENTICATED_STATE     =       2, /* challenge recvd and auth succeeded */
  INBOX_ROUTE_STATE       =       4, /* inbox routed to source */
  IN_ROUTE_LIST_STATE     =       8, /* is a member of the route list */
  SENT_ZADD_STATE         =    0x10, /* sent a zadd to peers after auth */
  IN_HB_QUEUE_STATE       =    0x20, /* is a member of the heartbeat queue */
  SUBS_REQUEST_STATE      =    0x40, /* is a member of the subs queue */
  ADJACENCY_REQUEST_STATE =    0x80, /* is a member of the adj queue */
  PING_STATE              =   0x100, /* is a member of the ping queue */
  ZOMBIE_STATE            =   0x200, /* timed out, no clear dead signal */
  DEAD_STATE              =   0x400, /* dead from bye or z.del */
  UCAST_URL_STATE         =   0x800, /* has ucast url */
  UCAST_URL_SRC_STATE     =  0x1000, /* routes through a ucast url */
  MESH_URL_STATE          =  0x2000, /* has a mesh url */
  HAS_HB_STATE            =  0x4000, /* recvd a hb */
  IS_INIT_STATE           =  0x8000, /* if initialized with reset() */
  IS_VALID_STATE          = 0x10000,
  DIRECT_LINK_STATE       = 0x20000,
  MESH_REQUEST_STATE      = 0x40000
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

struct ThrottleState {
  uint64_t       mono_time;
  uint32_t     & state;
  uint32_t       req_count;
  const uint32_t state_bit;
  ThrottleState( uint32_t &stat,  UserNonceState bit )
    : mono_time( 0 ), state( stat ), req_count( 0 ), state_bit( bit ) {}
};

struct UserBridge;
struct UserDB;
struct NameSvc;
union  NameInbox;
struct UserRoute : public UserStateTest<UserRoute> {
  static const uint32_t NO_RTE  = -1,
                        NO_HOPS = -1;
  UserBridge      & n;
  TransportRoute  & rte;           /* transport */
  uint32_t          mcast_fd,      /* fd src, tcp fd or pgm fd */
                    inbox_fd,      /* inbox fd */
                    state,         /* whether in route list */
                    url_hash,      /* hash of ucast_url, mesh_url */
                    hb_seqno,      /* hb sequence on this transport */
                    list_id;       /* the user route list ptr */
  uint64_t          bytes_sent,    /* bytes sent ptp */
                    msgs_sent;     /* msgs sent ptp */
  StringVal         ucast_url,
                    mesh_url;
  const UserRoute * ucast_src;     /* route through url on another route */
  UserRoute       * next,          /* link in route list */
                  * back;
  void * operator new( size_t, void *ptr ) { return ptr; }
  UserRoute( UserBridge &u,  TransportRoute &r )
    : n( u ), rte( r ), next( 0 ), back( 0 ) {
    this->reset();
  }
  bool is_init( void ) const {
    return this->is_set( IS_INIT_STATE ) != 0;
  }
  bool is_valid( void ) const {
    return this->is_init() &&
           this->is_set( IS_VALID_STATE ) != 0;
  }
  void invalidate( void ) {
    this->state      = IS_INIT_STATE;
    this->ucast_url.zero();
    this->mesh_url.zero();
    this->url_hash   = 0;
    this->hb_seqno   = 0;
    this->bytes_sent = 0;
    this->msgs_sent  = 0;
    this->ucast_src  = NULL;
  }
  void connected( uint32_t hops ) {
    this->set( IS_VALID_STATE );
    if ( hops == 0 )
      this->set( DIRECT_LINK_STATE );
    else
      this->clear( DIRECT_LINK_STATE );
  }
  uint32_t hops( void ) const {
    if ( ! this->is_set( IS_VALID_STATE ) )
      return NO_HOPS;
    return this->is_set( DIRECT_LINK_STATE ) ? 0 : 1;
  }
  void reset( void ) {
    this->mcast_fd = NO_RTE;
    this->inbox_fd = NO_RTE;
    this->list_id  = NO_RTE;
    this->invalidate();
  }
  bool set_ucast( UserDB &user_db,  const void *p,  size_t len,
                  const UserRoute *src ) noexcept;
  bool set_mesh( UserDB &user_db,  const void *p,  size_t len ) noexcept;

  char * inbox_route_str( char *buf,  size_t buflen ) noexcept;
};

struct InboxSeqno {
  uint64_t recv_seqno, /* recv side inbox seqno */
           send_seqno; /* inbox seqnos for ptp links */
  uint8_t  recv_type[ 32 ],
           send_type[ 32 ];
  uint32_t * send_counter;
  void init( uint32_t *ctr ) {
    this->recv_seqno = this->send_seqno = 0;
    ::memset( this->recv_type, 0, sizeof( this->recv_type ) );
    ::memset( this->send_type, 0, sizeof( this->send_type ) );
    this->send_counter = ctr;
  }
  void set_recv( uint64_t seqno,  uint8_t pub_type ) {
    this->recv_type[ seqno % 32 ] = pub_type;
    this->recv_seqno = seqno;
  }
  uint64_t next_send( uint8_t pub_type ) {
    uint64_t seqno = ++this->send_seqno;
    this->send_type[ seqno % 32 ] = pub_type;
    this->send_counter[ pub_type & ( MAX_PUB_TYPE - 1 ) ]++;
    return seqno;
  }
};

struct Rtt {
  uint64_t latency,
           mono_time;
};
struct RttHistory : public kv::ArrayCount< Rtt, 32 > {
  void append( Rtt &x ) {
    this->push( x );
    if ( x.mono_time - this->ptr[ 0 ].mono_time > sec_to_ns( 60 * 60 ) &&
         this->count > 32 ) {
      size_t amt = this->count / 4;
      ::memmove( this->ptr, &this->ptr[ this->count - amt ],
                 amt * sizeof( this->ptr[ 0 ] ) );
      this->count -= amt;
    }
  }
};

/* peer sessions */
struct UserBridge : public UserStateTest<UserBridge> {
  HashDigest         peer_key,            /* peer session key */
                     peer_hello;
  PeerEntry        & peer;                /* configuration entry */
  UserNonce          bridge_id;           /* the user hmac and nonce */
  ForwardCache       forward_path[ COST_PATH_COUNT ]; /* which tports to fwd */
  kv::BloomRoute   * bloom_rt[ COST_PATH_COUNT ];
  UidSrcPath         src_path[ COST_PATH_COUNT ];
  kv::BloomRef       bloom;               /* the subs by this user */
  AdjacencyTab       adjacency;           /* what nonce routes are adjacent */
  Nonce              uid_csum,            /* current xor of adjacency */
                     hb_cnonce;           /* last cnonce used for hb */
  ec25519_key        hb_pubkey;           /* last pubkey used for hb */
  UserRoute        * user_route;          /* the routes for this user */
  uint32_t           state,               /* UserNonceState bits */
                     uid,                 /* unique id for route */
                     hb_interval,         /* interval of heartbeat */
                     primary_route,       /* route with min hops */
                     hb_skew_ref,         /* uid reference for hb skew */
                     skew_upd;            /* if skew updated */
  int64_t            hb_skew,             /* time diff from hb */
                     ping_skew,           /* time diff from ping recv */
                     pong_skew,           /* time diff w/rtt from pong recv */
                     clock_skew;          /* best clock skew estimate */
  uint64_t           hb_seqno,            /* users hb seqno */
                     hb_time,             /* users hb time */
                     hb_mono_time,        /* time hb recvd */
                     start_time,          /* start timestamp */
                     sub_seqno,           /* seqno used for start/stop sub */
                     link_state_seqno;    /* seqno used for link state db */
  UserRoute        * u_buf[ 24 ];         /* indexes user_route */
  StageAuth          auth[ 2 ];           /* auth handshake state */
  uint32_t           ping_send_seqno,     /* seqnos for pings */
                     ping_recv_seqno,
                     pong_send_seqno,
                     pong_recv_seqno,
                     ping_send_count,
                     ping_recv_count,
                     pong_recv_count,
                     ping_fail_count,     /* ping counters */
                     challenge_count,     /* count of challenges */
                     hb_miss,             /* count of hb missed */
                     unknown_adj_refs,    /* link refs are yet to be resolved */
                     auth_count,          /* number of times authenticated */
                     bridge_nonce_int;    /* first 4 bytes of bridge_id.nonce */
  AuthStage          last_auth_type;
  uint64_t           unknown_link_seqno,  /* edge of link_state_seqno */
                     peer_recv_seqno,     /* seqno used for add/del/blm peer */
                     mcast_recv_seqno,    /* recv side mcast seqno */
                     start_mono_time,     /* uptime from hb */
                     auth_mono_time,      /* when auth happens */
                     challenge_mono_time, /* time challenge sent */
                     subs_mono_time,      /* time subs reqeust sent */
                     sub_recv_mono_time,  /* time subscription reqeust recv */
                     ping_mono_time,      /* time start in ping state */
                     round_trip_time,     /* ping/pong */
                     min_rtt,             /* ping pong min rt time */
                     ping_send_time,      /* track ping times */
                     ping_recv_time,
                     pong_recv_time,      /* ping times */
                     stats_seqno,         /* _N.PEER. stats */
                     msg_repeat_count,    /* count mcast sub out of sequence */
                     msg_repeat_time,
                     msg_not_subscr_count, /* count mcast sub not subscribed */
                     msg_not_subscr_time,
                     msg_loss_time,       /* multicast message loss */
                     msg_loss_count,      /* count mcast msg loss */
                     inbox_msg_loss_time,
                     inbox_msg_loss_count,/* inbox message loss */
                     name_recv_seqno,     /* name service seqno/times */
                     name_recv_time,
                     name_recv_mask,
                     last_idl_pub,        /* one loss if many clients subscr */
                     inbound_msg_loss;    /* count of msg loss from subs */
  kv::UIntHashTab  * inbound_svc_loss;    /* service msg loss map */
  InboxSeqno         inbox;               /* track inbox sent/recv */
  RttHistory         rtt;
  ThrottleState      adj_req_throttle,
                     mesh_req_throttle;

  void * operator new( size_t, void *ptr ) { return ptr; }

  UserBridge( PeerEntry &pentry,  kv::BloomDB &db,  uint32_t seed,
              uint32_t *ctr )
      : peer( pentry ), bloom( seed, pentry.user.val, db ),
        adj_req_throttle( this->state, ADJACENCY_REQUEST_STATE ),
        mesh_req_throttle( this->state, MESH_REQUEST_STATE ) {
    ::memset( this->bloom_rt, 0, sizeof( this->bloom_rt ) );
    this->peer_key.zero();
    this->peer_hello.zero();
    this->uid_csum.zero();
    this->hb_cnonce.zero();
    this->hb_pubkey.zero();
    this->inbox.init( ctr );
    ::memset( &this->user_route , 0,
              (char *) (void *) &this->inbox -
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
    uint64_t ival_ns = sec_to_ns( this->hb_interval );
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
    uint64_t ival_ns = sec_to_ns( (uint64_t) 1 << count );
    return this->challenge_mono_time + ival_ns;
  }
  static bool is_challenge_older( UserBridge *r1,  UserBridge *r2 ) {
    return r1->challenge_timeout() > r2->challenge_timeout();
  }
  /* when to allow repeat subs request */
  uint64_t subs_timeout( void ) const {
    return this->subs_mono_time + sec_to_ns( 5 );
  }
  static bool is_subs_older( UserBridge *r1,  UserBridge *r2 ) {
    return r1->subs_timeout() > r2->subs_timeout();
  }
  uint64_t adj_timeout( void ) const {
    return this->adj_req_throttle.mono_time + sec_to_ns( 5 );
  }
  static bool is_adj_older( UserBridge *r1,  UserBridge *r2 ) {
    return r1->adj_timeout() > r2->adj_timeout();
  }
  uint64_t mesh_timeout( void ) const {
    return this->mesh_req_throttle.mono_time + sec_to_ns( 5 );
  }
  static bool is_mesh_older( UserBridge *r1,  UserBridge *r2 ) {
    return r1->mesh_timeout() > r2->mesh_timeout();
  }
  bool throttle_request( uint32_t inc,  ThrottleState &throttle,
                         uint64_t cur_mono = 0 ) noexcept;
  bool throttle_adjacency( uint32_t inc,  uint64_t cur_mono = 0 ) {
    return this->throttle_request( inc, this->adj_req_throttle, cur_mono );
  }
  bool throttle_mesh( uint32_t inc,  uint64_t cur_mono = 0 ) {
    return this->throttle_request( inc, this->mesh_req_throttle, cur_mono );
  }
  uint64_t ping_timeout( void ) const {
    return this->ping_mono_time + sec_to_ns( 5 );
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

struct SourceRouteList : public kv::ArrayCount< UserRouteList, 128 > {
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
  StringVal         tport_name,
                    mesh_url;
  uint32_t          url_hash;
  uint64_t          conn_mono_time,
                    start_mono_time;
  bool              is_mesh,
                    is_connected;
  void * operator new( size_t, void *ptr ) { return ptr; }
  void operator delete( void *ptr ) { ::free( ptr ); }
  MeshRoute( TransportRoute &r,  const StringVal &tport,  const StringVal &url,
             uint32_t h,  const Nonce &n,  bool is_me )
    : next( 0 ), back( 0 ), rte( r ), b_nonce( n ), tport_name( tport ),
      mesh_url( url ), url_hash( h ), conn_mono_time( 0 ),
      start_mono_time( 0 ), is_mesh( is_me ), is_connected( false ) {}
};

struct MeshDirectList : public kv::DLinkList< MeshRoute > {
  uint64_t last_process_mono;
  MeshDirectList() : last_process_mono( 0 ) {}
  /*void update( UserRoute *u ) noexcept;*/
  void update( TransportRoute &rte,  const StringVal &tport,
               const StringVal &url,  uint32_t h,
               const Nonce &b_nonce,  bool is_mesh = true ) noexcept;
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
                        UserBridge::is_mesh_older >      UserMeshQueue;
typedef struct kv::PrioQueue< UserBridge *,
                        UserBridge::is_ping_older >      UserPingQueue;
typedef struct kv::PrioQueue< UserPendingRoute *,
                        UserPendingRoute::is_pending_older > UserPendingQueue;

/* nonce -> node_ht[ uid ] -> UserBridge */
typedef kv::IntHashTabT< Hash128Elem, uint32_t > NodeHashTab;
typedef kv::UIntHashTab HostHashTab;

struct SubDB;
struct StringTab;
struct UserDB {
  static const uint32_t MY_UID = 0;      /* bridge_tab[ 0 ] reserved for me */
  /* my transports */
  TransportTab          transport_tab;    /* transport array */
  ForwardCache          forward_path[ COST_PATH_COUNT ];/* which tports fwd */
  TransportRoute      * ipc_transport;    /* transport[ 0 ], internal routes */
  kv::EvPoll          & poll;

  /* my identity */
  ConfigTree::User    & user;            /* my user */
  ConfigTree::Service & svc;             /* my service */
  SubDB               & sub_db;          /* my subscriptions */
  StringTab           & string_tab;      /* string const (config, user, tport)*/
  EventRecord         & events;          /* event recorder, what happened when*/
  kv::BitSpace        & router_set;
  uint64_t              start_mono_time, /* monotonic stamp */
                        start_time;      /* set on initialization, used widely*/
  /* my instance */
  UserNonce             bridge_id;       /* user hmac + session nonce */
  DSA                 * svc_dsa,
                      * user_dsa;
  HashDigest          * session_key,     /* session key */
                      * hello_key;       /* svc + user key */
  CnonceRandom        * cnonce;          /* random nonce generator */
  EC25519             * hb_keypair;      /* session keypair for auth */
  Nonce                 uid_csum;        /* xor of link_state nonces */

  /* indexes of node instances */
  NodeHashTab         * node_ht,         /* nonce -> uid */
                      * zombie_ht;       /* timed out nodes */
  HostHashTab         * host_ht;
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
  UserMeshQueue         mesh_queue;      /* throttle mesh request */
  UserPingQueue         ping_queue;      /* test pingable */
  UserPendingQueue      pending_queue;   /* retry user/peer resolve */
  AdjPendingList        adjacency_unknown; /* adjacency recv not resolved */
  AdjChangeList         adjacency_change;  /* adjacency send pending */
  MeshDirectList        mesh_pending;    /* mesh connect pending */

  /* cache of peer keys */
  PeerKeyHashTab      * peer_key_ht;     /* index cache by src uid, dest uid */
  PeerKeyCache        * peer_keys;       /* cache of peer keys encrypted */

  /* uid bits */
  kv::BitSpace          uid_authenticated, /* uids authenticated */
                        uid_rtt;           /* uids with ping pending */
  /* system subjects after auth */
  kv::BloomRef          peer_bloom;      /* allow after auth (_S.JOIN, _X.HB) */

  /* counters, seqnos */
  uint32_t              hb_interval,     /* seconds between _X.HB publish */
                        reliability,     /* seconds of send/recv window */
                        next_uid,        /* next_uid available */
                        free_uid_count,  /* num uids freed */
                        my_src_fd,       /* my src fd */
                        uid_auth_count,  /* total trusted nodes */
                        uid_hb_count,    /* total hb / distance zero nones */
                        uid_ping_count,
                        next_ping_uid,
                        bridge_nonce_int,
                        msg_send_counter[ MAX_PUB_TYPE ];
  uint64_t              send_peer_seqno, /* a unique seqno for peer multicast */
                        link_state_seqno,/* seqno of adjacency updates */
                        link_state_sum,  /* sum of all link state seqno */
                        mcast_send_seqno,/* seqno of mcast subjects */
                        hb_ival_ns,      /* heartbeat interval */
                        hb_ival_mask,    /* ping ival = pow2 hb_ival * 1.5 */
                        next_ping_mono,  /* when next ping is sent */
                        last_auth_mono,  /* when last uid was authenticated */
                        converge_time,   /* time of convergence */
                        converge_mono,   /* convergence mono time */
                        net_converge_time, /* time that network agrees */
                        name_send_seqno,
                        name_send_time;
  kv::rand::xoroshiro128plus rand;       /* used to generate bloom seeds */

  /* memory buffers for keys and peer nodes */
  kv::SLinkList<UserAllocBuf> buf_list;  /* secure buf alloc for nodes, keys */

  /* adjacency calculations working space */
  AdjDistance           peer_dist;       /* calc distance between nodes */
  ServiceBuf            my_svc;          /* pub key for service */

  UserDB( kv::EvPoll &p,  ConfigTree::User &u, ConfigTree::Service &s,
          SubDB &sdb,  StringTab &st,  EventRecord &ev,
          kv::BitSpace &rs ) noexcept;
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
  UserBridge *make_user_bridge( size_t len,  PeerEntry &peer,
                                kv::BloomDB &db,  uint32_t seed ) {
    return new ( this->alloc( len ) ) UserBridge( peer, db, seed,
                                                  this->msg_send_counter );
  }
  PeerEntry *make_peer_entry( size_t len ) {
    return new ( this->alloc( len ) ) PeerEntry();
  }
  void update_link_state_seqno( uint64_t &old_val,  uint32_t new_val ) {
    this->link_state_sum -= old_val;
    this->link_state_sum += new_val;
    old_val = new_val;
  }
  /* release secure mem */
  void release_alloc( void ) noexcept;

  uint32_t next_tport_id( void ) const { return this->transport_tab.count; }
  uint32_t next_svc_id( uint32_t f ) const { return ( f & TPORT_IS_IPC ) ? 0 :
                                                    this->next_tport_id(); }
  bool init( const CryptPass &pwd,  uint32_t my_fd, ConfigTree &tree ) noexcept;

  void calc_hello_key( uint64_t start_time, const HmacDigest &user_hmac,
                       HashDigest &ha ) noexcept;
  void calc_secret_hmac( UserBridge &n,  PolyHmacDigest &secret_hmac ) noexcept;

  void check_inbox_route( UserBridge &n,  UserRoute &u_rte ) noexcept;

  /* use primary route for inbox */
  bool forward_to_primary_inbox( UserBridge &n,  InboxBuf &ibx,  uint32_t h,
                                 const void *msg,  size_t msglen,
                                 kv::BPData *data = NULL,
                                 const void *frag = NULL,
                                 size_t frag_size = 0,
                                 uint32_t src_route = 0 ) {
    if ( frag_size == 0 )
      return this->forward_to_primary_inbox( n, ibx.buf, ibx.len(), h,
                                             msg, msglen, data );
    return this->forward_to_primary_inbox( n, ibx.buf, ibx.len(), h,
                                           msg, msglen, data,
                                           frag, frag_size, src_route );
  }
  bool forward_to_primary_inbox( UserBridge &n,  const char *sub,  size_t sublen,
                                 uint32_t h,  const void *msg,  size_t msglen,
                                 kv::BPData *data = NULL ) noexcept;
  bool forward_to_primary_inbox( UserBridge &n,  const char *sub,  size_t sublen,
                                 uint32_t h,  const void *msg,  size_t msglen,
                                 kv::BPData *data,  const void *frag,
                               size_t frag_size,  uint32_t src_route ) noexcept;
  /* use route that request used (n.user_route) for reply */
  bool forward_to_inbox( UserBridge &n,  InboxBuf &ibx,  uint32_t h,
                         const void *msg, size_t msglen ) {
    return this->forward_to_inbox( n, ibx.buf, ibx.len(), h, msg, msglen, NULL );
  }
  bool forward_to_inbox( UserBridge &n,  const char *sub,  size_t sublen,
                         uint32_t h,  const void *msg, size_t msglen,
                         kv::BPData *data = NULL ) noexcept;
  /* use u_rte for inbox */
  bool forward_to( UserBridge &n,  const char *sub,  size_t sublen, 
                   uint32_t h,  const void *msg, size_t msglen,
                   UserRoute &u_rte,  kv::BPData *data ) noexcept;
  /* use u_rte with fragments for inbox */
  bool forward_to( UserBridge &n,  const char *sub,  size_t sublen,  uint32_t h,
                   const void *msg,  size_t msglen,  kv::BPData *data,
                   const void *frag,  size_t frag_size,
                   uint32_t src_route ) noexcept;

  PeerEntry *make_peer( const StringVal &user, const StringVal &svc,
                        const StringVal &create,
                        const StringVal &expires ) noexcept;
  PeerEntry *find_peer( const char *u,  uint32_t ulen,
                        const char *c,  uint32_t clen,
                        const char *e,  uint32_t elen,
                        const HmacDigest &hmac ) noexcept;
  PeerEntry * find_peer( const MsgHdrDecoder &dec,
                         const HmacDigest &hmac ) noexcept;
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
  bool recv_ping_request( MsgFramePublish &pub,  UserBridge &n,
                          const MsgHdrDecoder &dec,
                          bool is_mcast_ping = false ) noexcept;
  bool recv_pong_result( MsgFramePublish &pub,  UserBridge &n,
                         const MsgHdrDecoder &dec ) noexcept;
  int64_t min_skew( UserBridge &n ) {
    if ( n.skew_upd == 0 )
      return n.clock_skew;
    return this->get_min_skew( n, 0 );
  }
  int64_t get_min_skew( UserBridge &n,  uint32_t i ) noexcept;
  void mcast_name( NameSvc &name ) noexcept;
  void send_name_advert( NameSvc &name,  TransportRoute &rte,
                         NameInbox *inbox ) noexcept;
  void on_name_svc( NameSvc &name,  CabaMsg *msg ) noexcept;
  /* auth.cpp */
  bool compare_version( UserBridge &n, MsgHdrDecoder &dec ) noexcept;
  bool on_inbox_auth( const MsgFramePublish &pub,  UserBridge &n,
                      MsgHdrDecoder &dec ) noexcept;
  bool on_bye( const MsgFramePublish &pub,  UserBridge &n,
               const MsgHdrDecoder &dec ) noexcept;
  bool recv_challenge( const MsgFramePublish &pub,  UserBridge &n,
                       const MsgHdrDecoder &dec, AuthStage stage ) noexcept;
  bool send_challenge( UserBridge &n,  AuthStage stage ) noexcept;
  bool send_trusted( const MsgFramePublish &pub,  UserBridge &n,
                     MsgHdrDecoder &dec ) noexcept;
  bool recv_trusted( const MsgFramePublish &pub,  UserBridge &n,
                     MsgHdrDecoder &dec ) noexcept;
  /* user_db.cpp */
  void check_user_timeout( uint64_t current_mono_time,
                           uint64_t current_time ) noexcept;
  bool converge_network( uint64_t current_mono_time,
                         uint64_t current_time, bool req_timeout ) noexcept;
  UserBridge * lookup_bridge( MsgFramePublish &pub,
                              const MsgHdrDecoder &dec ) noexcept;
  UserBridge * lookup_user( MsgFramePublish &pub,
                            const MsgHdrDecoder &dec ) noexcept;
  void add_user_route( UserBridge &n,  TransportRoute &rte,
                       uint32_t fd,  const MsgHdrDecoder &dec,
                       const UserRoute *src ) noexcept;
  UserBridge * add_user( TransportRoute &rte,  const UserRoute *src,
                         uint32_t fd,  const UserNonce &b_nonce,
                         PeerEntry &peer,  uint64_t start,
                         const MsgHdrDecoder &dec,
                         HashDigest &hello ) noexcept;
  UserBridge * add_user2( const UserNonce &user_bridge_id,  
                          PeerEntry &peer,  uint64_t start,
                          HashDigest &hello ) noexcept;
  bool check_uid_csum( const UserBridge &n,  const Nonce &peer_csum ) noexcept;
  void set_ucast_url( UserRoute &u_rte, const MsgHdrDecoder &dec,
                      const char *src ) noexcept;
  void set_ucast_url( UserRoute &u_rte, const UserRoute *ucast_src,
                      const char *src ) noexcept;
  void set_ucast_url( UserRoute &u_rte, const char *url,  size_t url_len,
                      const char *src ) noexcept;
  void set_mesh_url( UserRoute &u_rte, const MsgHdrDecoder &dec,
                     const char *src ) noexcept;
  void find_adjacent_routes( void ) noexcept;
  void process_mesh_pending( uint64_t curr_mono ) noexcept;
  UserBridge * closest_peer_route( TransportRoute &rte,  UserBridge &n,
                                   uint32_t &cost ) noexcept;
  uint32_t new_uid( void ) noexcept;
  uint32_t random_uid_walk( void ) noexcept;
  void retire_source( TransportRoute &rte,  uint32_t fd ) noexcept;
  void add_bloom_routes( UserBridge &n,  TransportRoute &rte ) noexcept;
  void add_transport( TransportRoute &rte ) noexcept;
  void add_inbox_route( UserBridge &n,  UserRoute *primary ) noexcept;
  void remove_inbox_route( UserBridge &n ) noexcept;
  void add_authenticated( UserBridge &n,  const MsgHdrDecoder &dec,
                          AuthStage stage,  UserBridge *src ) noexcept;
  void remove_authenticated( UserBridge &n,  AuthStage bye ) noexcept;

  /* link_state.cpp */
  void save_unauthorized_adjacency( MsgFramePublish &fpub ) noexcept;
  void print_adjacency( const char *s,  UserBridge &n ) noexcept;
  void save_unknown_adjacency( UserBridge &n,  TransportRoute &rte,
                               uint64_t seqno,  AdjacencyRec *recs,
                               bool is_change ) noexcept;
  void add_unknown_adjacency( UserBridge &n ) noexcept;
  void clear_unknown_adjacency( UserBridge &n ) noexcept;
  void remove_adjacency( UserBridge &n ) noexcept;

  UserBridge *close_source_route( uint32_t fd ) noexcept;
  void push_source_route( UserBridge &n ) noexcept;
  void push_user_route( UserBridge &n,  UserRoute &u_rte ) noexcept;
  void pop_source_route( UserBridge &n ) noexcept;
  void push_connected_user_route( UserBridge &n,  UserRoute &u_rte ) noexcept;
  void set_connected_user_route( UserBridge &n,  UserRoute &u_rte ) noexcept;
  void pop_user_route( UserBridge &n,  UserRoute &u_rte ) noexcept;

  void send_adjacency_change( void ) noexcept;
  size_t adjacency_size( UserBridge *sync ) noexcept;
  void adjacency_submsg( UserBridge *sync,  MsgCat &m ) noexcept;
  bool recv_adjacency_change( const MsgFramePublish &pub,  UserBridge &n,
                              MsgHdrDecoder &dec ) noexcept;
  AdjacencyRec * apply_adjacency_change( UserBridge &n,
                                         AdjacencyRec *rec_list ) noexcept;
  bool add_adjacency_change( UserBridge &n,  AdjacencyRec &rec ) noexcept;
  bool send_adjacency( UserBridge &n,  UserBridge *sync,  InboxBuf &ibx,
                       uint64_t time_val,  uint32_t reas,  int which ) noexcept;
  bool send_adjacency_request( UserBridge &n,  AdjacencyRequest reas ) noexcept;
  /*bool send_adjacency_request2( UserBridge &n, AdjacencyRequest reas ) noexcept;*/
  bool recv_adjacency_request( const MsgFramePublish &pub,  UserBridge &n,
                               MsgHdrDecoder &dec ) noexcept;
  bool recv_adjacency_result( const MsgFramePublish &pub,  UserBridge &n,
                              MsgHdrDecoder &dec ) noexcept;
  /* peer.cpp */
  /* sync info about peer n to send to inbox of dest */
  void make_peer_sync_msg( UserBridge &dest,  UserBridge &n,
                           const char *sub,  size_t sublen,  uint32_t h,
                           MsgCat &m,  uint32_t hops ) noexcept;
  bool recv_sync_request( const MsgFramePublish &pub,  UserBridge &n,
                          const MsgHdrDecoder &dec ) noexcept;

  /* use src.sesion_key, src.nonce, dest.nonce to create another private key */
  void get_peer_key2( uint32_t src_uid,  const Nonce &dest_nonce,
                      HashDigest &hash ) noexcept;
  void get_peer_key( uint32_t src_uid,  uint32_t dest_id,
                     HashDigest &hash ) noexcept;
  /* decode peer data from a sync message */
  bool decode_peer_msg( UserBridge &from_n,  const MsgHdrDecoder &dec,
                        UserNonce &sync_bridge_id,  HashDigest &ha1,
                        UserBridge *&user_n,  UserBuf *user,
                        uint64_t &start ) noexcept;
  /* create a peer bridge from a sync message */
  UserBridge * make_peer_session( const MsgFramePublish &pub,
                                  UserBridge &from_n,
                                  const MsgHdrDecoder &dec,
                                  UserBridge *user_n ) noexcept;

  /* recv a list of peers, bridge ids and user names */
  bool recv_peer_db( const MsgFramePublish &pub,  UserBridge &n,
                     MsgHdrDecoder &dec,  AuthStage stage ) noexcept;
  bool make_peer_db_msg( UserBridge &n,  const char *sub,  size_t sublen,
                         uint32_t h,  MsgCat &m ) noexcept;
  size_t peer_db_size( UserBridge &n,  bool is_adj_req = false ) noexcept;
  void peer_db_submsg( UserBridge &n,  MsgCat &m,
                       bool is_adj_req = false ) noexcept;
  /* send peer db to inbox of peer */
  void send_peer_db( UserBridge &n ) noexcept;

  /* recv _Z.ADD, _I.Nonce.ADD_RTE messages for new peers */
  bool recv_peer_add( const MsgFramePublish &pub,  UserBridge &n,
                      MsgHdrDecoder &dec,  AuthStage stage ) noexcept;
  bool recv_add_route( const MsgFramePublish &pub,  UserBridge &n,
                       MsgHdrDecoder &dec ) noexcept;
  bool recv_sync_result( const MsgFramePublish &pub,  UserBridge &n,
                         MsgHdrDecoder &dec ) noexcept;
  /* send _Z.ADD message to add peers except source */
  void send_peer_add( UserBridge &n,
                      const TransportRoute *except_rte = NULL ) noexcept;
  /* send _Z.DEL message to del peers */
  void send_peer_del( UserBridge &n ) noexcept;
  bool recv_peer_del( const MsgFramePublish &pub,  UserBridge &n,
                      const MsgHdrDecoder &dec ) noexcept;

  /* recv and construct mesh db */
  bool recv_mesh_db( const MsgFramePublish &pub,  UserBridge &n,
                     MsgHdrDecoder &dec ) noexcept;
  bool recv_ucast_db( const MsgFramePublish &pub,  UserBridge &n,
                      MsgHdrDecoder &dec ) noexcept;
  size_t url_db_size( TransportRoute &rte,  UrlDBFilter &filter ) noexcept;
  void url_db_submsg( TransportRoute &rte,  UrlDBFilter &filter,
                       MsgCat &m ) noexcept;
  bool recv_mesh_request( const MsgFramePublish &pub,  UserBridge &n,
                          MsgHdrDecoder &dec ) noexcept;
  bool recv_mesh_result( const MsgFramePublish &pub,  UserBridge &n,
                         MsgHdrDecoder &dec ) noexcept;
  bool send_mesh_request( UserBridge &n,  MsgHdrDecoder &dec,
                          const Nonce &peer_csum ) noexcept;

  /* try to resolve unknown peers and adjacency */
  void process_unknown_adjacency( uint64_t current_mono_time ) noexcept;
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
  void remove_pending_peer( const Nonce *b_nonce,  uint64_t pseqno ) noexcept;

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

  bool bcast_pub( const MsgFramePublish &pub, const UserBridge &n,
                  const MsgHdrDecoder &dec ) noexcept;
  bool mcast_pub( const MsgFramePublish &pub, UserBridge &n,
                  const MsgHdrDecoder &dec ) noexcept;
  void debug_uids( kv::BitSpace &uids,  Nonce &csum ) noexcept;
  const char * uid_names( const kv::BitSpace &uids,  char *buf,
                          size_t buflen ) noexcept;
  const char * uid_names( const kv::UIntBitSet &uids,  uint32_t max_uid,
                          char *buf,  size_t buflen ) noexcept;
};

}
}
#endif
