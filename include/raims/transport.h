#ifndef __rai_raims__transport_h__
#define __rai_raims__transport_h__

#include <raikv/ev_net.h>
#include <raikv/ev_tcp.h>
#include <raikv/ev_cares.h>
#include <raims/config_tree.h>
#include <raims/crypt.h>
#include <raims/auth.h>
#include <raims/peer.h>
#include <raims/state_test.h>
#include <raims/debug.h>
#include <raims/config_const.h>

namespace rai {
namespace ms {

struct SessionMgr;
struct UserDB;
struct TransportRoute;
struct EvPgmTransport;
struct EvTcpTransportClient;
struct EvTcpTransportParameters;
struct EvInboxTransport;
struct EvTcpTransportListen;
struct EvRvTransportListen;
struct RvTransportService;
struct EvNatsTransportListen;
struct NameSvc;
struct ConnectDB;
struct IpcRte;

struct ConnectCtx : public kv::EvConnectionNotify,
                    public kv::EvTimerCallback,
                    public kv::EvCaresCallback {
  enum ConnectState {
    CONN_IDLE        = 0,
    CONN_GET_ADDRESS = 1,
    CONN_ACTIVE      = 2,
    CONN_TIMER       = 3,
    CONN_SHUTDOWN    = 4
  };
  ConnectDB        & db;
  kv::CaresAddrInfo  addr_info;      /* connect dns resolve */
  kv::EvConnection * client;         /* the socket connection */
  const uint64_t     event_id;       /* which transport client belongs to */
  uint64_t           start_mono_time;/* when connect started  */
  uint32_t           connect_tries,  /* how many times since start */
                     timeout;        /* config parameter timeout seconds */
  int                opts;           /* tcp connect sock options */
  ConnectState       state;          /* state enum above */
  IpcRte           * ipc_rte;
  uint32_t           ctx_id;
  bool               timer_active;

  void * operator new( size_t, void *ptr ) { return ptr; }
  ConnectCtx( kv::EvPoll &poll,  ConnectDB &d,  uint64_t id )
    : db( d ), addr_info( &poll, this ), client( 0 ), event_id( id ),
      start_mono_time( 0 ), connect_tries( 0 ), timeout( 15 ),
      state( CONN_SHUTDOWN ), ipc_rte( 0 ), ctx_id( 0 ),
      timer_active( false ) {}

  uint32_t next_timeout( void ) const {
    if ( this->connect_tries < 7 )
      return ( 100 << this->connect_tries );
    return 10000;
  }
  void set_state( ConnectState new_state,  bool clear_timer ) noexcept;
  void connect( const char *host,  int port,  int opts,  int timeout ) noexcept;
  void reconnect( void ) noexcept;
  bool expired( uint64_t cur_time = 0 ) noexcept;
  /* EvConnectNotify */
  virtual void on_connect( kv::EvSocket &conn ) noexcept;
  virtual void on_shutdown( kv::EvSocket &conn, const char *msg,
                            size_t len ) noexcept;
  /* EvTimerCallback */
  virtual bool timer_cb( uint64_t, uint64_t ) noexcept; 
  /* EvCaresCallback */
  virtual void addr_resolve_cb( kv::CaresAddrInfo &info ) noexcept;
};

struct ConnectDB {
  kv::EvPoll & poll;
  kv::ArrayCount<ConnectCtx *, 16> ctx_array; /* tcp connect contexts */
  const uint8_t sock_type;                    /* the client sock type */
  uint32_t ctx_count;

  ConnectDB( kv::EvPoll &p,  uint8_t st )
    : poll( p ), sock_type( st ), ctx_count( 0 ) {}
  ConnectCtx *create( uint64_t id ) noexcept;
  ConnectCtx *create2( IpcRte *ipc ) noexcept;
  virtual bool connect( ConnectCtx &ctx ) noexcept = 0;
  virtual void on_connect( ConnectCtx &ctx ) noexcept = 0;
  virtual bool on_shutdown( ConnectCtx &ctx,  const char *msg,
                            size_t len ) noexcept = 0;
  virtual void on_timeout( ConnectCtx &ctx ) noexcept = 0;
  virtual void on_dns( ConnectCtx &ctx,  const char *host,  int port,
                       int opts ) noexcept = 0;
};

struct ConnectMgr : public ConnectDB {
  SessionMgr & mgr;
  UserDB     & user_db;
  uint64_t     next_timer; /* timer_ids used by connections */

  ConnectMgr( SessionMgr &m,  UserDB &u,  kv::EvPoll &p,  uint8_t st )
    : ConnectDB( p, st ), mgr( m ), user_db( u ),
      next_timer( (uint64_t) st << 56 ) {}
  virtual bool connect( ConnectCtx &ctx ) noexcept;
  virtual void on_connect( ConnectCtx &ctx ) noexcept;
  virtual bool on_shutdown( ConnectCtx &ctx,  const char *msg,
                            size_t len ) noexcept;
  virtual void on_timeout( ConnectCtx &ctx ) noexcept;
  virtual void on_dns( ConnectCtx &ctx,  const char *host,  int port,
                       int opts ) noexcept;
};

enum TransportRouteState {
  TPORT_IS_LISTEN     = 1,   /* is a listener */
  TPORT_IS_MCAST      = 2,   /* is pgm / inbox */
  TPORT_IS_MESH       = 4,   /* in a mesh connection */
  TPORT_IS_CONNECT    = 8,   /* active connecting */
  TPORT_IS_TCP        = 16,  /* uses a tcp connection */
  TPORT_IS_EDGE       = 32,  /* is edge route */
  TPORT_IS_IPC        = 64,  /* is ipc route */
  TPORT_IS_SHUTDOWN   = 128, /* not running, disconnect or shutdown */
  TPORT_IS_DEVICE     = 256, /* uses name + dev multicast */
  TPORT_IS_INPROGRESS = 512, /* connect in progress */
  TPORT_HAS_TIMER     = 1024 /* if timer_id of rte is used */
};

enum RvOptions {
  RV_NO_PERMANENT = 1,
  RV_NO_HTTP      = 2,
  RV_NO_MCAST     = 4
};

struct IpcRte : public StateTest<IpcRte> {
  IpcRte                * next,
                        * back;
  ConfigTree::Transport & transport; /* the config for listener */
  kv::EvTcpListen       * listener;  /* the listener if ipc type (rv,nats,..) */
  kv::EvConnection      * connection;
  ConnectCtx            * connect_ctx;
  uint32_t                state;

  void * operator new( size_t, void *ptr ) { return ptr; }
  void operator delete( void *ptr ) { ::free( ptr ); }

  IpcRte( ConfigTree::Transport &t,  kv::EvTcpListen *l )
    : next( 0 ), back( 0 ), transport( t ), listener( l ), connection( 0 ),
      connect_ctx( 0 ), state( 0 ) {}
  IpcRte( ConfigTree::Transport &t,  kv::EvConnection *c )
    : next( 0 ), back( 0 ), transport( t ), listener( 0 ), connection( c ),
      connect_ctx( 0 ), state( 0 ) {}
};

struct IpcRteList : public kv::RouteNotify {
  TransportRoute      & rte;  /* usually rte tport_id = 0 */
  kv::DLinkList<IpcRte> list; /* list of ipc listeners */

  void * operator new( size_t, void *ptr ) { return ptr; }
  void operator delete( void *ptr ) { ::free( ptr ); }
  IpcRteList( TransportRoute &rte ) noexcept;

  IpcRte *find( ConfigTree::Transport &tport ) {
    for ( IpcRte *el = this->list.hd; el != NULL; el = el->next )
      if ( &el->transport == &tport )
        return el;
    return NULL;
  }
  /* sub notify */
  virtual void on_sub( kv::NotifySub &sub ) noexcept;
  virtual void on_unsub( kv::NotifySub &sub ) noexcept;
  virtual void on_resub( kv::NotifySub &sub ) noexcept;
  virtual void on_psub( kv::NotifyPattern &pat ) noexcept;
  virtual void on_punsub( kv::NotifyPattern &pat ) noexcept;
  virtual void on_repsub( kv::NotifyPattern &pat ) noexcept;
  virtual void on_sub_q( kv::NotifyQueue &sub ) noexcept;
  virtual void on_resub_q( kv::NotifyQueue &sub ) noexcept;
  virtual void on_unsub_q( kv::NotifyQueue &sub ) noexcept;
  virtual void on_psub_q( kv::NotifyPatternQueue &pat ) noexcept;
  virtual void on_repsub_q( kv::NotifyPatternQueue &pat ) noexcept;
  virtual void on_punsub_q( kv::NotifyPatternQueue &pat ) noexcept;
  virtual void on_reassert( uint32_t fd,  kv::RouteVec<kv::RouteSub> &sub_db,
                            kv::RouteVec<kv::RouteSub> &pat_db ) noexcept;
  virtual void on_bloom_ref( kv::BloomRef &ref ) noexcept;
  virtual void on_bloom_deref( kv::BloomRef &ref ) noexcept;
  bool punsub_test( kv::NotifyPattern &pat ) noexcept;
  void send_listen( const kv::PeerId &src,  const char *subj,  size_t sublen,
                    const char *reply,  size_t replen,  uint32_t refcnt,
                    int sub_flags ) noexcept;
};

struct BitRefCount {
  kv::BitSpace      bits; /* one bit for first ref count */
  kv::UIntHashTab * ht;   /* more counter bits if ref count > 1 */
  BitRefCount() : ht( 0 ) {}
  ~BitRefCount() { if ( this->ht != NULL ) delete this->ht; }

  bool is_member( uint32_t i ) const { return this->bits.is_member( i ); }
  bool first( uint32_t &i )    const { return this->bits.first( i ); }
  bool next( uint32_t &i )     const { return this->bits.next( i ); }
  uint32_t ref( uint32_t i )   noexcept; /* return ref_count++ */
  uint32_t deref( uint32_t i ) noexcept; /* return --ref_count */
};

struct MeshCsumCache {
  uint32_t uid;  /* which uid sent hb */
  Nonce    csum; /* ths mesh csum the uid sent */

  void * operator new( size_t, void *ptr ) { return ptr; }
  void operator delete( void *ptr ) { ::free( ptr ); }
  MeshCsumCache() : uid( 0 ) {
    this->csum.zero();
  }
};

typedef kv::ArrayCount<kv::BloomRoute *, 4> BloomRouteArray;

struct TransportRoute : public kv::EvSocket, public kv::EvConnectionNotify,
                        public kv::BPData, public StateTest<TransportRoute> {
  kv::EvPoll            & poll;           /* event poller */
  SessionMgr            & mgr;            /* session of transport */
  UserDB                & user_db;        /* session of transport */
  kv::RoutePublish      & sub_route;      /* bus for transport */
  kv::BloomRoute        * router_rt;
  kv::BitSpace            connected,      /* which fds are connected */
                          connected_auth; /* which fds are authenticated */
  BitRefCount             mesh_connected, /* shared with uid_in_mesh */
                        * uid_in_mesh,    /* all tports point to one mesh */
                        * uid_in_device;  /* all tports point to one device */
  AdjacencySpace          uid_connected;  /* which uids are connected */
  Nonce                 * mesh_csum,      /* ptr to mesh_csum2 of listener */
                          mesh_csum2,     /* mesh csum of nodes connected */
                          hb_cnonce;      /* the last cnonce used for hb */
  uint64_t                hb_time,        /* last hb time usecs */
                          hb_mono_time,   /* last hb time monotonic usecs */
                          hb_seqno,       /* last hb seqno */
                          stats_seqno,    /* seqno for _N.PORT msgs */
                          timer_id;       /* unique timer id serial */
  int64_t                 delta_recv;
  StageAuth               auth[ 3 ];      /* history of last 3 hb */
  uint32_t                tport_id,       /* index in transport_tab[] */
                          hb_count,       /* count of new hb recvd */
                          hb_fast,        /* sends hb after initial connect */
                          connect_count,  /* count of connections */
                          last_connect_count, /* sends hb when new conn */
                          state;          /* TPORT_IS_... */
  TransportRoute        * mesh_id,        /* mesh listener */
                        * dev_id;         /* device listener */
  kv::EvTcpListen       * listener;       /* the listener if svc */
  ConnectCtx            * connect_ctx,    /* if connnect manager */
                        * notify_ctx;     /* if accept drop, notify reconnect */
  EvPgmTransport        * pgm_tport;      /* if pgm mcast */
  EvInboxTransport      * ibx_tport;      /* if pgm, point-to-point ucast */
  RvTransportService    * rv_svc;         /* host db for ipc transport */
  StringVal               ucast_url,      /* url address of ucast ptp */
                          mesh_url,       /* url address of mesh listener */
                          conn_url;       /* url address of connection */
  kv::PeerId              inbox,          /* fd of ucast ptp */
                          mcast;          /* fd of mcast pgm */
  uint32_t                mesh_url_hash,  /* hash of mesh_url */
                          conn_hash,      /* hash of connecting url */
                          ucast_url_hash, /* hash of outgoing inbox url */
                          oldest_uid;     /* which uid is oldest connect */
  IpcRteList            * ext;            /* list of ipc listeners */
  MeshCsumCache         * mesh_cache;     /* cache of hb mesh csum */
  AdjCost                 initial_cost;
  ConfigTree::Service   & svc;            /* service definition */
  ConfigTree::Transport & transport;      /* transport definition */

  void * operator new( size_t, void *ptr ) { return ptr; }
  void operator delete( void *ptr ) { ::free( ptr ); }

  TransportRoute( kv::EvPoll &p,  SessionMgr &m,  ConfigTree::Service &s,
                  ConfigTree::Transport &t,  const char *svc_name,
                  uint32_t f ) noexcept;

  bool is_shutdown( void ) const { return this->is_set( TPORT_IS_SHUTDOWN ) != 0; }
  bool is_listen( void )   const { return this->is_set( TPORT_IS_LISTEN ) != 0; }
  bool is_connect( void )  const { return this->is_set( TPORT_IS_CONNECT ) != 0; }
  bool is_device( void )   const { return this->is_set( TPORT_IS_DEVICE ) != 0; }
  bool is_mcast( void )    const { return this->is_set( TPORT_IS_MCAST ) != 0; }
  bool is_mesh( void )     const { return this->is_set( TPORT_IS_MESH ) != 0; }
  bool is_edge( void )     const { return this->is_set( TPORT_IS_EDGE ) != 0; }
  bool is_ipc( void )      const { return this->is_set( TPORT_IS_IPC ) != 0; }
  bool mesh_equal( const char *url,  uint32_t hash ) const {
    if ( hash != this->mesh_url_hash ) return false;
    return this->mesh_url.equals( url );
  }

  int init( void ) noexcept;
  void init_state( void ) noexcept;
  void set_peer_name( kv::PeerData &pd,  const char *suff ) noexcept;
  bool update_cost( UserBridge &n,  StringVal &tport,  AdjCost *cost,
                    uint32_t rem_tport_id,  const char *s ) noexcept;
  const char * connected_names( char *buf,  size_t buflen ) noexcept;
  /*const char * reachable_names( char *buf,  size_t buflen ) noexcept;*/
  size_t port_status( char *buf, size_t buflen ) noexcept;
  bool check_flow_control( bool b ) {
    if ( ! b && this->bp_in_list() )
      this->push( kv::EV_WRITE_POLL );
    return b;
  }
  /* EvSocket */
  virtual void write( void ) noexcept;
  virtual void read( void ) noexcept;
  virtual void process( void ) noexcept;
  virtual void release( void ) noexcept;
  virtual bool on_msg( kv::EvPublish &pub ) noexcept;
  virtual size_t get_userid( char userid[ MAX_USERID_LEN ] ) noexcept;
  virtual size_t get_session( uint16_t svc,
                              char session[ MAX_SESSION_LEN ] ) noexcept;
  virtual size_t get_subscriptions( uint16_t svc,
                                    kv::SubRouteDB &subs ) noexcept;
  virtual size_t get_patterns( uint16_t svc,  int pat_fmt,  
                               kv::SubRouteDB &pats ) noexcept;
  /*virtual bool timer_expire( uint64_t tid, uint64_t eid ) noexcept;*/
  virtual void on_write_ready( void ) noexcept;

  static void make_url_from_sock( StringTab &string_tab,  StringVal &url,
                                  EvSocket &sock, const char *proto ) noexcept;
  void create_listener_mesh_url( void ) noexcept;
  void create_listener_conn_url( void ) noexcept;
  bool create_transport( ConfigTree::Transport &tport ) noexcept;
  void change_any( const char *type,  NameSvc &name ) noexcept;

  bool add_mesh_connect( const char *mesh_url,  uint32_t mesh_hash ) noexcept;
  bool add_tcp_connect( const char *conn_url,  uint32_t conn_hash ) noexcept;

  EvTcpTransportListen *create_tcp_listener(
                                        ConfigTree::Transport &tport ) noexcept;
  bool create_tcp_connect( ConfigTree::Transport &tport ) noexcept;

  void get_tport_service( ConfigTree::Transport &tport,
                          const char *&service,  size_t &service_len,
                          uint16_t &rv_svc ) noexcept;
  void get_tport_service_host( ConfigTree::Transport &tport,
                               const char *&service,  size_t &service_len,
                               uint16_t &rv_svc,  void **rv_host ) noexcept;
  bool create_rv_listener( ConfigTree::Transport &tport ) noexcept;
  bool create_rv_connection( ConfigTree::Transport &tport ) noexcept;

  bool create_ipc_listener( ConfigTree::Transport &tport ) noexcept;
  bool create_ipc_connection( ConfigTree::Transport &tport ) noexcept;

  EvTcpTransportListen *create_mesh_listener(
                                        ConfigTree::Transport &tport ) noexcept;
  bool create_pgm( int kind,  ConfigTree::Transport &tport ) noexcept;

  bool forward_to_connected( kv::EvPublish &pub ) {
    return this->sub_route.forward_set_no_route( pub, this->connected );
  }
  bool forward_to_connected_auth( kv::EvPublish &pub ) {
    return this->sub_route.forward_set_no_route( pub, this->connected_auth );
  }
  bool forward_to_connected_auth_not_fd( kv::EvPublish &pub,  uint32_t fd ) {
    return this->sub_route.forward_set_no_route_not_fd( pub,
                                                     this->connected_auth, fd );
  }
  uint32_t shutdown( ConfigTree::Transport &t ) noexcept;
  bool start_listener( kv::EvTcpListen *l,
                       ConfigTree::Transport &tport ) noexcept;
  bool is_self_connect( kv::EvSocket &conn ) noexcept;
  void close_self_connect( TransportRoute &rte, kv::EvSocket &conn ) noexcept;
  /* a new connection */
  virtual void on_connect( kv::EvSocket &conn ) noexcept;
  /* a disconnect */
  virtual void on_shutdown( kv::EvSocket &conn,  const char *,
                            size_t ) noexcept;
  virtual void on_data_loss( kv::EvSocket &conn,  kv::EvPublish &pub ) noexcept;
  void on_timeout( uint32_t connect_tries,  uint64_t nsecs ) noexcept;
  int printf( const char *fmt, ... ) const noexcept __attribute__((format(printf,2,3)));
  int printe( const char *fmt, ... ) const noexcept __attribute__((format(printf,2,3)));
};

struct TransportTab : public kv::ArrayCount<TransportRoute *, 4> {
  TransportRoute *find_transport( ConfigTree::Transport *t ) {
    if ( t != NULL ) {
      for ( size_t i = 0; i < this->count; i++ ) {
        if ( &this->ptr[ i ]->transport == t )
          return this->ptr[ i ];
      }
    }
    return NULL;
  }
};

}
namespace natsmd {
struct EvNatsService;
}
namespace sassrv {
struct EvRvService;
struct RvHost;
}
namespace ds {
struct EvRedisService;
}
namespace ms {
struct TransportRvHost {
  TransportRoute  & rte;
  kv::EvSocket    & conn;
  sassrv::RvHost ** rv_host;
  uint16_t          rv_service;

  TransportRvHost( TransportRoute &r,  kv::EvSocket &c ) noexcept;
  int start_session( void ) noexcept;
  void stop_session( void ) noexcept;
  static size_t ip4_string( uint32_t host_id,  char *buf ) noexcept;
  static size_t ip4_hex_string( uint32_t host_id,  char *buf ) noexcept;
};
}
}

#endif
