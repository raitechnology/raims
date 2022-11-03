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
struct EvNatsTransportListen;
struct NameSvc;
struct ConnectDB;

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
  kv::CaresAddrInfo  addr_info;
  kv::EvConnection * client;
  uint64_t           event_id,
                     start_time;
  uint32_t           connect_tries,
                     timeout;
  int                opts;
  ConnectState       state;

  void * operator new( size_t, void *ptr ) { return ptr; }
  ConnectCtx( kv::EvPoll &poll,  ConnectDB &d )
    : db( d ), addr_info( poll, this ), client( 0 ), event_id( 0 ),
      start_time( 0 ), connect_tries( 0 ), timeout( 15 ),
      state( CONN_SHUTDOWN ) {}

  uint32_t next_timeout( void ) const {
    if ( this->connect_tries < 7 )
      return ( 100 << this->connect_tries );
    return 10000;
  }
  void connect( const char *host,  int port,  int opts ) noexcept;
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
  kv::ArrayCount<ConnectCtx *, 16> ctx_array;
  const uint8_t sock_type;

  ConnectDB( kv::EvPoll &p,  uint8_t st ) : poll( p ), sock_type( st ) {}
  ConnectCtx *create( uint64_t id ) noexcept;
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

  ConnectMgr( SessionMgr &m,  UserDB &u,  kv::EvPoll &p,  uint8_t st )
    : ConnectDB( p, st ), mgr( m ), user_db( u ) {}
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
  TPORT_IS_INPROGRESS = 512  /* connect in progress */
};

enum RvOptions {
  RV_NO_PERMANENT = 1,
  RV_NO_HTTP      = 2,
  RV_NO_MCAST     = 4
};

struct IpcRte {
  IpcRte                * next,
                        * back;
  ConfigTree::Transport & transport;
  kv::EvTcpListen       * listener;       /* the listener if svc */

  void * operator new( size_t, void *ptr ) { return ptr; }
  void operator delete( void *ptr ) { ::free( ptr ); }

  IpcRte( ConfigTree::Transport &t,  kv::EvTcpListen *l )
    : next( 0 ), back( 0 ), transport( t ), listener( l ) {}
};

struct IpcRteList : public kv::RouteNotify {
  TransportRoute      & rte;
  kv::DLinkList<IpcRte> list;

  void * operator new( size_t, void *ptr ) { return ptr; }
  void operator delete( void *ptr ) { ::free( ptr ); }
  IpcRteList( TransportRoute &rte ) noexcept;

  /* sub notify */
  virtual void on_sub( kv::NotifySub &sub ) noexcept;
  virtual void on_unsub( kv::NotifySub &sub ) noexcept;
  virtual void on_psub( kv::NotifyPattern &pat ) noexcept;
  virtual void on_punsub( kv::NotifyPattern &pat ) noexcept;
  virtual void on_reassert( uint32_t fd,  kv::RouteVec<kv::RouteSub> &sub_db,
                            kv::RouteVec<kv::RouteSub> &pat_db ) noexcept;
};

struct TransportRoute : public kv::EvSocket, public kv::EvConnectionNotify,
                        public StateTest<TransportRoute> {
  kv::EvPoll            & poll;           /* event poller */
  SessionMgr            & mgr;            /* session of transport */
  UserDB                & user_db;        /* session of transport */
  kv::RoutePublish      & sub_route;      /* bus for transport */
  kv::BloomRoute        * router_rt[ COST_PATH_COUNT ]; /* router 4 subs */
  kv::BitSpace            connected,      /* which fds are connected */
                          connected_auth, /* which fds are authenticated */
                          mesh_connected, /* shared with uid_in_mesh */
                        * uid_in_mesh,    /* all tports point to one mesh */
                        * uid_in_device;  /* all tports point to one device */
  AdjacencySpace          uid_connected;  /* which uids are connected */
  Nonce                 * mesh_csum,
                          mesh_csum2,     /* mesh csum of nodes connected */
                          hb_cnonce;      /* the last cnonce used for hb */
  uint64_t                hb_time,        /* last hb time usecs */
                          hb_mono_time,   /* last hb time monotonic usecs */
                          hb_seqno,       /* last hb seqno */
                          stats_seqno;
  StageAuth               auth[ 3 ];      /* history of last 3 hb */
  uint32_t                tport_id,       /* index in transport_tab[] */
                          hb_count,       /* count of new hb recvd */
                          last_hb_count,  /* sends hb when new hb */
                          connect_count,  /* count of connections */
                          last_connect_count, /* sends hb when new conn */
                          state;          /* TPORT_IS_... */
  TransportRoute        * mesh_id,        /* mesh listener */
                        * dev_id;         /* device listener */
  kv::EvTcpListen       * listener;       /* the listener if svc */
  ConnectCtx            * connect_ctx;    /* if connnect manager */
  EvPgmTransport        * pgm_tport;      /* if pgm mcast */
  EvInboxTransport      * ibx_tport;      /* if pgm, point-to-point ucast */
  StringVal               ucast_url,      /* url address of ucast ptp */
                          mesh_url,       /* url address of mesh listener */
                          conn_url;       /* url address of connection */
  uint32_t                inbox_fd,       /* fd of ucast ptp */
                          mcast_fd,       /* fd of mcast pgm */
                          mesh_url_hash,  /* hash of mesh_url */
                          conn_hash,      /* hash of connecting url */
                          oldest_uid,     /* which uid is oldest connect */
                          primary_count;
  IpcRteList            * ext;      
  ConfigTree::Service   & svc;            /* service definition */
  ConfigTree::Transport & transport;      /* transport definition */

  void * operator new( size_t, void *ptr ) { return ptr; }
  void operator delete( void *ptr ) { ::free( ptr ); }

  TransportRoute( kv::EvPoll &p,  SessionMgr &m,  ConfigTree::Service &s,
                  ConfigTree::Transport &t,  const char *svc_name,
                  uint32_t svc_id,  uint32_t id,  uint32_t f ) noexcept;

  bool is_listen( void ) const { return this->is_set( TPORT_IS_LISTEN ) != 0; }
  bool is_mcast( void )  const { return this->is_set( TPORT_IS_MCAST ) != 0; }
  bool is_mesh( void )   const { return this->is_set( TPORT_IS_MESH ) != 0; }
  bool is_edge( void )   const { return this->is_set( TPORT_IS_EDGE ) != 0; }

  int init( void ) noexcept;
  void init_state( void ) noexcept;
  void set_peer_name( kv::PeerData &pd,  const char *suff ) noexcept;
  void update_cost( UserBridge &n,  uint32_t cost[ COST_PATH_COUNT ] ) noexcept;
  const char * connected_names( char *buf,  size_t buflen ) noexcept;
  const char * reachable_names( char *buf,  size_t buflen ) noexcept;
  size_t port_status( char *buf, size_t buflen ) noexcept;
  /* EvSocket */
  virtual void write( void ) noexcept;
  virtual void read( void ) noexcept;
  virtual void process( void ) noexcept;
  virtual void release( void ) noexcept;
  virtual bool on_msg( kv::EvPublish &pub ) noexcept;

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
                          const char *&service,  size_t &service_len ) noexcept;
  bool create_rv_listener( ConfigTree::Transport &tport ) noexcept;
  bool create_rv_connect( ConfigTree::Transport &tport ) noexcept;

  bool create_nats_listener( ConfigTree::Transport &tport ) noexcept;
  bool create_nats_connect( ConfigTree::Transport &tport ) noexcept;

  bool create_redis_listener( ConfigTree::Transport &tport ) noexcept;
  bool create_redis_connect( ConfigTree::Transport &tport ) noexcept;

  EvTcpTransportListen *create_mesh_listener(
                                        ConfigTree::Transport &tport ) noexcept;
  bool create_pgm( int kind,  ConfigTree::Transport &tport ) noexcept;

  bool forward_to_connected( kv::EvPublish &pub ) {
    return this->sub_route.forward_set( pub, this->connected );
  }
  bool forward_to_connected_auth( kv::EvPublish &pub ) {
    return this->sub_route.forward_set( pub, this->connected_auth );
  }
  bool forward_to_connected_auth_not_fd( kv::EvPublish &pub,  uint32_t fd ) {
    return this->sub_route.forward_set_not_fd( pub, this->connected_auth, fd );
  }
  uint32_t shutdown( void ) noexcept;
  bool start_listener( kv::EvTcpListen *l,
                       ConfigTree::Transport &tport ) noexcept;
  bool is_self_connect( kv::EvSocket &conn ) noexcept;
  /* a new connection */
  virtual void on_connect( kv::EvSocket &conn ) noexcept;
  /* a disconnect */
  virtual void on_shutdown( kv::EvSocket &conn,  const char *,
                            size_t ) noexcept;
  void on_timeout( uint32_t connect_tries,  uint64_t nsecs ) noexcept;
  int printf( const char *fmt, ... ) const noexcept __attribute__((format(printf,2,3)));
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
}

#endif
