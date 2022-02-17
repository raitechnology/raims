#ifndef __rai_raims__transport_h__
#define __rai_raims__transport_h__

#include <raikv/ev_net.h>
#include <raikv/ev_tcp.h>
#include <raims/config_tree.h>
#include <raims/crypt.h>
#include <raims/auth.h>
#include <raims/state_test.h>
#include <raims/debug.h>

namespace rai {
namespace ms {

struct SessionMgr;
struct UserDB;
struct TransportRoute;
struct TcpConnectionMgr;
struct PeerUidSet;
struct EvPgmTransport;
struct EvInboxTransport;
struct EvTcpTransportListen;
struct EvRvTransportListen;
struct EvNatsTransportListen;

struct ConnectionMgr : public kv::EvConnectionNotify,
                       public kv::EvTimerCallback {
  TransportRoute      & rte;
  kv::EvConnection    * conn;
  void                * parameters;
  double                reconnect_time, /* when reconnect started */
                        connect_time;
  uint32_t              connect_timeout_secs; /* how long to try */
  uint16_t              reconnect_timeout_secs; /* next connect try */
  bool                  is_reconnecting, /* if connect in progress */
                        is_shutdown; /* if should stop reconnecting */

  void * operator new( size_t, void *ptr ) { return ptr; }
  void operator delete( void *ptr ) { ::free( ptr ); }

  ConnectionMgr( TransportRoute &r )
    : rte( r ), conn( 0 ), parameters( 0 ), reconnect_time( 0 ),
      connect_time( 0 ), connect_timeout_secs( 0 ), reconnect_timeout_secs( 1 ),
      is_reconnecting( false ), is_shutdown( true ) {}

  void set_parm( void *parm ) {
    if ( this->parameters != NULL )
      ::free( this->parameters );
    this->parameters = parm;
  }
  void restart( void ) {
    this->is_shutdown = false;
    this->reconnect_time = 0;
    this->reconnect_timeout_secs = 1;
  }
  void connect_failed( kv::EvSocket &conn ) noexcept;
  bool setup_reconnect( void ) noexcept;
  /* protocol */
  bool do_connect( void ) noexcept;
  /* EvConnectNotify */
  virtual void on_connect( kv::EvSocket &conn ) noexcept;
  virtual void on_shutdown( kv::EvSocket &conn,  const char *,
                            size_t ) noexcept;
  /* EvTimerCallback */
  virtual bool timer_cb( uint64_t, uint64_t ) noexcept;
};

enum TransportRouteState {
  TPORT_IS_SVC       = 1,
  TPORT_IS_LISTEN    = 2,
  TPORT_IS_MCAST     = 4,
  TPORT_IS_MESH      = 8,
  TPORT_IS_CONNECT   = 16,
  TPORT_IS_TCP       = 32,
  TPORT_IS_EDGE      = 64,
  TPORT_IS_EXTERNAL  = 128,
  TPORT_IS_SHUTDOWN  = 256,
  TPORT_IS_PREFERRED = 512
};

struct ExtRte {
  ExtRte                * next,
                        * back;
  ConfigTree::Transport & transport;
  kv::EvTcpListen       * listener;       /* the listener if svc */

  void * operator new( size_t, void *ptr ) { return ptr; }
  void operator delete( void *ptr ) { ::free( ptr ); }

  ExtRte( ConfigTree::Transport &t,  kv::EvTcpListen *l )
    : next( 0 ), back( 0 ), transport( t ), listener( l ) {}
};

struct ExtRteList : public kv::RouteNotify {
  TransportRoute      & rte;
  kv::DLinkList<ExtRte> list;

  void * operator new( size_t, void *ptr ) { return ptr; }
  void operator delete( void *ptr ) { ::free( ptr ); }
  ExtRteList( TransportRoute &rte ) noexcept;

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
  /*TransportRoute        * next;*/
  kv::EvPoll            & poll;           /* event poller */
  SessionMgr            & mgr;            /* session of transport */
  UserDB                & user_db;        /* session of transport */
  kv::RoutePublish      & sub_route;      /* bus for transport */
  kv::BloomRoute        * switch_rt,      /* local and system subs */
                        * eswitch_rt,     /* external subs attached to local */
                        * router_rt;      /* remote subs to other users */
  kv::BitSpace            connected,      /* which fds are connected */
                          connected_auth, /* which fds are authenticated */
                          uid_connected,  /* which uids are connected */
                          mesh_connected, /* shared with uid_in_mesh */
                          reachable,      /* uids reachable */
                        * uid_in_mesh;    /* all tports point to one mesh */
  Nonce                 * mesh_csum,
                          mesh_csum2,     /* mesh csum of nodes connected */
                          hb_cnonce;      /* the last cnonce used for hb */
  uint64_t                hb_time,        /* last hb time usecs */
                          hb_mono_time,   /* last hb time monotonic usecs */
                          hb_seqno,       /* last hb seqno */
                          reachable_seqno;/* adjacency seqno of reachable */
  StageAuth               auth[ 3 ];      /* history of last 3 hb */
  uint32_t                tport_id,       /* index in transport_tab[] */
                          hb_count,       /* count of new hb recvd */
                          last_hb_count,  /* sends hb when new hb */
                          connect_count,  /* count of connections */
                          last_connect_count, /* sends hb when new conn */
                          state;          /* TPORT_IS_... */
  TransportRoute        * mesh_id;        /* mesh listener */
  kv::EvTcpListen       * listener;       /* the listener if svc */
  ConnectionMgr           connect_mgr;    /* if connnect manager */
  EvPgmTransport        * pgm_tport;      /* if pgm mcast */
  EvInboxTransport      * ibx_tport;      /* if pgm, point-to-point ucast */
  char                  * ucast_url_addr, /* url address of ucast ptp */
                        * mesh_url_addr;  /* url address of mesh listener */
  uint16_t                ucast_url_len,  /* len of urls */
                          mesh_url_len;
  uint32_t                inbox_fd,       /* fd of ucast ptp */
                          mcast_fd,       /* fd of mcast pgm */
                          mesh_conn_hash, /* hash of mesh url */
                          oldest_uid,     /* which uid is oldest connect */
                          primary_count;
  ExtRteList            * ext;      
  ConfigTree::Service   & svc;            /* service definition */
  ConfigTree::Transport & transport;      /* transport definition */

  void * operator new( size_t, void *ptr ) { return ptr; }
  void operator delete( void *ptr ) { ::free( ptr ); }

  TransportRoute( kv::EvPoll &p,  SessionMgr &m,  ConfigTree::Service &s,
                  ConfigTree::Transport &t,  const char *svc_name,
                  uint32_t svc_id,  uint32_t id,  uint32_t f ) noexcept;

  bool is_svc( void )   const { return this->is_set( TPORT_IS_SVC ) != 0; }
  bool is_mcast( void ) const { return this->is_set( TPORT_IS_MCAST ) != 0; }
  bool is_mesh( void )  const { return this->is_set( TPORT_IS_MESH ) != 0; }
  bool is_edge( void )  const { return this->is_set( TPORT_IS_EDGE ) != 0; }

  int init( void ) noexcept;
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
  bool create_transport( ConfigTree::Transport &tport ) noexcept;

  bool add_mesh_connect( const char *mesh_url,  uint32_t mesh_hash ) noexcept;

  EvTcpTransportListen *create_tcp_listener( bool rand_port,
                                        ConfigTree::Transport &tport ) noexcept;
  bool create_tcp_connect( ConfigTree::Transport &tport ) noexcept;

  bool create_rv_listener( ConfigTree::Transport &tport ) noexcept;
  bool create_rv_connect( ConfigTree::Transport &tport ) noexcept;

  bool create_nats_listener( ConfigTree::Transport &tport ) noexcept;
  bool create_nats_connect( ConfigTree::Transport &tport ) noexcept;

  bool create_redis_listener( ConfigTree::Transport &tport ) noexcept;
  bool create_redis_connect( ConfigTree::Transport &tport ) noexcept;

  EvTcpTransportListen *create_mesh_listener(
                                        ConfigTree::Transport &tport ) noexcept;
  /*TcpConnectionMgr *create_mesh_connect( void ) noexcept;*/
  EvTcpTransportListen *create_mesh_rendezvous( 
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
  uint32_t shutdown( ConfigTree::Transport &tport ) noexcept;
  bool start_listener( kv::EvTcpListen *l,  bool rand_port,
                       ConfigTree::Transport &tport ) noexcept;
  /* a new connection */
  virtual void on_connect( kv::EvSocket &conn ) noexcept;
  /* a disconnect */
  virtual void on_shutdown( kv::EvSocket &conn,  const char *,
                            size_t ) noexcept;
};

/*struct TransportList : public kv::SLinkList<TransportRoute> {
  uint32_t tport_count;
  TransportList() : tport_count( 0 ) {}
};*/

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

#if 0
template <class Protocol>
struct ConnectionMgr : public Protocol, public ReconnectMgr,
                       public kv::EvTimerCallback {
  void * operator new( size_t, void *ptr ) { return ptr; }
  void operator delete( void *ptr ) { ::free( ptr ); }

  ConnectionMgr( kv::EvPoll &p,  uint8_t type )
    : Protocol( p, type ), ReconnectMgr( p, *this ) {}

  bool do_connect( void ) {
    if ( ! this->Protocol::connect( this ) ) {
      this->ReconnectMgr::connect_failed( *this );
      return false;
    }
    return true;
  }
  virtual bool timer_cb( uint64_t, uint64_t ) noexcept {
    if ( this->ReconnectMgr::is_reconnecting ) {
      this->ReconnectMgr::is_reconnecting = false;
      if ( ! this->ReconnectMgr::is_shutdown &&
           ! this->ReconnectMgr::poll.quit )
        this->do_connect();
    }
    return false;
  }
};
#endif
}
}

#endif
