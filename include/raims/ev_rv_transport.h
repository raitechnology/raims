#ifndef __rai_raims__ev_rv_transport_h__
#define __rai_raims__ev_rv_transport_h__

#include <sassrv/ev_rv.h>
#include <raims/msg.h>
#include <raims/sub.h>
#include <raims/config_tree.h>
#include <raikv/dlinklist.h>

namespace rai {
namespace ms {

struct TransportRoute;

enum NetTransport {
  NET_NONE         = 0,
  NET_ANY          = 1,
  NET_MESH         = 2,
  NET_MESH_LISTEN  = 3,
  NET_MESH_CONNECT = 4,
  NET_TCP          = 5,
  NET_TCP_LISTEN   = 6,
  NET_TCP_CONNECT  = 7,
  NET_MCAST        = 8
};

struct RvMcast2 : public sassrv::RvMcast {
  NetTransport type;
  RvMcast2() : type( NET_NONE ) {}
  int parse_network2( const char *net,  size_t net_len ) noexcept;
  static NetTransport net_to_transport( const char *net,
                                        size_t &net_len ) noexcept;
};

struct RvHostRoute {
  RvHostRoute           * next,
                        * back;
  sassrv::RvHost        * host;       /* service/network pair */
  TransportRoute        * rte;        /* route for host */
  ConfigTree::Transport * cfg;        /* config for the host */
  uint64_t                last_active_mono; /* start or stop time */
  bool                    is_active,    /* is running */
                          tport_exists; /* whether network exists */

  void * operator new( size_t, void *ptr ) { return ptr; }
  void operator delete( void *ptr ) { ::free( ptr ); }

  RvHostRoute( sassrv::RvHost *h,  TransportRoute *r,
               ConfigTree::Transport *t )
    : next( 0 ), back( 0 ), host( h ), rte( r ), cfg( t ),
      last_active_mono( 0 ), is_active( false ), tport_exists( false ) {}
};

struct RvHostTab {
  kv::DLinkList<RvHostRoute> list;

  RvHostRoute *find( sassrv::RvHost *h ) {
    RvHostRoute *p = this->list.hd;
    if ( p == NULL || p->host == h )
      return p;
    for ( p = p->next; p != NULL; p = p->next ) {
      if ( p->host == h ) {
        this->list.pop( p );
        this->list.push_hd( p );
        return p;
      }
    }
    return NULL;
  }
  RvHostRoute *add( sassrv::RvHost *h,  TransportRoute *r,
                    ConfigTree::Transport *t ) {
    void * p = ::malloc( sizeof( RvHostRoute ) );
    this->list.push_hd( new ( p ) RvHostRoute( h, r, t ) );
    return this->list.hd;
  }
};

struct RvTransportService : public kv::EvTimerCallback {
  TransportRoute & rte;
  sassrv::RvHostDB db;               /* tables of rv hosts, rv daemons */
  RvHostTab        tab;              /* connect the host to the network (rte) */
  uint64_t         last_active_mono; /* time started or stopped */
  uint32_t         active_cnt,       /* number of clients connected any rv */
                   start_cnt;        /* start ref count, keep host alive */
  bool             no_mcast,         /* config no_mcast setting */
                   no_permanent,     /* command line -no-perm */
                   no_fakeip;        /* whether to use real ip addresses */

  void * operator new( size_t, void *ptr ) { return ptr; }
  RvTransportService( TransportRoute &r ) noexcept;

  void start( void ) noexcept;
  ConfigTree::Transport *get_rv_transport( sassrv::RvHost &host,
                                           bool create ) noexcept;
  void make_rv_transport( ConfigTree::Transport *&t,  sassrv::RvHost &host,
                          bool &is_listener ) noexcept;

  int start_host( sassrv::RvHost &host, const sassrv::RvHostNet &hn,
                  uint32_t &delay_secs ) noexcept;
  void stop_host( sassrv::RvHost &host ) noexcept;
  /* EvTimerCallback */
  virtual bool timer_cb( uint64_t, uint64_t ) noexcept;
  void outbound_data_loss( uint16_t svc,  uint32_t msg_loss,  uint32_t pub_host,
                           const char *pub_host_id ) noexcept;
};

struct EvRvTransportListen : public sassrv::EvRvListen {
  TransportRoute     & rte;
  RvTransportService & svc;   /* the host and daemons */
  EvRvTransportListen( kv::EvPoll &p,  TransportRoute &r,
                       RvTransportService &s ) noexcept;
  /* sassrv rv listen */
  virtual EvSocket *accept( void ) noexcept;
  virtual int listen( const char *ip,  int port,  int opts ) noexcept;
  virtual int start_host( sassrv::RvHost &host,
                          const sassrv::RvHostNet &hn ) noexcept;
  virtual int stop_host( sassrv::RvHost &host ) noexcept;
};

}
}

#endif
