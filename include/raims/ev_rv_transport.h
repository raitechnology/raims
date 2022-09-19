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

struct RvHostRoute {
  RvHostRoute           * next,
                        * back;
  sassrv::RvHost        * host;       /* service/network pair */
  TransportRoute        * rte;        /* route for host */
  ConfigTree::Transport * cfg;
  uint64_t                last_active_mono;
  bool                    is_active,
                          tport_exists;

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

struct EvRvTransportListen : public sassrv::EvRvListen {
  TransportRoute & rte;
  RvHostTab        tab;
  uint64_t         last_active_mono;
  uint32_t         active_cnt;
  bool             no_mcast,
                   no_perminent;
  EvRvTransportListen( kv::EvPoll &p,  TransportRoute &r ) noexcept;

  ConfigTree::Transport *get_rv_transport( sassrv::RvHost &host,
                                           bool create ) noexcept;
  void make_rv_transport( ConfigTree::Transport *&t,  sassrv::RvHost &host,
                          bool &is_listener ) noexcept;
  /* sassrv rv listen */
  virtual EvSocket *accept( void ) noexcept;
  virtual int listen( const char *ip,  int port,  int opts ) noexcept;
  virtual int start_host( sassrv::RvHost &host, const char *net, size_t net_len,
                           const char *svc,  size_t svc_len ) noexcept;
  virtual int stop_host( sassrv::RvHost &host ) noexcept;
  virtual bool timer_expire( uint64_t tid,  uint64_t kind ) noexcept;
};

}
}

#endif
