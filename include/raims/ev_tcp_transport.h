#ifndef __rai_raims__ev_tcp_transport_h__
#define __rai_raims__ev_tcp_transport_h__

#include <raikv/ev_tcp.h>
#include <raims/msg.h>

namespace rai {
namespace ms {

struct TransportRoute;
/* tcp listener for accepting EvTcpTransportService connections */
struct EvTcpTransportListen : public kv::EvTcpListen {
  TransportRoute & rte;

  void * operator new( size_t, void *ptr ) { return ptr; }

  EvTcpTransportListen( kv::EvPoll &p, TransportRoute &r ) noexcept;
  /* EvListen */
  virtual bool accept( void ) noexcept;
  int listen( const char *ip,  int port,  int opts ) noexcept;
  virtual void release( void ) noexcept final;
};

struct EvTcpTransport : public kv::EvConnection {
  MsgFrameDecoder    msg_in;
  TransportRoute   * rte;
  /*size_t           * tport_count;
  uint32_t           not_fd2;*/
  bool               fwd_all_msgs,   /* send publishes */
                     is_connect;

  EvTcpTransport( kv::EvPoll &p,  uint8_t t ) noexcept;
  void start( void ) noexcept;

  bool dispatch_msg( void ) noexcept;
  bool fwd_msg( kv::EvPublish &pub ) noexcept;

  virtual void process( void ) noexcept final; /* decode read buffer */
  virtual void release( void ) noexcept final; /* after shutdown release mem */
  virtual bool on_msg( kv::EvPublish &pub ) noexcept; /* fwd to NATS network */
};

struct EvTcpTransportParameters {
  const char * host;    /* connect host */
  int          port,    /* connect port */
               opts,    /* tcp opts */
               timeout; /* connect timeout seconds */
  bool         edge;    /* if listen edge true, don't create transport*/
  void * operator new( size_t, void *ptr ) { return ptr; }
  EvTcpTransportParameters( const char *h = NULL,  int p = 4222,
                            int o = ( kv::DEFAULT_TCP_CONNECT_OPTS &
                                     ~kv::OPT_REUSEPORT &
                                     ~kv::OPT_VERBOSE ) | kv::OPT_CONNECT_NB )
    : host( h ), port( p ), opts( o ), timeout( 15 ), edge( false ) {}

  void copy( const EvTcpTransportParameters &p,  char *host_buf ) {
    if ( p.host != NULL ) {
      this->host = host_buf;
      ::strcpy( host_buf, p.host );
    }
    else {
      this->host = NULL;
    }
    this->port    = p.port;
    this->opts    = p.opts;
    this->timeout = p.timeout;
    this->edge    = p.edge;
  }
};

struct EvTcpTransportClient : public EvTcpTransport {
  EvTcpTransportParameters parm;
  char host_buf[ 256 ];
  void * operator new( size_t, void *ptr ) { return ptr; }

  EvTcpTransportClient( kv::EvPoll &p,  uint8_t t )
    : EvTcpTransport( p, t ), parm( this->host_buf ) {
    this->host_buf[ 0 ] = '\0';
    this->fwd_all_msgs = false;
  }

  bool connect( kv::EvConnectionNotify *n ) noexcept;
};

struct EvTcpTransportService : public EvTcpTransport {
  void * operator new( size_t, void *ptr ) { return ptr; }

  EvTcpTransportService( kv::EvPoll &p,  const uint8_t t )
    : EvTcpTransport( p, t ) {
    this->fwd_all_msgs = false;
  }
};

}
}

#endif
