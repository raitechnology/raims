#ifndef __rai_raims__ev_tcp_transport_h__
#define __rai_raims__ev_tcp_transport_h__

#include <raikv/ev_tcp.h>
#include <raims/msg.h>
#include <raims/config_tree.h>

namespace rai {
namespace ms {

struct TransportRoute;
/* tcp listener for accepting EvTcpTransportService connections */
struct EvTcpTransportListen : public kv::EvTcpListen {
  TransportRoute & rte;

  void * operator new( size_t, void *ptr ) { return ptr; }

  EvTcpTransportListen( kv::EvPoll &p, TransportRoute &r ) noexcept;
  /* EvListen */
  virtual EvSocket *accept( void ) noexcept;
  virtual int listen( const char *ip,  int port,  int opts ) noexcept;
  virtual void release( void ) noexcept final;
  virtual void process_close( void ) noexcept final;
};

struct EvTcpTransport : public kv::EvConnection {
  MsgFrameDecoder    msg_in;
  TransportRoute   * rte;
  bool               fwd_all_msgs,   /* send publishes */
                     is_connect;

  EvTcpTransport( kv::EvPoll &p,  uint8_t t ) noexcept;
  void start( void ) noexcept;

  bool dispatch_msg( void ) noexcept;
  bool fwd_msg( kv::EvPublish &pub ) noexcept;

  virtual void process( void ) noexcept final; /* decode read buffer */
  virtual void release( void ) noexcept final; /* after shutdown release mem */
  virtual void process_close( void ) noexcept final;
  virtual bool on_msg( kv::EvPublish &pub ) noexcept; /* fwd to NATS network */
};

static const size_t MAX_TCP_HOST_LEN = 256,
                    MAX_TCP_HOSTS    = 8;
enum {
  PARAM_REUSEPORT  = 1,
  PARAM_NB_CONNECT = 2,
  PARAM_LISTEN     = 4
};

struct EvTcpTransportParameters {
  const char * host[ MAX_TCP_HOSTS ]; /* connect host */
  int          port[ MAX_TCP_HOSTS ], /* connect port */
               opts,      /* tcp opts */
               timeout;   /* connect timeout seconds */
  uint32_t     hash[ MAX_TCP_HOSTS ];
  bool         edge;      /* if listen edge true, don't create transport*/
  char         buf[ MAX_TCP_HOSTS ][ MAX_TCP_HOST_LEN ];
  void * operator new( size_t, void *ptr ) { return ptr; }

  EvTcpTransportParameters() {
    for ( size_t i = 0; i < MAX_TCP_HOSTS; i++ ) {
      this->host[ i ] = NULL;
      this->port[ i ] = 0;
      this->hash[ i ] = 0;
      this->buf[ i ][ 0 ] = '\0';
    }
    this->opts    = kv::DEFAULT_TCP_CONNECT_OPTS;
    this->opts   &= ~( kv::OPT_REUSEPORT | kv::OPT_VERBOSE );
    this->opts   |= kv::OPT_CONNECT_NB;
    this->timeout = 10;
    this->edge    = false;
  }

  static size_t copy_host_buf( char buf[ MAX_TCP_HOST_LEN ],  size_t off,
                               const char * host ) {
    size_t len = ::strlen( host );
    if ( off + len >= MAX_TCP_HOST_LEN )
      len = MAX_TCP_HOST_LEN - ( off + 1 );
    ::memcpy( &buf[ off ], host, len );
    buf[ off + len ] = '\0';
    return off + len;
  }

  EvTcpTransportParameters( const EvTcpTransportParameters &p ) {
    this->opts    = p.opts;
    this->timeout = p.timeout;
    this->edge    = p.edge;
    ::memcpy( this->buf, p.buf, sizeof( this->buf ) );

    for ( size_t i = 0; i < MAX_TCP_HOSTS; i++ ) {
      this->port[ i ] = p.port[ i ];
      this->hash[ i ] = p.hash[ i ];
      if ( p.host[ i ] == NULL )
        this->host[ i ] = NULL;
      else {
        this->host[ i ] = this->buf[ i ];
        copy_host_buf( this->buf[ i ], 0, p.host[ i ] );
      }
    }
  }

  void set_host_port( const char *ho,  int po,  uint32_t h,  int k ) {
    this->port[ k ] = po;
    this->host[ k ] = this->buf[ k ];
    this->hash[ k ] = h;
    copy_host_buf( this->buf[ k ], 0, ho );
  }

  void set_host_port( const char *h[ MAX_TCP_HOSTS ], int p[ MAX_TCP_HOSTS ] ) {
    for ( size_t i = 0; i < MAX_TCP_HOSTS; i++ ) {
      this->port[ i ] = p[ i ];
      if ( h[ i ] == NULL )
        this->host[ i ] = NULL;
      else {
        this->host[ i ] = this->buf[ i ];
        copy_host_buf( this->buf[ i ], 0, h[ i ] );
      }
    }
  }

  EvTcpTransportParameters *copy( void ) const {
    void *m = ::malloc( sizeof( EvTcpTransportParameters ) );
    EvTcpTransportParameters *p = new ( m ) EvTcpTransportParameters( *this );
    return p;
  }

  void parse_tport( ConfigTree::Transport &tport,  int ptype ) noexcept;
};

struct EvTcpTransportClient : public EvTcpTransport {
  /*EvTcpTransportParameters parm;
  char host_buf[ 256 ];*/
  void * operator new( size_t, void *ptr ) { return ptr; }

  EvTcpTransportClient( kv::EvPoll &p,  uint8_t t )
    : EvTcpTransport( p, t )/*, parm( this->host_buf )*/ {
    /*this->host_buf[ 0 ] = '\0';*/
    this->fwd_all_msgs = false;
  }
  bool connect( EvTcpTransportParameters &p,
                kv::EvConnectionNotify *n,  int index ) noexcept;
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
