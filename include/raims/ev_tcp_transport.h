#ifndef __rai_raims__ev_tcp_transport_h__
#define __rai_raims__ev_tcp_transport_h__

#include <raikv/ev_tcp.h>
#include <raims/ev_tcp_aes.h>
#include <raims/msg.h>
#include <raims/config_tree.h>

namespace rai {
namespace ms {

extern int no_tcp_aes; /* turn off tcp aes encryption */
struct TransportRoute;
struct SessionMgr;
/* tcp listener for accepting EvTcpTransportService connections */
struct EvTcpTransportListen : public kv::EvTcpListen {
  TransportRoute & rte;
  bool encrypt;

  void * operator new( size_t, void *ptr ) { return ptr; }

  EvTcpTransportListen( kv::EvPoll &p, TransportRoute &r ) noexcept;
  /* EvListen */
  virtual EvSocket *accept( void ) noexcept;
  virtual int listen( const char *ip,  int port,  int opts ) noexcept;
  virtual void release( void ) noexcept;
  virtual void process_close( void ) noexcept;
};

struct EvTcpTransport : public AES_Connection, public kv::BPData {
  enum {
    TCP_BACKPRESSURE = 1,
    TCP_BUFFERSIZE   = 2,
    TCP_HAS_TIMER    = 4
  };
  MsgFrameDecoder    msg_in;
  TransportRoute   * rte;
  uint64_t           timer_id;
  uint8_t            tcp_state;
  bool               fwd_all_msgs,   /* send publishes */
                     is_connect,
                     encrypt;

  EvTcpTransport( kv::EvPoll &p,  uint8_t t ) noexcept;
  void start( uint64_t tid ) noexcept;

  enum { TCP_FLOW_GOOD = 0, TCP_FLOW_BACKPRESSURE = 1, TCP_FLOW_STALLED = 2 };
  int dispatch_msg( void ) noexcept;
  bool fwd_msg( kv::EvPublish &pub ) noexcept;

  virtual void process( void ) noexcept; /* decode read buffer */
  virtual void release( void ) noexcept; /* after shutdown release mem */
  virtual void process_close( void ) noexcept;
  virtual void read( void ) noexcept;
  virtual bool on_msg( kv::EvPublish &pub ) noexcept; /* fwd to NATS network */
  virtual bool timer_expire( uint64_t tid, uint64_t eid ) noexcept;
  virtual void on_write_ready( void ) noexcept;
};

static const size_t MAX_TCP_HOST_LEN = 256;

enum {
  PARAM_REUSEPORT  = 1,
  PARAM_NB_CONNECT = 2,
  PARAM_LISTEN     = 4
};
static const int TCP_OPT_ENCRYPT = 0x10000; /* u16 reserved */
static const int TCP_TRANSPORT_CONNECT_OPTS =
  ( kv::DEFAULT_TCP_CONNECT_OPTS &
  ~( kv::OPT_REUSEPORT | kv::OPT_VERBOSE ) ) |
  kv::OPT_CONNECT_NB;

struct EvTcpTransportOpts {
  int  opts,      /* tcp opts */
       timeout;   /* connect timeout seconds */
  bool edge,      /* if listen edge true, don't create transport*/
       noencrypt; /* don't encrypt connection */

  EvTcpTransportOpts() {
    this->opts      = TCP_TRANSPORT_CONNECT_OPTS;
    this->timeout   = 10;
    this->edge      = false;
    this->noencrypt = false;
  }
  void parse( ConfigTree::Transport &tport,  int ptype,
              SessionMgr &mgr ) noexcept;
};

struct HostPort {
  char * host;
  int    port;
  char   buf[ MAX_TCP_HOST_LEN ];
};

struct HostPortArray : public kv::ArrayCount<HostPort, 4> {
  void append( const char *host,  int port ) {
    HostPort & hp = this->push();
    hp.port = port;
    if ( host == NULL )
      hp.host = NULL;
    else {
      size_t len = ::strlen( host );
      hp.host = hp.buf;
      if ( len > sizeof( hp.buf ) )
        len = sizeof( hp.buf ) - 1;
      ::memcpy( hp.buf, host, len );
      hp.buf[ len ] = '\0';
    }
  }
};

struct EvTcpTransportParameters : public EvTcpTransportOpts {
  HostPortArray hosts;
  int default_port;

  int port( size_t n ) {
    if ( n < this->hosts.count )
      return this->hosts.ptr[ n ].port;
    return this->default_port;
  }
  const char * host( size_t n ) {
    if ( n < this->hosts.count )
      return this->hosts.ptr[ n ].host;
    return NULL;
  }
  EvTcpTransportParameters() : default_port( 0 ) {}
  void parse_tport( ConfigTree::Transport &tport,  int ptype,
                    SessionMgr &mgr ) noexcept;
  static int get_listen_port( ConfigTree::Transport &tport ) noexcept;
};

struct EvTcpTransportClient : public EvTcpTransport {
  void * operator new( size_t, void *ptr ) { return ptr; }
  EvTcpTransportClient( kv::EvPoll &p,  uint8_t t )
    : EvTcpTransport( p, t )/*, parm( this->host_buf )*/ {
    /*this->host_buf[ 0 ] = '\0';*/
    this->fwd_all_msgs = false;
  }
  bool connect( int opts, kv::EvConnectionNotify *n,
                struct addrinfo *addr_list,  uint64_t timer_id ) noexcept;
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
