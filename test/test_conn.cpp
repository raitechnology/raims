#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <raims/transport.h>
#include <raims/ev_tcp_aes.h>
#include <raikv/ev_cares.h>
#include <raikv/array_space.h>

using namespace rai;
using namespace kv;
using namespace ms;

struct TcpPing : public AES_Connection {
  void * operator new( size_t, void *ptr ) { return ptr; }
  TcpPing( EvPoll &p,  uint8_t st ) : AES_Connection( p, st ) {}
  void start( void ) noexcept;
  void send_ping( void ) noexcept;
  virtual bool timer_expire( uint64_t, uint64_t ) noexcept;
  virtual void process( void ) noexcept;
  virtual void release( void ) noexcept;
  virtual void process_shutdown( void ) noexcept;
  virtual void process_close( void ) noexcept;
};

struct ConnectPing : public ConnectDB {
  ConnectPing( EvPoll &p,  uint8_t st ) : ConnectDB( p, st ) {}
  virtual bool connect( ConnectCtx &ctx ) noexcept;
  virtual void on_connect( ConnectCtx &ctx ) noexcept;
  virtual bool on_shutdown( ConnectCtx &ctx,  const char *msg,
                            size_t len ) noexcept;
  virtual void on_timeout( ConnectCtx &ctx ) noexcept;
  virtual void on_dns( ConnectCtx &ctx,  const char *host,  int port,
                       int opts ) noexcept;
};

bool
ConnectPing::connect( ConnectCtx &ctx ) noexcept
{
  TcpPing *ping = this->poll.get_free_list<TcpPing>( this->sock_type );
  ping->notify = &ctx;
  if ( EvTcpConnection::connect3( *ping, ctx.addr_info.addr_list,
                                  ctx.opts, "tcp_ping", -1 ) == 0 ) {
    ctx.client = ping;
    ping->start();
    return true;
  }
  this->poll.push_free_list( ping );
  return false;
}

void
ConnectPing::on_connect( ConnectCtx &ctx ) noexcept
{
  ((TcpPing *) ctx.client)->send_ping();
}

bool
ConnectPing::on_shutdown( ConnectCtx &ctx,  const char *msg,
                          size_t len ) noexcept
{
  printf( "on shutdown %lu %.*s\n", ctx.event_id, (int) len, msg );
  return true;
}

void
ConnectPing::on_timeout( ConnectCtx &ctx ) noexcept
{
  printf( "on timeout, connect tries %u, time %.1f\n", ctx.connect_tries,
    (double) ( current_monotonic_time_ns() - ctx.start_time ) / 1000000000.0 );
}

void
ConnectPing::on_dns( ConnectCtx &,  const char *host,  int port,
                     int opts ) noexcept
{
  printf( "resolving %s:%d opts(%x)\n", host, port, opts );
}

static uint64_t timer_id;
void
TcpPing::start( void ) noexcept
{
  printf( "start\n" );
  this->init_exchange( NULL, 0 );
  this->send_key();
  this->send_ping();
  this->poll.timer.add_timer_seconds( this->fd, 1, ++timer_id, 1 );
}

void
TcpPing::process( void ) noexcept
{
  for (;;) {
    double d;
    size_t buflen = this->len - this->off;
    if ( buflen >= 8 + sizeof( d ) &&
         ::memcmp( &this->recv[ this->off ], "ping1234", 8 ) == 0 ) {
      ::memcpy( &d, &this->recv[ this->off + 8 ], sizeof( d ) );
      printf( "latency: %.6f\n", current_monotonic_time_s() - d );
      this->off += 8 + sizeof( d );
      this->msgs_recv++;
    }
    else {
      break;
    }
  }
  this->pop( EV_PROCESS );
}

void
TcpPing::process_shutdown( void ) noexcept
{
  printf( "shutdown %.*s (%d)\n", (int) this->get_peer_address_strlen(),
          this->peer_address.buf, this->fd );
  this->pushpop( EV_CLOSE, EV_SHUTDOWN );
}

void
TcpPing::release( void ) noexcept
{
  if ( ! this->poll.timer.remove_timer( this->fd, timer_id, 1 ) )
    printf( "no timer\n" );
  printf( "release %.*s\n", (int) this->get_peer_address_strlen(),
          this->peer_address.buf );
  this->AES_Connection::release_aes();
  this->EvConnection::release_buffers();
  if ( this->notify != NULL )
    this->notify->on_shutdown( *this, NULL, 0 );
}

void
TcpPing::process_close( void ) noexcept
{
  printf( "close %.*s\n", (int) this->get_peer_address_strlen(),
          this->peer_address.buf );
  this->EvSocket::process_close();
}

void
TcpPing::send_ping( void ) noexcept
{
  double d = current_monotonic_time_s();
  this->append2( "ping1234", 8, &d, sizeof( d ) );
  this->msgs_sent++;
  this->idle_push( EV_WRITE );
}

bool
TcpPing::timer_expire( uint64_t, uint64_t ) noexcept
{
  this->send_ping();
  return true;
}
int
main( int argc, char** argv )
{
  SignalHandler sighndl;
  EvPoll poll;
  ConnectPing mgr( poll, poll.register_type( "tcp_ping" ) );
  int idle_count = 0;

  poll.init( 5, false );
  for ( int i = 1; i < argc; i++ ) {
    const char * dest = argv[ i ];
    const char * ptr = ::strchr( dest, ':' );
    if ( ptr == NULL )
      continue;
    size_t len  = ptr - dest;
    char   host[ 256 ];
    if ( len >= sizeof( host ) )
      len = sizeof( host ) - 1;
    ::memcpy( host, dest, len );
    host[ len ] = '\0';
    int port = atoi( ptr + 1 );

    const char * h = ( ::strcmp( host, "null" ) == 0 ? NULL : host );
    mgr.create( i )->connect( h, port, DEFAULT_TCP_CONNECT_OPTS |
                                       OPT_CONNECT_NB, 15 );
  }
  sighndl.install();
  for (;;) {
    /* loop 5 times before quiting, time to flush writes */
    if ( poll.quit >= 5 && idle_count > 0 )
      break;
    /* dispatch network events */
    int idle = poll.dispatch();
    if ( idle == EvPoll::DISPATCH_IDLE )
      idle_count++;
    else
      idle_count = 0;
    /* wait for network events */
    poll.wait( idle_count > 2 ? 100 : 0 );
    if ( sighndl.signaled )
      poll.quit++;
  }
  return 0;
}

