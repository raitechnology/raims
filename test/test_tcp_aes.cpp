#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <raims/ev_tcp_aes.h>
#include <raikv/ev_tcp.h>

using namespace rai;
using namespace kv;
using namespace ms;

struct TcpListen : public EvTcpListen {
  bool encrypt;

  TcpListen( EvPoll &p ) noexcept;

  virtual EvSocket *accept( void ) noexcept;
};

struct TcpConn : public AES_Connection {
  void * operator new( size_t, void *ptr ) { return ptr; }
  TcpConn( EvPoll &p,  uint8_t st ) : AES_Connection( p, st ) {}
  virtual void process( void ) noexcept;
  virtual void release( void ) noexcept;
  virtual void process_shutdown( void ) noexcept;
  virtual void process_close( void ) noexcept;
};

struct TcpPing : public AES_Connection {
  void * operator new( size_t, void *ptr ) { return ptr; }
  TcpPing( EvPoll &p ) : AES_Connection( p, 0 ) {}
  void send_ping( void ) noexcept;
  virtual bool timer_expire( uint64_t, uint64_t ) noexcept;
  virtual void process( void ) noexcept;
  virtual void release( void ) noexcept;
  virtual void process_shutdown( void ) noexcept;
  virtual void process_close( void ) noexcept;
};

TcpListen::TcpListen( EvPoll &p ) noexcept
         : EvTcpListen( p, "tcp_listen", "aes_conn" ), encrypt( true ) {}

EvSocket *
TcpListen::accept( void ) noexcept
{
  TcpConn *c = this->poll.get_free_list<TcpConn>( this->accept_sock_type );
  if ( c == NULL )
    return NULL;
  if ( this->accept2( *c, "aes_accept" ) ) {
    printf( "accept %.*s\n", (int) c->get_peer_address_strlen(),
            c->peer_address.buf );
    if ( this->encrypt ) {
      c->init_exchange( NULL, 0 );
      c->send_key();
    }
    return c;
  }
  return NULL;
}

void
TcpConn::process( void ) noexcept
{
  if ( this->off < this->len ) {
    this->append( &this->recv[ this->off ], ( this->len - this->off ) );
    this->off = this->len;
    this->msgs_recv++;
    this->msgs_sent++;
  }
  this->pop( EV_PROCESS );
  this->push_write();
}

void
TcpConn::release( void ) noexcept
{
  printf( "release %.*s\n", (int) this->get_peer_address_strlen(),
          this->peer_address.buf );
  this->EvConnection::release_buffers();
}

void
TcpConn::process_shutdown( void ) noexcept
{
  printf( "shutdown %.*s\n", (int) this->get_peer_address_strlen(),
          this->peer_address.buf );
  this->pushpop( EV_CLOSE, EV_SHUTDOWN );
}

void
TcpConn::process_close( void ) noexcept
{
  printf( "close %.*s\n", (int) this->get_peer_address_strlen(),
          this->peer_address.buf );
  this->EvSocket::process_close();
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
  printf( "shutdown %.*s\n", (int) this->get_peer_address_strlen(),
          this->peer_address.buf );
  this->pushpop( EV_CLOSE, EV_SHUTDOWN );
}

void
TcpPing::release( void ) noexcept
{
  printf( "release %.*s\n", (int) this->get_peer_address_strlen(),
          this->peer_address.buf );
  this->EvConnection::release_buffers();
}

void
TcpPing::process_close( void ) noexcept
{
  printf( "close %.*s\n", (int) this->get_peer_address_strlen(),
          this->peer_address.buf );
  if ( this->poll.quit == 0 )
    this->poll.quit = 1;
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

static const char *
get_arg( int argc, char *argv[], int b, const char *f,
         const char *def ) noexcept
{
  for ( int i = 1; i < argc - b; i++ ) {
    if ( ::strcmp( f, argv[ i ] ) == 0 ) {
      if ( b == 0 || argv[ i + b ][ 0 ] != '-' )
        return argv[ i + b ];
      return def;
    }
  }
  return def; /* default value */
}

int
main( int argc, char *argv[] )
{ 
  SignalHandler sighndl;
  EvPoll poll;
  TcpListen test( poll );
  TcpPing   ping( poll );
  const char * host;
  int idle_count = 0; 
  bool encrypt = true;
  poll.init( 5, false );
  
  if ( get_arg( argc, argv, 0, "-n", NULL ) ) {
    encrypt = false;
    printf( "disabling encryption\n" );
  }
  if ( get_arg( argc, argv, 0, "-c", NULL ) != NULL ) {
    host = get_arg( argc, argv, 1, "-c", NULL );
    if ( EvTcpConnection::connect( ping, host, 9000,
                              DEFAULT_TCP_CONNECT_OPTS | OPT_CONNECT_NB ) != 0 )
      return 1;
    if ( encrypt ) {
      ping.init_exchange( NULL, 0 );
      ping.send_key();
    }
    ping.send_ping();
    poll.timer.add_timer_seconds( ping.fd, 1, 1, 1 );
  }
  else {
    test.encrypt = encrypt;
    if ( test.listen( NULL, 9000, DEFAULT_TCP_LISTEN_OPTS ) != 0 )
      return 1;
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

